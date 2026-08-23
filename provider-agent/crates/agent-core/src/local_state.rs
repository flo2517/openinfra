use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Mutex;
use thiserror::Error;

const HEARTBEAT_SEQUENCE_KEY: &[u8] = b"heartbeat_sequence";
const WORKLOAD_TREE: &str = "workloads-v1";
const METERING_TREE: &str = "metering-cursors-v1";

#[derive(Debug, Error)]
pub enum LocalStateError {
    #[error("local state storage failed: {0}")]
    Storage(#[from] sled::Error),
    #[error("stored heartbeat sequence is corrupt")]
    CorruptSequence,
    #[error("heartbeat sequence overflow")]
    SequenceOverflow,
    #[error("metering sequence overflow for workload {0}")]
    MeteringSequenceOverflow(String),
    #[error("stored metering cursor for workload {0} is corrupt")]
    CorruptMeteringCursor(String),
    #[error("workload state serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("workload {0} was not found")]
    WorkloadNotFound(String),
    #[error("workload {0} already exists with another specification")]
    WorkloadConflict(String),
    #[error("maximum active workload count ({0}) reached")]
    WorkloadCapacity(usize),
    #[error("workload state lock is poisoned")]
    LockPoisoned,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum WorkloadPhase {
    Provisioning,
    Starting,
    Running,
    Stopping,
    Stopped,
    Failed,
    Lost,
}

impl WorkloadPhase {
    pub fn consumes_capacity(self) -> bool {
        !matches!(self, Self::Stopped | Self::Failed | Self::Lost)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkloadRecord {
    pub workload_id: String,
    pub lease_id: String,
    pub image: String,
    pub spec_hash: [u8; 32],
    pub container_id: Option<String>,
    pub phase: WorkloadPhase,
    /// ADR-025 §3: the workload's reserved egress rate, Mbps, persisted
    /// (not just held transiently in the DeployRequest) so a process
    /// restart's `recover()` and a retried `deploy()` call both know
    /// whether a `tc` rule needs (re)applying without needing the
    /// original request again. 0 means "no bandwidth requirement
    /// declared", matching `ContainerSpec::egress_mbps`'s own convention.
    /// `#[serde(default)]` so records persisted before this field existed
    /// deserialize to 0 (no rate limit expected), not a hard error.
    #[serde(default)]
    pub egress_mbps: i32,
    /// Whether `rate_limit()` has actually succeeded for this workload's
    /// current container. Deliberately separate from `phase`: a rate
    /// limit failure must never be conflated with the *container itself*
    /// failing (see `WorkloadPhase::consumes_capacity` -- marking a
    /// still-running container `Failed` would silently free a capacity
    /// slot for a container that is, in fact, still consuming real
    /// resources unthrottled). `deploy()`'s retry path and `recover()`
    /// both check this to decide whether a `tc` rule still needs
    /// (re)applying. `#[serde(default)]` for the same backward-compat
    /// reason as `egress_mbps`.
    #[serde(default)]
    pub rate_limited: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reservation {
    New,
    Existing,
}

/// One workload's next signed usage-evidence window, returned by
/// `next_metering_period`. `sequence` is the value the caller must place
/// on the `MeteringSummary` it signs and sends; `period_start`/
/// `period_end` are Unix seconds bounding the usage window that sequence
/// covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeteringPeriod {
    pub sequence: u64,
    pub period_start: u64,
    pub period_end: u64,
}

fn encode_metering_cursor(next_sequence: u64, period_start: u64) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&next_sequence.to_be_bytes());
    bytes[8..].copy_from_slice(&period_start.to_be_bytes());
    bytes
}

fn decode_metering_cursor(workload_id: &str, bytes: &[u8]) -> Result<(u64, u64), LocalStateError> {
    if bytes.len() != 16 {
        return Err(LocalStateError::CorruptMeteringCursor(
            workload_id.to_string(),
        ));
    }
    let next_sequence = u64::from_be_bytes(bytes[..8].try_into().unwrap());
    let period_start = u64::from_be_bytes(bytes[8..].try_into().unwrap());
    Ok((next_sequence, period_start))
}

pub struct LocalState {
    database: sled::Db,
    workloads: sled::Tree,
    metering: sled::Tree,
    workload_lock: Mutex<()>,
}

impl LocalState {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LocalStateError> {
        let database = sled::open(path)?;
        let workloads = database.open_tree(WORKLOAD_TREE)?;
        let metering = database.open_tree(METERING_TREE)?;
        Ok(Self {
            database,
            workloads,
            metering,
            workload_lock: Mutex::new(()),
        })
    }

    /// Reserves the next monotonic sequence and bounded usage window for
    /// `workload_id`, persisting the advance durably (sled, like
    /// `next_heartbeat_sequence`) before returning it -- a process
    /// restart reopens the same cursor rather than silently restarting
    /// from sequence 1 (issue #20's "restart must not be silently
    /// treated as a valid continuation" acceptance criterion: this store
    /// makes a restart a non-event for sequence continuity; the Control
    /// Plane's own monotonicity check, internal/metering, is the
    /// authoritative backstop regardless of what this store contains).
    ///
    /// The very first call for a never-before-seen `workload_id` starts
    /// the period at `now` (sequence 1) -- this store has no
    /// container-start timestamp to anchor an earlier boundary, so
    /// nothing before the first call is billed. Every later call starts
    /// where the previous one's window ended.
    ///
    /// `period_end` is bounded to `period_start + max_period_seconds`
    /// (never further than `now`), and never regresses before
    /// `period_start` even if `now` is behind it (a regressed wall
    /// clock yields a valid, zero-length window rather than an error --
    /// the sequence still advances so a later, correctly-timed call is
    /// never blocked).
    pub fn next_metering_period(
        &self,
        workload_id: &str,
        now: u64,
        max_period_seconds: u64,
    ) -> Result<MeteringPeriod, LocalStateError> {
        loop {
            let current = self.metering.get(workload_id.as_bytes())?;
            let (next_sequence, period_start) = match current.as_deref() {
                Some(bytes) => {
                    let (sequence, period_start) = decode_metering_cursor(workload_id, bytes)?;
                    let next_sequence = sequence.checked_add(1).ok_or_else(|| {
                        LocalStateError::MeteringSequenceOverflow(workload_id.to_string())
                    })?;
                    (next_sequence, period_start)
                }
                None => (1, now),
            };
            let bound = period_start.saturating_add(max_period_seconds);
            let period_end = now.min(bound).max(period_start);
            let next_bytes = encode_metering_cursor(next_sequence, period_end);
            match self.metering.compare_and_swap(
                workload_id.as_bytes(),
                current.as_deref(),
                Some(next_bytes.as_slice()),
            )? {
                Ok(()) => {
                    self.metering.flush()?;
                    return Ok(MeteringPeriod {
                        sequence: next_sequence,
                        period_start,
                        period_end,
                    });
                }
                Err(_) => continue,
            }
        }
    }

    pub fn next_heartbeat_sequence(&self) -> Result<u64, LocalStateError> {
        loop {
            let current = self.database.get(HEARTBEAT_SEQUENCE_KEY)?;
            let sequence = match current.as_deref() {
                Some(bytes) => u64::from_be_bytes(
                    bytes
                        .try_into()
                        .map_err(|_| LocalStateError::CorruptSequence)?,
                ),
                None => 0,
            };
            let next = sequence
                .checked_add(1)
                .ok_or(LocalStateError::SequenceOverflow)?;
            let next_bytes = next.to_be_bytes();
            match self.database.compare_and_swap(
                HEARTBEAT_SEQUENCE_KEY,
                current.as_deref(),
                Some(next_bytes.as_slice()),
            )? {
                Ok(()) => {
                    self.database.flush()?;
                    return Ok(next);
                }
                Err(_) => continue,
            }
        }
    }

    pub fn reserve_workload(
        &self,
        candidate: &WorkloadRecord,
        max_active: usize,
    ) -> Result<Reservation, LocalStateError> {
        let _guard = self
            .workload_lock
            .lock()
            .map_err(|_| LocalStateError::LockPoisoned)?;
        if let Some(encoded) = self.workloads.get(candidate.workload_id.as_bytes())? {
            let existing: WorkloadRecord = serde_json::from_slice(&encoded)?;
            if existing.spec_hash != candidate.spec_hash {
                return Err(LocalStateError::WorkloadConflict(
                    candidate.workload_id.clone(),
                ));
            }
            return Ok(Reservation::Existing);
        }
        let active = self
            .workloads
            .iter()
            .values()
            .map(|value| -> Result<_, LocalStateError> {
                Ok(serde_json::from_slice::<WorkloadRecord>(&value?)?)
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|record| record.phase.consumes_capacity())
            .count();
        if active >= max_active {
            return Err(LocalStateError::WorkloadCapacity(max_active));
        }
        self.workloads.insert(
            candidate.workload_id.as_bytes(),
            serde_json::to_vec(candidate)?,
        )?;
        self.workloads.flush()?;
        Ok(Reservation::New)
    }

    pub fn workload(&self, workload_id: &str) -> Result<WorkloadRecord, LocalStateError> {
        let encoded = self
            .workloads
            .get(workload_id.as_bytes())?
            .ok_or_else(|| LocalStateError::WorkloadNotFound(workload_id.to_string()))?;
        Ok(serde_json::from_slice(&encoded)?)
    }

    pub fn store_workload(&self, record: &WorkloadRecord) -> Result<(), LocalStateError> {
        let _guard = self
            .workload_lock
            .lock()
            .map_err(|_| LocalStateError::LockPoisoned)?;
        if !self.workloads.contains_key(record.workload_id.as_bytes())? {
            return Err(LocalStateError::WorkloadNotFound(
                record.workload_id.clone(),
            ));
        }
        self.workloads
            .insert(record.workload_id.as_bytes(), serde_json::to_vec(record)?)?;
        self.workloads.flush()?;
        Ok(())
    }

    pub fn workloads(&self) -> Result<Vec<WorkloadRecord>, LocalStateError> {
        self.workloads
            .iter()
            .values()
            .map(|value| -> Result<_, LocalStateError> {
                Ok(serde_json::from_slice::<WorkloadRecord>(&value?)?)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_survives_reopen() {
        let directory = tempfile::tempdir().expect("temporary directory");
        {
            let state = LocalState::open(directory.path()).expect("open state");
            assert_eq!(state.next_heartbeat_sequence().expect("first sequence"), 1);
        }
        let state = LocalState::open(directory.path()).expect("reopen state");
        assert_eq!(state.next_heartbeat_sequence().expect("second sequence"), 2);
    }

    #[test]
    fn workload_mapping_survives_reopen_and_enforces_conflicts() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let record = WorkloadRecord {
            workload_id: "workload-1".to_string(),
            lease_id: "lease-1".to_string(),
            image: "example@sha256:digest".to_string(),
            spec_hash: [7; 32],
            container_id: Some("container-1".to_string()),
            phase: WorkloadPhase::Running,
            egress_mbps: 0,
            rate_limited: false,
        };
        {
            let state = LocalState::open(directory.path()).expect("open state");
            assert_eq!(
                state.reserve_workload(&record, 1).expect("reserve"),
                Reservation::New
            );
        }
        let state = LocalState::open(directory.path()).expect("reopen state");
        assert_eq!(state.workload("workload-1").expect("mapping"), record);
        assert_eq!(
            state.reserve_workload(&record, 1).expect("retry"),
            Reservation::Existing
        );
        let mut conflicting = record.clone();
        conflicting.spec_hash = [8; 32];
        assert!(matches!(
            state.reserve_workload(&conflicting, 1),
            Err(LocalStateError::WorkloadConflict(_))
        ));
    }

    #[test]
    fn metering_first_period_starts_at_now_with_sequence_one() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let state = LocalState::open(directory.path()).expect("open state");
        let period = state
            .next_metering_period("workload-1", 1_700_000_000, 3600)
            .expect("first metering period");
        assert_eq!(period.sequence, 1);
        assert_eq!(period.period_start, 1_700_000_000);
        assert_eq!(period.period_end, 1_700_000_000);
    }

    #[test]
    fn metering_sequence_survives_reopen_and_next_period_starts_where_last_ended() {
        let directory = tempfile::tempdir().expect("temporary directory");
        {
            let state = LocalState::open(directory.path()).expect("open state");
            let first = state
                .next_metering_period("workload-1", 1_700_000_000, 3600)
                .expect("first metering period");
            assert_eq!(first.sequence, 1);
            let second = state
                .next_metering_period("workload-1", 1_700_000_900, 3600)
                .expect("second metering period");
            assert_eq!(second.sequence, 2);
            assert_eq!(second.period_start, first.period_end);
            assert_eq!(second.period_end, 1_700_000_900);
        }
        // Simulates an Agent process restart: reopening the same sled
        // path must resume from sequence 3, not silently reset to 1 --
        // issue #20's restart acceptance criterion.
        let state = LocalState::open(directory.path()).expect("reopen state");
        let third = state
            .next_metering_period("workload-1", 1_700_001_800, 3600)
            .expect("third metering period after reopen");
        assert_eq!(third.sequence, 3);
        assert_eq!(third.period_start, 1_700_000_900);
    }

    #[test]
    fn metering_period_is_bounded_by_max_period_seconds() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let state = LocalState::open(directory.path()).expect("open state");
        let first = state
            .next_metering_period("workload-1", 1_700_000_000, 3600)
            .expect("first metering period");
        // `now` is far beyond period_start + max_period_seconds: the
        // window must be capped, not stretched to cover the whole gap in
        // one unbounded summary.
        let second = state
            .next_metering_period("workload-1", first.period_end + 100_000, 3600)
            .expect("second metering period");
        assert_eq!(second.period_start, first.period_end);
        assert_eq!(second.period_end, first.period_end + 3600);
    }

    #[test]
    fn metering_sequence_is_independent_per_workload() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let state = LocalState::open(directory.path()).expect("open state");
        let a1 = state
            .next_metering_period("workload-a", 1_700_000_000, 3600)
            .expect("workload-a period");
        let b1 = state
            .next_metering_period("workload-b", 1_700_000_000, 3600)
            .expect("workload-b period");
        assert_eq!(a1.sequence, 1);
        assert_eq!(b1.sequence, 1);
        let a2 = state
            .next_metering_period("workload-a", 1_700_000_100, 3600)
            .expect("workload-a second period");
        assert_eq!(a2.sequence, 2);
    }
}
