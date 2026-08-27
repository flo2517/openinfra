use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Mutex;
use thiserror::Error;

const HEARTBEAT_SEQUENCE_KEY: &[u8] = b"heartbeat_sequence";
// ADR-027 §3: the durably persisted, strictly increasing per-provider
// counter RenewCertificateRequest.nonce signs -- the renewal-specific
// sibling of HEARTBEAT_SEQUENCE_KEY, deliberately a separate counter (a
// renewal roughly once a day must not be starved by, or interfere with,
// the heartbeat sequence ticking every ~15s).
const RENEWAL_NONCE_KEY: &[u8] = b"renewal_nonce";
// ADR-027 §2/§3/§5: the Agent's current mTLS leaf identity -- its own
// freshly generated private key (never transmitted anywhere, per §5) and
// the Control-Plane-issued certificate for it. A single key, not a tree:
// there is exactly one leaf identity in use for new connections at a
// time; the ADR's overlap window is about already-open connections
// continuing on whatever certificate they authenticated with, not about
// this Agent process needing to remember more than one.
const LEAF_CERTIFICATE_KEY: &[u8] = b"leaf_certificate";
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

/// ADR-033 §3: which execution model owns a `WorkloadRecord`. Docker
/// (`max_workloads`) and VM (`max_vm_workloads`) capacity are counted
/// independently -- see `reserve_workload`'s `runtime` parameter -- since
/// a VM's per-instance overhead is not comparable to a container's (ADR
/// §6). `#[serde(default)]` on `WorkloadRecord::runtime` deserializes
/// every record persisted before this field existed as `Container`,
/// which is exactly correct: no VM workload could have existed before
/// this PR.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum WorkloadRuntime {
    #[default]
    Container,
    Vm,
}

/// ADR-034 §1/§3/§7: one Cinder volume this workload's container has
/// mounted. `volume_name` is the underlying Docker named volume's own
/// name (deterministically derived from the Cinder `volume_id`, not the
/// Cinder `volume_id` string re-used verbatim -- see
/// `agent_executor::docker_volume_name`'s doc comment), so `recover()`
/// can check it directly against `bollard`'s volume API without any
/// other lookup. Mirrors `agent.proto`'s `VolumeAttachment` wire message
/// field-for-field, kept as its own local type (not a re-export of the
/// generated proto type) the same way every other `WorkloadRecord` field
/// is its own plain value, never a borrowed proto type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VolumeMount {
    pub volume_name: String,
    pub mount_path: String,
    pub read_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkloadRecord {
    pub workload_id: String,
    pub lease_id: String,
    pub image: String,
    pub spec_hash: [u8; 32],
    pub container_id: Option<String>,
    /// ADR-033 §3/§6: the VM-side "container_id-equivalent handle" the
    /// ADR calls for -- a Cloud Hypervisor API-socket path, populated
    /// only for `runtime == Vm` records. Kept as its own field rather
    /// than repurposing `container_id`, so a record's runtime is never
    /// ambiguous from which handle field happens to be set.
    /// `#[serde(default)]` for the same backward-compat reason as every
    /// other field added after this struct's original shape.
    #[serde(default)]
    pub vm_handle: Option<String>,
    #[serde(default)]
    pub runtime: WorkloadRuntime,
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
    /// ADR-028 §3: when this workload's lease authorization ends, unix
    /// seconds, sourced from `DeployRequest.lease_end`. `agent-executor`'s
    /// `deployment()` requires every new `DeployRequest` to carry it (see
    /// that function's validation), so this is only ever `None` for a
    /// record persisted before this field existed --
    /// `#[serde(default)]` for the same backward-compat reason as
    /// `egress_mbps`/`rate_limited`. A `None` record is never auto-stopped
    /// by `enforce_lease_expiry` (it has no known term to enforce) but
    /// remains fully visible via `recover()`/heartbeats -- deliberately
    /// not backfilled with a guessed value, matching this ADR's "never
    /// fabricate" principle for locally-synthesized authority.
    #[serde(default)]
    pub lease_end: Option<i64>,
    /// ADR-034 §3/§7: the Cinder volumes this workload's container was
    /// deployed with, mirroring `DeployRequest.volumes`. Used by
    /// `recover()` to detect drift after an Agent restart (does each
    /// named Docker volume this record claims still exist?) the same way
    /// `container_id` already is for the container itself.
    /// `#[serde(default)]` for the same backward-compat reason as every
    /// other field added after this struct's original shape -- a record
    /// persisted before this field existed had, definitionally, no
    /// volumes attached.
    #[serde(default)]
    pub volume_mounts: Vec<VolumeMount>,
}

/// ADR-027 §2/§3/§5: the Agent's current mTLS leaf identity, persisted by
/// `LocalState::store_leaf_certificate` alongside the workload map and the
/// heartbeat/renewal counters. `private_key_pem` never leaves this Agent
/// process -- only `certificate_pem` (already just the CA-signed public
/// half) and, at renewal time, a *new* raw public key ever cross the wire
/// (ADR-027 §5).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeafCertificate {
    /// PKCS8 PEM, matching what `rcgen::KeyPair::serialize_pem()` and
    /// `tonic::transport::Identity::from_pem`'s key argument both expect.
    pub private_key_pem: String,
    /// The Control-Plane-issued certificate (PEM) for private_key_pem's
    /// public half.
    pub certificate_pem: String,
    /// Decimal serial number, as the Control Plane's own
    /// `x509.Certificate.SerialNumber.String()` renders it -- the exact
    /// string a future `RenewCertificateRequest.current_certificate_serial`
    /// must echo back for the Control Plane's own re-derivation of the
    /// connection's peer certificate serial to match (see
    /// control-plane/internal/providerjoin/certificates.go's
    /// RenewCertificate).
    pub serial: String,
    /// Unix seconds this certificate's `NotAfter` falls on -- the renewal
    /// timer computes "50% elapsed" as exactly "12 hours before this,"
    /// matching ADR-027 §3's fixed 24h TTL without needing to separately
    /// track issuance time.
    pub expires_at_unix: i64,
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

    /// ADR-027 §3's renewal nonce watermark, the exact same
    /// compare-and-swap pattern next_heartbeat_sequence already uses for
    /// the heartbeat sequence -- a separate counter (see
    /// RENEWAL_NONCE_KEY's doc comment), but identical durability and
    /// monotonicity guarantees.
    pub fn next_renewal_nonce(&self) -> Result<u64, LocalStateError> {
        loop {
            let current = self.database.get(RENEWAL_NONCE_KEY)?;
            let nonce = match current.as_deref() {
                Some(bytes) => u64::from_be_bytes(
                    bytes
                        .try_into()
                        .map_err(|_| LocalStateError::CorruptSequence)?,
                ),
                None => 0,
            };
            let next = nonce
                .checked_add(1)
                .ok_or(LocalStateError::SequenceOverflow)?;
            let next_bytes = next.to_be_bytes();
            match self.database.compare_and_swap(
                RENEWAL_NONCE_KEY,
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

    /// Persists the Agent's current mTLS leaf identity (ADR-027 §2/§3),
    /// replacing whatever was stored before -- a successful renewal
    /// atomically supersedes the previous leaf certificate/key as the one
    /// used for new connections going forward, per store_leaf_certificate's
    /// single-key design (see LEAF_CERTIFICATE_KEY's doc comment).
    pub fn store_leaf_certificate(
        &self,
        certificate: &LeafCertificate,
    ) -> Result<(), LocalStateError> {
        self.database.insert(
            LEAF_CERTIFICATE_KEY,
            serde_json::to_vec(certificate)?.as_slice(),
        )?;
        self.database.flush()?;
        Ok(())
    }

    /// Returns the Agent's current mTLS leaf identity, or `None` if this
    /// Agent has never completed ADR-027 §2 enrollment (a legacy Agent on
    /// the pre-ADR-027 static-cert path, or one that hasn't run `join`
    /// with mTLS enrollment enabled yet).
    pub fn leaf_certificate(&self) -> Result<Option<LeafCertificate>, LocalStateError> {
        match self.database.get(LEAF_CERTIFICATE_KEY)? {
            Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Reserves a capacity slot for `candidate`, counted independently
    /// per `WorkloadRuntime` (ADR-033 §6: a Docker `max_workloads` slot
    /// and a VM `max_vm_workloads` slot are never fungible with each
    /// other) -- `max_active` is `candidate.runtime`'s own ceiling
    /// (`ExecutorSettings::max_workloads` for `Container`,
    /// `max_vm_workloads` for `Vm`), and only records already stored with
    /// the *same* runtime count against it.
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
            .filter(|record| {
                record.runtime == candidate.runtime && record.phase.consumes_capacity()
            })
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
    fn renewal_nonce_survives_reopen_and_is_independent_of_heartbeat_sequence() {
        let directory = tempfile::tempdir().expect("temporary directory");
        {
            let state = LocalState::open(directory.path()).expect("open state");
            assert_eq!(state.next_heartbeat_sequence().expect("heartbeat 1"), 1);
            assert_eq!(state.next_renewal_nonce().expect("renewal 1"), 1);
            assert_eq!(state.next_heartbeat_sequence().expect("heartbeat 2"), 2);
        }
        let state = LocalState::open(directory.path()).expect("reopen state");
        assert_eq!(
            state.next_renewal_nonce().expect("renewal survives reopen"),
            2
        );
        assert_eq!(
            state
                .next_heartbeat_sequence()
                .expect("heartbeat survives reopen"),
            3
        );
    }

    #[test]
    fn leaf_certificate_is_absent_until_stored_then_survives_reopen() {
        let directory = tempfile::tempdir().expect("temporary directory");
        {
            let state = LocalState::open(directory.path()).expect("open state");
            assert_eq!(
                state.leaf_certificate().expect("read before store"),
                None,
                "a fresh Agent has no leaf certificate until enrollment"
            );
            let certificate = LeafCertificate {
                private_key_pem: "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n"
                    .to_string(),
                certificate_pem: "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n"
                    .to_string(),
                serial: "123456789012345678901234567890".to_string(),
                expires_at_unix: 1_700_100_000,
            };
            state
                .store_leaf_certificate(&certificate)
                .expect("store leaf certificate");
            assert_eq!(
                state.leaf_certificate().expect("read after store"),
                Some(certificate)
            );
        }
        let state = LocalState::open(directory.path()).expect("reopen state");
        let reloaded = state
            .leaf_certificate()
            .expect("read after reopen")
            .expect("leaf certificate persisted across reopen");
        assert_eq!(reloaded.serial, "123456789012345678901234567890");
    }

    #[test]
    fn storing_a_renewed_leaf_certificate_replaces_the_previous_one() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let state = LocalState::open(directory.path()).expect("open state");
        let first = LeafCertificate {
            private_key_pem: "first-key".to_string(),
            certificate_pem: "first-cert".to_string(),
            serial: "1".to_string(),
            expires_at_unix: 1_700_000_000,
        };
        let second = LeafCertificate {
            private_key_pem: "second-key".to_string(),
            certificate_pem: "second-cert".to_string(),
            serial: "2".to_string(),
            expires_at_unix: 1_700_100_000,
        };
        state
            .store_leaf_certificate(&first)
            .expect("store first leaf certificate");
        state
            .store_leaf_certificate(&second)
            .expect("store renewed leaf certificate");
        assert_eq!(state.leaf_certificate().expect("read"), Some(second));
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
            vm_handle: None,
            runtime: WorkloadRuntime::Container,
            phase: WorkloadPhase::Running,
            egress_mbps: 0,
            rate_limited: false,
            lease_end: Some(1_700_000_000),
            volume_mounts: Vec::new(),
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
    fn reserve_workload_counts_container_and_vm_capacity_independently() {
        // ADR-033 §6: a VM's per-instance overhead is not comparable to
        // a container's, so max_workloads and max_vm_workloads must be
        // enforced as two independent ceilings, never sharing one active
        // count.
        let directory = tempfile::tempdir().expect("temporary directory");
        let state = LocalState::open(directory.path()).expect("open state");
        let container_record = |id: &str| WorkloadRecord {
            workload_id: id.to_string(),
            lease_id: "lease".to_string(),
            image: "example:tag".to_string(),
            spec_hash: [1; 32],
            container_id: Some("container-1".to_string()),
            vm_handle: None,
            runtime: WorkloadRuntime::Container,
            phase: WorkloadPhase::Running,
            egress_mbps: 0,
            rate_limited: false,
            lease_end: Some(1_700_000_000),
            volume_mounts: Vec::new(),
        };
        let vm_record = |id: &str| WorkloadRecord {
            workload_id: id.to_string(),
            lease_id: "lease".to_string(),
            image: "https://example.com/image.qcow2".to_string(),
            spec_hash: [2; 32],
            container_id: None,
            vm_handle: Some("/tmp/vm-1.sock".to_string()),
            runtime: WorkloadRuntime::Vm,
            phase: WorkloadPhase::Running,
            egress_mbps: 0,
            rate_limited: false,
            lease_end: Some(1_700_000_000),
            volume_mounts: Vec::new(),
        };

        // A container workload at max_active=1 fills the Container
        // ceiling...
        assert_eq!(
            state
                .reserve_workload(&container_record("c1"), 1)
                .expect("reserve container"),
            Reservation::New
        );
        // ...but must not count against a *separate* Vm reservation at
        // the same max_active=1: a VM workload still gets its own slot.
        assert_eq!(
            state
                .reserve_workload(&vm_record("v1"), 1)
                .expect("reserve vm"),
            Reservation::New
        );
        // A second container now correctly hits the Container ceiling...
        assert!(matches!(
            state.reserve_workload(&container_record("c2"), 1),
            Err(LocalStateError::WorkloadCapacity(1))
        ));
        // ...and a second VM correctly hits the (independent) Vm
        // ceiling, not the container one.
        assert!(matches!(
            state.reserve_workload(&vm_record("v2"), 1),
            Err(LocalStateError::WorkloadCapacity(1))
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
