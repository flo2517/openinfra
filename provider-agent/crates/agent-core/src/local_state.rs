use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Mutex;
use thiserror::Error;

const HEARTBEAT_SEQUENCE_KEY: &[u8] = b"heartbeat_sequence";
const WORKLOAD_TREE: &str = "workloads-v1";

#[derive(Debug, Error)]
pub enum LocalStateError {
    #[error("local state storage failed: {0}")]
    Storage(#[from] sled::Error),
    #[error("stored heartbeat sequence is corrupt")]
    CorruptSequence,
    #[error("heartbeat sequence overflow")]
    SequenceOverflow,
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reservation {
    New,
    Existing,
}

pub struct LocalState {
    database: sled::Db,
    workloads: sled::Tree,
    workload_lock: Mutex<()>,
}

impl LocalState {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LocalStateError> {
        let database = sled::open(path)?;
        let workloads = database.open_tree(WORKLOAD_TREE)?;
        Ok(Self {
            database,
            workloads,
            workload_lock: Mutex::new(()),
        })
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
}
