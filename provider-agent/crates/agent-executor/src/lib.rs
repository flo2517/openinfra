use agent_api::proto::{get_workload_status_response::State, DeployRequest};
use agent_api::{Executor, WorkloadStatus};
use agent_core::local_state::{
    LocalState, LocalStateError, Reservation, WorkloadPhase, WorkloadRecord,
};
use agent_core::ExecutorSettings;
use anyhow::Result;
use async_trait::async_trait;
use bollard::container::{
    Config, CreateContainerOptions, RemoveContainerOptions, StopContainerOptions,
};
use bollard::models::HostConfig;
use bollard::Docker;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::{error, info, warn};
use uuid::Uuid;

const MIB: i64 = 1024 * 1024;
const NANOS_PER_CPU: f64 = 1_000_000_000.0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerSpec {
    pub name: String,
    pub image: String,
    pub labels: HashMap<String, String>,
    pub memory_bytes: i64,
    pub nano_cpus: i64,
    pub pids_limit: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerObservation {
    pub running: bool,
    pub status: String,
}

#[async_trait]
pub trait ContainerEngine: Send + Sync {
    async fn create(&self, spec: &ContainerSpec) -> Result<String, ExecutorError>;
    async fn start(&self, container_id: &str) -> Result<(), ExecutorError>;
    async fn stop(&self, container_id: &str) -> Result<(), ExecutorError>;
    async fn inspect(&self, container_id: &str) -> Result<ContainerObservation, ExecutorError>;
    async fn remove(&self, container_id: &str) -> Result<(), ExecutorError>;
}

pub struct BollardEngine {
    docker: Docker,
}

impl BollardEngine {
    pub fn connect() -> Result<Self, ExecutorError> {
        Ok(Self {
            docker: Docker::connect_with_local_defaults()
                .map_err(|error| ExecutorError::Engine(error.to_string()))?,
        })
    }
}

#[async_trait]
impl ContainerEngine for BollardEngine {
    async fn create(&self, spec: &ContainerSpec) -> Result<String, ExecutorError> {
        let host_config = HostConfig {
            memory: Some(spec.memory_bytes),
            memory_swap: Some(spec.memory_bytes),
            nano_cpus: Some(spec.nano_cpus),
            pids_limit: Some(spec.pids_limit),
            security_opt: Some(vec!["no-new-privileges:true".to_string()]),
            cap_drop: Some(vec!["ALL".to_string()]),
            init: Some(true),
            ..Default::default()
        };
        let config = Config {
            image: Some(spec.image.clone()),
            labels: Some(spec.labels.clone()),
            host_config: Some(host_config),
            ..Default::default()
        };
        let options = CreateContainerOptions {
            name: spec.name.clone(),
            platform: None,
        };
        self.docker
            .create_container(Some(options), config)
            .await
            .map(|response| response.id)
            .map_err(|error| ExecutorError::Engine(error.to_string()))
    }

    async fn start(&self, container_id: &str) -> Result<(), ExecutorError> {
        self.docker
            .start_container::<String>(container_id, None)
            .await
            .map_err(|error| ExecutorError::Engine(error.to_string()))
    }

    async fn stop(&self, container_id: &str) -> Result<(), ExecutorError> {
        self.docker
            .stop_container(container_id, Some(StopContainerOptions { t: 10 }))
            .await
            .map_err(|error| ExecutorError::Engine(error.to_string()))
    }

    async fn inspect(&self, container_id: &str) -> Result<ContainerObservation, ExecutorError> {
        let response = self
            .docker
            .inspect_container(container_id, None)
            .await
            .map_err(|error| ExecutorError::Engine(error.to_string()))?;
        let state = response.state.unwrap_or_default();
        Ok(ContainerObservation {
            running: state.running.unwrap_or(false),
            status: state
                .status
                .map(|status| format!("{status:?}").to_ascii_lowercase())
                .unwrap_or_else(|| "unknown".to_string()),
        })
    }

    async fn remove(&self, container_id: &str) -> Result<(), ExecutorError> {
        self.docker
            .remove_container(
                container_id,
                Some(RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            )
            .await
            .map_err(|error| ExecutorError::Engine(error.to_string()))
    }
}

#[derive(Debug, Error)]
pub enum ExecutorError {
    #[error("invalid deployment request: {0}")]
    InvalidRequest(String),
    #[error("container engine failed: {0}")]
    Engine(String),
    #[error("local workload state failed: {0}")]
    State(#[from] LocalStateError),
    #[error("container {0} did not reach the required state")]
    StateConfirmation(String),
}

pub struct DockerExecutor {
    engine: Arc<dyn ContainerEngine>,
    state: Arc<LocalState>,
    settings: ExecutorSettings,
    operation_lock: Mutex<()>,
}

impl DockerExecutor {
    pub async fn connect(
        state: Arc<LocalState>,
        settings: ExecutorSettings,
    ) -> Result<Self, ExecutorError> {
        Self::validate_settings(&settings)?;
        let executor = Self {
            engine: Arc::new(BollardEngine::connect()?),
            state,
            settings,
            operation_lock: Mutex::new(()),
        };
        executor.recover().await?;
        Ok(executor)
    }

    #[cfg(test)]
    fn with_engine(
        engine: Arc<dyn ContainerEngine>,
        state: Arc<LocalState>,
        settings: ExecutorSettings,
    ) -> Result<Self, ExecutorError> {
        Self::validate_settings(&settings)?;
        Ok(Self {
            engine,
            state,
            settings,
            operation_lock: Mutex::new(()),
        })
    }

    fn validate_settings(settings: &ExecutorSettings) -> Result<(), ExecutorError> {
        if settings.max_workloads == 0
            || !settings.max_cpu_cores.is_finite()
            || settings.max_cpu_cores <= 0.0
            || settings.max_memory_mb <= 0
            || settings.pids_limit <= 0
        {
            return Err(ExecutorError::InvalidRequest(
                "executor policy values must be positive and finite".to_string(),
            ));
        }
        Ok(())
    }

    fn deployment(
        &self,
        request: &DeployRequest,
    ) -> Result<(WorkloadRecord, ContainerSpec), ExecutorError> {
        Uuid::parse_str(&request.workload_id)
            .map_err(|_| ExecutorError::InvalidRequest("workload_id must be a UUID".to_string()))?;
        if Uuid::parse_str(&request.lease_id).is_err()
            && request
                .lease_id
                .parse::<u64>()
                .ok()
                .filter(|id| *id > 0)
                .is_none()
        {
            return Err(ExecutorError::InvalidRequest(
                "lease_id must be a positive on-chain integer or legacy UUID".to_string(),
            ));
        }
        if request.image.is_empty()
            || request.image.len() > 255
            || request.image.chars().any(char::is_whitespace)
            || request.image.contains("://")
        {
            return Err(ExecutorError::InvalidRequest(
                "image must be a non-empty Docker reference without whitespace or URL scheme"
                    .to_string(),
            ));
        }
        let limits = request.limits.as_ref().ok_or_else(|| {
            ExecutorError::InvalidRequest("resource limits are required".to_string())
        })?;
        if !limits.cpu_cores.is_finite()
            || limits.cpu_cores <= 0.0
            || limits.cpu_cores > self.settings.max_cpu_cores
        {
            return Err(ExecutorError::InvalidRequest(
                "cpu_cores must be positive, finite, and within policy".to_string(),
            ));
        }
        if limits.memory_mb <= 0 || limits.memory_mb > self.settings.max_memory_mb {
            return Err(ExecutorError::InvalidRequest(
                "memory_mb must be positive and within policy".to_string(),
            ));
        }
        let memory_bytes = limits.memory_mb.checked_mul(MIB).ok_or_else(|| {
            ExecutorError::InvalidRequest("memory limit overflows bytes".to_string())
        })?;
        let nano_cpus = (f64::from(limits.cpu_cores) * NANOS_PER_CPU).round();
        if nano_cpus > i64::MAX as f64 {
            return Err(ExecutorError::InvalidRequest(
                "CPU limit overflows NanoCPUs".to_string(),
            ));
        }
        let nano_cpus = nano_cpus as i64;
        let mut hasher = Sha256::new();
        hasher.update(request.lease_id.as_bytes());
        hasher.update([0]);
        hasher.update(request.image.as_bytes());
        hasher.update(limits.cpu_cores.to_bits().to_be_bytes());
        hasher.update(limits.memory_mb.to_be_bytes());
        let spec_hash: [u8; 32] = hasher.finalize().into();
        let labels = HashMap::from([
            ("openinfra.managed".to_string(), "true".to_string()),
            (
                "openinfra.workload_id".to_string(),
                request.workload_id.clone(),
            ),
            ("openinfra.lease_id".to_string(), request.lease_id.clone()),
            ("openinfra.spec_hash".to_string(), hex::encode(spec_hash)),
        ]);
        Ok((
            WorkloadRecord {
                workload_id: request.workload_id.clone(),
                lease_id: request.lease_id.clone(),
                image: request.image.clone(),
                spec_hash,
                container_id: None,
                phase: WorkloadPhase::Provisioning,
            },
            ContainerSpec {
                name: format!("openinfra-{}", request.workload_id),
                image: request.image.clone(),
                labels,
                memory_bytes,
                nano_cpus,
                pids_limit: self.settings.pids_limit,
            },
        ))
    }

    async fn recover(&self) -> Result<(), ExecutorError> {
        for mut record in self.state.workloads()? {
            let Some(container_id) = record.container_id.as_deref() else {
                if record.phase.consumes_capacity() {
                    record.phase = WorkloadPhase::Failed;
                    self.state.store_workload(&record)?;
                }
                continue;
            };
            match self.engine.inspect(container_id).await {
                Ok(observation) => {
                    record.phase = if observation.running {
                        WorkloadPhase::Running
                    } else if record.phase == WorkloadPhase::Stopping {
                        WorkloadPhase::Stopped
                    } else {
                        WorkloadPhase::Failed
                    };
                }
                Err(error) => {
                    warn!(workload_id = %record.workload_id, %error, "persisted container is unavailable");
                    record.phase = WorkloadPhase::Lost;
                }
            }
            self.state.store_workload(&record)?;
        }
        Ok(())
    }

    fn map_observation(observation: &ContainerObservation) -> State {
        if observation.running {
            State::Running
        } else {
            match observation.status.as_str() {
                "created" => State::Created,
                "restarting" => State::Pending,
                "removing" => State::Stopping,
                "exited" => State::Completed,
                "dead" => State::Failed,
                _ => State::Pending,
            }
        }
    }
}

#[async_trait]
impl Executor for DockerExecutor {
    async fn deploy(&self, request: DeployRequest) -> Result<String> {
        let _guard = self.operation_lock.lock().await;
        let (candidate, spec) = self.deployment(&request)?;
        let reservation = self
            .state
            .reserve_workload(&candidate, self.settings.max_workloads)?;
        let mut record = self.state.workload(&candidate.workload_id)?;

        if reservation == Reservation::Existing {
            if let Some(container_id) = record.container_id.as_deref() {
                let observation = self.engine.inspect(container_id).await?;
                if observation.running {
                    record.phase = WorkloadPhase::Running;
                    self.state.store_workload(&record)?;
                    return Ok(container_id.to_string());
                }
                if record.phase == WorkloadPhase::Stopped {
                    return Err(ExecutorError::StateConfirmation(container_id.to_string()).into());
                }
            }
        }

        let container_id = match record.container_id.clone() {
            Some(container_id) => container_id,
            None => {
                let container_id = self.engine.create(&spec).await?;
                record.container_id = Some(container_id.clone());
                record.phase = WorkloadPhase::Starting;
                if let Err(error) = self.state.store_workload(&record) {
                    if let Err(cleanup_error) = self.engine.remove(&container_id).await {
                        error!(%container_id, %cleanup_error, "failed to remove container after persistence failure");
                    }
                    return Err(error.into());
                }
                container_id
            }
        };

        if let Err(error) = self.engine.start(&container_id).await {
            record.phase = WorkloadPhase::Failed;
            self.state.store_workload(&record)?;
            return Err(error.into());
        }
        let observation = self.engine.inspect(&container_id).await?;
        if !observation.running {
            record.phase = WorkloadPhase::Failed;
            self.state.store_workload(&record)?;
            return Err(ExecutorError::StateConfirmation(container_id).into());
        }
        record.phase = WorkloadPhase::Running;
        self.state.store_workload(&record)?;
        info!(workload_id = %record.workload_id, %container_id, "Docker confirmed workload running");
        Ok(container_id)
    }

    async fn stop(&self, workload_id: &str) -> Result<()> {
        let _guard = self.operation_lock.lock().await;
        let mut record = self.state.workload(workload_id)?;
        if record.phase == WorkloadPhase::Stopped {
            return Ok(());
        }
        let container_id = record.container_id.clone().ok_or_else(|| {
            ExecutorError::StateConfirmation(format!("workload {workload_id} has no container"))
        })?;
        record.phase = WorkloadPhase::Stopping;
        self.state.store_workload(&record)?;
        self.engine.stop(&container_id).await?;
        let observation = self.engine.inspect(&container_id).await?;
        if observation.running {
            return Err(ExecutorError::StateConfirmation(container_id).into());
        }
        record.phase = WorkloadPhase::Stopped;
        self.state.store_workload(&record)?;
        info!(%workload_id, %container_id, "Docker confirmed workload stopped");
        Ok(())
    }

    async fn get_status(&self, workload_id: &str) -> Result<WorkloadStatus> {
        let record = self.state.workload(workload_id)?;
        let container_id = record.container_id.ok_or_else(|| {
            ExecutorError::StateConfirmation(format!("workload {workload_id} has no container"))
        })?;
        let observation = self.engine.inspect(&container_id).await?;
        Ok(WorkloadStatus {
            state: Self::map_observation(&observation) as i32,
            details: format!("Docker state: {}", observation.status),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_api::proto::ResourceLimits;
    use std::sync::Mutex as StdMutex;

    #[derive(Default)]
    struct FakeEngine {
        created: StdMutex<Vec<ContainerSpec>>,
        started: StdMutex<Vec<String>>,
        stopped: StdMutex<Vec<String>>,
        observations: StdMutex<HashMap<String, ContainerObservation>>,
    }

    #[async_trait]
    impl ContainerEngine for FakeEngine {
        async fn create(&self, spec: &ContainerSpec) -> Result<String, ExecutorError> {
            self.created
                .lock()
                .expect("created lock")
                .push(spec.clone());
            let id = format!(
                "container-{}",
                self.created.lock().expect("created lock").len()
            );
            self.observations.lock().expect("observations lock").insert(
                id.clone(),
                ContainerObservation {
                    running: false,
                    status: "created".to_string(),
                },
            );
            Ok(id)
        }

        async fn start(&self, container_id: &str) -> Result<(), ExecutorError> {
            self.started
                .lock()
                .expect("started lock")
                .push(container_id.to_string());
            self.observations.lock().expect("observations lock").insert(
                container_id.to_string(),
                ContainerObservation {
                    running: true,
                    status: "running".to_string(),
                },
            );
            Ok(())
        }

        async fn stop(&self, container_id: &str) -> Result<(), ExecutorError> {
            self.stopped
                .lock()
                .expect("stopped lock")
                .push(container_id.to_string());
            self.observations.lock().expect("observations lock").insert(
                container_id.to_string(),
                ContainerObservation {
                    running: false,
                    status: "exited".to_string(),
                },
            );
            Ok(())
        }

        async fn inspect(&self, container_id: &str) -> Result<ContainerObservation, ExecutorError> {
            self.observations
                .lock()
                .expect("observations lock")
                .get(container_id)
                .cloned()
                .ok_or_else(|| ExecutorError::Engine("container not found".to_string()))
        }

        async fn remove(&self, _container_id: &str) -> Result<(), ExecutorError> {
            Ok(())
        }
    }

    fn request(workload_id: Uuid, lease_id: Uuid) -> DeployRequest {
        DeployRequest {
            workload_id: workload_id.to_string(),
            lease_id: lease_id.to_string(),
            image: "busybox:1.36".to_string(),
            limits: Some(ResourceLimits {
                cpu_cores: 1.5,
                memory_mb: 256,
            }),
        }
    }

    fn executor(engine: Arc<FakeEngine>, path: &std::path::Path, max: usize) -> DockerExecutor {
        let settings = ExecutorSettings {
            max_workloads: max,
            ..Default::default()
        };
        DockerExecutor::with_engine(
            engine,
            Arc::new(LocalState::open(path).expect("state")),
            settings,
        )
        .expect("executor")
    }

    #[tokio::test]
    async fn deploy_enforces_security_limits_and_is_idempotent() {
        let directory = tempfile::tempdir().expect("directory");
        let engine = Arc::new(FakeEngine::default());
        let executor = executor(engine.clone(), directory.path(), 2);
        let request = request(Uuid::new_v4(), Uuid::new_v4());
        let first = executor
            .deploy(request.clone())
            .await
            .expect("first deploy");
        let second = executor.deploy(request).await.expect("retry deploy");
        assert_eq!(first, second);
        let created = engine.created.lock().expect("created lock");
        assert_eq!(created.len(), 1);
        assert_eq!(created[0].memory_bytes, 256 * MIB);
        assert_eq!(created[0].nano_cpus, 1_500_000_000);
        assert_eq!(created[0].pids_limit, 128);
        assert_eq!(
            created[0].labels.get("openinfra.managed"),
            Some(&"true".to_string())
        );
    }

    #[tokio::test]
    async fn deploy_rejects_invalid_limits_conflicts_and_capacity() {
        let directory = tempfile::tempdir().expect("directory");
        let engine = Arc::new(FakeEngine::default());
        let executor = executor(engine, directory.path(), 1);
        let mut invalid = request(Uuid::new_v4(), Uuid::new_v4());
        invalid.limits.as_mut().expect("limits").cpu_cores = f32::NAN;
        assert!(executor.deploy(invalid).await.is_err());

        let first = request(Uuid::new_v4(), Uuid::new_v4());
        executor.deploy(first.clone()).await.expect("first");
        let mut conflict = first;
        conflict.image = "alpine:3.22".to_string();
        assert!(executor.deploy(conflict).await.is_err());
        assert!(executor
            .deploy(request(Uuid::new_v4(), Uuid::new_v4()))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn stop_and_status_use_the_persisted_exact_container_id() {
        let directory = tempfile::tempdir().expect("directory");
        let engine = Arc::new(FakeEngine::default());
        let executor = executor(engine.clone(), directory.path(), 1);
        let request = request(Uuid::new_v4(), Uuid::new_v4());
        let container_id = executor.deploy(request.clone()).await.expect("deploy");
        let status = executor
            .get_status(&request.workload_id)
            .await
            .expect("status");
        assert_eq!(status.state, State::Running as i32);
        executor.stop(&request.workload_id).await.expect("stop");
        assert_eq!(
            engine.stopped.lock().expect("stopped lock").as_slice(),
            &[container_id]
        );
        executor
            .stop(&request.workload_id)
            .await
            .expect("idempotent stop");
    }

    #[tokio::test]
    async fn persisted_running_workload_is_recovered_without_duplicate_creation() {
        let directory = tempfile::tempdir().expect("directory");
        let engine = Arc::new(FakeEngine::default());
        let request = request(Uuid::new_v4(), Uuid::new_v4());
        let container_id = {
            let executor = executor(engine.clone(), directory.path(), 1);
            executor.deploy(request.clone()).await.expect("deploy")
        };
        let recovered = executor(engine.clone(), directory.path(), 1);
        recovered.recover().await.expect("recover");
        assert_eq!(
            recovered.deploy(request).await.expect("idempotent retry"),
            container_id
        );
        assert_eq!(engine.created.lock().expect("created lock").len(), 1);
    }

    #[tokio::test]
    async fn docker_integration_applies_mandatory_controls() {
        let image = match std::env::var("OPENINFRA_TEST_DOCKER_IMAGE") {
            Ok(image) => image,
            Err(_) => return,
        };
        let directory = tempfile::tempdir().expect("directory");
        let settings = ExecutorSettings {
            max_workloads: 1,
            max_cpu_cores: 1.0,
            max_memory_mb: 128,
            pids_limit: 32,
            ..Default::default()
        };
        let executor = DockerExecutor::connect(
            Arc::new(LocalState::open(directory.path()).expect("state")),
            settings,
        )
        .await
        .expect("connect Docker");
        let request = DeployRequest {
            workload_id: Uuid::new_v4().to_string(),
            lease_id: Uuid::new_v4().to_string(),
            image,
            limits: Some(ResourceLimits {
                cpu_cores: 0.5,
                memory_mb: 64,
            }),
        };
        let container_id = executor.deploy(request.clone()).await.expect("deploy");
        let docker = Docker::connect_with_local_defaults().expect("Docker client");
        let inspected = docker
            .inspect_container(&container_id, None)
            .await
            .expect("inspect container");
        let host = inspected.host_config.expect("host config");
        assert_eq!(host.memory, Some(64 * MIB));
        assert_eq!(host.memory_swap, Some(64 * MIB));
        assert_eq!(host.nano_cpus, Some(500_000_000));
        assert_eq!(host.pids_limit, Some(32));
        assert!(host
            .security_opt
            .unwrap_or_default()
            .iter()
            .any(|value| value == "no-new-privileges" || value == "no-new-privileges:true"));
        assert!(host
            .cap_drop
            .unwrap_or_default()
            .iter()
            .any(|value| value == "ALL"));
        executor.stop(&request.workload_id).await.expect("stop");
        docker
            .remove_container(
                &container_id,
                Some(RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            )
            .await
            .expect("remove container");
    }
}
