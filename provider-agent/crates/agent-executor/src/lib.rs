mod bandwidth;
mod rate_limit;

use agent_api::proto::{get_workload_status_response::State, DeployRequest};
use agent_api::{Executor, UsageSample, WorkloadStatus};
use agent_core::local_state::{
    LocalState, LocalStateError, Reservation, WorkloadPhase, WorkloadRecord,
};
use agent_core::ExecutorSettings;
use anyhow::Result;
use async_trait::async_trait;
pub use bandwidth::WorkloadBandwidth;
use bollard::container::{
    Config, CreateContainerOptions, RemoveContainerOptions, StopContainerOptions,
};
use bollard::models::HostConfig;
use bollard::Docker;
pub use rate_limit::{CommandRunner, RateLimiter, SystemCommandRunner};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;
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
    /// ADR-025 §3: the workload's reserved egress rate, Mbps. 0 means
    /// "no bandwidth requirement declared" -- no `tc` rule is applied,
    /// matching `ResourceLimits.egress_mbps`'s own wire convention.
    pub egress_mbps: i32,
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
    /// ADR-025 §2: this workload's cumulative bandwidth counters, read
    /// from the host side of its veth pair. See `bandwidth::read_bandwidth`
    /// for the exact mechanism.
    async fn bandwidth(&self, container_id: &str) -> Result<WorkloadBandwidth, ExecutorError>;
    /// ADR-025 §3: applies this workload's reserved egress rate as a host-
    /// side `tc` ceiling against its veth pair. Callers must only invoke
    /// this when `egress_mbps > 0` (see `RateLimiter::apply`'s doc
    /// comment) -- `DockerExecutor::deploy` is the single call site and
    /// already guards on that.
    async fn rate_limit(&self, container_id: &str, egress_mbps: i32) -> Result<(), ExecutorError>;
}

pub struct BollardEngine {
    docker: Docker,
    rate_limiter: RateLimiter,
}

impl BollardEngine {
    pub fn connect() -> Result<Self, ExecutorError> {
        Ok(Self {
            docker: Docker::connect_with_local_defaults()
                .map_err(|error| ExecutorError::Engine(error.to_string()))?,
            rate_limiter: RateLimiter::new(Arc::new(SystemCommandRunner)),
        })
    }

    /// Resolves `container_id`'s host-visible PID via Docker inspect --
    /// the same lookup `bandwidth()` needs (for `read_bandwidth`) and
    /// `rate_limit()` needs (for `RateLimiter::apply`), factored out so
    /// neither re-implements "container has no state"/"container has no
    /// pid" error handling independently.
    async fn container_pid(&self, container_id: &str) -> Result<i64, ExecutorError> {
        let response = self
            .docker
            .inspect_container(container_id, None)
            .await
            .map_err(|error| ExecutorError::Engine(error.to_string()))?;
        let state = response
            .state
            .ok_or_else(|| ExecutorError::Engine("container has no state".to_string()))?;
        state
            .pid
            .filter(|pid| *pid > 0)
            .ok_or_else(|| ExecutorError::Engine("container has no pid".to_string()))
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

    async fn bandwidth(&self, container_id: &str) -> Result<WorkloadBandwidth, ExecutorError> {
        let response = self
            .docker
            .inspect_container(container_id, None)
            .await
            .map_err(|error| ExecutorError::Engine(error.to_string()))?;
        let state = response
            .state
            .ok_or_else(|| ExecutorError::Engine("container has no state".to_string()))?;
        let pid = state
            .pid
            .filter(|pid| *pid > 0)
            .ok_or_else(|| ExecutorError::Engine("container has no pid".to_string()))?;
        let started_at = state
            .started_at
            .as_deref()
            .ok_or_else(|| ExecutorError::Engine("container has no started_at".to_string()))
            .and_then(parse_docker_timestamp)?;
        bandwidth::read_bandwidth(Path::new("/"), pid, started_at)
    }

    async fn rate_limit(&self, container_id: &str, egress_mbps: i32) -> Result<(), ExecutorError> {
        let pid = self.container_pid(container_id).await?;
        self.rate_limiter.apply(Path::new("/"), pid, egress_mbps)
    }
}

/// Docker's API reports container timestamps as RFC3339 strings (not a
/// typed timestamp -- bollard's `ContainerState.started_at` is a plain
/// `Option<String>`). Parsed with `chrono` rather than hand-rolled, since
/// a wrong parse here would silently corrupt `window_started_at`, and
/// with it every future heartbeat's "did the counters reset" comparison
/// downstream (control-plane/internal/providerjoin).
fn parse_docker_timestamp(value: &str) -> Result<SystemTime, ExecutorError> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(SystemTime::from)
        .map_err(|error| {
            ExecutorError::Engine(format!("parse container started_at {value:?}: {error}"))
        })
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
            || settings.max_egress_mbps <= 0
        {
            return Err(ExecutorError::InvalidRequest(
                "executor policy values must be positive and finite".to_string(),
            ));
        }
        Ok(())
    }

    /// Applies `record.egress_mbps`'s `tc` ceiling to `container_id` if a
    /// bandwidth reservation was declared (`egress_mbps > 0`) and hasn't
    /// already been successfully applied (`!record.rate_limited`) --
    /// idempotent both ways: a no-op if there's nothing to do, and safe
    /// to call again after a prior failure.
    ///
    /// A `rate_limit()` failure is deliberately never propagated as an
    /// error and never changes `record.phase`: by the time every caller
    /// of this method reaches it, the container is already confirmed
    /// running via Docker inspect, so it is genuinely consuming real
    /// CPU/memory/network resources regardless of whether its egress
    /// ceiling could be applied. Marking the workload `Failed` here would
    /// remove it from `WorkloadPhase::consumes_capacity`'s count (see
    /// that method's own doc comment) -- silently freeing a capacity
    /// slot for a container that is still actually running unthrottled,
    /// which is worse than the missing rate limit itself. Instead:
    /// `record.rate_limited` stays `false`, which is exactly the signal
    /// this method itself checks on its next call -- from a retried
    /// `deploy()` (the control-plane resending a DEPLOYING attempt whose
    /// previous response was lost, the same path that already handles
    /// idempotent create()/start()) or from `recover()` after an Agent
    /// restart. Errors are logged, not swallowed silently.
    async fn apply_rate_limit_if_needed(&self, record: &mut WorkloadRecord, container_id: &str) {
        if record.egress_mbps <= 0 || record.rate_limited {
            return;
        }
        match self
            .engine
            .rate_limit(container_id, record.egress_mbps)
            .await
        {
            Ok(()) => record.rate_limited = true,
            Err(error) => {
                warn!(
                    workload_id = %record.workload_id,
                    %container_id,
                    egress_mbps = record.egress_mbps,
                    %error,
                    "rate limit not applied for a running workload; will retry on the next deploy/recover call"
                );
            }
        }
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
        // ADR-025 §3: 0 is the valid, common "no bandwidth requirement
        // declared" case (see ResourceLimits.egress_mbps's doc comment) --
        // only negative is rejected below that line, unlike cpu_cores/
        // memory_mb above which require strictly positive because every
        // workload has some real CPU/memory footprint. Above policy is
        // still rejected either way, the same defense-in-depth check
        // cpu_cores/memory_mb already get against a buggy or compromised
        // scheduler sending an unreasonable reservation.
        if limits.egress_mbps < 0 || limits.egress_mbps > self.settings.max_egress_mbps {
            return Err(ExecutorError::InvalidRequest(
                "egress_mbps must not be negative and must be within policy".to_string(),
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
                egress_mbps: limits.egress_mbps,
                rate_limited: false,
            },
            ContainerSpec {
                name: format!("openinfra-{}", request.workload_id),
                image: request.image.clone(),
                labels,
                memory_bytes,
                nano_cpus,
                pids_limit: self.settings.pids_limit,
                egress_mbps: limits.egress_mbps,
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
                    if observation.running {
                        // ADR-025 §3: an Agent restart between the
                        // container being confirmed running and
                        // rate_limit() completing -- or a tc qdisc lost
                        // out-of-band (e.g. the veth was recreated) --
                        // otherwise has no path back to enforcement, since
                        // nothing else in this codebase periodically
                        // reconciles tc rules. This is that path.
                        // container_id is reborrowed as an owned String
                        // first: apply_rate_limit_if_needed needs &mut
                        // record, which the existing container_id
                        // (borrowed from record) would conflict with.
                        let container_id = container_id.to_string();
                        self.apply_rate_limit_if_needed(&mut record, &container_id)
                            .await;
                        record.phase = WorkloadPhase::Running;
                    } else if record.phase == WorkloadPhase::Stopping {
                        record.phase = WorkloadPhase::Stopped;
                    } else {
                        record.phase = WorkloadPhase::Failed;
                    }
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

/// ADR-025 §2: reads bandwidth for every locally-known workload the
/// Agent currently believes is `Running`, using `engine` (a caller-
/// supplied `ContainerEngine` so this stays testable against `FakeEngine`
/// without a real Docker daemon or a full `DockerExecutor`).
///
/// A workload whose reading fails (container briefly unreachable, veth
/// not resolvable, etc.) is skipped with a warning rather than aborting
/// the whole heartbeat -- one bad workload must not blank out every
/// other workload's legitimate data for this round, mirroring
/// `active_validators`' identical single-bad-entry tolerance on the
/// Control Plane side. A workload that never successfully reads is
/// simply absent from this round's report, which the Control Plane must
/// render as "no data", never as "zero usage" (ADR-025 §5).
pub async fn collect_workload_bandwidth(
    state: &LocalState,
    engine: &dyn ContainerEngine,
) -> Vec<(String, WorkloadBandwidth)> {
    let workloads = match state.workloads() {
        Ok(workloads) => workloads,
        Err(error) => {
            warn!(%error, "failed to list local workloads; omitting bandwidth from this heartbeat");
            return Vec::new();
        }
    };

    let mut readings = Vec::new();
    for record in workloads {
        if record.phase != WorkloadPhase::Running {
            continue;
        }
        let Some(container_id) = record.container_id.as_deref() else {
            continue;
        };
        match engine.bandwidth(container_id).await {
            Ok(reading) => readings.push((record.workload_id, reading)),
            Err(error) => {
                warn!(
                    workload_id = %record.workload_id,
                    %error,
                    "bandwidth usage unavailable for workload; omitting from this heartbeat"
                );
            }
        }
    }
    readings
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
            if let Some(container_id) = record.container_id.clone() {
                let observation = self.engine.inspect(&container_id).await?;
                if observation.running {
                    // Retried deploy() for an already-running container --
                    // e.g. the control-plane retrying a DEPLOYING attempt
                    // whose previous response was lost. Confirming
                    // "running" is not enough on its own: a prior attempt
                    // may have gotten this far and then failed to apply
                    // the tc rule (see apply_rate_limit_if_needed's doc
                    // comment). This is what actually reconciles that
                    // case, not just start()/create() idempotency.
                    self.apply_rate_limit_if_needed(&mut record, &container_id)
                        .await;
                    record.phase = WorkloadPhase::Running;
                    self.state.store_workload(&record)?;
                    return Ok(container_id);
                }
                if record.phase == WorkloadPhase::Stopped {
                    return Err(ExecutorError::StateConfirmation(container_id).into());
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
        // ADR-025 §3: the fourth quota, applied only now that Docker has
        // actually allocated the container's veth pair (start + a
        // confirmed running observation, same ordering the ADR requires).
        // See apply_rate_limit_if_needed's doc comment for why a failure
        // here does not fail deploy() or mark the workload Failed.
        self.apply_rate_limit_if_needed(&mut record, &container_id)
            .await;
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

    /// ADR-029 §6 / issue #20. `record.lease_id` and the
    /// sequence/period bounds (`LocalState::next_metering_period`) are
    /// real and durable; `WorkloadNotFound` propagates unchanged so
    /// agent-api's `executor_status_error` maps it to `NotFound`, the
    /// same way `get_status` already does for a missing workload.
    ///
    /// **The five usage counters below are honest zero stubs** -- see
    /// `UsageSample`'s own doc comment. No per-container CPU/RAM/storage
    /// metric source exists anywhere in this codebase yet (bollard's
    /// container stats API -- `Docker::stats` -- is not called by
    /// `ContainerEngine`/`BollardEngine` today), and this workload's
    /// live network byte counters (`bandwidth::read_bandwidth`) need a
    /// container PID this method has no cheap way to obtain without a
    /// second Docker inspect call per invocation -- deliberately left
    /// for the real-collection follow-up issue named in the implementing
    /// PR's description, rather than half-wiring one dimension now.
    async fn usage_summary(
        &self,
        workload_id: &str,
        now: u64,
        max_period_seconds: u64,
    ) -> Result<UsageSample> {
        let record = self.state.workload(workload_id)?;
        let period = self
            .state
            .next_metering_period(workload_id, now, max_period_seconds)?;
        Ok(UsageSample {
            lease_id: record.lease_id,
            sequence: period.sequence,
            period_start: period.period_start,
            period_end: period.period_end,
            cpu_core_seconds: 0,
            ram_mb_seconds: 0,
            storage_gb_seconds: 0,
            network_egress_mb: 0,
            network_ingress_mb: 0,
            gpu_seconds: 0,
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
        // ADR-025 §2: per-container_id canned bandwidth outcome -- `Ok`
        // for a configured reading, `Err` (or simply absent) to exercise
        // collect_workload_bandwidth's skip-and-warn degrade path.
        bandwidth_readings: StdMutex<HashMap<String, Result<WorkloadBandwidth, String>>>,
        // ADR-025 §3: every rate_limit() call this engine received, in
        // order, as (container_id, egress_mbps) -- lets tests assert
        // deploy() invoked it with exactly the right target and rate (or
        // not at all).
        rate_limit_calls: StdMutex<Vec<(String, i32)>>,
        // Per-container_id configured failure for rate_limit(); absent
        // means succeed.
        rate_limit_failures: StdMutex<HashMap<String, String>>,
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

        async fn bandwidth(&self, container_id: &str) -> Result<WorkloadBandwidth, ExecutorError> {
            match self
                .bandwidth_readings
                .lock()
                .expect("bandwidth readings lock")
                .get(container_id)
            {
                Some(Ok(reading)) => Ok(reading.clone()),
                Some(Err(reason)) => Err(ExecutorError::Engine(reason.clone())),
                None => Err(ExecutorError::Engine(format!(
                    "no bandwidth reading configured for {container_id}"
                ))),
            }
        }

        async fn rate_limit(
            &self,
            container_id: &str,
            egress_mbps: i32,
        ) -> Result<(), ExecutorError> {
            self.rate_limit_calls
                .lock()
                .expect("rate limit calls lock")
                .push((container_id.to_string(), egress_mbps));
            if let Some(reason) = self
                .rate_limit_failures
                .lock()
                .expect("rate limit failures lock")
                .get(container_id)
            {
                return Err(ExecutorError::Engine(reason.clone()));
            }
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
                egress_mbps: 0,
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
    async fn recover_reapplies_a_rate_limit_that_never_succeeded() {
        // ADR-025 §3's other reconciliation path: an Agent process
        // restart between the container being confirmed running and
        // rate_limit() completing must not leave the workload
        // permanently unthrottled -- recover() is the only code that
        // runs unconditionally on every Agent start, so it has to be the
        // one that checks record.rate_limited and retries.
        let directory = tempfile::tempdir().expect("directory");
        let engine = Arc::new(FakeEngine::default());
        engine
            .rate_limit_failures
            .lock()
            .expect("rate limit failures lock")
            .insert(
                "container-1".to_string(),
                "tc: RTNETLINK answers: Permission denied".to_string(),
            );
        let mut request = request(Uuid::new_v4(), Uuid::new_v4());
        request.limits.as_mut().expect("limits").egress_mbps = 50;
        let workload_id = request.workload_id.clone();
        {
            let executor = executor(engine.clone(), directory.path(), 1);
            executor
                .deploy(request)
                .await
                .expect("deploy succeeds despite the tc failure");
        }
        assert_eq!(
            engine
                .rate_limit_calls
                .lock()
                .expect("rate limit calls lock")
                .len(),
            1,
            "one attempt during the original deploy"
        );

        // The Agent process restarts; the backend has recovered by then.
        engine
            .rate_limit_failures
            .lock()
            .expect("rate limit failures lock")
            .remove("container-1");
        let recovered = executor(engine.clone(), directory.path(), 1);
        recovered.recover().await.expect("recover");

        let calls = engine
            .rate_limit_calls
            .lock()
            .expect("rate limit calls lock")
            .clone();
        assert_eq!(
            calls.len(),
            2,
            "recover() must reapply the rate limit for a running-but-not-yet-limited workload: {calls:?}"
        );
        let record = recovered
            .state
            .workload(&workload_id)
            .expect("workload record after recover");
        assert_eq!(record.phase, WorkloadPhase::Running);
        assert!(
            record.rate_limited,
            "rate_limited must be true once recover()'s retry succeeds"
        );
    }

    #[tokio::test]
    async fn collect_workload_bandwidth_reports_only_running_workloads() {
        let directory = tempfile::tempdir().expect("directory");
        let engine = Arc::new(FakeEngine::default());
        let executor = executor(engine.clone(), directory.path(), 2);

        let running = request(Uuid::new_v4(), Uuid::new_v4());
        let running_container = executor
            .deploy(running.clone())
            .await
            .expect("deploy running");
        let reading = WorkloadBandwidth {
            ingress_bytes_total: 111,
            egress_bytes_total: 222,
            window_started_at: std::time::UNIX_EPOCH,
        };
        engine
            .bandwidth_readings
            .lock()
            .expect("bandwidth readings lock")
            .insert(running_container, Ok(reading.clone()));

        // A second workload is deployed and then stopped -- its bandwidth
        // must not appear in the report even though it still has a
        // container_id on record, matching "cumulative since container
        // start" (a stopped container's counters are stale, not current).
        let stopped = request(Uuid::new_v4(), Uuid::new_v4());
        executor
            .deploy(stopped.clone())
            .await
            .expect("deploy stopped");
        executor.stop(&stopped.workload_id).await.expect("stop");

        let readings = collect_workload_bandwidth(&executor.state, engine.as_ref()).await;
        assert_eq!(readings.len(), 1);
        assert_eq!(readings[0].0, running.workload_id);
        assert_eq!(readings[0].1, reading);
    }

    #[tokio::test]
    async fn collect_workload_bandwidth_skips_a_workload_whose_reading_fails() {
        let directory = tempfile::tempdir().expect("directory");
        let engine = Arc::new(FakeEngine::default());
        let executor = executor(engine.clone(), directory.path(), 2);

        let ok_request = request(Uuid::new_v4(), Uuid::new_v4());
        let ok_container = executor
            .deploy(ok_request.clone())
            .await
            .expect("deploy ok");
        let reading = WorkloadBandwidth {
            ingress_bytes_total: 1,
            egress_bytes_total: 2,
            window_started_at: std::time::UNIX_EPOCH,
        };
        engine
            .bandwidth_readings
            .lock()
            .expect("bandwidth readings lock")
            .insert(ok_container, Ok(reading.clone()));

        // failing_request's container is deliberately left unconfigured in
        // bandwidth_readings, so FakeEngine::bandwidth returns an error for
        // it -- collect_workload_bandwidth must skip it, not fail the call.
        let failing_request = request(Uuid::new_v4(), Uuid::new_v4());
        executor
            .deploy(failing_request.clone())
            .await
            .expect("deploy failing");

        let readings = collect_workload_bandwidth(&executor.state, engine.as_ref()).await;
        assert_eq!(readings.len(), 1);
        assert_eq!(readings[0].0, ok_request.workload_id);
        assert_eq!(readings[0].1, reading);
    }

    // ADR-025 §3: deploy() must apply the fourth quota (egress rate) only
    // when the workload actually reserved bandwidth, targeting the exact
    // container Docker just confirmed running.
    #[tokio::test]
    async fn deploy_applies_rate_limit_when_bandwidth_is_reserved() {
        let directory = tempfile::tempdir().expect("directory");
        let engine = Arc::new(FakeEngine::default());
        let executor = executor(engine.clone(), directory.path(), 1);
        let mut request = request(Uuid::new_v4(), Uuid::new_v4());
        request.limits.as_mut().expect("limits").egress_mbps = 50;

        let container_id = executor.deploy(request).await.expect("deploy");

        let calls = engine
            .rate_limit_calls
            .lock()
            .expect("rate limit calls lock");
        assert_eq!(calls.as_slice(), &[(container_id, 50)]);
    }

    #[tokio::test]
    async fn deploy_skips_rate_limit_when_no_bandwidth_is_reserved() {
        let directory = tempfile::tempdir().expect("directory");
        let engine = Arc::new(FakeEngine::default());
        let executor = executor(engine.clone(), directory.path(), 1);
        // request()'s default egress_mbps is 0 -- "no bandwidth
        // requirement declared" must mean "no tc rule applied", not "a
        // zero-rate ceiling".
        let request = request(Uuid::new_v4(), Uuid::new_v4());

        executor.deploy(request).await.expect("deploy");

        assert!(engine
            .rate_limit_calls
            .lock()
            .expect("rate limit calls lock")
            .is_empty());
    }

    #[tokio::test]
    async fn deploy_succeeds_and_retains_capacity_when_rate_limit_application_fails() {
        // Pinned by code review on PR #126: a failed tc application must
        // never mark the workload Failed, because the container is
        // genuinely running (Docker create+start+inspect all already
        // succeeded by the time rate_limit() is even attempted) --
        // WorkloadPhase::Failed is excluded from consumes_capacity(), so
        // marking it Failed would silently free this workload's capacity
        // slot for a container that is still actually running
        // unthrottled. This replaces a previous version of this test that
        // asserted the opposite (now-fixed) behavior.
        let directory = tempfile::tempdir().expect("directory");
        let engine = Arc::new(FakeEngine::default());
        // FakeEngine::create names containers deterministically
        // ("container-<n>" by creation order), so the first container a
        // fresh engine creates in this test is known ahead of deploy().
        engine
            .rate_limit_failures
            .lock()
            .expect("rate limit failures lock")
            .insert(
                "container-1".to_string(),
                "tc: RTNETLINK answers: Permission denied".to_string(),
            );
        let executor = executor(engine.clone(), directory.path(), 1);
        let mut first_request = request(Uuid::new_v4(), Uuid::new_v4());
        first_request.limits.as_mut().expect("limits").egress_mbps = 50;
        let workload_id = first_request.workload_id.clone();

        let result = executor.deploy(first_request).await;

        assert!(
            result.is_ok(),
            "a failed tc application must not fail deploy: {result:?}"
        );
        let record = executor
            .state
            .workload(&workload_id)
            .expect("workload record after deploy");
        assert_eq!(
            record.phase,
            WorkloadPhase::Running,
            "the container is genuinely running regardless of the tc failure"
        );
        assert!(
            !record.rate_limited,
            "rate_limited must stay false so a retry knows to reapply it"
        );

        // The capacity slot must still be held: with max_workloads=1, a
        // second, distinct workload must be rejected, not silently
        // admitted because the first was wrongly marked Failed.
        let mut second_request = request(Uuid::new_v4(), Uuid::new_v4());
        second_request.limits.as_mut().expect("limits").egress_mbps = 0;
        let second_result = executor.deploy(second_request).await;
        assert!(
            second_result.is_err(),
            "capacity must still be held by the degraded-but-running workload: {second_result:?}"
        );
    }

    #[tokio::test]
    async fn deploy_retry_reapplies_the_rate_limit_after_a_prior_failure() {
        // The other half of the fix above: record.rate_limited staying
        // false is only useful if something actually acts on it. A
        // retried deploy() for the same workload_id (the control-plane
        // resending a DEPLOYING attempt whose previous response was
        // lost, per orchestrator/worker.go) must reapply the tc rule via
        // the Reservation::Existing fast path, not just report success
        // again.
        let directory = tempfile::tempdir().expect("directory");
        let engine = Arc::new(FakeEngine::default());
        engine
            .rate_limit_failures
            .lock()
            .expect("rate limit failures lock")
            .insert(
                "container-1".to_string(),
                "tc: RTNETLINK answers: Permission denied".to_string(),
            );
        let executor = executor(engine.clone(), directory.path(), 1);
        let mut request = request(Uuid::new_v4(), Uuid::new_v4());
        request.limits.as_mut().expect("limits").egress_mbps = 50;
        let workload_id = request.workload_id.clone();

        executor
            .deploy(request.clone())
            .await
            .expect("first deploy succeeds despite the tc failure");
        assert_eq!(
            engine
                .rate_limit_calls
                .lock()
                .expect("rate limit calls lock")
                .len(),
            1,
            "exactly one rate_limit attempt on the first deploy"
        );

        // The backend recovers (e.g. a transient permission/lock issue
        // clears); the control-plane retries the same DeployRequest.
        engine
            .rate_limit_failures
            .lock()
            .expect("rate limit failures lock")
            .remove("container-1");
        executor
            .deploy(request)
            .await
            .expect("retried deploy succeeds");

        let calls = engine
            .rate_limit_calls
            .lock()
            .expect("rate limit calls lock")
            .clone();
        assert_eq!(
            calls.len(),
            2,
            "the retry must reapply the rate limit, not skip it: {calls:?}"
        );
        let record = executor
            .state
            .workload(&workload_id)
            .expect("workload record after retry");
        assert!(
            record.rate_limited,
            "rate_limited must be true once the retry actually succeeds"
        );
    }

    #[tokio::test]
    async fn deploy_rejects_negative_egress_mbps() {
        let directory = tempfile::tempdir().expect("directory");
        let engine = Arc::new(FakeEngine::default());
        let executor = executor(engine, directory.path(), 1);
        let mut request = request(Uuid::new_v4(), Uuid::new_v4());
        request.limits.as_mut().expect("limits").egress_mbps = -1;

        assert!(executor.deploy(request).await.is_err());
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
                // 0: this integration test targets Docker's own
                // HostConfig quotas (mandatory even without CAP_NET_ADMIN,
                // which this test environment is not guaranteed to have);
                // ADR-025 §3's tc ceiling is covered by the CommandRunner-
                // level unit tests in rate_limit.rs instead, see this
                // module's own tests for the invocation-level coverage.
                egress_mbps: 0,
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
