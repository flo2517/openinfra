mod bandwidth;
mod rate_limit;
pub mod vm;

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
use bollard::image::CreateImageOptions;
use bollard::models::HostConfig;
use bollard::network::CreateNetworkOptions;
use bollard::Docker;
use futures_util::StreamExt;
pub use rate_limit::{CommandRunner, RateLimiter, SystemCommandRunner};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::{error, info, warn};
use uuid::Uuid;

const MIB: i64 = 1024 * 1024;
const NANOS_PER_CPU: f64 = 1_000_000_000.0;

/// Issue #174: every workload container is attached to this dedicated
/// bridge network instead of implicitly joining Docker's default bridge,
/// with inter-container communication (ICC) disabled on it -- see
/// `BollardEngine::ensure_workload_network`'s doc comment for the
/// mechanism and `BollardEngine::create`'s call site for where it's
/// applied. Two workload containers on this network can each still reach
/// the outside world (this is an ordinary NAT'd bridge, not `internal:
/// true`), but Docker refuses to forward traffic *between* them.
///
/// This is deliberately orthogonal to ADR-010's WireGuard-attach path
/// (`control-plane/internal/wireguard`'s `AttachNamespace`): that backend
/// resolves a workload's container PID and operates directly on its
/// network *namespace* (the same technique this crate's own
/// `bandwidth::resolve_veth_name` uses -- matching a host-side interface
/// by the container `eth0`'s `iflink`), never through Docker's own
/// network abstraction. Which bridge a container's `eth0` happens to be
/// attached to has no bearing on that -- confirmed by inspection, and
/// exercised by this crate's `docker_integration_isolates_workload_
/// containers_from_each_other` test alongside the existing WireGuard/
/// veth-resolution tests, which keep passing unmodified.
const WORKLOAD_NETWORK_NAME: &str = "openinfra-workloads";

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

// Issue #17: `Docker::connect_with_local_defaults()` on Unix is a thin
// wrapper over `connect_with_unix_defaults()` (bollard's own
// docker.rs), which *only* honors `DOCKER_HOST` when it starts with the
// literal `unix://` scheme -- for any other value (a `tcp://` URL, most
// notably: deployments/docker-compose.yml sets
// `DOCKER_HOST=tcp://docker-socket-proxy:2375` for the containerized
// Agent, which never has a real Docker socket mounted, by design) it
// silently falls back to bollard's hardcoded default *unix socket path*
// and ignores `DOCKER_HOST` entirely. That path does not exist in this
// container, so every real Docker operation (create/start/inspect/...)
// fails with "error trying to connect: No such file or directory" --
// confirmed live, 100% reproducing, while developing tests/e2e/: the
// always-on Compose provider-agent could never actually deploy a
// workload through docker-socket-proxy. `connect_with_local_defaults()`
// was never wrong for a host-run Agent (no `DOCKER_HOST`, the real local
// socket at the default path) -- only for the container's TCP case,
// which this dispatches to `connect_with_http_defaults()`
// (bollard.rs's own doc comment: "sourced from the DOCKER_HOST
// environment variable") instead.
fn connect_docker() -> Result<Docker, bollard::errors::Error> {
    let uses_tcp = std::env::var("DOCKER_HOST")
        .map(|host| host.starts_with("tcp://") || host.starts_with("http://"))
        .unwrap_or(false);
    if uses_tcp {
        Docker::connect_with_http_defaults()
    } else {
        Docker::connect_with_local_defaults()
    }
}

pub struct BollardEngine {
    docker: Docker,
    rate_limiter: RateLimiter,
}

impl BollardEngine {
    pub fn connect() -> Result<Self, ExecutorError> {
        Ok(Self {
            docker: connect_docker().map_err(|error| ExecutorError::Engine(error.to_string()))?,
            rate_limiter: RateLimiter::new(Arc::new(SystemCommandRunner)),
        })
    }

    /// Issue #154: pulls `image` (any reference bollard's `from_image`
    /// accepts -- `repo`, `repo:tag`, or `repo@sha256:digest`) into the
    /// local Docker daemon, bounded by `IMAGE_PULL_TIMEOUT` so a large
    /// image or an unreachable/slow registry cannot hang `deploy()`
    /// indefinitely (a distinct, inner bound from the orchestrator's own
    /// bounded-retry budget, #138 -- that one paces retries across
    /// separate `Deploy` attempts; this one bounds a single attempt).
    /// Consumes bollard's progress stream to completion (or to its first
    /// error) rather than dropping it -- dropping the stream early would
    /// cancel the pull (`create_image`'s own doc comment: "The pull is
    /// cancelled if the HTTP connection is closed").
    async fn pull_image(&self, image: &str) -> Result<(), ExecutorError> {
        const IMAGE_PULL_TIMEOUT: Duration = Duration::from_secs(180);
        let options = CreateImageOptions {
            from_image: image.to_string(),
            ..Default::default()
        };
        let mut stream = self.docker.create_image(Some(options), None, None);
        let pull = async {
            while let Some(event) = stream.next().await {
                event.map_err(|error| {
                    ExecutorError::Engine(format!("pulling image {image}: {error}"))
                })?;
            }
            Ok(())
        };
        tokio::time::timeout(IMAGE_PULL_TIMEOUT, pull)
            .await
            .map_err(|_| {
                ExecutorError::Engine(format!(
                    "timed out after {IMAGE_PULL_TIMEOUT:?} pulling image {image}"
                ))
            })?
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

    /// Issue #174: idempotently ensures `WORKLOAD_NETWORK_NAME` exists,
    /// creating it on first use. Called from `create()` rather than once
    /// at Agent startup: unlike `pull_image`, this only needs to run
    /// before an actual container creation (not before every heartbeat's
    /// `BollardEngine::connect()` -- see agent-cli's `workload_bandwidth_
    /// usage`, which reconnects fresh every ~15s purely to read existing
    /// counters and never needs this network to exist), so tying it to
    /// `create()` keeps that frequent, read-only path free of an extra
    /// network round-trip and an extra `docker-socket-proxy` NETWORKS
    /// dependency it never otherwise needed.
    ///
    /// Race-safe: in the local dev "multi-node" Compose profile, multiple
    /// Agent processes share one Docker daemon through the same
    /// `docker-socket-proxy` (see `deployments/docker-compose.yml`'s own
    /// comment on `provider-agent-2`/`-3`), so more than one `create()`
    /// can race to create this network the first time. `check_duplicate:
    /// true` makes Docker itself reject a second create for the same name
    /// -- confirmed against the Engine API, this surfaces as 403
    /// Forbidden (some Docker versions instead 409) -- either is treated
    /// as success here, not a failure, since the network exists either
    /// way by the time this returns.
    async fn ensure_workload_network(docker: &Docker) -> Result<(), ExecutorError> {
        match docker
            .inspect_network::<String>(WORKLOAD_NETWORK_NAME, None)
            .await
        {
            Ok(_) => return Ok(()),
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 404, ..
            }) => {}
            Err(error) => return Err(ExecutorError::Engine(error.to_string())),
        }
        let options = CreateNetworkOptions {
            name: WORKLOAD_NETWORK_NAME.to_string(),
            check_duplicate: true,
            driver: "bridge".to_string(),
            // Docker's bridge-driver option to disable inter-container
            // communication on this specific bridge -- the exact
            // mechanism issue #174 asks for ("disable ICC ... on
            // whatever bridge is actually in use"), scoped to this one
            // dedicated bridge rather than the daemon-wide `--icc=false`
            // startup flag (which this codebase has no way to set: the
            // Agent only ever reaches Docker through docker-socket-
            // proxy's HTTP API, never dockerd's own command line).
            options: HashMap::from([(
                "com.docker.network.bridge.enable_icc".to_string(),
                "false".to_string(),
            )]),
            ..Default::default()
        };
        match docker.create_network(options).await {
            Ok(_) => Ok(()),
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 403 | 409,
                ..
            }) => Ok(()),
            Err(error) => Err(ExecutorError::Engine(error.to_string())),
        }
    }
}

#[async_trait]
impl ContainerEngine for BollardEngine {
    async fn create(&self, spec: &ContainerSpec) -> Result<String, ExecutorError> {
        // Issue #174: must exist before create_container below references
        // it by name via HostConfig.network_mode -- Docker rejects
        // creation against an unknown network name outright, so this is
        // the one place that has to run before every genuinely new
        // container (not the Reservation::Existing / idempotent-retry
        // paths in DockerExecutor::deploy, which never reach here).
        Self::ensure_workload_network(&self.docker).await?;
        let host_config = HostConfig {
            memory: Some(spec.memory_bytes),
            memory_swap: Some(spec.memory_bytes),
            nano_cpus: Some(spec.nano_cpus),
            pids_limit: Some(spec.pids_limit),
            security_opt: Some(vec!["no-new-privileges:true".to_string()]),
            cap_drop: Some(vec!["ALL".to_string()]),
            init: Some(true),
            // Issue #174: replaces implicit membership in Docker's
            // default bridge (zero inter-container isolation) with the
            // dedicated, ICC-disabled network -- see
            // WORKLOAD_NETWORK_NAME's doc comment.
            network_mode: Some(WORKLOAD_NETWORK_NAME.to_string()),
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
        match self
            .docker
            .create_container(Some(options.clone()), config.clone())
            .await
        {
            Ok(response) => Ok(response.id),
            // Issue #154: confirmed live -- a workload with a valid, correctly
            // pinned image reference stuck retrying forever because the
            // Agent never pulls an image it doesn't already have cached.
            // `status_code == 404` (not a message-substring match) is
            // bollard's own structured signal for exactly this case
            // (bollard::errors::Error::DockerResponseServerError). Pull once,
            // bounded, then retry create() exactly once -- a second 404
            // after a successful pull, or a pull failure/timeout, is
            // surfaced as-is and not retried again here: distinguishing
            // "wasn't cached yet" (this fixes it) from "genuinely doesn't
            // exist" or "registry unreachable" (must still fail loudly, not
            // loop). The orchestrator's own bounded-retry budget (#138) is
            // the outer safety net for a reference that's really bad, not
            // this.
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 404, ..
            }) => {
                self.pull_image(&spec.image).await?;
                self.docker
                    .create_container(Some(options), config)
                    .await
                    .map(|response| response.id)
                    .map_err(|error| ExecutorError::Engine(error.to_string()))
            }
            Err(error) => Err(ExecutorError::Engine(error.to_string())),
        }
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
    /// ADR-033 §6/§7: `max_vm_workloads == 0` (the default) -- every VM
    /// deploy attempt is rejected with this specific, identifiable
    /// error, never silently ignored and never conflated with an
    /// ordinary validation failure. See `vm::VmExecutor::deploy`.
    #[error("VM workloads are disabled on this Agent (max_vm_workloads=0)")]
    VmDisabled,
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
        // ADR-028 §3: required, not optional -- without a known lease_end
        // the Agent has no local basis to bound how long it stays
        // authorized to run this workload if it becomes disconnected from
        // the Control Plane. This is a stricter reading than the ADR's own
        // text (which only says the field is *added*, not that it is
        // mandatory); the more conservative interpretation is chosen
        // deliberately, per this ADR's own "when ambiguous, refuse rather
        // than guess" instruction.
        let lease_end = request
            .lease_end
            .as_ref()
            .ok_or_else(|| ExecutorError::InvalidRequest("lease_end is required".to_string()))?;
        if lease_end.seconds <= 0 {
            return Err(ExecutorError::InvalidRequest(
                "lease_end must be a positive timestamp".to_string(),
            ));
        }
        let lease_end_unix = lease_end.seconds;
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
                vm_handle: None,
                runtime: agent_core::local_state::WorkloadRuntime::Container,
                phase: WorkloadPhase::Provisioning,
                egress_mbps: limits.egress_mbps,
                rate_limited: false,
                lease_end: Some(lease_end_unix),
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

    /// ADR-028 §3: local, deterministic lease-expiry enforcement, bounded
    /// strictly by each workload's own `lease_end` -- not by any separate,
    /// arbitrary "how long can the Agent stay disconnected" timeout (the
    /// ADR deliberately introduces none). Intended to run unconditionally
    /// on the Agent's existing 15s heartbeat cadence (agent-cli's own
    /// background task), whether or not the Agent is currently connected:
    /// while connected, the Control Plane normally sends an explicit
    /// `StopRequest` at lease end anyway, so this rarely fires first;
    /// while disconnected, it is the only thing that does.
    ///
    /// `now` is caller-supplied (not read internally) so tests can assert
    /// the exact clock-skew boundary deterministically rather than racing
    /// the real clock.
    ///
    /// Only `Starting`/`Running` records are considered: `Provisioning`
    /// has no container yet (nothing to stop), and
    /// `Stopping`/`Stopped`/`Failed`/`Lost` already fall outside
    /// `WorkloadPhase::consumes_capacity` -- there is nothing left
    /// authorized to keep running for them either. A record with no
    /// persisted `lease_end` (only possible for one written before this
    /// field existed) is left alone -- see `WorkloadRecord::lease_end`'s
    /// doc comment for why guessing one would violate this ADR's
    /// never-fabricate principle.
    ///
    /// Returns the workload_ids actually stopped this pass, for the
    /// caller to log. A single workload's `stop()` failure is logged and
    /// does not abort the pass -- one bad workload must not block
    /// reclaiming every other already-expired lease on the same tick; it
    /// is retried on the next tick since its phase/lease_end are
    /// unchanged.
    pub async fn enforce_lease_expiry(&self, now: SystemTime) -> Result<Vec<String>> {
        // ADR-028 §3: the same 2-minute clock-skew tolerance
        // `providerjoin.maxHeartbeatClockSkew` already uses, reused
        // rather than inventing a new number.
        const CLOCK_SKEW_TOLERANCE_SECS: i64 = 120;
        let now_unix = now
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs() as i64)
            .unwrap_or(0);
        let mut stopped = Vec::new();
        for record in self.state.workloads()? {
            if !matches!(
                record.phase,
                WorkloadPhase::Starting | WorkloadPhase::Running
            ) {
                continue;
            }
            let Some(lease_end) = record.lease_end else {
                continue;
            };
            if now_unix < lease_end.saturating_add(CLOCK_SKEW_TOLERANCE_SECS) {
                continue;
            }
            match Executor::stop(self, &record.workload_id).await {
                Ok(()) => {
                    info!(
                        workload_id = %record.workload_id,
                        lease_end,
                        now_unix,
                        "lease expired while disconnected or connected; stopped the workload locally"
                    );
                    stopped.push(record.workload_id.clone());
                }
                Err(error) => {
                    warn!(
                        workload_id = %record.workload_id,
                        %error,
                        "failed to stop a workload past its lease_end; will retry on the next tick"
                    );
                }
            }
        }
        Ok(stopped)
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
        // ADR-028 §4: Stop is idempotent for a workload_id already
        // Stopped/Failed, and for one this Agent has never heard of --
        // stopping something that is already stopped, or that isn't (or
        // is no longer) known here, is not a failure condition. This is
        // what makes a Stop redelivered after a reconnect a safe no-op
        // rather than a surfaced error.
        let mut record = match self.state.workload(workload_id) {
            Ok(record) => record,
            Err(LocalStateError::WorkloadNotFound(_)) => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        if matches!(record.phase, WorkloadPhase::Stopped | WorkloadPhase::Failed) {
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
        // Issue #17: this used to end at the inspect() above, leaving a
        // stopped-but-never-removed container on the host forever -- a
        // real, unbounded resource leak (confirmed live: an E2E stop
        // never observed the container actually disappear, no matter how
        // long it waited) with no user-visible signal that anything was
        // wrong, since WorkloadPhase::Stopped/capacity accounting never
        // depended on the container object still existing. Removing it
        // here is the same idempotent, force-remove call deploy()'s own
        // persistence-failure cleanup path already uses (see `remove`'s
        // call site above in this file).
        self.engine.remove(&container_id).await?;
        record.phase = WorkloadPhase::Stopped;
        self.state.store_workload(&record)?;
        info!(%workload_id, %container_id, "Docker confirmed workload stopped");
        Ok(())
    }

    async fn get_status(&self, workload_id: &str) -> Result<WorkloadStatus> {
        let record = self.state.workload(workload_id)?;
        if record.phase == WorkloadPhase::Stopped {
            // Issue #17: checked before ever touching container_id/
            // inspect(). stop() now removes the container (see its own
            // doc comment) but does not clear the now-stale
            // container_id off the record -- inspecting it here would
            // 404 ("No such container"), which propagated as a hard
            // error (same failure shape as the container_id==None case
            // below) and left control-plane's StopAndConfirm confirming
            // a stop that had, in fact, already fully succeeded,
            // retrying forever. STATE_COMPLETED is exactly what
            // StopAndConfirm (control-plane/internal/agentmanager/
            // client.go) already waits for.
            return Ok(WorkloadStatus {
                state: State::Completed as i32,
                details: "stopped".to_string(),
            });
        }
        let Some(container_id) = record.container_id else {
            // Issue #17: this used to be a hard error
            // (ExecutorError::StateConfirmation, mapped by agent-api's
            // executor_status_error to a gRPC Internal status). A record
            // that exists locally but has no container yet is not an
            // error to report status for -- it is the normal, if
            // narrow, state between deploy()'s workload reservation and
            // its call to engine.create() (including the state a failed
            // first create() attempt leaves behind forever, since deploy()
            // returns before ever setting container_id on failure).
            // internal/orchestrator/worker.go's DEPLOYING reconciliation
            // path (GetRunningWorkload) treats a non-NotFound error as
            // "unknown, retry the status check again" and -- confirmed
            // live, repeatedly -- never falls through to attempt a fresh
            // Deploy, permanently stranding the workload after any
            // transient first-attempt failure. Reporting STATE_DEPLOYING
            // here instead is both accurate (the workload genuinely is
            // still mid-deploy, not lost) and lets that same client code
            // path already handles the false/nil result cleanly.
            return Ok(WorkloadStatus {
                state: State::Deploying as i32,
                details: "no container yet".to_string(),
            });
        };
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
    use std::fs;
    use std::sync::Mutex as StdMutex;

    #[derive(Default)]
    struct FakeEngine {
        created: StdMutex<Vec<ContainerSpec>>,
        started: StdMutex<Vec<String>>,
        stopped: StdMutex<Vec<String>>,
        removed: StdMutex<Vec<String>>,
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

        async fn remove(&self, container_id: &str) -> Result<(), ExecutorError> {
            self.removed
                .lock()
                .expect("removed lock")
                .push(container_id.to_string());
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

    // ADR-028 §3: a lease_end comfortably in the future, so ordinary
    // deploy()/stop() tests aren't incidentally exercising lease-expiry
    // enforcement. Tests that specifically exercise enforce_lease_expiry
    // override this field directly.
    fn future_lease_end() -> prost_types::Timestamp {
        prost_types::Timestamp {
            seconds: 4_102_444_800, // 2100-01-01T00:00:00Z
            nanos: 0,
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
            lease_end: Some(future_lease_end()),
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
            std::slice::from_ref(&container_id)
        );
        // Issue #17: Stop must not just mark the workload Stopped, it
        // must actually remove the container -- confirmed live that this
        // previously never happened, leaking a stopped container behind
        // every workload forever.
        assert_eq!(
            engine.removed.lock().expect("removed lock").as_slice(),
            &[container_id],
            "stop() must remove the container, not just stop it"
        );
        executor
            .stop(&request.workload_id)
            .await
            .expect("idempotent stop");
        // A second stop() on an already-Stopped workload short-circuits
        // before touching the engine at all (see the `record.phase ==
        // WorkloadPhase::Stopped` early return) -- remove() must not be
        // called a second time for the same container.
        assert_eq!(engine.removed.lock().expect("removed lock").len(), 1);
        // Issue #17: get_status() after stop() must report COMPLETED
        // (what control-plane's StopAndConfirm actually waits for), not
        // error trying to inspect the now-removed container_id still on
        // the record -- confirmed live: this previously 404'd ("No such
        // container") and control-plane retried StopAndConfirm forever
        // even though the stop had already fully succeeded.
        let status = executor
            .get_status(&request.workload_id)
            .await
            .expect("get_status after stop must not error");
        assert_eq!(status.state, State::Completed as i32);
    }

    #[tokio::test]
    async fn get_status_reports_deploying_not_an_error_for_a_record_with_no_container_yet() {
        // Issue #17: get_status() used to return a hard error here
        // (mapped by agent-api to a gRPC Internal status, not NotFound),
        // for the entirely normal case of a workload record that exists
        // locally but has no container yet -- the state deploy() leaves
        // behind forever if its own engine.create() call ever fails once
        // (a transient Docker connection error, for example). Confirmed
        // live: control-plane's orchestrator treats any non-NotFound
        // status-check error as "unknown, retry the check again" and
        // never re-attempts Deploy, permanently stranding the workload.
        // Reporting STATE_DEPLOYING instead lets that same reconciliation
        // path treat it as an ordinary "not running yet" and retry
        // Deploy again, the same way it already does for STATE_CREATED/
        // STATE_PENDING/STATE_DEPLOYING responses from a real container.
        let directory = tempfile::tempdir().expect("directory");
        let engine = Arc::new(FakeEngine::default());
        let executor = executor(engine, directory.path(), 1);
        let workload_id = Uuid::new_v4().to_string();
        let candidate = agent_core::local_state::WorkloadRecord {
            workload_id: workload_id.clone(),
            lease_id: Uuid::new_v4().to_string(),
            image: "registry.example/image:tag".to_string(),
            spec_hash: [0u8; 32],
            container_id: None,
            vm_handle: None,
            runtime: agent_core::local_state::WorkloadRuntime::Container,
            phase: agent_core::local_state::WorkloadPhase::Provisioning,
            egress_mbps: 0,
            rate_limited: false,
            lease_end: None,
        };
        // reserve_workload (not store_workload -- that requires an
        // existing row) is deploy()'s own first step: reserve the
        // capacity slot and persist the record *before* ever calling
        // engine.create(), which is exactly what leaves a container-less
        // record behind if create() then fails.
        executor
            .state
            .reserve_workload(&candidate, 1)
            .expect("reserve a container-less record");

        let status = executor
            .get_status(&workload_id)
            .await
            .expect("get_status must not error for a record with no container yet");
        assert_eq!(status.state, State::Deploying as i32);
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

    // --- ADR-028: disconnected mode / durable command reconciliation ---

    #[tokio::test]
    async fn deploy_rejects_a_request_with_no_lease_end() {
        let directory = tempfile::tempdir().expect("directory");
        let engine = Arc::new(FakeEngine::default());
        let executor = executor(engine, directory.path(), 1);
        let mut request = request(Uuid::new_v4(), Uuid::new_v4());
        request.lease_end = None;

        let error = executor
            .deploy(request)
            .await
            .expect_err("a DeployRequest with no lease_end must be rejected");
        assert!(error.to_string().contains("lease_end"));
    }

    #[tokio::test]
    async fn deploy_rejects_a_non_positive_lease_end() {
        let directory = tempfile::tempdir().expect("directory");
        let engine = Arc::new(FakeEngine::default());
        let executor = executor(engine, directory.path(), 1);
        let mut request = request(Uuid::new_v4(), Uuid::new_v4());
        request.lease_end = Some(prost_types::Timestamp {
            seconds: 0,
            nanos: 0,
        });

        assert!(executor.deploy(request).await.is_err());
    }

    /// ADR-028 §4 "duplicate command" acceptance test, unknown-workload
    /// case: a Stop for a workload_id this Agent has never heard of (e.g.
    /// redelivered after a reconnect against a since-restarted Agent, or
    /// simply never seen here) must succeed, not error.
    #[tokio::test]
    async fn stop_is_idempotent_for_a_workload_unknown_to_this_agent() {
        let directory = tempfile::tempdir().expect("directory");
        let engine = Arc::new(FakeEngine::default());
        let executor = executor(engine, directory.path(), 1);

        executor
            .stop("00000000-0000-0000-0000-000000000000")
            .await
            .expect("stop of an unknown workload_id must succeed, not error");
    }

    /// ADR-028 §4 "duplicate command" acceptance test, Failed case: a
    /// second Stop after the first already drove the workload to Failed
    /// (e.g. a start() failure) must also succeed, not error -- Stopped is
    /// already covered by stop_and_status_use_the_persisted_exact_
    /// container_id above.
    #[tokio::test]
    async fn stop_is_idempotent_for_an_already_failed_workload() {
        let directory = tempfile::tempdir().expect("directory");
        let engine = Arc::new(FakeEngine::default());
        let executor = executor(engine.clone(), directory.path(), 1);
        let request = request(Uuid::new_v4(), Uuid::new_v4());
        let workload_id = request.workload_id.clone();
        executor.deploy(request).await.expect("deploy");
        let mut record = executor
            .state
            .workload(&workload_id)
            .expect("workload record");
        record.phase = WorkloadPhase::Failed;
        executor.state.store_workload(&record).expect("store");

        executor
            .stop(&workload_id)
            .await
            .expect("stop of an already-failed workload must succeed, not error");
    }

    /// ADR-028 §3 "expired lease" acceptance test: a Running workload
    /// whose lease_end has passed (beyond the clock-skew tolerance) must
    /// be stopped by enforce_lease_expiry on its own, with no Control
    /// Plane involvement.
    #[tokio::test]
    async fn enforce_lease_expiry_stops_a_running_workload_past_its_lease_end() {
        let directory = tempfile::tempdir().expect("directory");
        let engine = Arc::new(FakeEngine::default());
        let executor = executor(engine.clone(), directory.path(), 1);
        let mut request = request(Uuid::new_v4(), Uuid::new_v4());
        let lease_end_seconds = 1_700_000_000i64;
        request.lease_end = Some(prost_types::Timestamp {
            seconds: lease_end_seconds,
            nanos: 0,
        });
        let workload_id = request.workload_id.clone();
        executor.deploy(request).await.expect("deploy");

        // Well past lease_end plus the 2-minute clock-skew tolerance.
        let now = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_500);
        let stopped = executor
            .enforce_lease_expiry(now)
            .await
            .expect("enforce_lease_expiry");

        assert_eq!(stopped, vec![workload_id.clone()]);
        let record = executor
            .state
            .workload(&workload_id)
            .expect("workload record");
        assert_eq!(record.phase, WorkloadPhase::Stopped);
        assert_eq!(
            engine.stopped.lock().expect("stopped lock").len(),
            1,
            "the container must actually have been stopped"
        );
    }

    #[tokio::test]
    async fn enforce_lease_expiry_leaves_a_workload_within_the_clock_skew_tolerance_running() {
        let directory = tempfile::tempdir().expect("directory");
        let engine = Arc::new(FakeEngine::default());
        let executor = executor(engine.clone(), directory.path(), 1);
        let mut request = request(Uuid::new_v4(), Uuid::new_v4());
        let lease_end_seconds = 1_700_000_000i64;
        request.lease_end = Some(prost_types::Timestamp {
            seconds: lease_end_seconds,
            nanos: 0,
        });
        let workload_id = request.workload_id.clone();
        executor.deploy(request).await.expect("deploy");

        // Exactly 60s past lease_end -- inside the 2-minute tolerance, must
        // not be stopped yet.
        let now = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_060);
        let stopped = executor
            .enforce_lease_expiry(now)
            .await
            .expect("enforce_lease_expiry");

        assert!(
            stopped.is_empty(),
            "a workload still inside clock-skew tolerance must not be stopped"
        );
        let record = executor
            .state
            .workload(&workload_id)
            .expect("workload record");
        assert_eq!(record.phase, WorkloadPhase::Running);
        assert!(engine.stopped.lock().expect("stopped lock").is_empty());
    }

    #[tokio::test]
    async fn enforce_lease_expiry_ignores_a_workload_with_no_persisted_lease_end() {
        // A record persisted before this ADR's lease_end field existed
        // (simulated here directly, since deploy() itself now requires
        // lease_end) must never be auto-stopped by a guessed expiry --
        // ADR-028's "never fabricate" principle applies to locally
        // synthesized authority too, not only to Control-Plane
        // acknowledgements.
        let directory = tempfile::tempdir().expect("directory");
        let engine = Arc::new(FakeEngine::default());
        let executor = executor(engine.clone(), directory.path(), 1);
        let request = request(Uuid::new_v4(), Uuid::new_v4());
        let workload_id = request.workload_id.clone();
        executor.deploy(request).await.expect("deploy");
        let mut record = executor
            .state
            .workload(&workload_id)
            .expect("workload record");
        record.lease_end = None;
        executor.state.store_workload(&record).expect("store");

        let far_future = std::time::UNIX_EPOCH + std::time::Duration::from_secs(4_102_444_800);
        let stopped = executor
            .enforce_lease_expiry(far_future)
            .await
            .expect("enforce_lease_expiry");

        assert!(stopped.is_empty());
        assert!(engine.stopped.lock().expect("stopped lock").is_empty());
    }

    /// ADR-028 "restart" acceptance test: an Agent process restart mid-
    /// disconnection must not lose the durable lease_end it needs to keep
    /// enforcing §3's policy, and must not double-continue (re-create) an
    /// already-running workload.
    #[tokio::test]
    async fn restart_preserves_lease_end_and_does_not_double_continue() {
        let directory = tempfile::tempdir().expect("directory");
        let engine = Arc::new(FakeEngine::default());
        let mut request = request(Uuid::new_v4(), Uuid::new_v4());
        let lease_end_seconds = 4_102_444_800i64; // far future
        request.lease_end = Some(prost_types::Timestamp {
            seconds: lease_end_seconds,
            nanos: 0,
        });
        let workload_id = request.workload_id.clone();
        let container_id = {
            let executor = executor(engine.clone(), directory.path(), 1);
            executor.deploy(request).await.expect("deploy")
        };

        // The process "restarts": a fresh DockerExecutor opens the same
        // sled directory and runs its startup recover() pass.
        let restarted = executor(engine.clone(), directory.path(), 1);
        restarted.recover().await.expect("recover");

        let record = restarted
            .state
            .workload(&workload_id)
            .expect("workload record survives the restart");
        assert_eq!(record.phase, WorkloadPhase::Running);
        assert_eq!(
            record.lease_end,
            Some(lease_end_seconds),
            "lease_end must survive the restart unchanged"
        );
        assert_eq!(record.container_id.as_deref(), Some(container_id.as_str()));
        assert_eq!(
            engine.created.lock().expect("created lock").len(),
            1,
            "recover() must not double-continue by creating a second container"
        );

        // lease-expiry enforcement must still work against the recovered
        // record, using the exact same lease_end recover() preserved.
        let far_future = std::time::UNIX_EPOCH + std::time::Duration::from_secs(4_200_000_000);
        let stopped = restarted
            .enforce_lease_expiry(far_future)
            .await
            .expect("enforce_lease_expiry after restart");
        assert_eq!(stopped, vec![workload_id]);
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
            lease_end: Some(future_lease_end()),
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
        // Issue #17: stop() now removes the container itself (it used to
        // stop but never remove -- a confirmed real leak), so there is no
        // longer a leftover container here for this test to clean up
        // manually. Assert that removal instead of redundantly (and, as
        // of this fix, incorrectly -- the container is already gone)
        // calling remove_container again.
        let removed = docker.inspect_container(&container_id, None).await;
        assert!(
            removed.is_err(),
            "container {container_id} should have been removed by stop(), but inspect still found it"
        );
    }

    /// Issue #174: real reproduction-then-fix for the cross-tenant
    /// network isolation gap -- confirmed via `grep` over this crate (no
    /// `NetworkMode`, no ICC-disable equivalent anywhere in
    /// `ContainerSpec`/`BollardEngine::create`) before this fix, per the
    /// issue's own description.
    ///
    /// Opt-in like `docker_integration_applies_mandatory_controls` above
    /// (needs a real Docker daemon), gated behind
    /// `OPENINFRA_TEST_DOCKER_NETWORK_TOOLS_IMAGE` -- deliberately a
    /// *different* env var from `OPENINFRA_TEST_DOCKER_IMAGE` (used by
    /// `docker_integration_applies_mandatory_controls`/`docker_
    /// integration_veth_resolution_survives_the_isolated_network`
    /// above/below): those go through the real `deploy()` path and need
    /// an image whose *own default command* keeps running (busybox's
    /// default `sh` exits almost instantly with no tty attached --
    /// confirmed live, flakes `deploy()`'s own running-confirmation check
    /// regardless of this fix -- see `docs/provider-agent/docker-
    /// executor.md`'s own recommendation of `registry.k8s.io/pause` for
    /// that case), while this test sets an explicit `Cmd` on both probe
    /// containers via raw bollard (see `probe_reachability` below) and
    /// instead needs BusyBox's `nc` applet specifically (e.g.
    /// `busybox:1.36`, the same image `request()`'s tests default to).
    /// One shared var could not satisfy both requirements at once.
    ///
    /// The two probe containers are created directly via bollard (not
    /// through `ContainerEngine`, which has no `Cmd` override -- needed
    /// here to run a listener and a fetch probe instead of each image's
    /// default command) but with the same mandatory `HostConfig` fields
    /// `BollardEngine::create` applies, so the *only* variable between
    /// the two groups below is which network they attach to:
    ///   - `"bridge"` reproduces the exact pre-fix bug: Docker's own
    ///     default bridge, where every workload container landed before
    ///     this fix (control group -- proves the probe technique itself
    ///     actually detects real connectivity, not just always failing).
    ///   - `WORKLOAD_NETWORK_NAME` is the actual fix: the dedicated,
    ///     ICC-disabled network `BollardEngine::create` now uses for
    ///     every workload.
    #[tokio::test]
    async fn docker_integration_isolates_workload_containers_from_each_other() {
        let image = match std::env::var("OPENINFRA_TEST_DOCKER_NETWORK_TOOLS_IMAGE") {
            Ok(image) => image,
            Err(_) => return,
        };
        let docker = Docker::connect_with_local_defaults().expect("Docker client");
        BollardEngine::ensure_workload_network(&docker)
            .await
            .expect("ensure workload network");

        assert!(
            probe_reachability(&docker, &image, "bridge").await,
            "control group: two containers on Docker's default bridge must be able to reach \
             each other (this is the exact pre-fix vulnerability #174 reports -- if this \
             assertion fails, the probe technique itself is broken, not the isolation fix)"
        );

        assert!(
            !probe_reachability(&docker, &image, WORKLOAD_NETWORK_NAME).await,
            "two workload containers on the isolated network must NOT be able to reach each \
             other -- this is issue #174's regression"
        );
    }

    /// Starts a BusyBox `nc` listener and a BusyBox `nc -z` prober, both
    /// attached to `network`, and returns whether the prober reached the
    /// listener's own network-scoped IP (exit code 0). A raw TCP connect
    /// check is used deliberately over an HTTP fetch: it distinguishes
    /// "reachable" from "unreachable" by connection outcome alone, with
    /// no dependency on the listener actually answering a well-formed
    /// response for whatever it's asked (confirmed live: BusyBox `httpd`
    /// serving `/` with no index file returns 404, which BusyBox `wget`
    /// treats as failure regardless of reachability -- the wrong signal
    /// for this test). Both containers are always removed before
    /// returning, success or failure, so a run against the isolated
    /// network -- expected to hang until `nc`'s own `-w` timeout -- never
    /// leaks containers.
    async fn probe_reachability(docker: &Docker, image: &str, network: &str) -> bool {
        let suffix = Uuid::new_v4();
        let probe_host_config = |network: &str| HostConfig {
            security_opt: Some(vec!["no-new-privileges:true".to_string()]),
            cap_drop: Some(vec!["ALL".to_string()]),
            init: Some(true),
            network_mode: Some(network.to_string()),
            ..Default::default()
        };

        let listener_name = format!("openinfra-test-listener-{suffix}");
        let listener_config = Config {
            image: Some(image.to_string()),
            cmd: Some(
                ["nc", "-l", "-p", "8080"]
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
            ),
            host_config: Some(probe_host_config(network)),
            ..Default::default()
        };
        let listener = docker
            .create_container(
                Some(CreateContainerOptions {
                    name: listener_name,
                    platform: None,
                }),
                listener_config,
            )
            .await
            .expect("create listener");
        docker
            .start_container::<String>(&listener.id, None)
            .await
            .expect("start listener");

        // Give BusyBox nc a moment to bind before probing it.
        tokio::time::sleep(Duration::from_millis(500)).await;

        let inspected = docker
            .inspect_container(&listener.id, None)
            .await
            .expect("inspect listener");
        let listener_ip = inspected
            .network_settings
            .and_then(|settings| settings.networks)
            .and_then(|networks| networks.get(network).cloned())
            .and_then(|endpoint| endpoint.ip_address)
            .filter(|ip| !ip.is_empty())
            .unwrap_or_else(|| panic!("listener has no IP address on network {network}"));

        let prober_name = format!("openinfra-test-prober-{suffix}");
        let prober_config = Config {
            image: Some(image.to_string()),
            cmd: Some(
                ["nc", "-z", "-w", "2", &listener_ip, "8080"]
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
            ),
            host_config: Some(probe_host_config(network)),
            ..Default::default()
        };
        let prober = docker
            .create_container(
                Some(CreateContainerOptions {
                    name: prober_name,
                    platform: None,
                }),
                prober_config,
            )
            .await
            .expect("create prober");
        docker
            .start_container::<String>(&prober.id, None)
            .await
            .expect("start prober");

        // Poll until the prober exits, bounded so a hung `nc -z` (the
        // expected outcome on the isolated network -- ICC-dropped
        // packets get no RST, just silence until nc's own `-w` timeout)
        // cannot hang this test indefinitely.
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        let exit_code = loop {
            let inspected = docker
                .inspect_container(&prober.id, None)
                .await
                .expect("inspect prober");
            let state = inspected.state.expect("prober state");
            if state.running == Some(false) {
                break state.exit_code.unwrap_or(-1);
            }
            if std::time::Instant::now() > deadline {
                break -1;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        };

        for id in [&listener.id, &prober.id] {
            let _ = docker
                .remove_container(
                    id,
                    Some(RemoveContainerOptions {
                        force: true,
                        ..Default::default()
                    }),
                )
                .await;
        }

        exit_code == 0
    }

    /// Issue #174 regression: ADR-010's WireGuard `AttachNamespace`
    /// backend and this crate's own ADR-025 §2/§3 bandwidth/rate-limit
    /// paths all resolve a workload's veth by matching its container
    /// PID's `eth0` `iflink` against a host-side interface (see
    /// `bandwidth::resolve_veth_name`'s doc comment) -- a mechanism that
    /// works purely off the container's network *namespace*, never off
    /// which Docker network/bridge its `eth0` happens to be attached to.
    /// This is the real-Docker proof that moving every workload off the
    /// default bridge onto `WORKLOAD_NETWORK_NAME` did not break that.
    ///
    /// Gated behind `OPENINFRA_TEST_DOCKER_IMAGE`, set to an image whose
    /// own default command keeps running (busybox's default `sh` exits
    /// almost instantly with no tty attached -- confirmed live, flakes
    /// `deploy()`'s own running-confirmation check regardless of this
    /// fix; `docs/provider-agent/docker-executor.md` already recommends
    /// `registry.k8s.io/pause` for exactly this reason).
    ///
    /// This deploys a real workload through the *actual* `DockerExecutor`
    /// and confirms it landed on the isolated network (not still the
    /// default bridge) -- the part that genuinely proves `deploy()`
    /// itself changed. `resolve_veth_name`'s *matching algorithm* is
    /// then exercised end-to-end against a second, disposable container
    /// on the same network rather than by calling `engine.bandwidth()`
    /// on the deployed workload directly: `bandwidth()`'s own
    /// `/proc/<pid>/root/...` read requires the same privilege as
    /// `ptrace(2)` over that pid (matching UID, or `CAP_SYS_PTRACE`),
    /// which this test process does not have for a container process
    /// running as root -- confirmed live, this permission wall is
    /// unconditional and predates this fix (reproduces identically
    /// against an unmodified `main`, for *any* container, isolated
    /// network or not). It is exactly the same class of environment gap
    /// `docker_integration_applies_mandatory_controls` already documents
    /// for `tc`/`CAP_NET_ADMIN` -- a real Agent process (host-run, or the
    /// containerized one with `cap_add: NET_ADMIN`) has what it needs;
    /// this sandboxed test process does not. `docker exec` sidesteps it
    /// by reading the iflink from *inside* the container's own mount
    /// namespace (dockerd itself performs the privileged part), then
    /// this test matches it against the host's `/sys/class/net` the same
    /// way `resolve_veth_name` does -- the exact algorithm, a
    /// permission-compatible source for its input.
    #[tokio::test]
    async fn docker_integration_veth_resolution_survives_the_isolated_network() {
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
                egress_mbps: 0,
            }),
            lease_end: Some(future_lease_end()),
        };
        let container_id = executor.deploy(request.clone()).await.expect("deploy");

        let docker = Docker::connect_with_local_defaults().expect("Docker client");
        let inspected = docker
            .inspect_container(&container_id, None)
            .await
            .expect("inspect container");
        let host = inspected.host_config.expect("host config");
        assert_eq!(
            host.network_mode.as_deref(),
            Some(WORKLOAD_NETWORK_NAME),
            "the workload container must be attached to the isolated network, not the default bridge"
        );
        executor.stop(&request.workload_id).await.expect("stop");

        // Second half: the veth-matching algorithm itself, against a
        // disposable BusyBox container on the same network (needs a
        // shell/`cat` for `docker exec`, which `registry.k8s.io/pause`
        // deliberately has neither of -- that's why this uses its own
        // fixed image rather than reusing `image` above).
        let suffix = Uuid::new_v4();
        let veth_probe_name = format!("openinfra-test-veth-probe-{suffix}");
        let veth_probe_config = Config {
            image: Some("busybox:1.36".to_string()),
            cmd: Some(vec!["sleep".to_string(), "30".to_string()]),
            host_config: Some(HostConfig {
                security_opt: Some(vec!["no-new-privileges:true".to_string()]),
                cap_drop: Some(vec!["ALL".to_string()]),
                init: Some(true),
                network_mode: Some(WORKLOAD_NETWORK_NAME.to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let veth_probe = docker
            .create_container(
                Some(CreateContainerOptions {
                    name: veth_probe_name,
                    platform: None,
                }),
                veth_probe_config,
            )
            .await
            .expect("create veth probe");
        docker
            .start_container::<String>(&veth_probe.id, None)
            .await
            .expect("start veth probe");

        let iflink_output = exec_stdout(
            &docker,
            &veth_probe.id,
            &["cat", "/sys/class/net/eth0/iflink"],
        )
        .await;
        let iflink: u64 = iflink_output
            .trim()
            .parse()
            .unwrap_or_else(|_| panic!("eth0 iflink is not a number: {iflink_output:?}"));

        let net_class_dir = std::path::Path::new("/sys/class/net");
        let mut matched_veth = None;
        for entry in fs::read_dir(net_class_dir).expect("read /sys/class/net") {
            let entry = entry.expect("dir entry");
            let Ok(contents) = fs::read_to_string(entry.path().join("ifindex")) else {
                continue;
            };
            let Ok(ifindex) = contents.trim().parse::<u64>() else {
                continue;
            };
            if ifindex == iflink {
                matched_veth = Some(entry.file_name().into_string().expect("utf8 ifname"));
                break;
            }
        }
        let veth = matched_veth.unwrap_or_else(|| {
            panic!(
                "no host-side interface matches iflink {iflink} for the workload on {WORKLOAD_NETWORK_NAME} \
                 -- the same failure mode that would break ADR-010's WireGuard AttachNamespace"
            )
        });
        fs::read_to_string(net_class_dir.join(&veth).join("statistics/rx_bytes"))
            .unwrap_or_else(|error| panic!("read {veth}'s rx_bytes counters: {error}"));

        let _ = docker
            .remove_container(
                &veth_probe.id,
                Some(RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            )
            .await;
    }

    /// Runs `cmd` inside `container_id` via `docker exec` and returns its
    /// combined stdout/stderr as a UTF-8 string. Used only by tests that
    /// need to read a value from *inside* a container's own namespace
    /// without needing this test process's own host-level permission
    /// over that container's PID (see
    /// `docker_integration_veth_resolution_survives_the_isolated_network`'s
    /// doc comment).
    async fn exec_stdout(docker: &Docker, container_id: &str, cmd: &[&str]) -> String {
        let exec = docker
            .create_exec(
                container_id,
                bollard::exec::CreateExecOptions {
                    cmd: Some(cmd.iter().map(|value| value.to_string()).collect()),
                    attach_stdout: Some(true),
                    attach_stderr: Some(true),
                    ..Default::default()
                },
            )
            .await
            .expect("create exec");
        let mut collected = String::new();
        if let bollard::exec::StartExecResults::Attached { mut output, .. } =
            docker.start_exec(&exec.id, None).await.expect("start exec")
        {
            while let Some(chunk) = output.next().await {
                collected.push_str(&chunk.expect("exec output chunk").to_string());
            }
        }
        collected
    }

    // Issue #154: confirmed live -- a workload with a valid, correctly
    // pinned image reference got stuck retrying forever because create()
    // never pulled an image it didn't already have cached, and 404'd every
    // time. Opt-in like docker_integration_applies_mandatory_controls
    // above (needs a real Docker daemon and, unlike that test, real
    // network access to actually pull) -- skipped by default so
    // `cargo test --workspace` never depends on either.
    #[tokio::test]
    async fn docker_integration_pulls_a_missing_image_before_create() {
        let image = match std::env::var("OPENINFRA_TEST_DOCKER_PULL_IMAGE") {
            Ok(image) => image,
            Err(_) => return,
        };
        let docker = Docker::connect_with_local_defaults().expect("Docker client");
        // Precondition this test actually proves something: remove the
        // image first (ignoring "wasn't there anyway"), so create()'s
        // success below can only come from the pull-on-404 path, not a
        // pre-existing local copy.
        let _ = docker.remove_image(&image, None, None).await;
        let engine = BollardEngine::connect().expect("connect Docker");
        let spec = ContainerSpec {
            name: format!("openinfra-test-{}", Uuid::new_v4()),
            image: image.clone(),
            labels: HashMap::new(),
            memory_bytes: 64 * MIB,
            nano_cpus: 500_000_000,
            pids_limit: 32,
            egress_mbps: 0,
        };
        let container_id = engine
            .create(&spec)
            .await
            .expect("create() should transparently pull the missing image and succeed");
        docker
            .remove_container(&container_id, None)
            .await
            .expect("clean up the container this test created");
    }
}
