//! ADR-033: the VM execution backend, parallel to (never replacing)
//! `ContainerEngine`/`DockerExecutor` above -- per the ADR's own explicit
//! architecture decision (§3), `ContainerEngine`/`BollardEngine` are left
//! completely untouched by this module. `VmEngine` mirrors
//! `ContainerEngine`'s shape (`create`/`start`/`stop`/`inspect`/
//! `remove`); `VmExecutor` mirrors `DockerExecutor`'s responsibilities
//! (capacity reservation, durable local state, crash recovery, lease
//! expiry) by reusing the *same* `agent-core::local_state::LocalState`
//! machinery, not a parallel storage mechanism.
//!
//! **Deliberately not wired into `agent-api::Executor`/the gRPC surface
//! in this PR.** ADR-033 §8/§9 explicitly defers "the exact `.proto`
//! changes (a `DeployRequest` runtime-selector field, a `VmSpec`
//! message...)" to the implementing PR as a decision still to be made,
//! not a foregone wire shape -- inventing that wire format here, without
//! a Control-Plane-side consumer or scheduler awareness of
//! `virtualization_capable` (also explicitly out of this PR's scope, see
//! the PR description), would be exactly the kind of unreviewed
//! trust-boundary expansion this repository's own `AGENTS.md` warns
//! against. `VmDeployRequest` below is this crate's own internal
//! request shape, deliberately not `agent_api::proto::DeployRequest` --
//! the next PR's job is threading a real wire request through to it.

pub mod cloud_hypervisor;
pub mod image;

use crate::ExecutorError;
use agent_api::proto::{get_workload_status_response::State, DeployRequest};
use agent_api::{Executor, UsageSample, WorkloadStatus};
use agent_core::local_state::{
    LocalState, LocalStateError, Reservation, WorkloadPhase, WorkloadRecord, WorkloadRuntime,
};
use agent_core::ExecutorSettings;
use async_trait::async_trait;
use image::ImageFetcher;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmSpec {
    pub name: String,
    pub vcpus: u32,
    pub memory_mb: i64,
    pub image_path: PathBuf,
    /// Empty means "use the engine's own configured default firmware" --
    /// see `CloudHypervisorEngine::create`. No per-workload firmware
    /// override exists on the wire yet; this field exists so the engine
    /// itself stays free of that policy decision.
    pub firmware_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmObservation {
    pub running: bool,
    pub status: String,
}

/// ADR-033 §3: shaped analogously to `ContainerEngine`
/// (`create`/`start`/`stop`/`inspect`/`remove`). Deliberately does not
/// include a `bandwidth`/`rate_limit` pair the way `ContainerEngine`
/// does -- the ADR's own §5 tap-device networking model (the VM
/// equivalent of `ContainerEngine`'s veth-pair-based mechanism) is not
/// implemented in this PR; see the PR description's follow-up list.
#[async_trait]
pub trait VmEngine: Send + Sync {
    /// Creates (but does not boot) the VM described by `spec`, returning
    /// an opaque handle -- in practice the Cloud Hypervisor API-socket
    /// path, matching ADR-033 §6's "VM UUID / Cloud Hypervisor
    /// API-socket path" language for `WorkloadRecord.vm_handle`.
    async fn create(&self, spec: &VmSpec) -> Result<String, ExecutorError>;
    async fn start(&self, handle: &str) -> Result<(), ExecutorError>;
    async fn stop(&self, handle: &str) -> Result<(), ExecutorError>;
    async fn inspect(&self, handle: &str) -> Result<VmObservation, ExecutorError>;
    async fn remove(&self, handle: &str) -> Result<(), ExecutorError>;
}

/// This crate's own internal VM deploy request shape -- see this
/// module's top doc comment for why it is not (yet) a proto message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmDeployRequest {
    pub workload_id: String,
    pub lease_id: String,
    pub vcpus: u32,
    pub memory_mb: i64,
    /// ADR-033 §4: required, HTTPS only, matching the image-handling
    /// discipline `deployment()`'s Docker-side validation already
    /// enforces for `lease_end` (required, not optional).
    pub vm_image_url: String,
    /// Required, exactly 64 lowercase hex characters -- see
    /// `image::validate_sha256_hex`.
    pub vm_image_sha256: String,
    /// Unix seconds. Required, matching `DeployRequest.lease_end`'s
    /// existing "required, not optional" precedent (ADR-028 §3).
    pub lease_end: i64,
}

pub struct VmExecutor {
    engine: Arc<dyn VmEngine>,
    state: Arc<LocalState>,
    settings: ExecutorSettings,
    image_fetcher: Arc<dyn ImageFetcher>,
    operation_lock: Mutex<()>,
}

impl VmExecutor {
    pub async fn connect(
        state: Arc<LocalState>,
        settings: ExecutorSettings,
    ) -> Result<Self, ExecutorError> {
        let engine = Arc::new(cloud_hypervisor::CloudHypervisorEngine::connect(
            settings.cloud_hypervisor_binary.clone(),
            settings.vm_sockets_dir.clone(),
            PathBuf::new(),
            cloud_hypervisor::VmmSecurityPolicy {
                setpriv_binary: settings.setpriv_binary.clone(),
                user: settings.vmm_user.clone(),
                group: settings.vmm_group.clone(),
                kvm_group: settings.vmm_kvm_group.clone(),
                seccomp: true,
            },
        ));
        let executor = Self::with_parts(
            engine,
            state,
            settings,
            Arc::new(image::HttpsImageFetcher::new()),
        )?;
        executor.recover().await?;
        Ok(executor)
    }

    fn with_parts(
        engine: Arc<dyn VmEngine>,
        state: Arc<LocalState>,
        settings: ExecutorSettings,
        image_fetcher: Arc<dyn ImageFetcher>,
    ) -> Result<Self, ExecutorError> {
        Ok(Self {
            engine,
            state,
            settings,
            image_fetcher,
            operation_lock: Mutex::new(()),
        })
    }

    #[cfg(test)]
    fn with_engine(
        engine: Arc<dyn VmEngine>,
        state: Arc<LocalState>,
        settings: ExecutorSettings,
        image_fetcher: Arc<dyn ImageFetcher>,
    ) -> Result<Self, ExecutorError> {
        Self::with_parts(engine, state, settings, image_fetcher)
    }

    /// Validates `request` against policy and produces the `WorkloadRecord`
    /// to reserve -- the VM analog of `DockerExecutor::deployment`. Does
    /// **not** touch the image cache or the engine; those are `deploy`'s
    /// own async steps, kept out of this synchronous validation function
    /// the same way Docker's `deployment()` builds a `ContainerSpec`
    /// without itself pulling the image.
    fn validate(&self, request: &VmDeployRequest) -> Result<WorkloadRecord, ExecutorError> {
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
        if request.vcpus == 0 || request.vcpus > self.settings.max_vm_vcpus {
            return Err(ExecutorError::InvalidRequest(
                "vcpus must be positive and within policy".to_string(),
            ));
        }
        if request.memory_mb <= 0 || request.memory_mb > self.settings.max_vm_memory_mb {
            return Err(ExecutorError::InvalidRequest(
                "memory_mb must be positive and within policy".to_string(),
            ));
        }
        image::validate_sha256_hex(&request.vm_image_sha256)?;
        if !request.vm_image_url.starts_with("https://") {
            return Err(ExecutorError::InvalidRequest(
                "vm_image_url must use https://".to_string(),
            ));
        }
        if request.lease_end <= 0 {
            return Err(ExecutorError::InvalidRequest(
                "lease_end must be a positive timestamp".to_string(),
            ));
        }
        let mut hasher = Sha256::new();
        hasher.update(request.lease_id.as_bytes());
        hasher.update([0]);
        hasher.update(request.vm_image_url.as_bytes());
        hasher.update([0]);
        hasher.update(request.vm_image_sha256.as_bytes());
        hasher.update(request.vcpus.to_be_bytes());
        hasher.update(request.memory_mb.to_be_bytes());
        let spec_hash: [u8; 32] = hasher.finalize().into();
        Ok(WorkloadRecord {
            workload_id: request.workload_id.clone(),
            lease_id: request.lease_id.clone(),
            image: request.vm_image_url.clone(),
            spec_hash,
            container_id: None,
            vm_handle: None,
            runtime: WorkloadRuntime::Vm,
            phase: WorkloadPhase::Provisioning,
            egress_mbps: 0,
            rate_limited: false,
            lease_end: Some(request.lease_end),
        })
    }

    /// ADR-033 §6/§7: the fail-closed quota gate. `max_vm_workloads == 0`
    /// (the default) rejects **every** deploy attempt explicitly, before
    /// any validation, image fetch, or capacity reservation runs -- never
    /// a silent no-op, and never something a malformed request could
    /// short-circuit past.
    fn check_vm_workloads_enabled(&self) -> Result<(), ExecutorError> {
        if self.settings.max_vm_workloads == 0 {
            return Err(ExecutorError::VmDisabled);
        }
        Ok(())
    }

    pub async fn deploy(&self, request: VmDeployRequest) -> Result<String, ExecutorError> {
        self.check_vm_workloads_enabled()?;
        let _guard = self.operation_lock.lock().await;
        let candidate = self.validate(&request)?;
        let reservation = self
            .state
            .reserve_workload(&candidate, self.settings.max_vm_workloads)?;
        let mut record = self.state.workload(&candidate.workload_id)?;
        if record.runtime != WorkloadRuntime::Vm {
            return Err(ExecutorError::InvalidRequest(format!(
                "workload {} is not a VM workload",
                record.workload_id
            )));
        }

        if reservation == Reservation::Existing {
            if let Some(handle) = record.vm_handle.clone() {
                let observation = self.engine.inspect(&handle).await?;
                if observation.running {
                    record.phase = WorkloadPhase::Running;
                    self.state.store_workload(&record)?;
                    return Ok(handle);
                }
                if record.phase == WorkloadPhase::Stopped {
                    return Err(ExecutorError::StateConfirmation(handle));
                }
            }
        }

        // ADR-033 §4: fetched and digest-verified before any engine call
        // -- never after, mirroring the Docker-side image-pull-before-
        // create ordering, but here the verification is the boot-safety
        // gate itself (Docker's own registry already enforces content
        // addressing by digest; a qcow2 blob over plain HTTPS has no
        // such built-in guarantee).
        let image_path = image::fetch_and_verify_image(
            self.image_fetcher.as_ref(),
            &self.settings.vm_image_cache_dir,
            &request.vm_image_url,
            &request.vm_image_sha256,
        )
        .await?;

        let handle = match record.vm_handle.clone() {
            Some(handle) => handle,
            None => {
                let spec = VmSpec {
                    name: format!("openinfra-{}", request.workload_id),
                    vcpus: request.vcpus,
                    memory_mb: request.memory_mb,
                    image_path,
                    firmware_path: PathBuf::new(),
                };
                let handle = self.engine.create(&spec).await?;
                record.vm_handle = Some(handle.clone());
                record.phase = WorkloadPhase::Starting;
                if let Err(error) = self.state.store_workload(&record) {
                    if let Err(cleanup_error) = self.engine.remove(&handle).await {
                        tracing::error!(%handle, %cleanup_error, "failed to remove VM after persistence failure");
                    }
                    return Err(error.into());
                }
                handle
            }
        };

        if let Err(error) = self.engine.start(&handle).await {
            record.phase = WorkloadPhase::Failed;
            self.state.store_workload(&record)?;
            return Err(error);
        }
        let observation = self.engine.inspect(&handle).await?;
        if !observation.running {
            record.phase = WorkloadPhase::Failed;
            self.state.store_workload(&record)?;
            return Err(ExecutorError::StateConfirmation(handle));
        }
        record.phase = WorkloadPhase::Running;
        self.state.store_workload(&record)?;
        info!(workload_id = %record.workload_id, %handle, "Cloud Hypervisor confirmed VM running");
        Ok(handle)
    }

    pub async fn stop(&self, workload_id: &str) -> Result<(), ExecutorError> {
        let _guard = self.operation_lock.lock().await;
        let mut record = match self.state.workload(workload_id) {
            Ok(record) => record,
            Err(LocalStateError::WorkloadNotFound(_)) => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        if record.runtime != WorkloadRuntime::Vm {
            return Err(ExecutorError::InvalidRequest(format!(
                "workload {workload_id} is not a VM workload"
            )));
        }
        if matches!(record.phase, WorkloadPhase::Stopped | WorkloadPhase::Failed) {
            return Ok(());
        }
        let handle = record.vm_handle.clone().ok_or_else(|| {
            ExecutorError::StateConfirmation(format!("workload {workload_id} has no VM handle"))
        })?;
        record.phase = WorkloadPhase::Stopping;
        self.state.store_workload(&record)?;
        self.engine.stop(&handle).await?;
        let observation = self.engine.inspect(&handle).await?;
        if observation.running {
            return Err(ExecutorError::StateConfirmation(handle));
        }
        self.engine.remove(&handle).await?;
        record.phase = WorkloadPhase::Stopped;
        self.state.store_workload(&record)?;
        info!(%workload_id, %handle, "Cloud Hypervisor confirmed VM stopped");
        Ok(())
    }

    /// The VM analog of `DockerExecutor::recover` -- same algorithm
    /// (inspect the real engine's live state on Agent startup, reconcile
    /// persisted `WorkloadPhase` against it), reused as ADR-033 §3
    /// prescribes, operating on `VmEngine::inspect`/`vm_handle` instead
    /// of `ContainerEngine::inspect`/`container_id`, and scoped to
    /// `runtime == Vm` records only so a Docker-workload record recovered
    /// by `DockerExecutor::recover` is never touched twice.
    async fn recover(&self) -> Result<(), ExecutorError> {
        for mut record in self.state.workloads()? {
            if record.runtime != WorkloadRuntime::Vm {
                continue;
            }
            let Some(handle) = record.vm_handle.clone() else {
                if record.phase.consumes_capacity() {
                    record.phase = WorkloadPhase::Failed;
                    self.state.store_workload(&record)?;
                }
                continue;
            };
            match self.engine.inspect(&handle).await {
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
                    warn!(workload_id = %record.workload_id, %error, "persisted VM is unavailable");
                    record.phase = WorkloadPhase::Lost;
                }
            }
            self.state.store_workload(&record)?;
        }
        Ok(())
    }

    /// The VM analog of `DockerExecutor::enforce_lease_expiry` -- same
    /// algorithm and clock-skew tolerance, reused verbatim per ADR-033
    /// §3 ("already operates purely against WorkloadPhase/lease_end with
    /// no Docker-specific logic in its body; reused verbatim by
    /// VmExecutor with no changes needed to its algorithm"), scoped to
    /// `runtime == Vm` records.
    pub async fn enforce_lease_expiry(
        &self,
        now: SystemTime,
    ) -> Result<Vec<String>, ExecutorError> {
        const CLOCK_SKEW_TOLERANCE_SECS: i64 = 120;
        let now_unix = now
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs() as i64)
            .unwrap_or(0);
        let mut stopped = Vec::new();
        for record in self.state.workloads()? {
            if record.runtime != WorkloadRuntime::Vm {
                continue;
            }
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
            match self.stop(&record.workload_id).await {
                Ok(()) => {
                    info!(
                        workload_id = %record.workload_id,
                        lease_end,
                        now_unix,
                        "VM lease expired while disconnected or connected; stopped locally"
                    );
                    stopped.push(record.workload_id.clone());
                }
                Err(error) => {
                    warn!(
                        workload_id = %record.workload_id,
                        %error,
                        "failed to stop a VM past its lease_end; will retry on the next tick"
                    );
                }
            }
        }
        Ok(stopped)
    }

    fn map_observation(observation: &VmObservation) -> State {
        if observation.running {
            return State::Running;
        }
        match observation.status.as_str() {
            "created" => State::Created,
            // ADR-033 §6: Cloud Hypervisor's vm.info reports "Shutdown"
            // both for a VM that was cleanly stopped and one that never
            // started -- STATE_COMPLETED matches DockerExecutor's own
            // "exited" mapping, which control-plane's orchestrator
            // already treats as terminal-not-an-error (Issue #17).
            "shutdown" => State::Completed,
            // "paused"/"breakpoint" are real cloud-hypervisor vm.info
            // states this Agent never itself requests (no pause/debug RPC
            // is wired anywhere) but must still map to *something* rather
            // than panic if observed (e.g. an operator drove the VMM
            // directly via its socket). Pending is the same conservative
            // "not confirmed running, not terminal" bucket
            // DockerExecutor::map_observation's fallback arm uses.
            _ => State::Pending,
        }
    }
}

/// ADR-033 §9 / issue #168: converts a wire `DeployRequest` (with
/// `runtime == RUNTIME_VM`) into this crate's own `VmDeployRequest`.
/// Deliberately thin -- only enough parsing to avoid unwrapping a `None`
/// field; range/format validation (vcpus/memory policy ceilings, the
/// https:// scheme, the sha256 hex shape, a positive lease_end) is
/// `VmExecutor::validate`'s job, exactly like `DockerExecutor::deployment`
/// keeps parsing and policy validation together for the container path --
/// this split exists only because the VM path's parsing step doubles as
/// the trait-boundary conversion `agent_api::Executor::deploy` needs and
/// `DockerExecutor::deploy` does not.
impl VmDeployRequest {
    fn try_from_proto(request: &DeployRequest) -> Result<Self, ExecutorError> {
        let vm_spec = request.vm.as_ref().ok_or_else(|| {
            ExecutorError::InvalidRequest(
                "vm spec is required for a VM-flavored DeployRequest".to_string(),
            )
        })?;
        let limits = request.limits.as_ref().ok_or_else(|| {
            ExecutorError::InvalidRequest("resource limits are required".to_string())
        })?;
        // A VM's vcpu count has no fractional analog the way Docker's
        // NanoCPUs does -- limits.cpu_cores is reused rather than adding
        // a duplicate integer field (see agent.proto's DeployRequest.vm
        // doc comment), so it must itself already be a positive whole
        // number here.
        if !limits.cpu_cores.is_finite()
            || limits.cpu_cores <= 0.0
            || limits.cpu_cores.fract() != 0.0
            || limits.cpu_cores > u32::MAX as f32
        {
            return Err(ExecutorError::InvalidRequest(
                "a VM's vcpu count (limits.cpu_cores) must be a positive whole number".to_string(),
            ));
        }
        let lease_end = request
            .lease_end
            .as_ref()
            .ok_or_else(|| ExecutorError::InvalidRequest("lease_end is required".to_string()))?;
        Ok(VmDeployRequest {
            workload_id: request.workload_id.clone(),
            lease_id: request.lease_id.clone(),
            vcpus: limits.cpu_cores as u32,
            memory_mb: limits.memory_mb,
            vm_image_url: vm_spec.vm_image_url.clone(),
            vm_image_sha256: vm_spec.vm_image_sha256.clone(),
            lease_end: lease_end.seconds,
        })
    }
}

/// ADR-033 §9 / issue #168 point 3: `VmExecutor` implementing
/// `agent_api::Executor`, mirroring `DockerExecutor`'s own impl of the
/// same trait -- this is what makes `VmExecutor` reachable from the gRPC
/// server at all (via `agent_executor::RoutingExecutor`, see this crate's
/// `lib.rs`). Note this does not shadow or conflict with `VmExecutor`'s
/// own inherent `deploy`/`stop` methods above (which take this module's
/// internal `VmDeployRequest`/`&str` types): Rust always resolves a
/// method call to an inherent method over a trait method when both share
/// a name, so every direct call in this module and its tests keeps
/// calling the inherent methods unchanged; only a caller going through
/// `dyn Executor` (agent-api's gRPC server, via `RoutingExecutor`) reaches
/// this impl.
#[async_trait]
impl Executor for VmExecutor {
    async fn deploy(&self, req: DeployRequest) -> anyhow::Result<String> {
        let vm_request = VmDeployRequest::try_from_proto(&req)?;
        self.deploy(vm_request).await.map_err(Into::into)
    }

    async fn stop(&self, workload_id: &str) -> anyhow::Result<()> {
        self.stop(workload_id).await.map_err(Into::into)
    }

    async fn get_status(&self, workload_id: &str) -> anyhow::Result<WorkloadStatus> {
        let record = self.state.workload(workload_id)?;
        if record.phase == WorkloadPhase::Stopped {
            // Mirrors DockerExecutor::get_status's identical short-circuit
            // (Issue #17): stop() already removed the VM but deliberately
            // leaves the stale vm_handle on the record, so inspecting it
            // here would fail against an already-deleted VM.
            return Ok(WorkloadStatus {
                state: State::Completed as i32,
                details: "stopped".to_string(),
            });
        }
        let Some(handle) = record.vm_handle else {
            // Mirrors DockerExecutor::get_status's identical "no
            // container/VM yet" case -- the normal state between
            // reserve_workload and the engine actually creating the VM,
            // including a first create() attempt that failed.
            return Ok(WorkloadStatus {
                state: State::Deploying as i32,
                details: "no VM yet".to_string(),
            });
        };
        let observation = self.engine.inspect(&handle).await?;
        Ok(WorkloadStatus {
            state: Self::map_observation(&observation) as i32,
            details: format!("Cloud Hypervisor state: {}", observation.status),
        })
    }

    /// Mirrors `DockerExecutor::usage_summary`'s own honesty: `lease_id`
    /// and the sequence/period bounds are real and durable
    /// (`LocalState::next_metering_period`, shared verbatim with the
    /// Docker path); the five usage counters are honest zero stubs --
    /// there is no per-VM CPU/RAM/storage/network metric source in this
    /// codebase yet, matching agent-api's `UsageSample` doc comment.
    async fn usage_summary(
        &self,
        workload_id: &str,
        now: u64,
        max_period_seconds: u64,
    ) -> anyhow::Result<UsageSample> {
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
    use sha2::Sha256 as ShaHasher;
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;

    #[derive(Default)]
    struct FakeVmEngine {
        created: StdMutex<Vec<VmSpec>>,
        started: StdMutex<Vec<String>>,
        stopped: StdMutex<Vec<String>>,
        removed: StdMutex<Vec<String>>,
        observations: StdMutex<HashMap<String, VmObservation>>,
        next_id: StdMutex<u64>,
    }

    #[async_trait]
    impl VmEngine for FakeVmEngine {
        async fn create(&self, spec: &VmSpec) -> Result<String, ExecutorError> {
            self.created
                .lock()
                .expect("created lock")
                .push(spec.clone());
            let mut next_id = self.next_id.lock().expect("next id lock");
            *next_id += 1;
            let handle = format!("/tmp/fake-vm-{next_id}.sock", next_id = *next_id);
            self.observations.lock().expect("observations lock").insert(
                handle.clone(),
                VmObservation {
                    running: false,
                    status: "created".to_string(),
                },
            );
            Ok(handle)
        }

        async fn start(&self, handle: &str) -> Result<(), ExecutorError> {
            self.started
                .lock()
                .expect("started lock")
                .push(handle.to_string());
            self.observations.lock().expect("observations lock").insert(
                handle.to_string(),
                VmObservation {
                    running: true,
                    status: "running".to_string(),
                },
            );
            Ok(())
        }

        async fn stop(&self, handle: &str) -> Result<(), ExecutorError> {
            self.stopped
                .lock()
                .expect("stopped lock")
                .push(handle.to_string());
            self.observations.lock().expect("observations lock").insert(
                handle.to_string(),
                VmObservation {
                    running: false,
                    status: "shutdown".to_string(),
                },
            );
            Ok(())
        }

        async fn inspect(&self, handle: &str) -> Result<VmObservation, ExecutorError> {
            self.observations
                .lock()
                .expect("observations lock")
                .get(handle)
                .cloned()
                .ok_or_else(|| ExecutorError::Engine("VM not found".to_string()))
        }

        async fn remove(&self, handle: &str) -> Result<(), ExecutorError> {
            self.removed
                .lock()
                .expect("removed lock")
                .push(handle.to_string());
            Ok(())
        }
    }

    struct FakeImageFetcher {
        bytes: Vec<u8>,
    }

    #[async_trait]
    impl ImageFetcher for FakeImageFetcher {
        async fn fetch(&self, _url: &str) -> Result<Vec<u8>, ExecutorError> {
            Ok(self.bytes.clone())
        }
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        let mut hasher = ShaHasher::new();
        hasher.update(bytes);
        hex::encode(<[u8; 32]>::from(hasher.finalize()))
    }

    fn image_fixture() -> (Vec<u8>, String) {
        let bytes = b"fake qcow2 bytes".to_vec();
        let digest = sha256_hex(&bytes);
        (bytes, digest)
    }

    fn request(workload_id: Uuid, lease_id: Uuid, digest: &str) -> VmDeployRequest {
        VmDeployRequest {
            workload_id: workload_id.to_string(),
            lease_id: lease_id.to_string(),
            vcpus: 2,
            memory_mb: 1024,
            vm_image_url: "https://example.com/image.qcow2".to_string(),
            vm_image_sha256: digest.to_string(),
            lease_end: 4_102_444_800, // 2100-01-01T00:00:00Z
        }
    }

    fn executor(
        engine: Arc<FakeVmEngine>,
        path: &std::path::Path,
        image_bytes: Vec<u8>,
        max_vm_workloads: usize,
        cache_dir: PathBuf,
    ) -> VmExecutor {
        let settings = ExecutorSettings {
            max_vm_workloads,
            vm_image_cache_dir: cache_dir,
            ..Default::default()
        };
        VmExecutor::with_engine(
            engine,
            Arc::new(LocalState::open(path).expect("state")),
            settings,
            Arc::new(FakeImageFetcher { bytes: image_bytes }),
        )
        .expect("executor")
    }

    #[tokio::test]
    async fn deploy_is_rejected_explicitly_when_vm_workloads_are_disabled_by_default() {
        // ADR-033 §7's central rollout gate: max_vm_workloads defaults to
        // 0, and a deploy attempt against that default must fail with a
        // specific, identifiable error -- never a silent no-op, and
        // never conflated with an ordinary validation failure.
        let directory = tempfile::tempdir().expect("dir");
        let cache = directory.path().join("cache");
        let (bytes, digest) = image_fixture();
        let engine = Arc::new(FakeVmEngine::default());
        // max_vm_workloads left at ExecutorSettings::default()'s 0.
        let vm_executor = executor(engine.clone(), directory.path(), bytes, 0, cache);

        let result = vm_executor
            .deploy(request(Uuid::new_v4(), Uuid::new_v4(), &digest))
            .await;

        assert!(matches!(result, Err(ExecutorError::VmDisabled)));
        assert!(
            engine.created.lock().expect("created lock").is_empty(),
            "a disabled VM executor must never reach the engine at all"
        );
    }

    #[tokio::test]
    async fn deploy_rejects_a_mismatched_image_digest_before_ever_calling_the_engine() {
        let directory = tempfile::tempdir().expect("dir");
        let cache = directory.path().join("cache");
        let (bytes, _correct_digest) = image_fixture();
        let wrong_digest = sha256_hex(b"not the image that will actually be fetched");
        let engine = Arc::new(FakeVmEngine::default());
        let vm_executor = executor(engine.clone(), directory.path(), bytes, 4, cache);

        let result = vm_executor
            .deploy(request(Uuid::new_v4(), Uuid::new_v4(), &wrong_digest))
            .await;

        assert!(result.is_err());
        assert!(
            engine.created.lock().expect("created lock").is_empty(),
            "a digest mismatch must reject before any VM is ever created/booted"
        );
    }

    #[tokio::test]
    async fn deploy_creates_starts_and_confirms_a_vm_and_is_idempotent() {
        let directory = tempfile::tempdir().expect("dir");
        let cache = directory.path().join("cache");
        let (bytes, digest) = image_fixture();
        let engine = Arc::new(FakeVmEngine::default());
        let vm_executor = executor(engine.clone(), directory.path(), bytes, 4, cache);
        let request = request(Uuid::new_v4(), Uuid::new_v4(), &digest);

        let first = vm_executor
            .deploy(request.clone())
            .await
            .expect("first deploy");
        let second = vm_executor.deploy(request).await.expect("idempotent retry");
        assert_eq!(first, second);
        assert_eq!(engine.created.lock().expect("created lock").len(), 1);
        assert_eq!(engine.started.lock().expect("started lock").len(), 1);
    }

    #[tokio::test]
    async fn deploy_enforces_the_max_vm_workloads_ceiling_independent_of_max_workloads() {
        let directory = tempfile::tempdir().expect("dir");
        let cache = directory.path().join("cache");
        let (bytes, digest) = image_fixture();
        let engine = Arc::new(FakeVmEngine::default());
        let vm_executor = executor(engine.clone(), directory.path(), bytes, 1, cache);

        vm_executor
            .deploy(request(Uuid::new_v4(), Uuid::new_v4(), &digest))
            .await
            .expect("first VM within quota");
        let second = vm_executor
            .deploy(request(Uuid::new_v4(), Uuid::new_v4(), &digest))
            .await;
        assert!(
            second.is_err(),
            "a second VM must exceed max_vm_workloads=1"
        );
    }

    #[tokio::test]
    async fn stop_removes_the_vm_and_is_idempotent() {
        let directory = tempfile::tempdir().expect("dir");
        let cache = directory.path().join("cache");
        let (bytes, digest) = image_fixture();
        let engine = Arc::new(FakeVmEngine::default());
        let vm_executor = executor(engine.clone(), directory.path(), bytes, 4, cache);
        let request = request(Uuid::new_v4(), Uuid::new_v4(), &digest);
        let handle = vm_executor.deploy(request.clone()).await.expect("deploy");

        vm_executor.stop(&request.workload_id).await.expect("stop");
        assert_eq!(
            engine.removed.lock().expect("removed lock").as_slice(),
            &[handle]
        );
        vm_executor
            .stop(&request.workload_id)
            .await
            .expect("idempotent stop");
        assert_eq!(engine.removed.lock().expect("removed lock").len(), 1);
    }

    #[tokio::test]
    async fn recover_reconciles_a_running_vm_without_recreating_it() {
        let directory = tempfile::tempdir().expect("dir");
        let cache = directory.path().join("cache");
        let (bytes, digest) = image_fixture();
        let engine = Arc::new(FakeVmEngine::default());
        let request = request(Uuid::new_v4(), Uuid::new_v4(), &digest);
        let handle = {
            let vm_executor = executor(
                engine.clone(),
                directory.path(),
                bytes.clone(),
                4,
                cache.clone(),
            );
            vm_executor.deploy(request.clone()).await.expect("deploy")
        };

        let recovered = executor(engine.clone(), directory.path(), bytes, 4, cache);
        recovered.recover().await.expect("recover");
        assert_eq!(
            recovered.deploy(request).await.expect("idempotent retry"),
            handle
        );
        assert_eq!(engine.created.lock().expect("created lock").len(), 1);
    }

    #[tokio::test]
    async fn enforce_lease_expiry_stops_a_vm_past_its_lease_end() {
        let directory = tempfile::tempdir().expect("dir");
        let cache = directory.path().join("cache");
        let (bytes, digest) = image_fixture();
        let engine = Arc::new(FakeVmEngine::default());
        let vm_executor = executor(engine.clone(), directory.path(), bytes, 4, cache);
        let mut request = request(Uuid::new_v4(), Uuid::new_v4(), &digest);
        request.lease_end = 1_700_000_000;
        vm_executor.deploy(request.clone()).await.expect("deploy");

        let stopped = vm_executor
            .enforce_lease_expiry(UNIX_EPOCH + std::time::Duration::from_secs(1_700_001_000))
            .await
            .expect("enforce lease expiry");

        assert_eq!(stopped, vec![request.workload_id.clone()]);
        assert_eq!(engine.stopped.lock().expect("stopped lock").len(), 1);
    }

    // --- agent_api::Executor impl: the proto DeployRequest conversion
    // path issue #168 point 3 adds (RoutingExecutor's own tests in
    // agent-executor's lib.rs cover dispatch; these cover VmExecutor's
    // own trait-boundary conversion logic).

    fn proto_vm_deploy_request(workload_id: &str, digest: &str) -> agent_api::proto::DeployRequest {
        agent_api::proto::DeployRequest {
            workload_id: workload_id.to_string(),
            lease_id: Uuid::new_v4().to_string(),
            image: String::new(),
            limits: Some(agent_api::proto::ResourceLimits {
                cpu_cores: 2.0,
                memory_mb: 1024,
                egress_mbps: 0,
            }),
            lease_end: Some(prost_types::Timestamp {
                seconds: 4_102_444_800,
                nanos: 0,
            }),
            runtime: agent_api::proto::Runtime::Vm as i32,
            vm: Some(agent_api::proto::VmSpec {
                vm_image_url: "https://example.com/image.qcow2".to_string(),
                vm_image_sha256: digest.to_string(),
            }),
        }
    }

    #[tokio::test]
    async fn executor_trait_deploy_converts_the_proto_request_and_deploys_a_vm() {
        let directory = tempfile::tempdir().expect("dir");
        let cache = directory.path().join("cache");
        let (bytes, digest) = image_fixture();
        let engine = Arc::new(FakeVmEngine::default());
        let vm_executor = executor(engine.clone(), directory.path(), bytes, 4, cache);
        let workload_id = Uuid::new_v4().to_string();

        let handle = Executor::deploy(&vm_executor, proto_vm_deploy_request(&workload_id, &digest))
            .await
            .expect("Executor::deploy via the proto conversion path");

        assert!(!handle.is_empty());
        assert_eq!(engine.created.lock().expect("created lock").len(), 1);
        let created = engine.created.lock().expect("created lock");
        assert_eq!(created[0].vcpus, 2);
        assert_eq!(created[0].memory_mb, 1024);
    }

    #[tokio::test]
    async fn executor_trait_deploy_rejects_a_fractional_vcpu_count() {
        let directory = tempfile::tempdir().expect("dir");
        let cache = directory.path().join("cache");
        let (bytes, digest) = image_fixture();
        let engine = Arc::new(FakeVmEngine::default());
        let vm_executor = executor(engine.clone(), directory.path(), bytes, 4, cache);
        let mut request = proto_vm_deploy_request(&Uuid::new_v4().to_string(), &digest);
        request.limits.as_mut().expect("limits").cpu_cores = 1.5;

        let result = Executor::deploy(&vm_executor, request).await;

        assert!(result.is_err());
        assert!(
            engine.created.lock().expect("created lock").is_empty(),
            "a fractional vcpu count must reject before ever reaching the engine"
        );
    }

    #[tokio::test]
    async fn executor_trait_deploy_rejects_a_request_with_no_vm_spec() {
        let directory = tempfile::tempdir().expect("dir");
        let cache = directory.path().join("cache");
        let (bytes, digest) = image_fixture();
        let engine = Arc::new(FakeVmEngine::default());
        let vm_executor = executor(engine.clone(), directory.path(), bytes, 4, cache);
        let mut request = proto_vm_deploy_request(&Uuid::new_v4().to_string(), &digest);
        request.vm = None;

        let result = Executor::deploy(&vm_executor, request).await;

        assert!(result.is_err());
        assert!(engine.created.lock().expect("created lock").is_empty());
    }

    #[tokio::test]
    async fn executor_trait_get_status_reports_deploying_then_running_then_completed() {
        let directory = tempfile::tempdir().expect("dir");
        let cache = directory.path().join("cache");
        let (bytes, digest) = image_fixture();
        let engine = Arc::new(FakeVmEngine::default());
        let vm_executor = executor(engine.clone(), directory.path(), bytes, 4, cache);
        let workload_id = Uuid::new_v4().to_string();

        Executor::deploy(&vm_executor, proto_vm_deploy_request(&workload_id, &digest))
            .await
            .expect("deploy");
        let running = Executor::get_status(&vm_executor, &workload_id)
            .await
            .expect("status while running");
        assert_eq!(
            running.state,
            agent_api::proto::get_workload_status_response::State::Running as i32
        );

        vm_executor.stop(&workload_id).await.expect("stop");
        let completed = Executor::get_status(&vm_executor, &workload_id)
            .await
            .expect("status after stop");
        assert_eq!(
            completed.state,
            agent_api::proto::get_workload_status_response::State::Completed as i32
        );
    }
}
