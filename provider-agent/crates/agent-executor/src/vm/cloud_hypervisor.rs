//! ADR-033 §2/§3: `CloudHypervisorEngine`, the `VmEngine` implementation
//! that drives Cloud Hypervisor's real local HTTP API over a Unix domain
//! socket -- one `cloud-hypervisor` process per VM, spawned by this
//! Agent, no libvirt and no shared daemon (the ADR's central rejection of
//! libvirt's dependency shape). The exact API paths and JSON request/
//! response schemas below were verified against Cloud Hypervisor's own
//! published OpenAPI spec (`vmm/src/api/openapi/cloud-hypervisor.yaml`,
//! fetched from the `cloud-hypervisor/cloud-hypervisor` `main` branch
//! while writing this module -- `PUT /vm.create` takes a `VmConfig` body
//! and returns 204; `PUT /vm.boot`/`vm.shutdown`/`vm.delete` return 204
//! with no body; `GET /vm.info` returns 200 with a `VmInfo` JSON body
//! whose `state` field is one of `Created`/`Running`/`Shutdown`/`Paused`/
//! `BreakPoint`), not guessed.
//!
//! **What this module cannot verify live, in this sandbox**: there is no
//! real `cloud-hypervisor` binary and no working `/dev/kvm` access here
//! (see `agent-inventory::kvm`'s own doc comment) -- spawning a real
//! process and actually booting a real VM is untested end-to-end. What
//! *is* tested for real: `UnixSocketTransport`'s request/response
//! handling against a genuine Unix-domain-socket HTTP server
//! (`hyperlocal`'s server side standing in for Cloud Hypervisor), and
//! `CloudHypervisorEngine`'s request-building/response-interpretation
//! logic against a `FakeTransport` double -- see this module's tests.
//!
//! **Security baseline (ADR-033 §6, issue #168 point 1)**: every
//! `cloud-hypervisor` process this engine spawns is wrapped with
//! `setpriv` (util-linux -- present on every mainstream Linux
//! distribution this Agent targets, the same "reuse a narrowly-scoped,
//! widely available mechanism" precedent `CommandRunner`'s `tc`
//! invocation and `KvmProbe`'s raw ioctl already set, rather than a
//! bespoke jailer binary or a new large dependency) that drops to a
//! dedicated unprivileged user/group, clears every supplementary group
//! except the one granting `/dev/kvm` access, narrows both the
//! inheritable and bounding Linux capability sets to exactly
//! `CAP_NET_ADMIN`, and sets `no_new_privs` -- see `VmmSecurityPolicy`.
//! `cloud-hypervisor`'s own mandatory seccomp filter (`--seccomp true`)
//! is passed explicitly rather than relied upon as a default, so a future
//! upstream default change can't silently disable it here.
//!
//! **Honest limit on what this proves in this sandbox**: there is no
//! `openinfra-vmm` user, no real `cloud-hypervisor` binary, and no
//! working `/dev/kvm` access here (see `agent-inventory::kvm`'s own doc
//! comment) -- an actual `setpriv`-wrapped `cloud-hypervisor` process has
//! never been spawned and observed to have the reduced capability set on
//! a real KVM host as part of this change. What *is* real and tested:
//! `setpriv` itself is present in this build environment (verified with
//! `which setpriv`) and `VmmSecurityPolicy::wrap`'s argv-building logic is
//! exercised directly (`security_baseline` tests below) -- the exact
//! flags a real invocation would receive, not a description of intent.
//! Verifying the *effect* (that a spawned process genuinely ends up
//! non-root with only `CAP_NET_ADMIN`) needs a real Linux host with a
//! `setpriv`-capable root Agent process and is tracked as a follow-up
//! (see this PR's description).
//!
//! **Networking (ADR-033 §5 / issue #176 point 1)**: `create()` attaches
//! each VM to a host tap device via `vm::tap::TapBackend`, named in Cloud
//! Hypervisor's `net` device config by the tap's device name (verified
//! against Cloud Hypervisor's own OpenAPI spec's `NetConfig.tap` field --
//! Cloud Hypervisor opens a pre-existing tap given by name, it does not
//! create one). `bandwidth()`/`rate_limit()` below read/enforce against
//! that same tap device, reusing `bandwidth::read_bandwidth_for_interface`
//! and `RateLimiter::apply_to_interface` directly -- see `vm::tap`'s own
//! top doc comment for the full design and honesty discipline (real tap
//! creation needs `CAP_NET_ADMIN` and a real kernel netlink socket,
//! neither available in this sandbox; what's tested for real is this
//! engine's tap-attach/detach/lookup *wiring*, against a `FakeTapBackend`
//! double, exactly like `VmmProcessSpawner`/`VmmTransport` already are).

use crate::rate_limit::RateLimiter;
use crate::{ExecutorError, WorkloadBandwidth};
use async_trait::async_trait;
use hyper::{Body, Client, Method, Request};
use hyperlocal::UnixClientExt;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::Mutex;
use tracing::warn;

use super::tap::TapBackend;
use super::{VmEngine, VmObservation, VmSpec};

const MIB: i64 = 1024 * 1024;

/// Low-level HTTP-over-Unix-socket call, abstracted so
/// `CloudHypervisorEngine`'s request-building/response-interpretation
/// logic is unit-testable against a `FakeTransport` without a real
/// socket or process -- the same seam `CommandRunner`/`KvmProbe`/
/// `ImageFetcher` already use for "this needs something a unit test
/// shouldn't depend on".
#[async_trait]
pub trait VmmTransport: Send + Sync {
    async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<(u16, Vec<u8>), ExecutorError>;
}

/// The real transport: a fresh `hyper` client per call (Cloud
/// Hypervisor's API is low-volume/lifecycle-only, not a hot path --
/// matching `BollardEngine`'s own per-call-cheap `Docker` client usage
/// pattern rather than pooling a long-lived connection this Agent would
/// then have to keep healthy across a VM's whole lifetime) against
/// `socket_path`, built with `hyperlocal` exactly the way `bollard`
/// itself already talks to Docker's own Unix socket.
pub struct UnixSocketTransport {
    socket_path: PathBuf,
}

impl UnixSocketTransport {
    pub fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }
}

#[async_trait]
impl VmmTransport for UnixSocketTransport {
    async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<(u16, Vec<u8>), ExecutorError> {
        let client: Client<hyperlocal::UnixConnector> = Client::unix();
        let uri: hyper::Uri = hyperlocal::Uri::new(&self.socket_path, path).into();
        let body_bytes = body.unwrap_or_default();
        let has_body = !body_bytes.is_empty();
        let mut builder = Request::builder().method(method).uri(uri);
        if has_body {
            builder = builder.header("content-type", "application/json");
        }
        let request = builder.body(Body::from(body_bytes)).map_err(|error| {
            ExecutorError::Engine(format!("building cloud-hypervisor API request: {error}"))
        })?;
        let response = client.request(request).await.map_err(|error| {
            ExecutorError::Engine(format!(
                "calling cloud-hypervisor API at {}: {error}",
                self.socket_path.display()
            ))
        })?;
        let status = response.status().as_u16();
        let bytes = hyper::body::to_bytes(response.into_body())
            .await
            .map_err(|error| {
                ExecutorError::Engine(format!("reading cloud-hypervisor API response: {error}"))
            })?;
        Ok((status, bytes.to_vec()))
    }
}

/// ADR-033 §6: the mandatory VMM security baseline, applied to every
/// spawned `cloud-hypervisor` process -- never optional, never a lighter
/// posture than Docker's own `cap_drop: ["ALL"]` + `no-new-privileges:
/// true` + dedicated-quota baseline. See this module's top doc comment
/// for the mechanism (`setpriv`) and why it was chosen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmmSecurityPolicy {
    /// Resolves via `PATH`, matching `cloud_hypervisor_binary`'s and
    /// `SystemCommandRunner`'s own convention of not hardcoding an
    /// absolute path.
    pub setpriv_binary: PathBuf,
    /// Dedicated unprivileged user the VMM process runs as -- never root,
    /// never the Agent's own uid (ADR-033 §6's `no-new-privileges`
    /// equivalent). The operator is responsible for provisioning this
    /// account and its membership in `kvm_group` (deployment/operational
    /// setup, not something this Agent process can create for itself
    /// without already running as root).
    pub user: String,
    pub group: String,
    /// The supplementary group granting `/dev/kvm` access (conventionally
    /// `kvm` on most distributions' udev rules). `wrap` clears every other
    /// supplementary group and adds back only this one -- `/dev/kvm`
    /// access has no Linux-capability equivalent (it's a device-file
    /// permission), so group membership is the actual mechanism, not an
    /// approximation of one.
    pub kvm_group: String,
    /// Explicit, not left to `cloud-hypervisor`'s own default, so a
    /// future upstream default change cannot silently disable it here.
    pub seccomp: bool,
}

impl Default for VmmSecurityPolicy {
    fn default() -> Self {
        Self {
            setpriv_binary: PathBuf::from("setpriv"),
            user: "openinfra-vmm".to_string(),
            group: "openinfra-vmm".to_string(),
            kvm_group: "kvm".to_string(),
            seccomp: true,
        }
    }
}

impl VmmSecurityPolicy {
    /// Builds the full `setpriv`-wrapped command line for `binary
    /// --api-socket api_socket`. Order matters and mirrors `setpriv(1)`'s
    /// own documented precedent for this exact combination:
    /// `--reuid`/`--regid` drop the real/effective/saved uid & gid first;
    /// `--clear-groups` + `--groups` replaces the supplementary group list
    /// with exactly `kvm_group` (nothing else survives); `--inh-caps`
    /// *and* `--bounding-set` both narrow to `CAP_NET_ADMIN` (a capability
    /// absent from either set cannot be used, so both must be narrowed,
    /// not just one); `--no-new-privs` matches Docker's own
    /// `no-new-privileges:true` `security_opt` exactly, so a compromised
    /// VMM process can never regain privilege through a setuid binary.
    /// `--seccomp` is passed explicitly (never left to
    /// `cloud-hypervisor`'s own default) per this struct's own doc
    /// comment.
    fn build(&self, binary: &Path, api_socket: &Path) -> std::process::Command {
        let mut command = std::process::Command::new(&self.setpriv_binary);
        command
            .arg("--reuid")
            .arg(&self.user)
            .arg("--regid")
            .arg(&self.group)
            .arg("--clear-groups")
            .arg("--groups")
            .arg(&self.kvm_group)
            .arg("--inh-caps=-all,+net_admin")
            .arg("--bounding-set=-all,+net_admin")
            .arg("--no-new-privs")
            .arg("--")
            .arg(binary)
            .arg("--seccomp")
            .arg(if self.seccomp { "true" } else { "false" })
            .arg("--api-socket")
            .arg(api_socket);
        command
    }
}

/// Spawns (and can kill) the `cloud-hypervisor` subprocess for one VM --
/// abstracted the same way `CommandRunner` abstracts `tc`, so
/// `CloudHypervisorEngine`'s lifecycle logic is testable without actually
/// executing a `cloud-hypervisor` binary this sandbox does not have.
#[async_trait]
pub trait VmmProcessSpawner: Send + Sync {
    async fn spawn(
        &self,
        binary: &Path,
        api_socket: &Path,
    ) -> Result<Box<dyn VmmProcessHandle>, ExecutorError>;
}

#[async_trait]
pub trait VmmProcessHandle: Send + Sync {
    async fn kill(&mut self) -> Result<(), ExecutorError>;
}

/// The real spawner: `setpriv`-wrapped `cloud-hypervisor --seccomp true
/// --api-socket <path>` (no VM config on the command line -- the config
/// is `PUT /vm.create`'d over the socket once it's up, matching Cloud
/// Hypervisor's own documented integration path), then polls for the
/// socket file to actually appear before returning, bounded by
/// `SOCKET_READY_TIMEOUT` so a binary-not-found or slow-starting process
/// can't hang `create()` indefinitely (the same bounded-wait discipline
/// `BollardEngine::pull_image` already applies to a slow image pull).
/// `policy` is ADR-033 §6's mandatory security baseline (see
/// `VmmSecurityPolicy` and this module's top doc comment) -- never
/// skippable, only its concrete user/group/binary path are configurable.
pub struct SystemVmmProcessSpawner {
    policy: VmmSecurityPolicy,
}

impl SystemVmmProcessSpawner {
    pub fn new(policy: VmmSecurityPolicy) -> Self {
        Self { policy }
    }
}

impl Default for SystemVmmProcessSpawner {
    fn default() -> Self {
        Self::new(VmmSecurityPolicy::default())
    }
}

const SOCKET_READY_TIMEOUT: Duration = Duration::from_secs(10);
const SOCKET_READY_POLL_INTERVAL: Duration = Duration::from_millis(50);

#[async_trait]
impl VmmProcessSpawner for SystemVmmProcessSpawner {
    async fn spawn(
        &self,
        binary: &Path,
        api_socket: &Path,
    ) -> Result<Box<dyn VmmProcessHandle>, ExecutorError> {
        if let Some(parent) = api_socket.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|error| {
                ExecutorError::Engine(format!("creating VM sockets dir: {error}"))
            })?;
        }
        // Best-effort: a stale socket file left behind by a previous,
        // uncleanly-terminated cloud-hypervisor process would otherwise
        // make this spawn's own readiness poll below observe a
        // pre-existing (but dead) file and return prematurely.
        let _ = tokio::fs::remove_file(api_socket).await;
        // ADR-033 §6: every cloud-hypervisor process is wrapped by
        // VmmSecurityPolicy::build -- see this module's top doc comment
        // and VmmSecurityPolicy's own doc comment for exactly what this
        // command line drops/narrows.
        let mut command: tokio::process::Command = self.policy.build(binary, api_socket).into();
        let child = command.kill_on_drop(true).spawn().map_err(|error| {
            ExecutorError::Engine(format!(
                "spawning {} (via {}): {error}",
                binary.display(),
                self.policy.setpriv_binary.display()
            ))
        })?;
        let deadline = tokio::time::Instant::now() + SOCKET_READY_TIMEOUT;
        while !api_socket.exists() {
            if tokio::time::Instant::now() >= deadline {
                return Err(ExecutorError::Engine(format!(
                    "cloud-hypervisor did not create its API socket at {} within {SOCKET_READY_TIMEOUT:?}",
                    api_socket.display()
                )));
            }
            tokio::time::sleep(SOCKET_READY_POLL_INTERVAL).await;
        }
        Ok(Box::new(SystemVmmProcessHandle { child: Some(child) }))
    }
}

struct SystemVmmProcessHandle {
    child: Option<tokio::process::Child>,
}

#[async_trait]
impl VmmProcessHandle for SystemVmmProcessHandle {
    async fn kill(&mut self) -> Result<(), ExecutorError> {
        if let Some(mut child) = self.child.take() {
            child.kill().await.map_err(|error| {
                ExecutorError::Engine(format!("killing cloud-hypervisor process: {error}"))
            })?;
        }
        Ok(())
    }
}

type TransportFactory = Arc<dyn Fn(PathBuf) -> Arc<dyn VmmTransport> + Send + Sync>;

/// A VM's tap device name plus the moment it was attached -- the latter
/// stands in for `bandwidth()`'s counter-window start (`bandwidth.rs`'s
/// `WorkloadBandwidth::window_started_at`). The Docker path reads this
/// from the container's own `started_at` timestamp (via bollard inspect);
/// there is no equivalent single source of truth for a VM's tap device,
/// but since this Agent creates the tap fresh per VM and its counters
/// start at zero, the attach time is the direct analog.
#[derive(Debug, Clone)]
struct TapAttachment {
    name: String,
    attached_at: SystemTime,
}

pub struct CloudHypervisorEngine {
    binary: PathBuf,
    sockets_dir: PathBuf,
    firmware_path: PathBuf,
    spawner: Arc<dyn VmmProcessSpawner>,
    transport_factory: TransportFactory,
    /// Handle string (the VM's API-socket path, doubling as
    /// `WorkloadRecord.vm_handle` -- see ADR-033 §6) -> the spawned
    /// process, so `remove()` can actually kill it. `create()`'s only
    /// mutation of this map; `remove()`'s only removal.
    processes: Mutex<HashMap<String, Box<dyn VmmProcessHandle>>>,
    /// ADR-033 §5: handle -> this VM's tap device attachment, so
    /// `bandwidth()`/`rate_limit()`/`remove()` can find the interface
    /// `create()` attached without re-deriving it. `create()`'s only
    /// mutation, `remove()`'s only removal -- the same lifecycle
    /// `processes` above already has.
    taps: Mutex<HashMap<String, TapAttachment>>,
    tap_backend: Arc<dyn TapBackend>,
    rate_limiter: RateLimiter,
    /// Root sysfs is read under for `bandwidth()`'s tap counter reads --
    /// `/` in production, overridable in tests so they never need a real
    /// `/sys/class/net` entry. Mirrors `BollardEngine`'s own hardcoded
    /// `Path::new("/")` for the Docker path; a field here (not a
    /// constant) only because this engine's tests need to override it.
    sys_root: PathBuf,
}

impl CloudHypervisorEngine {
    /// `security_policy` is ADR-033 §6's mandatory VMM security baseline
    /// (see `VmmSecurityPolicy`) -- there is no variant of `connect` that
    /// skips it; a caller who wants the defaults passes
    /// `VmmSecurityPolicy::default()` explicitly, matching Docker's own
    /// non-optional `cap_drop: ["ALL"]`/`no-new-privileges:true` baseline.
    pub fn connect(
        binary: PathBuf,
        sockets_dir: PathBuf,
        firmware_path: PathBuf,
        security_policy: VmmSecurityPolicy,
    ) -> Self {
        Self::with_parts(
            binary,
            sockets_dir,
            firmware_path,
            Arc::new(SystemVmmProcessSpawner::new(security_policy)),
            Arc::new(|socket_path: PathBuf| -> Arc<dyn VmmTransport> {
                Arc::new(UnixSocketTransport::new(socket_path))
            }),
            Arc::new(super::tap::SystemTapBackend::new(Arc::new(
                crate::rate_limit::SystemCommandRunner,
            ))),
            RateLimiter::new(Arc::new(crate::rate_limit::SystemCommandRunner)),
            PathBuf::from("/"),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn with_parts(
        binary: PathBuf,
        sockets_dir: PathBuf,
        firmware_path: PathBuf,
        spawner: Arc<dyn VmmProcessSpawner>,
        transport_factory: TransportFactory,
        tap_backend: Arc<dyn TapBackend>,
        rate_limiter: RateLimiter,
        sys_root: PathBuf,
    ) -> Self {
        Self {
            binary,
            sockets_dir,
            firmware_path,
            spawner,
            transport_factory,
            processes: Mutex::new(HashMap::new()),
            taps: Mutex::new(HashMap::new()),
            tap_backend,
            rate_limiter,
            sys_root,
        }
    }

    #[cfg(test)]
    fn for_test(spawner: Arc<dyn VmmProcessSpawner>, transport_factory: TransportFactory) -> Self {
        Self::for_test_full(
            spawner,
            transport_factory,
            Arc::new(tests::FakeTapBackend::default()),
            Arc::new(tests::FakeCommandRunner::default()),
            std::env::temp_dir(),
        )
    }

    /// The fully-parameterized test constructor -- used directly by this
    /// module's own tap/bandwidth/rate-limit tests; `for_test` above is
    /// just this with always-succeeding fakes plumbed in, for the
    /// existing create/start/stop/inspect/remove tests that don't care
    /// about networking at all.
    #[cfg(test)]
    fn for_test_full(
        spawner: Arc<dyn VmmProcessSpawner>,
        transport_factory: TransportFactory,
        tap_backend: Arc<dyn TapBackend>,
        command_runner: Arc<dyn crate::rate_limit::CommandRunner>,
        sys_root: PathBuf,
    ) -> Self {
        Self::with_parts(
            PathBuf::from("cloud-hypervisor"),
            std::env::temp_dir(),
            PathBuf::from("/usr/share/cloud-hypervisor/CLOUDHV.fd"),
            spawner,
            transport_factory,
            tap_backend,
            RateLimiter::new(command_runner),
            sys_root,
        )
    }

    fn socket_path(&self, name: &str) -> PathBuf {
        self.sockets_dir.join(format!("{name}.sock"))
    }

    /// `create()`'s body, split out only so `create()` itself can wrap it
    /// in one shared tap-cleanup-on-failure block (see `create()`'s doc
    /// comment) instead of repeating that cleanup at every one of this
    /// method's several fallible steps.
    async fn create_after_tap(
        &self,
        spec: &VmSpec,
        socket_path: &Path,
        tap_name: &str,
    ) -> Result<String, ExecutorError> {
        let process = self.spawner.spawn(&self.binary, socket_path).await?;
        let transport = (self.transport_factory)(socket_path.to_path_buf());
        let memory_bytes = spec.memory_mb.checked_mul(MIB).ok_or_else(|| {
            ExecutorError::InvalidRequest("VM memory limit overflows bytes".to_string())
        })?;
        let firmware = if spec.firmware_path.as_os_str().is_empty() {
            &self.firmware_path
        } else {
            &spec.firmware_path
        };
        // Field names/shape verified against Cloud Hypervisor's own
        // OpenAPI spec (VmConfig/CpusConfig/MemoryConfig/PayloadConfig/
        // DiskConfig/NetConfig) -- see this module's top doc comment.
        // `net[0].tap` names the host tap device by name rather than
        // supplying a raw fd -- the simpler of Cloud Hypervisor's two
        // documented options, and the one that doesn't require this
        // Agent to keep a tap fd alive across the `cloud-hypervisor`
        // subprocess boundary.
        let body = serde_json::json!({
            "cpus": {"boot_vcpus": spec.vcpus, "max_vcpus": spec.vcpus},
            "memory": {"size": memory_bytes},
            "payload": {"firmware": firmware.to_string_lossy()},
            "disks": [{"path": spec.image_path.to_string_lossy(), "readonly": false}],
            "net": [{"tap": tap_name}],
        });
        let body_bytes = serde_json::to_vec(&body).map_err(|error| {
            ExecutorError::Engine(format!("encoding cloud-hypervisor VmConfig: {error}"))
        })?;
        let (status, response) = transport
            .request(Method::PUT, "/vm.create", Some(body_bytes))
            .await?;
        if status != 204 {
            return Err(ExecutorError::Engine(format!(
                "cloud-hypervisor vm.create returned HTTP {status}: {}",
                String::from_utf8_lossy(&response)
            )));
        }
        let handle = socket_path.to_string_lossy().to_string();
        self.taps.lock().await.insert(
            handle.clone(),
            TapAttachment {
                name: tap_name.to_string(),
                attached_at: SystemTime::now(),
            },
        );
        self.processes.lock().await.insert(handle.clone(), process);
        Ok(handle)
    }

    /// Looks up the tap device `create()` attached for `handle`, for
    /// `bandwidth()`/`rate_limit()` -- an unknown handle is a clear error
    /// rather than a panic or a silently-wrong default interface, the
    /// same "fail closed on an unrecognized handle" posture `inspect`/
    /// `remove` already have via their own transport/HTTP-status checks.
    async fn tap_for_handle(&self, handle: &str) -> Result<TapAttachment, ExecutorError> {
        self.taps.lock().await.get(handle).cloned().ok_or_else(|| {
            ExecutorError::Engine(format!("no tap device recorded for VM handle {handle}"))
        })
    }
}

#[async_trait]
impl VmEngine for CloudHypervisorEngine {
    async fn create(&self, spec: &VmSpec) -> Result<String, ExecutorError> {
        let socket_path = self.socket_path(&spec.name);
        // ADR-033 §5: the tap device must exist before vm.create's `net`
        // config below can reference it by name -- Cloud Hypervisor opens
        // a pre-existing tap given by name, it does not create one (see
        // this module's top doc comment and `vm::tap`'s). Attached before
        // spawning the process: creation order relative to the VMM
        // process doesn't matter (only "before vm.create is called"
        // does), but attaching first means a spawn failure's cleanup path
        // below is the only cleanup path this method needs, not two.
        let tap_name = super::tap::tap_device_name(&spec.name);
        self.tap_backend.attach(&tap_name)?;
        let result = self.create_after_tap(spec, &socket_path, &tap_name).await;
        if result.is_err() {
            if let Err(cleanup_error) = self.tap_backend.detach(&tap_name) {
                warn!(%tap_name, %cleanup_error, "failed to remove tap device after a failed VM create");
            }
        }
        result
    }

    async fn start(&self, handle: &str) -> Result<(), ExecutorError> {
        let transport = (self.transport_factory)(PathBuf::from(handle));
        let (status, response) = transport.request(Method::PUT, "/vm.boot", None).await?;
        if status != 204 {
            return Err(ExecutorError::Engine(format!(
                "cloud-hypervisor vm.boot returned HTTP {status}: {}",
                String::from_utf8_lossy(&response)
            )));
        }
        Ok(())
    }

    async fn stop(&self, handle: &str) -> Result<(), ExecutorError> {
        let transport = (self.transport_factory)(PathBuf::from(handle));
        let (status, response) = transport.request(Method::PUT, "/vm.shutdown", None).await?;
        if status != 204 {
            return Err(ExecutorError::Engine(format!(
                "cloud-hypervisor vm.shutdown returned HTTP {status}: {}",
                String::from_utf8_lossy(&response)
            )));
        }
        Ok(())
    }

    async fn inspect(&self, handle: &str) -> Result<VmObservation, ExecutorError> {
        let transport = (self.transport_factory)(PathBuf::from(handle));
        let (status, response) = transport.request(Method::GET, "/vm.info", None).await?;
        if status != 200 {
            return Err(ExecutorError::Engine(format!(
                "cloud-hypervisor vm.info returned HTTP {status}"
            )));
        }
        let info: serde_json::Value = serde_json::from_slice(&response).map_err(|error| {
            ExecutorError::Engine(format!(
                "parsing cloud-hypervisor vm.info response: {error}"
            ))
        })?;
        let state = info
            .get("state")
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                ExecutorError::Engine("cloud-hypervisor vm.info response missing state".to_string())
            })?;
        Ok(VmObservation {
            running: state == "Running",
            status: state.to_ascii_lowercase(),
        })
    }

    async fn remove(&self, handle: &str) -> Result<(), ExecutorError> {
        let transport = (self.transport_factory)(PathBuf::from(handle));
        let (status, response) = transport.request(Method::PUT, "/vm.delete", None).await?;
        // 404 ("VM information is not available because the VM is not
        // created") is treated as already-removed, the same
        // remove-is-idempotent posture `BollardEngine::remove`'s
        // `force: true` already gives the Docker side.
        if status != 204 && status != 404 {
            return Err(ExecutorError::Engine(format!(
                "cloud-hypervisor vm.delete returned HTTP {status}: {}",
                String::from_utf8_lossy(&response)
            )));
        }
        if let Some(mut process) = self.processes.lock().await.remove(handle) {
            if let Err(error) = process.kill().await {
                warn!(%handle, %error, "failed to kill cloud-hypervisor process after vm.delete");
            }
        }
        if let Err(error) = std::fs::remove_file(handle) {
            if error.kind() != std::io::ErrorKind::NotFound {
                warn!(%handle, %error, "failed to remove cloud-hypervisor API socket file");
            }
        }
        // ADR-033 §5: tap teardown happens last, only after the VM itself
        // is confirmed gone -- mirrors vm.delete's own idempotency, since
        // a retried remove() for an already-torn-down VM must not error
        // just because the tap (or the map entry recording it) is
        // already gone; a missing map entry here is not itself an error,
        // it just means there is nothing left to detach.
        if let Some(attachment) = self.taps.lock().await.remove(handle) {
            if let Err(error) = self.tap_backend.detach(&attachment.name) {
                warn!(%handle, tap_name = %attachment.name, %error, "failed to remove tap device after vm.delete");
            }
        }
        Ok(())
    }

    /// ADR-033 §5: this workload's cumulative bandwidth counters, read
    /// from its tap device. See `bandwidth::read_bandwidth_for_interface`
    /// for the exact mechanism and direction convention.
    async fn bandwidth(&self, handle: &str) -> Result<WorkloadBandwidth, ExecutorError> {
        let attachment = self.tap_for_handle(handle).await?;
        crate::bandwidth::read_bandwidth_for_interface(
            &self.sys_root,
            &attachment.name,
            attachment.attached_at,
        )
    }

    /// ADR-033 §5: applies `egress_mbps` as a host-side `tc` ceiling
    /// against this workload's tap device. See
    /// `RateLimiter::apply_to_interface`'s doc comment for the exact
    /// mechanism; callers (`VmExecutor::apply_rate_limit_if_needed`) must
    /// only invoke this when `egress_mbps > 0`, the same convention
    /// `ContainerEngine::rate_limit`'s callers already follow.
    async fn rate_limit(&self, handle: &str, egress_mbps: i32) -> Result<(), ExecutorError> {
        let attachment = self.tap_for_handle(handle).await?;
        self.rate_limiter
            .apply_to_interface(&attachment.name, egress_mbps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    // --- ADR-033 §6 security baseline: VmmSecurityPolicy::build's argv,
    // asserted field-by-field. This is the "real, not just documented"
    // half named in this module's top doc comment -- what's NOT proven
    // here is that a real setpriv + cloud-hypervisor process, run on a
    // real Linux host with a real openinfra-vmm user, actually ends up
    // with exactly CAP_NET_ADMIN and no more; that needs a real host (see
    // this PR's own description for the follow-up).

    fn args(command: &std::process::Command) -> Vec<String> {
        command
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect()
    }

    #[test]
    fn security_baseline_wraps_the_vmm_with_setpriv_dropping_to_the_dedicated_user() {
        let policy = VmmSecurityPolicy::default();
        let command = policy.build(
            Path::new("/usr/local/bin/cloud-hypervisor"),
            Path::new("/tmp/wl-1.sock"),
        );

        assert_eq!(command.get_program().to_string_lossy(), "setpriv");
        let argv = args(&command);
        assert_eq!(
            argv,
            vec![
                "--reuid",
                "openinfra-vmm",
                "--regid",
                "openinfra-vmm",
                "--clear-groups",
                "--groups",
                "kvm",
                "--inh-caps=-all,+net_admin",
                "--bounding-set=-all,+net_admin",
                "--no-new-privs",
                "--",
                "/usr/local/bin/cloud-hypervisor",
                "--seccomp",
                "true",
                "--api-socket",
                "/tmp/wl-1.sock",
            ]
        );
    }

    #[test]
    fn security_baseline_never_grants_more_than_net_admin_even_with_custom_accounts() {
        // A deployment-configured user/group must still narrow to exactly
        // CAP_NET_ADMIN -- the capability strings are not derived from
        // user/group at all, so a custom account can never widen them.
        let policy = VmmSecurityPolicy {
            setpriv_binary: PathBuf::from("/usr/bin/setpriv"),
            user: "vmm-provider-7".to_string(),
            group: "vmm-provider-7".to_string(),
            kvm_group: "kvm-restricted".to_string(),
            seccomp: true,
        };
        let command = policy.build(Path::new("cloud-hypervisor"), Path::new("wl.sock"));
        let argv = args(&command);
        assert!(argv.contains(&"vmm-provider-7".to_string()));
        assert!(argv.contains(&"kvm-restricted".to_string()));
        assert!(argv.contains(&"--inh-caps=-all,+net_admin".to_string()));
        assert!(argv.contains(&"--bounding-set=-all,+net_admin".to_string()));
        assert!(argv.contains(&"--no-new-privs".to_string()));
    }

    #[test]
    fn security_baseline_passes_seccomp_explicitly_never_relying_on_a_default() {
        let enabled = VmmSecurityPolicy::default();
        assert!(
            args(&enabled.build(Path::new("cloud-hypervisor"), Path::new("wl.sock")))
                .windows(2)
                .any(|pair| pair == ["--seccomp", "true"])
        );

        let disabled = VmmSecurityPolicy {
            seccomp: false,
            ..VmmSecurityPolicy::default()
        };
        assert!(
            args(&disabled.build(Path::new("cloud-hypervisor"), Path::new("wl.sock")))
                .windows(2)
                .any(|pair| pair == ["--seccomp", "false"])
        );
    }

    #[test]
    fn setpriv_binary_is_present_in_this_build_environment() {
        // Not a claim that a real cloud-hypervisor process was ever
        // wrapped and spawned with it (see this module's top doc
        // comment) -- only that the mechanism this security baseline
        // depends on is not itself missing/hypothetical here.
        let found = std::env::var_os("PATH")
            .map(|path| std::env::split_paths(&path).any(|dir| dir.join("setpriv").is_file()))
            .unwrap_or(false);
        assert!(found, "setpriv (util-linux) not found on PATH");
    }

    // --- CloudHypervisorEngine request-building / response-parsing
    // tests, against a FakeTransport (no real socket, no real process).

    type RecordedCall = (Method, String, Option<Vec<u8>>);

    #[derive(Default)]
    struct FakeTransport {
        calls: StdMutex<Vec<RecordedCall>>,
        responses: StdMutex<HashMap<String, (u16, Vec<u8>)>>,
    }

    impl FakeTransport {
        fn respond(&self, path: &str, status: u16, body: Vec<u8>) {
            self.responses
                .lock()
                .expect("responses lock")
                .insert(path.to_string(), (status, body));
        }
    }

    #[async_trait]
    impl VmmTransport for FakeTransport {
        async fn request(
            &self,
            method: Method,
            path: &str,
            body: Option<Vec<u8>>,
        ) -> Result<(u16, Vec<u8>), ExecutorError> {
            self.calls
                .lock()
                .expect("calls lock")
                .push((method, path.to_string(), body));
            Ok(self
                .responses
                .lock()
                .expect("responses lock")
                .get(path)
                .cloned()
                .unwrap_or((204, Vec::new())))
        }
    }

    struct FakeSpawner {
        calls: StdMutex<Vec<(PathBuf, PathBuf)>>,
        // ADR-033 §5: when true, spawn() fails every call -- used by the
        // tap-cleanup-on-failure tests below to exercise create()'s
        // cleanup path without needing vm.create itself to fail.
        fails: bool,
    }

    impl Default for FakeSpawner {
        fn default() -> Self {
            Self {
                calls: StdMutex::new(Vec::new()),
                fails: false,
            }
        }
    }

    impl FakeSpawner {
        fn failing() -> Self {
            Self {
                calls: StdMutex::new(Vec::new()),
                fails: true,
            }
        }
    }

    struct FakeProcessHandle {
        killed: Arc<StdMutex<bool>>,
    }

    #[async_trait]
    impl VmmProcessHandle for FakeProcessHandle {
        async fn kill(&mut self) -> Result<(), ExecutorError> {
            *self.killed.lock().expect("killed lock") = true;
            Ok(())
        }
    }

    #[async_trait]
    impl VmmProcessSpawner for FakeSpawner {
        async fn spawn(
            &self,
            binary: &Path,
            api_socket: &Path,
        ) -> Result<Box<dyn VmmProcessHandle>, ExecutorError> {
            self.calls
                .lock()
                .expect("calls lock")
                .push((binary.to_path_buf(), api_socket.to_path_buf()));
            if self.fails {
                return Err(ExecutorError::Engine("spawn failed (test)".to_string()));
            }
            Ok(Box::new(FakeProcessHandle {
                killed: Arc::new(StdMutex::new(false)),
            }))
        }
    }

    // --- ADR-033 §5: fakes for the tap-device networking seams
    // (`TapBackend`, `CommandRunner`), the same double-per-privileged-
    // mechanism pattern `FakeTransport`/`FakeSpawner` above already use.

    #[derive(Default)]
    pub(super) struct FakeTapBackend {
        pub(super) attached: StdMutex<Vec<String>>,
        pub(super) detached: StdMutex<Vec<String>>,
        attach_failures: StdMutex<HashMap<String, String>>,
        detach_failures: StdMutex<HashMap<String, String>>,
    }

    impl FakeTapBackend {
        fn fail_attach(&self, name: &str, reason: &str) {
            self.attach_failures
                .lock()
                .expect("attach failures lock")
                .insert(name.to_string(), reason.to_string());
        }

        fn fail_detach(&self, name: &str, reason: &str) {
            self.detach_failures
                .lock()
                .expect("detach failures lock")
                .insert(name.to_string(), reason.to_string());
        }
    }

    impl TapBackend for FakeTapBackend {
        fn attach(&self, name: &str) -> Result<(), ExecutorError> {
            self.attached
                .lock()
                .expect("attached lock")
                .push(name.to_string());
            if let Some(reason) = self.attach_failures.lock().expect("lock").get(name) {
                return Err(ExecutorError::Engine(reason.clone()));
            }
            Ok(())
        }

        fn detach(&self, name: &str) -> Result<(), ExecutorError> {
            self.detached
                .lock()
                .expect("detached lock")
                .push(name.to_string());
            if let Some(reason) = self.detach_failures.lock().expect("lock").get(name) {
                return Err(ExecutorError::Engine(reason.clone()));
            }
            Ok(())
        }
    }

    #[derive(Default)]
    pub(super) struct FakeCommandRunner {
        pub(super) invocations: StdMutex<Vec<(String, Vec<String>)>>,
    }

    impl crate::rate_limit::CommandRunner for FakeCommandRunner {
        fn run(&self, program: &str, args: &[String]) -> std::io::Result<std::process::Output> {
            use std::os::unix::process::ExitStatusExt;
            self.invocations
                .lock()
                .expect("invocations lock")
                .push((program.to_string(), args.to_vec()));
            Ok(std::process::Output {
                status: std::process::ExitStatus::from_raw(0),
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        }
    }

    fn engine_with_fake_transport() -> (CloudHypervisorEngine, Arc<FakeTransport>) {
        let transport = Arc::new(FakeTransport::default());
        let transport_for_factory = transport.clone();
        let engine = CloudHypervisorEngine::for_test(
            Arc::new(FakeSpawner::default()),
            Arc::new(move |_socket_path: PathBuf| -> Arc<dyn VmmTransport> {
                transport_for_factory.clone()
            }),
        );
        (engine, transport)
    }

    /// Like `engine_with_fake_transport`, but also returns the
    /// `FakeTapBackend`/`FakeCommandRunner` doubles directly, for tests
    /// that assert on tap-device attach/detach calls or `tc` invocations
    /// rather than just Cloud Hypervisor API calls.
    fn engine_with_networking_fakes() -> (
        CloudHypervisorEngine,
        Arc<FakeTransport>,
        Arc<FakeTapBackend>,
        Arc<FakeCommandRunner>,
    ) {
        engine_with_networking_fakes_and_spawner(Arc::new(FakeSpawner::default()))
    }

    fn engine_with_networking_fakes_and_spawner(
        spawner: Arc<dyn VmmProcessSpawner>,
    ) -> (
        CloudHypervisorEngine,
        Arc<FakeTransport>,
        Arc<FakeTapBackend>,
        Arc<FakeCommandRunner>,
    ) {
        engine_with_networking_fakes_and_spawner_and_sysroot(spawner, std::env::temp_dir())
    }

    /// The fully general form -- also lets `bandwidth()`'s tests point
    /// counter reads at a fake `/sys/class/net` tree instead of the real
    /// root.
    fn engine_with_networking_fakes_and_spawner_and_sysroot(
        spawner: Arc<dyn VmmProcessSpawner>,
        sys_root: PathBuf,
    ) -> (
        CloudHypervisorEngine,
        Arc<FakeTransport>,
        Arc<FakeTapBackend>,
        Arc<FakeCommandRunner>,
    ) {
        let transport = Arc::new(FakeTransport::default());
        let transport_for_factory = transport.clone();
        let tap_backend = Arc::new(FakeTapBackend::default());
        let command_runner = Arc::new(FakeCommandRunner::default());
        let engine = CloudHypervisorEngine::for_test_full(
            spawner,
            Arc::new(move |_socket_path: PathBuf| -> Arc<dyn VmmTransport> {
                transport_for_factory.clone()
            }),
            tap_backend.clone(),
            command_runner.clone(),
            sys_root,
        );
        (engine, transport, tap_backend, command_runner)
    }

    fn spec() -> VmSpec {
        VmSpec {
            name: "wl-1".to_string(),
            vcpus: 2,
            memory_mb: 1024,
            image_path: PathBuf::from("/var/lib/openinfra/vm-images/abc.qcow2"),
            firmware_path: PathBuf::new(),
        }
    }

    #[tokio::test]
    async fn create_sends_the_documented_vm_create_request_and_returns_the_socket_handle() {
        let (engine, transport) = engine_with_fake_transport();
        let handle = engine.create(&spec()).await.expect("create");
        assert!(handle.ends_with("wl-1.sock"));

        let calls = transport.calls.lock().expect("calls");
        assert_eq!(calls.len(), 1);
        let (method, path, body) = &calls[0];
        assert_eq!(*method, Method::PUT);
        assert_eq!(path, "/vm.create");
        let body: serde_json::Value =
            serde_json::from_slice(body.as_deref().expect("create has a body")).expect("json");
        assert_eq!(body["cpus"]["boot_vcpus"], 2);
        assert_eq!(body["memory"]["size"], 1024 * MIB);
        assert_eq!(
            body["disks"][0]["path"],
            "/var/lib/openinfra/vm-images/abc.qcow2"
        );
        // No per-VM firmware override was set on the spec -- the
        // engine's own configured default firmware_path must be used.
        assert_eq!(
            body["payload"]["firmware"],
            "/usr/share/cloud-hypervisor/CLOUDHV.fd"
        );
        // ADR-033 §5: the tap device this engine attached must be named
        // in the net config by exactly the name `vm::tap::tap_device_name`
        // derives from the spec's own name.
        assert_eq!(
            body["net"][0]["tap"],
            crate::vm::tap::tap_device_name(&spec().name)
        );
    }

    #[tokio::test]
    async fn create_surfaces_a_non_204_response_as_an_error() {
        let (engine, transport) = engine_with_fake_transport();
        transport.respond("/vm.create", 400, b"bad config".to_vec());

        let result = engine.create(&spec()).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("400"));
    }

    #[tokio::test]
    async fn start_and_stop_hit_the_documented_boot_and_shutdown_paths() {
        let (engine, transport) = engine_with_fake_transport();
        let handle = engine.create(&spec()).await.expect("create");

        engine.start(&handle).await.expect("start");
        engine.stop(&handle).await.expect("stop");

        let calls = transport.calls.lock().expect("calls");
        assert_eq!(calls[1].1, "/vm.boot");
        assert_eq!(calls[2].1, "/vm.shutdown");
    }

    #[tokio::test]
    async fn inspect_parses_the_running_state_from_vm_info() {
        let (engine, transport) = engine_with_fake_transport();
        let handle = engine.create(&spec()).await.expect("create");
        transport.respond(
            "/vm.info",
            200,
            serde_json::to_vec(&serde_json::json!({"state": "Running"})).unwrap(),
        );

        let observation = engine.inspect(&handle).await.expect("inspect");
        assert!(observation.running);
        assert_eq!(observation.status, "running");
    }

    #[tokio::test]
    async fn inspect_reports_not_running_for_a_shutdown_vm() {
        let (engine, transport) = engine_with_fake_transport();
        let handle = engine.create(&spec()).await.expect("create");
        transport.respond(
            "/vm.info",
            200,
            serde_json::to_vec(&serde_json::json!({"state": "Shutdown"})).unwrap(),
        );

        let observation = engine.inspect(&handle).await.expect("inspect");
        assert!(!observation.running);
        assert_eq!(observation.status, "shutdown");
    }

    #[tokio::test]
    async fn remove_deletes_and_treats_a_404_as_already_removed() {
        let (engine, transport) = engine_with_fake_transport();
        let handle = engine.create(&spec()).await.expect("create");
        transport.respond("/vm.delete", 404, Vec::new());

        engine.remove(&handle).await.expect("remove tolerates 404");
        assert!(
            !engine.processes.lock().await.contains_key(&handle),
            "the process handle must be dropped from tracking even on a 404 vm.delete"
        );
    }

    #[tokio::test]
    async fn spawner_is_invoked_with_the_configured_binary_and_a_per_vm_socket_path() {
        let spawner = Arc::new(FakeSpawner::default());
        let transport: Arc<dyn VmmTransport> = Arc::new(FakeTransport::default());
        let engine = CloudHypervisorEngine::for_test(
            spawner.clone(),
            Arc::new(move |_p: PathBuf| transport.clone()),
        );
        engine.create(&spec()).await.expect("create");

        let calls = spawner.calls.lock().expect("calls");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, PathBuf::from("cloud-hypervisor"));
        assert!(calls[0].1.ends_with("wl-1.sock"));
    }

    // --- ADR-033 §5 / issue #176 point 1: tap-device networking wiring
    // (create/remove attach-detach, bandwidth/rate_limit), against the
    // FakeTapBackend/FakeCommandRunner doubles above -- see this module's
    // and vm::tap's top doc comments for exactly what this does and does
    // not prove (no real CAP_NET_ADMIN/kernel netlink socket here).

    #[tokio::test]
    async fn create_attaches_the_tap_device_before_calling_vm_create() {
        let (engine, _transport, tap_backend, _runner) = engine_with_networking_fakes();

        let handle = engine.create(&spec()).await.expect("create");

        let expected_tap = crate::vm::tap::tap_device_name(&spec().name);
        assert_eq!(
            tap_backend
                .attached
                .lock()
                .expect("attached lock")
                .as_slice(),
            &[expected_tap]
        );
        assert!(engine.taps.lock().await.contains_key(&handle));
    }

    #[tokio::test]
    async fn create_surfaces_a_tap_attach_failure_and_never_calls_vm_create() {
        let (engine, transport, tap_backend, _runner) = engine_with_networking_fakes();
        let expected_tap = crate::vm::tap::tap_device_name(&spec().name);
        tap_backend.fail_attach(&expected_tap, "RTNETLINK answers: Permission denied");

        let result = engine.create(&spec()).await;

        let error = result.expect_err("a tap attach failure must surface");
        assert!(error.to_string().contains("Permission denied"));
        assert!(
            transport.calls.lock().expect("calls lock").is_empty(),
            "vm.create must never be called when the tap could not be attached"
        );
    }

    #[tokio::test]
    async fn create_detaches_the_tap_device_when_the_vmm_process_fails_to_spawn() {
        let (engine, _transport, tap_backend, _runner) =
            engine_with_networking_fakes_and_spawner(Arc::new(FakeSpawner::failing()));

        let result = engine.create(&spec()).await;

        assert!(result.is_err());
        let expected_tap = crate::vm::tap::tap_device_name(&spec().name);
        assert_eq!(
            tap_backend.attached.lock().expect("lock").as_slice(),
            std::slice::from_ref(&expected_tap),
            "the tap must still have been attached before the spawn failure"
        );
        assert_eq!(
            tap_backend.detached.lock().expect("lock").as_slice(),
            std::slice::from_ref(&expected_tap),
            "a failed create() must clean up the tap device it already attached"
        );
    }

    #[tokio::test]
    async fn create_detaches_the_tap_device_when_vm_create_returns_a_non_204() {
        let (engine, transport, tap_backend, _runner) = engine_with_networking_fakes();
        transport.respond("/vm.create", 400, b"bad config".to_vec());

        let result = engine.create(&spec()).await;

        assert!(result.is_err());
        let expected_tap = crate::vm::tap::tap_device_name(&spec().name);
        assert_eq!(
            tap_backend.detached.lock().expect("lock").as_slice(),
            &[expected_tap],
            "a rejected vm.create must not leave an orphaned tap device"
        );
    }

    #[tokio::test]
    async fn remove_detaches_the_tap_device_after_vm_delete_succeeds() {
        let (engine, _transport, tap_backend, _runner) = engine_with_networking_fakes();
        let handle = engine.create(&spec()).await.expect("create");
        let expected_tap = crate::vm::tap::tap_device_name(&spec().name);

        engine.remove(&handle).await.expect("remove");

        assert_eq!(
            tap_backend.detached.lock().expect("lock").as_slice(),
            &[expected_tap]
        );
        assert!(
            !engine.taps.lock().await.contains_key(&handle),
            "the tap attachment must be dropped from tracking after remove()"
        );
    }

    #[tokio::test]
    async fn remove_tolerates_a_tap_detach_failure_and_still_succeeds() {
        let (engine, _transport, tap_backend, _runner) = engine_with_networking_fakes();
        let handle = engine.create(&spec()).await.expect("create");
        let expected_tap = crate::vm::tap::tap_device_name(&spec().name);
        tap_backend.fail_detach(&expected_tap, "device busy");

        engine
            .remove(&handle)
            .await
            .expect("a tap detach failure must not fail remove() -- the VM itself is already gone");
    }

    #[tokio::test]
    async fn remove_is_idempotent_about_the_tap_when_called_twice() {
        let (engine, _transport, tap_backend, _runner) = engine_with_networking_fakes();
        let handle = engine.create(&spec()).await.expect("create");

        engine.remove(&handle).await.expect("first remove");
        engine
            .remove(&handle)
            .await
            .expect("second remove must also succeed");

        // Only the first remove() found a tracked tap to detach; the
        // second found none, which is not an error (see tap_for_handle's
        // doc comment / remove()'s own comment).
        assert_eq!(tap_backend.detached.lock().expect("lock").len(), 1);
    }

    #[tokio::test]
    async fn bandwidth_reads_the_attached_taps_counters() {
        let directory = tempfile::tempdir().expect("dir");
        let (engine, _transport, _tap_backend, _runner) =
            engine_with_networking_fakes_and_spawner_and_sysroot(
                Arc::new(FakeSpawner::default()),
                directory.path().to_path_buf(),
            );
        let handle = engine.create(&spec()).await.expect("create");
        let tap_name = crate::vm::tap::tap_device_name(&spec().name);
        std::fs::create_dir_all(
            directory
                .path()
                .join("sys/class/net")
                .join(&tap_name)
                .join("statistics"),
        )
        .expect("create fixture dirs");
        std::fs::write(
            directory
                .path()
                .join("sys/class/net")
                .join(&tap_name)
                .join("statistics/rx_bytes"),
            "1024\n",
        )
        .expect("write rx_bytes");
        std::fs::write(
            directory
                .path()
                .join("sys/class/net")
                .join(&tap_name)
                .join("statistics/tx_bytes"),
            "2048\n",
        )
        .expect("write tx_bytes");

        let reading = engine.bandwidth(&handle).await.expect("bandwidth");

        assert_eq!(reading.egress_bytes_total, 1024);
        assert_eq!(reading.ingress_bytes_total, 2048);
    }

    #[tokio::test]
    async fn bandwidth_fails_clearly_for_an_unrecognized_handle() {
        let (engine, _transport, _tap_backend, _runner) = engine_with_networking_fakes();

        let result = engine.bandwidth("/no/such/vm.sock").await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn rate_limit_applies_tc_directly_to_the_tap_device_by_name() {
        let (engine, _transport, _tap_backend, runner) = engine_with_networking_fakes();
        let handle = engine.create(&spec()).await.expect("create");
        let expected_tap = crate::vm::tap::tap_device_name(&spec().name);

        engine.rate_limit(&handle, 75).await.expect("rate_limit");

        let invocations = runner.invocations.lock().expect("invocations lock");
        assert_eq!(invocations.len(), 1);
        let (program, args) = &invocations[0];
        assert_eq!(program, "tc");
        assert_eq!(
            args,
            &[
                "qdisc",
                "replace",
                "dev",
                expected_tap.as_str(),
                "root",
                "tbf",
                "rate",
                "75mbit",
                "burst",
                "32768",
                "latency",
                "50ms",
            ]
        );
    }

    #[tokio::test]
    async fn rate_limit_fails_clearly_for_an_unrecognized_handle() {
        let (engine, _transport, _tap_backend, runner) = engine_with_networking_fakes();

        let result = engine.rate_limit("/no/such/vm.sock", 50).await;

        assert!(result.is_err());
        assert!(
            runner.invocations.lock().expect("lock").is_empty(),
            "tc must never be invoked for a handle this engine never created"
        );
    }

    // --- UnixSocketTransport tests, against a real Unix-domain-socket
    // HTTP server (hyperlocal's server side) standing in for Cloud
    // Hypervisor -- see this module's and vm/mod.rs's doc comments for
    // exactly what this does and does not prove.

    #[tokio::test]
    async fn unix_socket_transport_round_trips_a_real_request_over_a_real_socket() {
        use hyper::service::{make_service_fn, service_fn};
        use hyper::{Body as HyperBody, Response, Server};
        use hyperlocal::UnixServerExt;

        let directory = tempfile::tempdir().expect("dir");
        let socket_path = directory.path().join("fake-ch.sock");
        let bound_path = socket_path.clone();

        let make_service = make_service_fn(move |_| {
            let socket_path = bound_path.clone();
            async move {
                Ok::<_, hyper::Error>(service_fn(move |req: Request<HyperBody>| {
                    let _ = &socket_path;
                    async move {
                        assert_eq!(req.uri().path(), "/vm.info");
                        Ok::<_, hyper::Error>(
                            Response::builder()
                                .status(200)
                                .body(HyperBody::from(r#"{"state":"Running"}"#))
                                .unwrap(),
                        )
                    }
                }))
            }
        });
        let server = Server::bind_unix(&socket_path)
            .expect("bind fake cloud-hypervisor socket")
            .serve(make_service);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server = server.with_graceful_shutdown(async {
            shutdown_rx.await.ok();
        });
        tokio::spawn(server);

        let transport = UnixSocketTransport::new(socket_path);
        let (status, body) = transport
            .request(Method::GET, "/vm.info", None)
            .await
            .expect("real unix socket request");

        shutdown_tx.send(()).ok();

        assert_eq!(status, 200);
        let value: serde_json::Value = serde_json::from_slice(&body).expect("json body");
        assert_eq!(value["state"], "Running");
    }
}
