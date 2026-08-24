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
//! **Security baseline not yet wired here** (ADR-033 §6, named as a
//! follow-up in the implementing PR's own report, not silently dropped):
//! the mandatory seccomp policy, the dedicated unprivileged VMM user, and
//! the capability drop to exactly `CAP_NET_ADMIN` + `/dev/kvm` access are
//! real `cloud-hypervisor` command-line/process-launch concerns
//! (`--seccomp`, running under a different uid/gid, Linux capability
//! sets) that need to be exercised against a real binary to get right --
//! `SystemVmmProcessSpawner::spawn` is the single, clearly marked call
//! site to extend for this.

use crate::ExecutorError;
use async_trait::async_trait;
use hyper::{Body, Client, Method, Request};
use hyperlocal::UnixClientExt;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::warn;

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

/// The real spawner: `cloud-hypervisor --api-socket <path>` (no VM
/// config on the command line -- the config is `PUT /vm.create`'d over
/// the socket once it's up, matching Cloud Hypervisor's own documented
/// integration path), then polls for the socket file to actually appear
/// before returning, bounded by `SOCKET_READY_TIMEOUT` so a
/// binary-not-found or slow-starting process can't hang `create()`
/// indefinitely (the same bounded-wait discipline
/// `BollardEngine::pull_image` already applies to a slow image pull).
pub struct SystemVmmProcessSpawner;

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
        // ADR-033 §6: the mandatory seccomp policy / dedicated
        // unprivileged VMM user / capability drop belong on this exact
        // command line -- not yet wired here, see this module's top doc
        // comment.
        let child = tokio::process::Command::new(binary)
            .arg("--api-socket")
            .arg(api_socket)
            .kill_on_drop(true)
            .spawn()
            .map_err(|error| {
                ExecutorError::Engine(format!("spawning {}: {error}", binary.display()))
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
}

impl CloudHypervisorEngine {
    pub fn connect(binary: PathBuf, sockets_dir: PathBuf, firmware_path: PathBuf) -> Self {
        Self::with_parts(
            binary,
            sockets_dir,
            firmware_path,
            Arc::new(SystemVmmProcessSpawner),
            Arc::new(|socket_path: PathBuf| -> Arc<dyn VmmTransport> {
                Arc::new(UnixSocketTransport::new(socket_path))
            }),
        )
    }

    fn with_parts(
        binary: PathBuf,
        sockets_dir: PathBuf,
        firmware_path: PathBuf,
        spawner: Arc<dyn VmmProcessSpawner>,
        transport_factory: TransportFactory,
    ) -> Self {
        Self {
            binary,
            sockets_dir,
            firmware_path,
            spawner,
            transport_factory,
            processes: Mutex::new(HashMap::new()),
        }
    }

    #[cfg(test)]
    fn for_test(spawner: Arc<dyn VmmProcessSpawner>, transport_factory: TransportFactory) -> Self {
        Self::with_parts(
            PathBuf::from("cloud-hypervisor"),
            std::env::temp_dir(),
            PathBuf::from("/usr/share/cloud-hypervisor/CLOUDHV.fd"),
            spawner,
            transport_factory,
        )
    }

    fn socket_path(&self, name: &str) -> PathBuf {
        self.sockets_dir.join(format!("{name}.sock"))
    }
}

#[async_trait]
impl VmEngine for CloudHypervisorEngine {
    async fn create(&self, spec: &VmSpec) -> Result<String, ExecutorError> {
        let socket_path = self.socket_path(&spec.name);
        let process = self.spawner.spawn(&self.binary, &socket_path).await?;
        let transport = (self.transport_factory)(socket_path.clone());
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
        // DiskConfig) -- see this module's top doc comment.
        let body = serde_json::json!({
            "cpus": {"boot_vcpus": spec.vcpus, "max_vcpus": spec.vcpus},
            "memory": {"size": memory_bytes},
            "payload": {"firmware": firmware.to_string_lossy()},
            "disks": [{"path": spec.image_path.to_string_lossy(), "readonly": false}],
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
        self.processes.lock().await.insert(handle.clone(), process);
        Ok(handle)
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
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

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
    }

    impl Default for FakeSpawner {
        fn default() -> Self {
            Self {
                calls: StdMutex::new(Vec::new()),
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
            Ok(Box::new(FakeProcessHandle {
                killed: Arc::new(StdMutex::new(false)),
            }))
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
