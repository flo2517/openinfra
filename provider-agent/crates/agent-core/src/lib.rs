pub mod disconnect;
pub mod errors;
pub mod identity;
pub mod local_state;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AgentConfig {
    pub agent: AgentSettings,
    pub security: SecuritySettings,
    pub control_plane: ControlPlaneSettings,
    #[serde(default)]
    pub executor: ExecutorSettings,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AgentSettings {
    pub id: Option<String>,
    pub protocol_version: String,
    pub agent_version: String,
    #[serde(default = "default_listen_address")]
    pub listen_address: String,
    #[serde(default)]
    pub advertised_endpoint: String,
    // Operator-declared sustained network capacity, megabits per second
    // (see protocol/proto Bandwidth for the exact unit convention). Unlike
    // CPU/RAM/storage, real link speed generally isn't auto-detectable in
    // virtualized/cloud environments (no reliable NIC-speed API sysinfo
    // or the OS can expose for virtio/cloud interfaces), so this is
    // operator-configured, the same trust boundary as the price/
    // reputation claims a provider already self-declares. Independent
    // measurement/validation of this claim is issue #30's still-open
    // remainder, not this field.
    #[serde(default)]
    pub bandwidth_ingress_mbps: i32,
    #[serde(default)]
    pub bandwidth_egress_mbps: i32,
    // Operator-declared availability zone (ADR-026), an opaque, free-form
    // string matched by exact equality against a workload's
    // WorkloadConstraints.required_zone -- no hierarchy, no allowlist.
    // Like bandwidth, a zone isn't auto-detectable from the machine
    // itself, so this is operator-configured, the same trust boundary as
    // the price/reputation/bandwidth claims a provider already
    // self-declares, and deliberately has no env-var override (unlike
    // ExecutorSettings's four fields). Empty string means "no zone
    // declared".
    #[serde(default)]
    pub zone: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SecuritySettings {
    pub key_path: PathBuf,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ControlPlaneSettings {
    pub endpoint: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExecutorSettings {
    pub state_path: PathBuf,
    pub max_workloads: usize,
    pub max_cpu_cores: f32,
    pub max_memory_mb: i64,
    pub pids_limit: i64,
    /// ADR-025 §3: policy ceiling on a workload's declared egress_mbps,
    /// the same defense-in-depth role max_cpu_cores/max_memory_mb already
    /// play against a buggy or compromised scheduler sending an
    /// unreasonable reservation -- without this, egress_mbps was the only
    /// one of the four quotas with no local check before being handed to
    /// `tc`.
    pub max_egress_mbps: i32,
    /// ADR-033 §6/§7: the VM-workload ceiling, independent of
    /// `max_workloads` -- VMs carry meaningfully heavier per-instance
    /// overhead (a full guest kernel and its own memory footprint before
    /// any workload runs inside it) than a shared-kernel container, so
    /// reusing `max_workloads` for both would misrepresent real host
    /// capacity, per the ADR's own reasoning. **Defaults to 0**: VM
    /// workloads are disabled unless an operator explicitly configures a
    /// nonzero value, matching the ADR's "off by default even on
    /// KVM-capable hardware" rollout posture (§7) -- a 0 here must cause
    /// every VM deploy attempt to be rejected explicitly, never silently
    /// ignored (see `VmExecutor::deploy`).
    #[serde(default)]
    pub max_vm_workloads: usize,
    /// Policy ceiling on a VM workload's declared vcpu count, the same
    /// defense-in-depth role `max_cpu_cores` plays for Docker workloads.
    #[serde(default = "default_max_vm_vcpus")]
    pub max_vm_vcpus: u32,
    /// Policy ceiling on a VM workload's declared memory, MB -- the
    /// VM-side equivalent of `max_memory_mb`.
    #[serde(default = "default_max_vm_memory_mb")]
    pub max_vm_memory_mb: i64,
    /// ADR-033 §4: where fetched, digest-verified qcow2 images are cached
    /// content-addressed (keyed by their pinned SHA-256 digest) so a
    /// repeated deploy of the same digest never re-fetches -- the VM
    /// analog of `state_path`'s durable-local-storage convention.
    #[serde(default = "default_vm_image_cache_dir")]
    pub vm_image_cache_dir: PathBuf,
    /// The `cloud-hypervisor` binary this Agent spawns per VM (ADR-033
    /// §2: a subprocess per VM, driven over its local Unix-socket API --
    /// no libvirt, no shared daemon). A bare command name resolves via
    /// `PATH`, matching how `tc`/`SystemCommandRunner` are already
    /// invoked without a hardcoded absolute path.
    #[serde(default = "default_cloud_hypervisor_binary")]
    pub cloud_hypervisor_binary: PathBuf,
    /// Directory holding each running VM's Cloud Hypervisor API Unix
    /// socket -- one file per VM, named after its workload_id.
    #[serde(default = "default_vm_sockets_dir")]
    pub vm_sockets_dir: PathBuf,
    /// ADR-033 §7 / issue #168 point 4: the operator's explicit opt-in to
    /// running the VM execution backend at all, distinct from
    /// `max_vm_workloads`. The ADR is explicit that hardware capability
    /// (`agent-inventory`'s KVM probe) and operator consent are two
    /// separate gates: a KVM-capable host must not run VM workloads
    /// merely because the hardware happens to support it -- running a
    /// second execution model has real operational cost (VMM process
    /// management, qcow2 image storage, additional attack surface) an
    /// operator should consciously accept. Defaults to `false`; even a
    /// nonzero `max_vm_workloads` configured while this is `false` must
    /// not enable VM deploys (see agent-cli's wiring, which only
    /// constructs a `VmExecutor` at all when this is `true`).
    #[serde(default)]
    pub vm_enabled: bool,
    /// ADR-033 §6: resolves via `PATH`, matching `cloud_hypervisor_binary`
    /// and `SystemCommandRunner`'s own convention. See
    /// `agent_executor::vm::cloud_hypervisor::VmmSecurityPolicy`.
    #[serde(default = "default_setpriv_binary")]
    pub setpriv_binary: PathBuf,
    /// Dedicated unprivileged user/group the VMM process runs as -- never
    /// root, never the Agent's own uid (ADR-033 §6). The operator
    /// provisions this account; the Agent does not create it.
    #[serde(default = "default_vmm_account")]
    pub vmm_user: String,
    #[serde(default = "default_vmm_account")]
    pub vmm_group: String,
    /// The supplementary group granting `/dev/kvm` access (conventionally
    /// `kvm` on most distributions' udev rules).
    #[serde(default = "default_vmm_kvm_group")]
    pub vmm_kvm_group: String,
}

fn default_max_vm_vcpus() -> u32 {
    8
}

fn default_max_vm_memory_mb() -> i64 {
    16_384
}

fn default_vm_image_cache_dir() -> PathBuf {
    PathBuf::from(".openinfra-state/vm-images")
}

fn default_cloud_hypervisor_binary() -> PathBuf {
    PathBuf::from("cloud-hypervisor")
}

fn default_vm_sockets_dir() -> PathBuf {
    PathBuf::from(".openinfra-state/vm-sockets")
}

fn default_setpriv_binary() -> PathBuf {
    PathBuf::from("setpriv")
}

fn default_vmm_account() -> String {
    "openinfra-vmm".to_string()
}

fn default_vmm_kvm_group() -> String {
    "kvm".to_string()
}

impl Default for ExecutorSettings {
    fn default() -> Self {
        Self {
            state_path: PathBuf::from(".openinfra-state"),
            max_workloads: 8,
            max_cpu_cores: 8.0,
            max_memory_mb: 16_384,
            pids_limit: 128,
            max_egress_mbps: 10_000,
            // ADR-033 §7: VM support is off by default, full stop --
            // even on hardware that would otherwise pass the KVM probe.
            max_vm_workloads: 0,
            max_vm_vcpus: default_max_vm_vcpus(),
            max_vm_memory_mb: default_max_vm_memory_mb(),
            vm_image_cache_dir: default_vm_image_cache_dir(),
            cloud_hypervisor_binary: default_cloud_hypervisor_binary(),
            vm_sockets_dir: default_vm_sockets_dir(),
            // ADR-033 §7: off by default even on KVM-capable hardware --
            // see this field's own doc comment.
            vm_enabled: false,
            setpriv_binary: default_setpriv_binary(),
            vmm_user: default_vmm_account(),
            vmm_group: default_vmm_account(),
            vmm_kvm_group: default_vmm_kvm_group(),
        }
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            agent: AgentSettings {
                id: None,
                protocol_version: "1".to_string(),
                agent_version: "0.1.0".to_string(),
                listen_address: default_listen_address(),
                advertised_endpoint: String::new(),
                bandwidth_ingress_mbps: 0,
                bandwidth_egress_mbps: 0,
                zone: String::new(),
            },
            security: SecuritySettings {
                key_path: PathBuf::from("identity.key"),
            },
            control_plane: ControlPlaneSettings {
                endpoint: "https://127.0.0.1:50051".to_string(),
            },
            executor: ExecutorSettings::default(),
        }
    }
}

fn default_listen_address() -> String {
    "127.0.0.1:50052".to_string()
}
