# ADR-033: VM execution backend alongside Docker

## Status

Accepted (by the repository owner, explicitly, relayed in-session — after reviewing a full summary
of this ADR's decisions and their reasoning, then confirming to proceed with implementation).

Originally written by Claude Code, autonomously, in direct response to the repository owner's
request ("prepare the ground for VMs") made immediately after accepting ADR-031 (OpenStack
compatibility architecture), which deliberately left this exact question open and named it as its
own required follow-up. This ADR explicitly lifted ADR-006's Docker-only prohibition — additively,
per this document's own design (Docker stays the default execution path; VMs are a second, opt-in
path). Nothing here is implemented yet by this ADR itself; issue #24's VM half is unblocked by this
acceptance and now carries the implementation work.

## Context

**What exists today, verified against source before writing anything below:**

- **ADR-006 fixed Docker specifically for stated reasons**: "a widely available workload runtime
  with a mature Rust API and observable lifecycle." Those reasons do not argue *against* a second
  runtime — they argue for Docker as the right MVP default, which this ADR does not dispute or
  reopen.
- **The Agent's only execution path today is `agent-executor`'s `ContainerEngine` trait**
  (`provider-agent/crates/agent-executor/src/lib.rs`), implemented exactly once, by `BollardEngine`.
  `DockerExecutor` (the sole implementer of agent-api's `Executor` trait — `deploy`/`stop`/
  `get_status`/`usage_summary`) owns: capacity reservation and the `max_workloads` ceiling
  (`LocalState::reserve_workload`), durable per-workload state (`WorkloadRecord`/`WorkloadPhase` in
  `agent-core::local_state`, a `sled`-backed embedded store), crash recovery (`recover()`,
  reconciling persisted state against the real engine's live observation on every Agent start),
  ADR-028 lease-expiry enforcement (`enforce_lease_expiry`, driven purely off `WorkloadPhase` and
  `lease_end`, with no Docker-specific logic in its body), and ADR-025 bandwidth accounting/rate
  limiting (`bandwidth()`/`rate_limit()` on `ContainerEngine`, backed by reading a container's veth
  pair via its host-visible PID — genuinely Docker-network-model-specific).
- **`agent-api`'s `Executor` trait is already engine-agnostic.** It is the boundary the gRPC server
  actually depends on, and nothing in its signature (`deploy(DeployRequest) -> Result<String>`,
  `stop`, `get_status`, `usage_summary`) mentions Docker, bollard, or containers. This is the correct
  existing seam for a second implementation to slot beside `DockerExecutor` — it does not need to be
  reshaped.
- **`agent-inventory` reports zero virtualization-capability data.** `InventoryManager::get_inventory`
  (`provider-agent/crates/agent-inventory/src/lib.rs`) reports `cpu_cores`, `total_memory_mb`,
  `available_memory_mb`, `total_storage_gb`, `available_storage_gb` — nothing about `/dev/kvm`,
  nested-virtualization support, or any hardware-virtualization feature flag. Issue #24's own
  acceptance criteria name "hardware virtualization capability discovery" as a requirement; today
  there is no code path anywhere that could answer "can this host run a VM" at all. This is a real,
  currently-unfilled prerequisite, not an oversight this ADR can wave past.
- **`DeployRequest` (agent.proto) has no runtime-selector field.** It carries `workload_id`,
  `lease_id`, `image`, `limits` (`ResourceLimits`: `cpu_cores`, `memory_mb`, `egress_mbps`), and
  `lease_end` — nothing that could distinguish "run this as a container" from "run this as a VM." A
  VM backend needs a wire-level way to say which one a given workload wants; that field does not
  exist today.
- **Container images are already digest-pinned and integrity-verified before use.**
  `workloadapi.digestImage` enforces `name@sha256:<64 hex>` at submission time; `agent-executor`'s
  `pull_image` (issue #154/PR #155) pulls the exact pinned digest before `create_container`, never
  trusting a locally cached image blindly. This is the precedent a VM image path must match, not an
  optional nicety.
- **ADR-010's WireGuard overlay already abstracts its privileged mechanism behind a `Backend`
  interface** specifically so unit tests don't need `CAP_NET_ADMIN` — the Control-Plane-side
  lifecycle (`internal/wireguard`: validate a non-expired Lease, allocate a short-lived UDP port,
  Attach only after finalized on-chain lease confirmation *and* Agent RUNNING confirmation, Revoke on
  stop) is a genuinely reusable pattern independent of what the peer attaches to underneath.
- **`AGENTS.md`'s security baseline for Docker workloads is explicit and non-negotiable**:
  "CPU/memory/PID quotas, `no-new-privileges`, a maximum workload count, and persistent
  workload-to-container mapping" — `BollardEngine::create` enforces exactly this today (`memory`,
  `memory_swap`, `nano_cpus`, `pids_limit`, `security_opt: ["no-new-privileges:true"]`,
  `cap_drop: ["ALL"]`, `init: true`). A VM backend needs an equivalent baseline stated with the same
  weight, not a lighter one, because AGENTS.md's rule is about the property (bounded, least-privilege
  execution), not the specific mechanism that currently delivers it.
- **ADR-031 §4 already scoped the Nova/Placement *API surface* against the existing Docker-only
  execution model, without touching ADR-006.** That work (flavors, server lifecycle, Placement
  read-shim) stands regardless of this ADR's outcome. This ADR is strictly about whether a *second*
  execution model is added underneath that API surface — additive to ADR-031, not a redo of it.
- **`gh issue view 24`** ("Add OpenStack Nova and Placement compatibility with VM workloads") names
  the acceptance criteria this ADR must give a concrete answer to: "trait-backed VM backend selected
  by ADR (for example libvirt/KVM); flavors, server lifecycle, scheduling allocations, metadata,
  console policy, and quotas; authoritative state reconciliation after crashes and partitions;
  hardware virtualization capability discovery; image provenance and tenant isolation; API
  microversion and lifecycle E2E tests." **`gh issue view 22`** is already answered by ADR-031 and
  is not reopened here. **`gh issue view 6`** (multi-node Substrate testnet, closed) is precedent
  only for how this repository scopes a new-execution-surface proposal ("remove development
  assumptions through an accepted governance ADR before treating [it] as production-like") — the
  same "don't silently expand trust" posture this ADR follows for VM workloads.

## Decision

### 1. Additive, not a replacement — the central framing

Docker stays the default and primary execution path for every workload that doesn't specifically
need a VM. Nothing about ADR-006's original reasoning ("widely available runtime, mature Rust API,
observable lifecycle") is undermined by adding a second, opt-in path — Docker workloads keep using
exactly the code that exists today, unchanged. A VM backend exists for the workloads that genuinely
need what only a VM provides: kernel-level isolation stronger than containers offer, a non-Linux
guest OS, or Nova-API-compatible "real virtual machine" semantics that issue #24 explicitly asks
for and that a container fundamentally cannot satisfy (a real guest kernel, a real boot process, true
console access). **Lifting ADR-006's prohibition means "VM orchestration is no longer categorically
deferred," not "Docker is deprecated."** Any future proposal to make VMs the default, or to remove
the Docker path, is a separate, much larger decision this ADR does not make or imply.

### 2. Hypervisor/mechanism choice: Cloud Hypervisor, invoked directly — not libvirt, not Firecracker

This is the second most consequential decision, made explicitly rather than by default.

**Rejected: libvirt as an abstraction layer.** libvirt is a mature, widely-used abstraction over
QEMU/KVM, but it is a large, C-language, typically-root-privileged, persistently-running daemon with
its own XML configuration surface and its own attack surface — a dependency shape inconsistent with
`agent-executor`'s existing model of a single Rust process that talks directly to narrowly-scoped
mechanisms (bollard's typed Docker API client, a purpose-built `CommandRunner` abstraction for `tc`).
Standing up a second privileged daemon the Agent depends on, with its own lifecycle and failure
modes independent of the Agent process, is a larger and less auditable addition than this project's
existing dependency discipline supports. libvirt remains available as a future alternative if a
follow-up implementation finds Cloud Hypervisor's device model too narrow for a specific need, but
it is not the recommended starting point.

**Rejected: Firecracker.** Firecracker (AWS's Rust-based microVM monitor) has the strongest
security pedigree of the options considered — a minimal device model, a `jailer` process for
seccomp/cgroup/chroot confinement, and production hardening at hyperscale (Lambda, Fargate). It is
rejected as the *primary* choice for this ADR's scope specifically because its minimalism is also a
functional limitation that conflicts with what issue #24 actually asks for: Firecracker boots only a
raw Linux kernel + initrd it is handed directly (no BIOS/UEFI, no arbitrary guest bootloader), has no
GPU/device-passthrough path, and has no practical route to non-Linux guests. Issue #24's acceptance
criteria don't require non-Linux guests today, but naming a mechanism that structurally forecloses
them is a heavier commitment than this ADR should make on the owner's behalf.

**Decision: Cloud Hypervisor**, driven directly by `agent-executor` over its local Unix-socket REST
API (spawn the `cloud-hypervisor` binary per VM, configure/boot/stop it over that socket) — no
libvirt, no shelling out to `virsh`. Justification against this project's actual constraints:

- **It's Rust, matching this project's own stack.** Cloud Hypervisor is written in Rust and built
  from the same `rust-vmm` crate ecosystem Firecracker uses (`kvm-ioctls`, `vm-memory`,
  `vhost`/`virtio-queue`, etc.) — the same minimal-TCB, memory-safe lineage as Firecracker's
  security model, without Firecracker's device-model restrictions. A future tighter integration
  (linking `rust-vmm` crates directly into `agent-executor` instead of spawning a subprocess) is a
  legitimate follow-on but not required for this ADR's MVP slice — the socket-API approach ships
  first and is already the mechanism Cloud Hypervisor's own documented integration path recommends.
- **It supports what Firecracker doesn't, without libvirt's dependency weight.** Full ACPI/UEFI
  boot (real guest bootloaders, not just direct-kernel-boot), broader virtio device support
  (virtio-net/block/fs/vsock, and — later, if ever needed — vfio-based GPU passthrough behind an
  explicit opt-in, §7), and, notably, documented Windows guest support via UEFI — directly relevant
  if this project ever needs non-Linux guests, without committing to build that now.
- **It is KVM-only, which is the right default given this project's isolation bar, but this is the
  one place this ADR names a real, load-bearing constraint plainly**: Cloud Hypervisor (like
  Firecracker and libvirt/QEMU-KVM) requires `/dev/kvm` — hardware virtualization exposed to the
  host kernel. **Nested virtualization (a provider host that is itself already a VM, common for
  "commodity provider hardware" run on cloud infrastructure) frequently does not expose a working
  `/dev/kvm`**, or exposes a degraded one. §8 below makes this a hard, fail-closed capability gate,
  not a soft warning: a provider without a real, verified KVM cannot advertise VM capability and
  will never be offered a VM workload. This is a real, permanent exclusion for some fraction of
  otherwise-eligible providers — named as an open question for the reviewer in the Open Questions
  section, not glossed over.

### 3. Agent-side architecture: a parallel `VmEngine` trait and a `VmExecutor`, sharing `agent-api`'s
existing `Executor` boundary — not a rename of `ContainerEngine`

`agent-api`'s `Executor` trait (the boundary the gRPC server actually calls through) is already
engine-agnostic and needs no change. The generalization happens one layer down, inside
`agent-executor`, concretely:

- **`ContainerEngine` and `BollardEngine` are left exactly as they are.** Renaming or generalizing
  the trait that a heavily-tested, working Docker path already implements (`bandwidth`/`rate_limit`
  are Docker-veth-specific by nature — forcing them into a shared, engine-neutral signature would
  either leak Docker-specific assumptions into the VM path or force a lossy least-common-denominator
  interface onto Docker) buys nothing and adds regression risk to the default path for no benefit.
- **A new, parallel `VmEngine` trait**, shaped analogously (`create`/`start`/`stop`/`inspect`/
  `remove`, plus its own bandwidth/rate-limit equivalent backed by the VM's tap device rather than a
  container's veth pair — §5), implemented by a `CloudHypervisorEngine`.
- **A new `VmExecutor`, implementing `agent-api::Executor` the same way `DockerExecutor` does today**,
  rather than one executor internally dispatching on a runtime-kind flag. This keeps the two
  execution models' state machines fully independent (a bug in VM lifecycle handling cannot corrupt
  Docker workload state and vice versa) — `agent-cli` wires up whichever executor(s) are configured
  and enabled (§8) and agent-api's gRPC server routes each `DeployRequest` to the right one, based on
  a new runtime-selector field this ADR names as required but does not fully spec (§9 — the exact
  `.proto` shape is implementation-time work, matching how ADR-031 also didn't pre-design its own
  eventual Cinder proto change).
- **What's reused, concretely, tracing through `DockerExecutor`'s actual responsibilities:**
  - **Capacity reservation and local state persistence** (`agent-core::local_state::LocalState`,
    `WorkloadRecord`, `WorkloadPhase`) — the storage engine and the phase state machine
    (`Provisioning → Starting → Running → Stopping → Stopped/Failed/Lost`) are execution-model-
    agnostic today and stay that way; `WorkloadRecord` gains a `container_id`-equivalent handle for
    VMs (a VM UUID / Cloud Hypervisor API-socket path) rather than inventing a parallel storage
    mechanism.
  - **Crash recovery (`recover()`)** — the pattern (inspect the real engine's live state on Agent
    startup, reconcile persisted `WorkloadPhase` against it) is reused as-is by `VmExecutor`,
    against `VmEngine::inspect` instead of `ContainerEngine::inspect`.
  - **ADR-028 lease-expiry enforcement (`enforce_lease_expiry`)** — already operates purely against
    `WorkloadPhase`/`lease_end` with no Docker-specific logic in its body; reused verbatim by
    `VmExecutor` with no changes needed to its algorithm.
  - **`operation_lock`, request validation shape, `spec_hash` conflict detection** — the pattern
    (not the Docker-specific field list) is reused; a `VmSpec` gets its own analogous validation
    (`vcpus`/`memory_mb` against a VM-specific policy ceiling, §8's `max_vm_workloads`).
  - **NOT reused, Docker-specific, needs a VM-specific equivalent**: `bandwidth()`/`rate_limit()`'s
    *mechanism* (veth-pair PID lookup, `tc` against a container's host-side interface) — the
    *interface shape* is reused (§5's networking section), the implementation is not.

### 4. Image/boot model: qcow2, digest-pinned, fetched over HTTPS, verified before first boot

Docker's `name@sha256:<64-hex-digest>` convention is the direct precedent. VM boot images use the
same shape of guarantee with a necessarily different transport, since there is no OCI registry
concept for a raw/qcow2 disk image: a plain HTTPS(S) URL to the image blob, paired with a pinned
SHA-256 digest the Agent verifies **before the image is ever booted**, mirroring issue #154/PR #155's
"never run before the artifact matches what was promised" discipline exactly. Concretely:
`vm_image_url` + `vm_image_sha256` (both required, matching `lease_end`'s "required, not optional"
precedent from ADR-028) rather than a single combined reference string, since there's no single
canonical URI scheme for this the way `name@sha256:digest` is canonical for OCI. Format: **qcow2 as
the default** (copy-on-write backing files make a shared base image cheap per-VM; broad tooling
support), raw supported as a secondary option. Fetched images are cached content-addressed (keyed by
digest) under the Agent's own state directory, the same durable-local-storage convention
`agent-core::local_state` already uses, so a repeated deploy of the same digest never re-fetches.
**This ADR does not build a Glance-equivalent artifact store** — no OpenInfra-hosted image hosting,
matching the same posture ADR-031 §6 took for Glance's raw-bytes upload endpoint (explicit non-goal);
the registry/host serving the qcow2 blob is always external, exactly like Docker Hub is external
today.

### 5. Networking: the same WireGuard lease-gated model, a new tap-device `Backend` underneath

A VM workload gets the identical networking *model* a Docker workload gets today: a WireGuard peer,
authorized by a finalized Lease, attached only after the workload is confirmed running, and revoked
on stop or lease revocation — ADR-010's Control-Plane-side lifecycle logic
(`internal/wireguard`: validate lease, allocate short-lived UDP port, Attach after finalized
confirmation, Revoke on stop) is reused entirely unchanged, because ADR-010 already abstracted the
privileged mechanism behind a `Backend` interface specifically so the lifecycle logic doesn't need
to know what it's attaching to. What's new is a **VM-specific implementation of that same `Backend`
interface**: instead of attaching a peer inside a container's network namespace via a veth pair, the
provider host creates a tap device, bridges/routes it to the VM's virtio-net interface (configured at
VM-create time via Cloud Hypervisor's API), and the WireGuard peer's traffic is routed through that
tap device. The authorization/timing guarantees ADR-010 was written to provide ("a peer... must
disappear when the workload stops or the lease is revoked") carry over exactly, because they live in
the Control-Plane-side code this ADR does not touch — only the host-mechanism half changes.

### 6. Security posture: a VM-specific mandatory baseline matching Docker's, not a lighter one

`AGENTS.md`'s Docker baseline is CPU/memory/PID quotas, `no-new-privileges`, a maximum workload
count, and persistent workload-to-container mapping. The VM-equivalent baseline, stated with the
same non-negotiable framing:

- **CPU/memory quotas**: enforced at VM-create time via Cloud Hypervisor's own vcpu-count and
  memory-size parameters (the direct equivalent of Docker's `nano_cpus`/`memory`), *and* the VMM
  process itself is additionally placed in a host cgroup matching the declared limits — belt and
  suspenders, mirroring how Docker's `HostConfig` limits and the underlying cgroup are really the
  same mechanism.
- **PID-limit equivalent**: a container's `pids_limit` has no direct hypervisor analog (a VM's guest
  process table is invisible to and unmanaged by the host). The host-side equivalent enforced here is
  a **mandatory seccomp filter on the VMM process** (Cloud Hypervisor supports a `--seccomp` policy)
  plus running each VMM inside a jailed, chroot/namespace-confined environment analogous to
  Firecracker's `jailer` — so a compromised guest cannot pivot into unbounded host resource
  consumption regardless of what happens inside the guest kernel.
- **`no-new-privileges` equivalent**: the VMM process runs as a dedicated, unprivileged, non-root
  user — never root, never the Agent's own uid — with Linux capabilities dropped to exactly
  `CAP_NET_ADMIN` (tap device creation) and whatever `/dev/kvm` access requires, nothing else.
  Mirrors Docker's `cap_drop: ["ALL"]` + narrow, explicit opt-in posture exactly.
- **No host device passthrough by default**: no VFIO/GPU passthrough, no arbitrary host-directory
  virtiofs share, no USB/PCI passthrough of any kind — a hard, mandatory default-deny. Any future
  device passthrough is explicit opt-in, out of scope for this ADR (§9).
- **`max_vm_workloads`**: a hard ceiling, independent of and configured separately from
  `max_workloads` — VMs carry meaningfully heavier per-instance overhead (a full guest kernel, its
  own memory footprint even before any workload runs inside it) than a shared-kernel container, so
  reusing the same numeric ceiling would misrepresent real host capacity. Defaults to **0 (VM
  workloads disabled)** unless an operator explicitly configures a nonzero value (§8).
- **Persistent workload-to-VM mapping**: the same `WorkloadRecord`-in-`LocalState` durability model
  Docker already uses, with the VM's Cloud Hypervisor API-socket path (or VM UUID) recorded in place
  of `container_id`, and the same `recover()` reconciliation-after-restart discipline reused as-is
  (§3).

### 7. Rollout/gating: fail-closed capability advertisement, explicit opt-in, narrow allowlist

Because this is a genuinely new, higher-risk surface — a second execution model, requiring a host
capability (`/dev/kvm`) not every provider has — it ships in a way that is safe by construction, not
merely by policy:

- **`agent-inventory` gains a `virtualization_capable: bool` field**, computed by checking not just
  `/dev/kvm`'s existence but an actual `KVM_GET_API_VERSION` ioctl probe against it (nested-virt
  environments sometimes expose a `/dev/kvm` node with degraded or non-functional KVM — file
  existence alone is not sufficient evidence). This is a new field on the existing inventory/heartbeat
  report path (additive, proto3-default-`false` for any Agent binary that hasn't been upgraded to
  compute it — old Agents simply never advertise the capability, which is exactly the fail-closed
  behavior wanted, not a wire break).
- **The scheduler must never offer a VM workload to a provider that hasn't explicitly reported
  `virtualization_capable = true`.** Absent/false is "cannot run VM workloads," never "unknown, try
  anyway" — the same fail-closed convention this codebase already applies to an unconfigured
  bandwidth declaration (ADR-025) treated as zero capacity for that dimension.
- **A separate, explicit operator opt-in**, distinct from the hardware capability check — matching
  `AgentSettings`'s existing self-declared-trust-boundary precedent for `bandwidth_*`/`zone`. Running
  a second execution model has real operational cost (VMM process management, qcow2 image storage,
  additional attack surface) an operator should consciously accept even on KVM-capable hardware, not
  something that turns on automatically the moment hardware happens to support it.
- **`max_vm_workloads` defaults to 0** (§6) — VM support is off by default even when both the
  hardware check and the operator flag are otherwise satisfiable, until explicitly sized.
- **A narrow, curated guest-image allowlist for the first slice** — rather than accepting any
  tenant-supplied qcow2 URL, the Control Plane enforces a small set of known-good, digest-pinned base
  images (a couple of stock Linux distributions), analogous to how flavors are already a static,
  operator-configured list under ADR-031 §4. Arbitrary tenant-supplied boot images are deferred until
  this ADR's image-provenance model has more operational experience behind it.
- **Staged rollout**: start with the narrow allowlist above and the WireGuard-overlay-only networking
  model (§5, no floating IPs, no device passthrough); expand guest-image choice and device support
  only incrementally, each as its own bounded follow-up rather than opened all at once.

### 8. What this ADR does NOT decide — explicitly deferred

- **Live migration** — no hypervisor-level migration support is designed or implied. Same non-goal
  ADR-031 §4 already named for the container-backed Nova slice, now also explicit here for the real
  VM path.
- **Console access (VNC/serial)** — genuinely new interactive-access surface; ADR-031 §4 already
  flagged this as impossible without a VM backend. This ADR makes the backend possible but does not
  design console access itself — it needs its own narrower follow-up given the security surface an
  interactive host-mediated console represents (analogous to how ADR-031 §5 held security-group
  enforcement for its own follow-up rather than folding it into a general implementation PR).
- **Snapshots-as-images, resize-in-place (flavor change without recreate), NUMA/CPU pinning, `hw:*`
  extra-specs** — all named non-goals for this slice, matching ADR-031 §4's own list for the
  container-backed Nova mapping.
- **GPU/device passthrough of any kind** — mandatory default-deny (§6); any future passthrough
  support is its own explicit opt-in, not designed here.
- **Non-Linux guest qualification** (e.g. Windows) — Cloud Hypervisor's UEFI support makes this
  *possible* in principle, but qualifying and supporting a non-Linux guest is real, separate work
  this ADR does not undertake.
- **The exact `.proto` changes** (a `DeployRequest` runtime-selector field, a `VmSpec` message, the
  new inventory `virtualization_capable` field's exact wire shape) — named here as necessary (§3, §7)
  but left to the implementing PR, matching how ADR-031 also declined to pre-design its own eventual
  Cinder proto change.
- **Cinder-style persistent, attachable VM disk volumes beyond the boot disk itself** — the boot
  image model (§4) is self-contained precisely so VM support does not have to wait on ADR-031 §6's
  still-undesigned Cinder follow-up.
- **A real Glance-equivalent artifact store for qcow2 images** — the reference-only model (§4) is
  reused, not a new hosting service.
- **Kubernetes-on-VM-nodes** — ADR-031 §7 already named this as gated on both its own dedicated ADR
  and (if the VM-node path is chosen) this ADR's acceptance. Accepting this ADR removes one of those
  two gates; it does not itself authorize Kubernetes in any form.

## Consequences

- **Lifts ADR-006's Docker-only prohibition, additively.** Docker remains the default and only
  execution path until an operator explicitly opts in to VM support (§7); nothing about existing
  Docker workload behavior changes.
- **New Rust dependency surface**: `agent-executor` gains a `cloud-hypervisor` process-management
  path (spawn, socket-API client, seccomp/jailer wrapping) alongside its existing bollard dependency.
- **New protocol surface** (named, not specified — §8): a runtime-selector on `DeployRequest`, a
  `VmSpec`-shaped message, and a new `virtualization_capable` inventory field — all additive/
  backward-compatible by construction (existing Agents/workloads unaffected).
- **New local state fields**: `WorkloadRecord` needs a VM-handle field parallel to `container_id`;
  `ExecutorSettings` needs VM-specific policy fields (`max_vm_workloads`, VM vcpu/memory ceilings,
  a `vm_enabled` operator flag) parallel to its existing Docker fields.
- **A permanent host-capability exclusion for some providers**: nested-virtualization-incapable
  hosts can never advertise VM capability under this design (§2, §7) — a real, expected-to-be-
  nonzero fraction of otherwise-eligible providers, named as an open question below rather than
  quietly accepted.
- **Three real follow-up design efforts this ADR does not do**: console access, the exact protocol
  changes, and (eventually) any device-passthrough opt-in — each is its own bounded, separately-
  reviewable piece of work, matching this repository's established pattern (ADR-031 §8) of not
  bundling multiple large trust-boundary decisions into one ADR.

## Out of scope

Any implementation — docs only, as directed. Everything listed in §8 above. Full parity with any
particular OpenStack Nova capability beyond what §8 names as in scope for the first slice — this ADR
does not attempt to close every gap ADR-031 §4's Nova mapping table left open for a real VM backend
in one pass.

## Open questions for the accepting reviewer

- **Is Cloud Hypervisor (§2) actually the right call**, versus Firecracker's narrower but more
  battle-tested security pedigree, or libvirt/QEMU-KVM's broader ecosystem and tooling maturity at
  the cost of a heavier, privileged-daemon dependency? This ADR argues Cloud Hypervisor as the
  practical middle ground given this project's Rust-first, single-process-Agent design and issue
  #24's implicit want for real guest flexibility, but a reviewer who weighs security-hardening
  pedigree above device/guest breadth may reasonably prefer Firecracker instead.
- **How large a fraction of "commodity provider hardware" does the fail-closed KVM requirement (§2,
  §7) actually exclude?** This ADR takes the position that excluding nested-virt-incapable hosts
  entirely is the only safe default, but does not attempt to estimate how much of the current or
  expected provider pool that removes from VM-eligibility — worth the owner's explicit weigh-in
  given it directly affects how useful VM support ends up being in practice.
- **Should VM workloads get their own on-chain reputation/availability accounting**, or is that
  assumed shared with the existing Docker-workload pallets without further change? Not addressed at
  all by this ADR — flagged as a real, currently-open gap rather than silently assumed either way.
- **Sequencing relative to ADR-031's own still-deferred pieces** (Cinder block storage, Neutron
  networks/security-groups) — ADR-031 §8 already raised, and left open, whether those should be
  coupled to the VM-backend decision, since persistent volumes and real tenant networks arguably
  matter more for VM workloads than for the container workloads ADR-031's direct-implementation
  slices cover. This ADR deliberately keeps its own boot-image model self-contained (§4) so VM
  support does not have to wait on Cinder, but does not resolve whether it *should* be sequenced
  after it for other reasons (e.g. attachable data volumes being a much more common real VM use case
  than for containers).

## Verification

Checked against source before writing: `AGENTS.md` (full file — frozen-architecture rule, Docker
baseline, prohibited-changes list, ADR-012 §6 gate table, confirmed no gate names VMs); `docs/adr/
006-docker-runtime.md` (full file — Decision and Consequences read directly, addressed above rather
than ignored); `docs/adr/010-wireguard-workload-overlay.md` (full file — `Backend` interface
abstraction, Attach/Revoke lifecycle, key-isolation rules); `docs/adr/012-decentralization-roadmap-
and-trust-boundaries.md` §6 (gate table, confirmed VM backend is not itself a named Stage 1-4 gate);
ADR-031 (`docs/adr/031-openstack-compatibility-architecture.md`, read from
`origin/docs/adr-openstack-compatibility-proposal` — full file, especially §4's Nova/compute mapping
and its explicit VM-backend deferral, §7's Kubernetes deferral, §8's sequencing table, and its own
Verification section's citations); `docs/adr/030-protocol-usage-fee.md` (format precedent, and the
"defer a second large trust boundary to its own ADR" reasoning this ADR's own scoping mirrors);
`provider-agent/crates/agent-executor/src/lib.rs` (full file — `ContainerEngine` trait,
`BollardEngine`, `DockerExecutor`'s `deploy`/`stop`/`get_status`/`recover`/
`enforce_lease_expiry`/`usage_summary`, confirmed which responsibilities are Docker-specific vs.
execution-model-agnostic); `provider-agent/crates/agent-core/src/local_state.rs` (`WorkloadRecord`,
`WorkloadPhase`, `Reservation`, `reserve_workload` — confirmed the persistence/capacity model's
actual shape); `provider-agent/crates/agent-core/src/lib.rs` (`ExecutorSettings`, `AgentSettings` —
confirmed the existing self-declared-trust-boundary precedent for `bandwidth_*`/`zone`);
`provider-agent/crates/agent-inventory/src/lib.rs` (full file — confirmed zero virtualization-
capability reporting exists anywhere today); `protocol/proto/openinfra/agent/v1/agent.proto`
(`DeployRequest`/`ResourceLimits` — confirmed no runtime-selector field exists); `docs/adr/`
directory listing on `main` (`001`-`030` plus two `legacy-*`, confirmed `031`/`032` are claimed by
real in-flight branches — `docs/adr-openstack-compatibility-proposal` for 031,
`docs/adr-tip-aware-signed-extension-proposal` for 032 — and every other locally-listed
`docs/adr-*` branch either has no diff against `main` under `docs/adr/` or only touches files already
merged through 030, confirming `033` is the true next-free number); `gh issue view 24`, `gh issue
view 22`, `gh issue view 6` (full text — acceptance criteria addressed by section above).

Refs #24. Related: ADR-006 (Docker-only runtime — the prohibition this ADR proposes lifting, its
stated reasoning addressed directly rather than ignored), ADR-010 (WireGuard overlay — the `Backend`
interface and lease-gated lifecycle §5 reuses), ADR-012 (decentralization roadmap — confirmed this
sits outside its Stage 1-4 gate table), ADR-025 (bandwidth QoS — the fail-closed "absent declaration
means zero capacity" precedent §7's capability gating follows), ADR-028 (disconnected-mode lease
expiry — the enforcement logic §3 reuses verbatim), ADR-031 (OpenStack compatibility architecture —
the ADR this document is the named follow-up to; complements it directly, since ADR-031 §4 built a
Nova-shaped API over the Docker-only model specifically so it would not have to wait on this
decision, and this ADR in turn does not revisit any of ADR-031's own API-surface choices).
