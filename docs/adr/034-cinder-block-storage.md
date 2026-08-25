# ADR-034: Cinder-compatible block storage

## Status

Proposed. Written by Claude Code, autonomously, in response to issue #171 (split off from #26 per
ADR-031 §6, which explicitly deferred Cinder to this follow-up ADR). **This needs the repository
owner's live review before acceptance** — unlike a narrower technical decision, this ADR adds a new
persistent, tenant-owned data class to a codebase that has none today, and issue #26 is tagged
`type:security` specifically because of this half of it (ADR-031 §6). Held Proposed on the same
footing ADR-016/025/026/027/028/029/030/031 were each held before an explicit owner sign-off,
rather than self-accepted.

## Context

**What exists today, verified against source before writing anything below:**

- **`agent-executor` has zero volume/mount support.** `grep -n "Volume\|Mount"` across
  `provider-agent/crates/agent-executor/src/lib.rs` (1935 lines) returns exactly one incidental hit
  — a comment about the containerized Agent never having a real Docker socket *mounted*, unrelated to
  workload volumes — and zero matches anywhere else in the crate, including `vm/`. `ContainerSpec`
  (the struct `BollardEngine::create` turns into a real container) carries `name`, `image`, `labels`,
  `memory_bytes`, `nano_cpus`, `pids_limit`, `egress_mbps` — no `Vec<Mount>`, no volume field of any
  kind. `DeployRequest` (`agent.proto`) carries `workload_id`, `lease_id`, `image`, `limits`,
  `lease_end` — nothing resembling a volume reference. Confirmed directly, not assumed, per this
  task's own instruction: this is a genuine, currently-unfilled gap, not an oversight to wave past.
- **ADR-031 §6 already settled Glance (images) as thin and Cinder as the hard half**, and named the
  concrete follow-up work needed at minimum: (a) `agent-executor` gaining Docker named-volume
  create/attach/detach support (bounded, additive, inside the existing Docker-only runtime — does not
  touch ADR-006); (b) a durable volume-lifecycle model in Postgres (`cinder_volumes`:
  create/attach/detach/snapshot/delete, `project_id`-scoped, explicit attachment state so
  double-attachment is structurally prevented); (c) an encryption-at-rest and secure-deletion policy,
  since a deleted tenant volume containing tenant data is exactly the class of "tenant-private, must
  be erasable" data ADR-012 §4 already names as cross-cutting. This ADR is that follow-up.
- **ADR-033's VM execution backend already exists and gives real, working precedent for the adjacent
  question this ADR must not conflate itself with.** `provider-agent/crates/agent-executor/src/vm/`
  (merged, PR #169, not aspirational) implements `VmSpec`/`VmDeployRequest`/`CloudHypervisorEngine`
  end to end: a VM's boot disk is `vm_image_url` + `vm_image_sha256` (both required, HTTPS-only),
  fetched once and cached content-addressed at `vm_image_cache_dir/<digest>.qcow2`
  (`vm/image.rs::fetch_and_verify`), then handed to Cloud Hypervisor as a read-effectively-immutable
  `VmSpec.image_path`. There is **no attach/detach concept anywhere in this code** — a VM gets exactly
  one boot disk, derived deterministically from its own digest, indistinguishable in kind from a
  Docker image reference. `agent_core::ExecutorSettings` carries `vm_image_cache_dir`,
  `max_vm_vcpus`, `max_vm_memory_mb`, `max_vm_workloads` (default `0`) — no volume-related field of
  any kind. This is direct, load-bearing evidence for §1's decision below, not a hypothetical.
- **`WorkloadRecord` (`agent-core::local_state`) already distinguishes `WorkloadRuntime::Container`
  vs. `::Vm`** via `container_id: Option<String>` / `vm_handle: Option<String>`, persisted in an
  embedded `sled` store — bounded, reconstructible-from-Postgres-on-recovery, per-Agent local state,
  never itself the authority. This is the exact seam a volume-attachment record needs to extend, not
  a new persistence mechanism to invent (§3).
- **`AGENTS.md`'s Docker security baseline is explicit and non-negotiable**: "CPU/memory/PID quotas,
  `no-new-privileges`, a maximum workload count, and persistent workload-to-container mapping" —
  enforced today via `HostConfig{ security_opt: ["no-new-privileges:true"], cap_drop: ["ALL"], ... }`
  in `BollardEngine::create`. A volume mechanism that lets a workload escape this container's declared
  boundary (e.g. a bind-mount reaching outside a scoped host directory) would defeat it; §5 addresses
  this directly.
- **ADR-012 §4 already classifies this exact data class.** Its table lists "Secrets" as
  tenant-controlled, secret-classified, requiring encryption "with tenant-held keys rather than merely
  access-controlled: erasure of the key is erasure of practical access to its encrypted data" — the
  precedent this ADR's §6 follows for volume contents, which are equally tenant-private and equally
  capable of containing secrets a workload writes to disk.
- **Issue #23 (Keystone projects/roles/quotas, ADR-031 §3) has not landed** — `grep -rn "project_id"
  control-plane/migrations/` finds no `projects`/`project_memberships` table yet; `workloads.owner_id`
  (a flat `users.user_id` FK, migration `000009`) is still the only ownership dimension today. ADR-031
  §3's `projects`/`project_memberships`/`project_quotas` design is referenced, not re-derived, and
  this ADR does not block on its exact final shape landing first — see §4.
- **`control-plane/migrations/` is at `000016`** (`metering_evidence_and_invoices.sql`) — the next
  migration for `cinder_volumes` would be `000017`, not designed here (§9), matching how ADR-031 §6
  and ADR-033 §9 both declined to pre-design their own eventual schema/proto changes.

## Decision

### 1. Backing mechanism: Docker named volumes for the MVP — explicit, not a default left undecided

**Rejected: a network-attached backend** (an NFS/iSCSI/Ceph-RBD-style volume reachable from more than
one provider host). Rejected for this MVP slice specifically because it is a materially larger
investment this repository's actual model does not need yet: every workload here already runs on
exactly one provider for its entire lease (`internal/scheduler`/`internal/orchestrator` bind a
workload to one provider at deploy time; there is no live migration, no multi-provider replica set,
no concept of a workload moving providers mid-lease). A volume that only ever needs to be reachable
from the one host its workload already runs on gains nothing from network-attached storage's actual
value proposition (cross-host portability) while adding a new infrastructure dependency (a storage
backend/cluster, its own availability and consistency story, its own credential surface) that
`AGENTS.md`'s prohibited-changes list would likely treat as "another database"-adjacent scope creep —
exactly the kind of new central dependency ADR-012 §5's "introduces no new central authority" proviso
for milestone v2.0 work should make this ADR wary of. Network-attached storage remains a reasonable
future upgrade if cross-provider volume portability ever becomes a real product requirement (§8) —
it is not rejected on merit, only as more scope than this MVP slice needs.

**Decision: Docker named volumes, host-local, one provider for the volume's entire life.** A Cinder
volume, under the hood, is a Docker named volume created via `bollard`'s volume API on the same
provider host as any workload it's ever attached to. This is the simplest mechanism that actually
satisfies issue #26's acceptance criteria (create/attach/detach/snapshot*/delete lifecycle,
tenant isolation, secure deletion) without inventing new infrastructure: Docker volumes are a normal,
already-well-understood Docker feature *within* ADR-006's existing runtime — using them is additive
work inside the existing Docker-only runtime, exactly as ADR-031 §6 already characterized this choice
("does not touch ADR-006"). Concretely:

- `agent-executor` gains volume operations on `ContainerEngine` (or a small parallel `VolumeEngine`
  trait, implementation-time choice, not pre-designed here) backed by `bollard::volume::{create_volume,
  remove_volume}` and `ContainerSpec` gains a `Vec<VolumeMount>` (volume name, container mount path,
  read-only flag) that becomes `HostConfig.mounts` at `create_container` time — the same place
  `no-new-privileges`/`cap_drop` are already set (§5).
- **Cross-provider portability is explicitly not provided** — a volume created on provider A cannot
  be attached to a workload scheduled on provider B. This is a real, named limitation (§8's non-goal
  list), not a silent gap: if a lease's provider becomes permanently unavailable, the volume's data is
  unavailable with it until/unless a future ADR adds replication or migration (out of scope here,
  same posture ADR-031 §8 already took toward its own deferred pieces).
- **`*snapshot` is scoped down for this MVP, named explicitly (§8):** issue #26's acceptance criteria
  ask for "block volume create/attach/detach/snapshot/delete." A snapshot of a host-local Docker
  volume is realistically a filesystem-level copy (e.g. `cp -a` or a filesystem snapshot if the host
  filesystem supports it, like ZFS/Btrfs) of the volume's backing directory into a new, independent
  named volume — buildable without new infrastructure, but explicitly out of scope for this ADR's
  first slice (§8) because it multiplies the state-machine surface (a snapshot is itself a
  volume-shaped object needing its own lifecycle, ownership, and secure-deletion story) before the
  base create/attach/detach/delete path has shipped and been exercised. Named as owed, not silently
  dropped from the issue's own acceptance criteria.

### 2. Lifecycle: a Cinder volume outlives its workload by default; reattachment is a normal operation

A volume is a first-class object independent of any single workload's lifetime — this is Cinder's own
core semantic (a volume survives instance deletion unless explicitly told otherwise) and is also what
issue #171 asks this ADR to decide explicitly, not assume:

- **Create**: `POST` creates a `cinder_volumes` row (Postgres, authoritative — §3) in `available`
  state, `project_id`-scoped, sized (`size_gb`), with no host binding yet. Nothing is created on any
  provider host until the volume is first attached — a `cinder_volumes` row with no attachment is
  metadata only, costs no provider disk space, and can be created before any workload exists that will
  use it (matching real Cinder's own "create volume, attach later" flow).
- **Attach**: binds the volume to a specific `(workload_id, provider_id)` pair at attach time — this
  is the moment the volume is pinned to a host, because the underlying Docker named volume must live
  on the provider that will mount it. Attach transitions the row to `in-use` and records the binding.
  **A volume can only be attached to one workload at a time** — attempting to attach an already-`in-
  use` volume is rejected, structurally preventing double-attachment (issue #26's own acceptance
  criterion), by the same "the query itself is the check" discipline ADR-016 established for
  ownership scoping (checking `state='available'` in the same transaction that flips it to `in-use`,
  not a separate read-then-write race).
- **First attach binds a volume's `provider_id` permanently** (§1: no cross-provider portability) —
  every subsequent attach of the same volume, to a new workload after a previous one detaches, must
  target a workload scheduled on that same provider, or the attach is rejected with a clear "volume is
  bound to provider X" error, not a silent failure or an attempt to migrate data.
- **Detach**: the workload releases the volume (explicit `DELETE` on the attachment, or implicitly
  when the workload stops/is deleted — both paths converge on the same detach operation, matching how
  `DockerExecutor::stop` already has one code path regardless of why a stop was triggered). Detach
  transitions the row back to `available`. **The Docker-level named volume is not deleted on detach**
  — only on an explicit volume `DELETE` (§1) — so the volume's data survives exactly as long as the
  owning tenant wants it to, independent of any one workload's or lease's lifetime.
- **Reattachment to a different workload, including a new lease on the same provider, is a normal,
  supported operation** — this is precisely what issue #171 asks this ADR to decide, and the answer is
  yes: an `available` volume already bound to provider P can be attached to any new workload the same
  tenant schedules on P, regardless of which lease created the original attachment. This is what makes
  a Cinder volume meaningfully different from a Docker `--rm`-style ephemeral mount, and is the actual
  product value of implementing Cinder at all (a database's data surviving a workload restart/upgrade
  is the canonical Cinder use case this ADR exists to satisfy).
- **Delete**: only permitted from `available` state (an `in-use` volume must be detached first —
  Cinder's own real behavior, not an OpenInfra invention) and triggers secure deletion (§6) before the
  `cinder_volumes` row itself is removed (soft-deleted with a `deleted_at` timestamp for audit,
  matching `internal/userauth`'s existing revocation-by-marking convention, rather than a hard
  `DELETE FROM`).

### 3. Durable state split: Postgres authoritative, Agent-local `sled` state bounded and reconstructible

Matching this repository's existing, non-negotiable split (`AGENTS.md`: "PostgreSQL is authoritative
off-chain; Redis contains only reconstructible state" — the same principle extends to the Agent's own
local `sled` store, which is already documented as reconstructible-from-Postgres-on-recovery for
workloads):

- **Postgres (Control Plane, authoritative)**: a new `cinder_volumes` table
  (`volume_id` [UUID], `project_id`, `name`, `size_gb`, `state` [`available`/`in-use`/`deleting`/
  `error`], `provider_id` [nullable until first attach], `attached_workload_id` [nullable],
  `encrypted` [bool, §6], `created_at`, `deleted_at`) — the durable source of truth for what volumes
  exist, who owns them, and their attachment state, exactly the shape ADR-031 §6 already sketched.
  This is the table any Control-Plane-side reconciliation (orphaned-volume detection after a
  provider partition, per issue #26's own acceptance criterion) reads against.
- **Agent-local `sled` state (bounded, reconstructible)**: `WorkloadRecord` gains a
  `volume_mounts: Vec<VolumeMount>` field (Docker volume name, mount path, read-only flag) — the
  Agent's own record of what it actually attached to a running container, used the same way
  `container_id`/`vm_handle` already are: to `recover()` on restart (does the Docker volume this
  record claims is mounted actually exist and match what Postgres's `cinder_volumes` row says?) and to
  detect drift (a volume Postgres says is `in-use` on this provider but the Agent has no record of
  mounting — an orphan to reconcile, not silently ignore).
- **Failure reconciliation, named per issue #26's own acceptance criterion:** a provider that
  crashes mid-attach must not leave Postgres believing a volume is `in-use` when no container actually
  has it mounted (or vice versa). The mechanism is the same `recover()`-reconciles-against-live-state
  pattern `DockerExecutor`/`VmExecutor` already use for containers/VMs — extended to volumes, not
  reinvented — with the Control Plane's orchestrator treating a heartbeat-silent provider's `in-use`
  volumes the same cautious way it already treats a heartbeat-silent provider's workloads (known gap:
  today's retry path has no maximum-attempt cutoff for a permanently-dead provider — noted in
  `CLAUDE.md`'s Known gaps, and a volume reconciliation policy inherits the same open problem rather
  than solving it here).

### 4. Multi-tenancy: `project_id`-scoped, following ADR-031 §3's model, not blocking on its landing

A `cinder_volumes.project_id` column, scoped and enforced exactly the way `workloads.project_id` will
be once issue #23 lands (ADR-031 §3: "every OpenStack-facing query scopes by `project_id` the same
literal way `internal/workloadapi` already scopes by `owner_id`" — the ownership-check-via-the-query-
itself pattern ADR-016 established). This ADR does not redesign projects/quotas — it reuses ADR-031
§3's model by reference, and does not block on issue #23's exact final shape landing first:

- **If issue #23 has not yet landed when Cinder implementation starts**, `cinder_volumes` can carry
  both `owner_id` (today's flat ownership, matching `workloads.owner_id`'s current state) and a
  nullable `project_id` (populated once projects exist), mirroring exactly the migration path ADR-031
  §3 already describes for `workloads.project_id` itself ("nullable during migration, required for any
  workload created through the OpenStack surface"). A volume never needs a *different* migration
  story than workloads do — it is the same tenant-ownership column, applied to a second resource type.
- **Quota interaction**: `project_quotas` (ADR-031 §3) gains a `max_storage_gb` dimension (already
  named in that ADR's sketch of the table's columns) — a volume's `size_gb` counts against it at
  create time, the same commit-time reservation-ledger check `internal/workloadapi`'s existing
  `ProviderCapacity`/`project_quotas` checks already run, not a new enforcement mechanism.
- **A volume with no project (pre-#23, `owner_id`-only) is scoped by `owner_id` exactly as
  `workloadapi` already scopes every other resource today** — no new authorization pattern, no gap
  where a volume is reachable without an ownership check while projects don't yet exist.

### 5. VM boot-disk relationship: deliberately separate mechanism, not the same as Cinder volumes

This is the second most consequential call in this ADR, made explicitly per this ADR's own brief.

**Decision: separate.** A VM's boot disk (ADR-033 §4) and a Cinder volume are not the same mechanism,
for reasons grounded directly in what ADR-033 already built, not a hypothetical comparison:

- **Different identity and mutability model.** A VM boot disk is *content-addressed* — its identity
  *is* its SHA-256 digest (`vm_image_cache_dir/<digest>.qcow2`), fetched once, cached, and effectively
  immutable for the life of that cache entry; two VMs booting the same `vm_image_sha256` share the
  exact same cached bytes, the same way two Docker containers pulling the same image digest share the
  same image layer. A Cinder volume is the opposite: its identity is an *opaque, mutable, tenant-owned
  container* (`volume_id`) whose entire purpose is that a workload writes to it and expects those
  writes to persist and be readable again later — there is no digest to verify because there is no
  fixed content to verify against. Collapsing these into one mechanism would force one of two bad
  outcomes: either a "boot disk" gains real read-write mutability it doesn't need and loses the
  cheap-content-addressed-caching property ADR-033 §4 specifically designed for, or a "volume" gains a
  digest-pinning requirement that makes no sense for data a tenant's own workload is actively writing.
- **Different attach cardinality.** ADR-033's `VmSpec` gives exactly one boot disk per VM, decided at
  create time, never reattached elsewhere — there is no attach/detach concept in `vm/mod.rs` at all
  (confirmed above, § Context). §2's Cinder lifecycle is fundamentally about attach/detach/reattach
  across different workloads over time. These are different state machines, not the same one with a
  different label.
- **Different lifetime coupling.** ADR-033 §8 itself already anticipated this exact question and
  answered it the same direction this ADR now confirms independently: "Cinder-style persistent,
  attachable VM disk volumes beyond the boot disk itself — the boot image model (§4) is self-contained
  precisely so VM support does not have to wait on ADR-031 §6's still-undesigned Cinder follow-up."
  This ADR does not need to revisit that framing; it only had to confirm the reverse direction (does
  Cinder need to wait on or merge into the VM boot-disk model?) — and the answer, per the two points
  above, is no.
- **What this decision explicitly leaves open, named for a future slice, not solved here:** attaching
  a Cinder volume *to* a VM workload (as a second, data virtio-blk device alongside its immutable boot
  disk — the real-Cinder-on-real-Nova pattern: instances boot from an image and separately attach
  data volumes) is a reasonable, likely-eventual extension of this same `cinder_volumes` mechanism, not
  a reason to unify it with the boot-disk mechanism now. It requires VM-side attach plumbing
  (`VmEngine` gaining a device-attach operation, and ADR-033 §5's still-undesigned tap-device-style
  networking precedent suggests a parallel "block-device Backend" abstraction would fit) that does not
  exist yet and is not designed here — named in §8 as future work, sequenced after this ADR's
  Docker-side slice ships and is exercised, matching this ADR's own reasoning (§1) for keeping the
  first slice narrow.

### 6. Security: encryption at rest is a stated non-goal for MVP; secure deletion is not

Two different questions, two different answers, stated with the same explicit weight ADR-012 §4 gives
this data class generally:

- **Encryption at rest: explicit non-goal for this MVP slice, not silently skipped.** Docker named
  volumes, host-local, are backed by plain host filesystem storage with no encryption layer by
  default. Implementing real tenant-held-key encryption at rest (ADR-012 §4's stated ideal: "encrypted
  with tenant-held keys rather than merely access-controlled") requires either a host-level encrypted-
  filesystem-per-volume mechanism (dm-crypt/LUKS per volume, real new host-privileged machinery, a
  key-management story this codebase has none of today) or an application-level encrypting proxy —
  both are real, separate infrastructure investments this ADR declines to bundle into the same PR as
  the base lifecycle (§1's create/attach/detach/delete slice), the same way ADR-031 §4 declined to
  bundle the VM-backend decision into the OpenStack-compatibility ADR. **Named explicitly as a gap,
  with reasoning, not glossed over:** this means a compromised or physically-accessed provider host
  can read the plaintext contents of any volume attached to it today — a real limitation this ADR
  states plainly rather than implying encryption exists because ADR-012 §4 names it as the ideal. This
  is the single most consequential open item for the reviewer (Open Questions, below) and this ADR
  takes the position that shipping the base lifecycle first, with encryption as a clearly-named
  follow-up, is the right sequencing — not that encryption doesn't matter.
- **Secure deletion: in scope, not deferred.** Unlike encryption, this ADR does implement a real
  answer rather than naming a non-goal, because the two have very different cost/risk shapes: secure
  deletion is a bounded, one-time operation at delete time (not a persistent new infrastructure
  dependency the way encryption-at-rest is), and skipping it would leave stale tenant data physically
  recoverable on disk indefinitely — a strictly worse and more silent failure mode than "no encryption,
  stated plainly." Concretely: on volume delete, before the `cinder_volumes` row is marked deleted,
  the Agent overwrites the Docker volume's backing directory contents (a bounded, single-pass zero-
  overwrite of the volume's files, followed by `bollard::volume::remove_volume`) rather than a bare
  `rm -rf`/`docker volume rm` that leaves filesystem blocks recoverable via undelete until overwritten
  by something else. This is a real, if modest, guarantee (not cryptographic erasure — without
  encryption-at-rest there is no key to discard, so "secure delete" here means "overwritten before
  removal," a plainly weaker guarantee than the encrypted-volume ideal, stated as such) and is
  explicitly the minimum this ADR is willing to ship without a non-goal label, because ADR-012 §4's
  erasure requirement is a repository-wide commitment, not a nice-to-have.
- **Cross-tenant reachability after deletion**: because a volume is permanently bound to one provider
  (§1/§2) and reattachment is scoped by `project_id`/`owner_id` (§4) at the Postgres layer *before* any
  Docker-level attach is even attempted, a different tenant's workload can never be handed the same
  Docker volume name — the authorization check happens above the mechanism that would make a stale
  volume reachable at all, the same defense-in-depth shape ADR-016 relies on for dashboard tenant
  isolation (deny at the query, not merely at the UI). Combined with the overwrite-before-remove step
  above, this closes the specific failure mode issue #171 names: "one tenant's volume data \[must
  never be] reachable by a different tenant's workload after deletion."
- **Bounding the Docker-level mount itself**: `ContainerSpec`'s new `VolumeMount` field mounts *only*
  the specific named Docker volume the attach operation authorized, at the exact path the tenant's
  workload spec requested — never a host directory bind-mount, never a wildcard/glob path. This keeps
  the existing `cap_drop: ["ALL"]`/`no-new-privileges` container boundary (`AGENTS.md`'s Docker
  baseline) intact: a named volume mount does not grant the container any capability it didn't already
  have, unlike an arbitrary host-path bind-mount would.

### 7. API surface (create/attach/detach/delete), sketched, not fully specified

Matching how ADR-031 §6 and ADR-033 §9 both declined to pre-design their own eventual proto/schema
changes, this ADR names the surface without fully specifying it — that is implementation-time work:

- **Control Plane (Go), Postgres-facing**: a small `internal/volumeapi` package (or a `cinder` sub-
  package under `internal/openstackapi` per ADR-031 §2's structure, if the OpenStack-wire-compatible
  surface lands first) exposing create/get/list/delete on `cinder_volumes`, and attach/detach as state
  transitions guarded by the same transactional check §2 describes.
- **Control Plane → Agent (protocol/proto)**: `DeployRequest` needs a `repeated VolumeAttachment`
  field (volume handle, container mount path, read-only flag) — a real, additive proto change, not
  designed here (matching ADR-031 §6's own deferral: "A future Cinder-volume ADR will need a real
  `DeployRequest`/`ResourceRequirements` proto change... named as that follow-up ADR's responsibility,
  not pre-designed here" — this is that follow-up ADR, and it is still leaving the exact wire shape to
  the implementing PR, consistent with how ADR-033 treated its own `VmSpec`/runtime-selector field).
- **Agent-side**: `agent-executor` gains volume create/remove calls against `bollard`'s volume API,
  and `ContainerSpec.mounts` (§1) threading into `HostConfig.mounts` at `create_container` time.

### 8. Explicitly out of scope for this MVP slice

- **Cross-provider volume replication or migration** (§1) — a volume is permanently bound to the
  provider it was first attached to; no mechanism moves its data elsewhere.
- **Snapshots** (§1) — named in issue #26's own acceptance criteria but deliberately deferred to a
  narrower follow-up slice once the base lifecycle has shipped and been exercised.
- **Resize-in-place** — growing or shrinking an existing volume's `size_gb` without recreating it.
  Real Cinder supports this; this ADR's first slice does not, matching the same "don't promise parity
  the data model can't support yet" posture ADR-031 §4 took for Nova resize.
- **Encryption at rest** (§6) — named as a real, explicit non-goal with reasoning, the single most
  consequential open item for the reviewer.
- **Attaching a Cinder volume to a VM workload** (§5) — a reasonable future extension of this same
  mechanism, not designed here; requires `VmEngine`-side attach plumbing that does not exist yet.
- **Volume types / QoS tiers / multiple storage backends per provider** — this ADR assumes one
  storage mechanism (Docker named volumes on local disk) per provider; a provider advertising multiple
  volume performance tiers is not designed here.
- **Cross-project volume sharing** — a volume belongs to exactly one project/owner; there is no
  Cinder-style "shareable" or multi-attach volume in this slice, consistent with §2's single-attachment
  invariant.

## Threat model / security note

Per this session's established caution around real security-relevant surfaces (ADR-016, ADR-025,
ADR-027, ADR-031 were each held for explicit owner sign-off rather than self-accepted; this ADR
follows the same posture):

- **Double-attachment / attach-race is the primary structural risk**, mirroring issue #26's own
  acceptance criterion. §2's transactional "check-and-flip `state` in one write" pattern is the
  mitigation; a review should specifically verify this is implemented as a single atomic
  read-modify-write against Postgres (e.g. `UPDATE cinder_volumes SET state='in-use', ... WHERE
  volume_id=$1 AND state='available'`, checking rows-affected), not a separate read-then-write that
  admits a race window.
- **Cross-tenant data reachability after deletion (§6)** is the second-highest-value risk this ADR
  names directly: a bug in the `project_id`/`owner_id` scoping check at attach time, not the overwrite-
  before-remove step, is the more dangerous failure mode (a scoping bug hands *live*, not merely
  undeleted, data to the wrong tenant). Needs the same class of cross-tenant denial tests ADR-031 §
  Threat model already calls for on its own identity-bridging surface, applied here: attempt to attach
  volume A (owned by project X) from a workload in project Y, confirm rejection, for every relevant
  role.
- **Absence of encryption-at-rest (§6) is a real, accepted risk for this slice**, not a silent gap —
  flagged here so the reviewer weighs it explicitly rather than discovering it later. A provider
  operator with host access (a real actor in this system's trust model — providers are independent,
  not OpenInfra-operated) can read any volume's plaintext contents on their own host today, with or
  without this ADR; this ADR does not change that baseline, it only makes tenant data more likely to
  exist in that reachable state (previously there was no persistent volume at all).
- **Orphaned volumes after a partitioned/dead provider** inherit `CLAUDE.md`'s already-known
  unbounded-retry gap (`internal/orchestrator/worker.go`'s retry path has no maximum-attempt cutoff) —
  this ADR does not fix that pre-existing gap, but a volume-reconciliation policy built on top of it
  should not assume it will be fixed first; named so the implementing PR doesn't quietly assume away a
  known problem.

## Consequences

- **New Postgres schema**: `cinder_volumes` (migration `000017` or later, exact number decided at
  implementation time), under the existing single Postgres instance — not "another database."
- **New Agent-local state**: `WorkloadRecord` gains a `volume_mounts` field (§3), reusing the existing
  `sled`-backed, reconstructible-on-recovery model.
- **New `agent-executor` capability**: Docker named-volume create/remove, and `ContainerSpec`/
  `HostConfig` gain a mounts field — additive, inside the existing Docker-only runtime, does not touch
  ADR-006.
- **New protocol surface, named but not specified** (§7): a `VolumeAttachment` message on
  `DeployRequest` — left to the implementing PR, matching ADR-031/ADR-033's own precedent for
  deferring their eventual proto changes.
- **A new tenant-private, erasable-on-request data class now exists in this system for the first
  time** — volume contents — governed by ADR-012 §4's cross-cutting erasure requirement, satisfied
  here via overwrite-before-remove (§6), explicitly not via encryption (named non-goal, §6/§8).
- **VM boot disks and Cinder volumes remain two separate mechanisms** (§5) — no shared code path, no
  shared identity model, confirmed against ADR-033's actual shipped implementation rather than assumed.
- **Reuses, does not redesign, ADR-031 §3's projects/quota model** (§4) — this ADR does not block on
  issue #23 landing first, and does not introduce a second tenancy model.

## Out of scope

Any implementation — docs only, as directed. Everything named in §8. Encryption at rest (§6, named
explicitly as the most consequential deferred item). Attaching Cinder volumes to VM workloads (§5).

## Open questions for the accepting reviewer

- **Is deferring encryption-at-rest (§6) the right call for this MVP slice**, given ADR-012 §4 already
  names tenant-held-key encryption as the standing ideal for exactly this data class? This ADR argues
  yes — ship the base lifecycle first, encryption as a clearly-scoped follow-up — but a reviewer who
  weighs the "provider operator can read plaintext volume contents" risk more heavily may reasonably
  want encryption folded into the first slice instead, at real additional engineering cost.
- **Is host-local-only, no-cross-provider-portability (§1) an acceptable permanent limitation**, or
  should this ADR instead scope in a network-attached backend now, accepting the larger infrastructure
  investment, on the theory that retrofitting portability onto a host-local design later is harder than
  building it in from the start? This ADR argues host-local is the right MVP call given today's
  one-provider-per-lease model, but the reviewer may weigh the future migration cost differently.
- **Should Cinder implementation be sequenced before or after issue #23 (projects) lands**, given §4's
  design tolerates either order but the *quota* enforcement half (`project_quotas.max_storage_gb`)
  is only meaningful once projects exist — ADR-031 §8 already left this exact sequencing question open
  for its own Cinder mention and this ADR does not resolve it further.
- **Should snapshots (§1/§8) be pulled into this ADR's first slice after all**, since issue #26's
  acceptance criteria name them explicitly and a reviewer may consider "create/attach/detach/delete
  without snapshot" an incomplete answer to that criterion rather than an acceptable first slice.

## Verification

Checked against source before writing: `AGENTS.md` (full file — frozen architecture, Docker security
baseline, prohibited-changes list, PostgreSQL-authoritative/Redis-reconstructible rule extended by
analogy to Agent-local `sled` state); `docs/adr/031-openstack-compatibility-architecture.md` (full
file, especially §3's projects/quotas model referenced by §4, §6's Glance/Cinder split and its named
minimum Cinder requirements, §8's sequencing table); `docs/adr/033-vm-execution-backend.md` (full
file, especially §4's qcow2 boot-disk model and §8's own "Cinder... deferred... boot image model is
self-contained" note, confirmed consistent with this ADR's §5 conclusion reached independently);
`provider-agent/crates/agent-executor/src/lib.rs` (`grep -n "Volume|Mount"`, one incidental,
unrelated hit confirmed — zero real volume/mount support; `ContainerSpec`, `ContainerEngine` trait,
`BollardEngine::create`'s `HostConfig` construction, `no-new-privileges`/`cap_drop` enforcement);
`provider-agent/crates/agent-executor/src/vm/mod.rs`, `vm/image.rs`, `vm/cloud_hypervisor.rs` (full
files — `VmSpec`, `VmDeployRequest`, content-addressed image caching, confirmed zero attach/detach
concept exists for VM disks, the direct evidence for §5); `provider-agent/crates/agent-core/src/
local_state.rs` (`WorkloadRecord`, `WorkloadPhase`, `WorkloadRuntime::{Container,Vm}`,
`container_id`/`vm_handle` fields — the seam §3 extends); `provider-agent/crates/agent-core/src/
lib.rs` (`ExecutorSettings` — confirmed no volume-related field exists today, confirmed
`vm_image_cache_dir`/`max_vm_workloads` as the precedent pattern); `control-plane/migrations/`
directory listing (`000001`-`000016`, confirmed no `cinder_volumes`/`projects` table exists yet,
confirmed `000017` as the next free migration number at implementation time); `docs/adr/
012-decentralization-roadmap-and-trust-boundaries.md` §4 (data-classification table, "Secrets"
row's tenant-held-key encryption/erasure language, the precedent §6 follows); `docs/adr/
016-dashboard-rbac-and-tenant-isolation.md` (full file — ownership-check-via-the-query pattern §2/§4/
§6 all reuse); `docs/adr/` directory listing (`001`-`033` plus two `legacy-*` and a duplicate `009`
pair, confirmed `034` is the next free number); `gh pr list --state open` (empty — confirmed no
open PR claims `034` or a competing Cinder/Neutron ADR number) and `git ls-remote --heads origin`
(confirmed only two stale, unrelated `docs/adr-015-*`/`docs/adr-026-*` branches exist, neither
touching this number); `gh issue view 171`, `gh issue view 26`, `gh issue view 23` (full text, every
scoped acceptance criterion addressed above by section); `CLAUDE.md` (Known gaps section — the
unbounded-retry gap named in the Threat model section above, not re-solved here).

Refs #171. Refs #26. Related: ADR-006 (Docker-only runtime — not touched by this ADR, per §1's own
reasoning), ADR-010 (WireGuard overlay — the `Backend`-interface-abstraction precedent this ADR's
§5 gestures at for a possible future VM block-device backend), ADR-012 (decentralization roadmap —
§4's data-classification table, the precedent §6 follows for tenant-private erasable data), ADR-016
(dashboard RBAC — the ownership-check-via-the-query pattern reused throughout), ADR-025 (bandwidth
QoS — the fail-safe-default precedent this ADR's quota fail-open reasoning, inherited from ADR-031
§3, ultimately traces to), ADR-028 (disconnected-mode reconciliation — the `recover()` pattern §3
extends to volumes), ADR-031 (OpenStack compatibility architecture — the ADR this document is the
named follow-up to, §3's projects model and §6's Cinder deferral this ADR fulfills), ADR-033 (VM
execution backend — the adjacent, deliberately-separate mechanism §5 analyzes directly against its
actual shipped implementation).
