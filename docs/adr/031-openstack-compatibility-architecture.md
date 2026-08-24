# ADR-031: OpenStack compatibility architecture and service mapping

## Status

Accepted (by the repository owner, explicitly, relayed in-session — after reviewing a full summary
of this ADR's decisions and their reasoning, then confirming to proceed with implementation).

Originally written by Claude Code, autonomously, in response to issue #22, and held as Proposed per
the convention established by ADR-016/018/025/026/027/028/029/030. This ADR deliberately does not
decide whether a VM execution backend is added — that would lift the frozen Docker-only runtime
decision (ADR-006) and needs its own ADR. The repository owner has separately requested that
follow-up ADR be drafted now, so groundwork for VM support can begin once it is itself accepted;
see the VM-backend ADR filed as a companion to this acceptance.

## Context

Issue #22 is milestone v2.0's entry point: "Design the OpenStack compatibility architecture and
service mapping... without moving responsibilities across existing components," covering Keystone,
Nova, Neutron, Cinder, Glance, Placement, quotas, projects, regions, availability zones, metadata,
and asynchronous operations. Issues #23-27 (Keystone identity, Nova/Placement compute, Neutron
networking, Glance/Cinder storage, optional Kubernetes) are downstream of whatever this ADR settles,
and #23/#25/#27 are tagged `type:security`.

**What exists today, verified against source before writing anything below:**

- **No OpenStack-facing surface exists anywhere in this codebase.** `grep -rin
  "openstack|keystone|nova|neutron|glance|cinder"` across `architecture.md`, `architecture_review.md`,
  and `ROADMAP.md` finds exactly one hit: `ROADMAP.md`'s one-paragraph v2.0 milestone summary, which
  names the six issues and nothing else. There is no aspirational design to reconcile against and no
  prior art in this repository to contradict — this ADR is starting from the actual code, not
  correcting a stale vision document (the caution `CLAUDE.md` gives about `architecture.md` doesn't
  even apply here; the file is simply silent on this topic).
- **The Control Plane already runs more than one wire protocol from one binary.**
  `cmd/controlplane` serves `ControlPlaneService` over gRPC+mTLS (protocol/proto) *and*
  `internal/dashboard`'s HTTP/JSON API (`GET/POST /api/v1/...`, `Server.Handler()` registering routes
  on one `http.ServeMux`, `dashboard.go:209-236`) from the same process, on a separate listener.
  RBAC for that HTTP surface is `internal/userauth`'s `role` column (`tenant` /
  `operator_readonly` / `operator_admin`, ADR-016) checked by a `requireRole` wrapper at route
  registration time.
- **Tenancy today is a single flat `owner_id` per workload, not projects.** `workloads.owner_id`
  (migration `000009_users_and_api_keys.sql`) ties one workload to one `users.user_id`; every
  `internal/workloadapi` query scopes by it directly (`WHERE workload_id=$1 AND owner_id=$2`,
  `service.go`). There is no concept of a project/tenant that can contain multiple users, no
  cross-user role grant scoped to a subset of resources, and no quota mechanism of any kind —
  `internal/scheduler`'s capacity ledger (`ReservedCPUMillicores`/`RAMMB`/`StorageGB`/
  `IngressMbps`/`EgressMbps` on `Workload`, `ProviderCapacity` as the ceiling, `service.go:56-83`)
  enforces *provider* capacity, never a *tenant's* budget.
- **Auth today is a bearer API key, not a token service.** `internal/userauth`'s `oiu_`-prefixed
  keys (`GenerateAPIKey`, `HashAPIKey`, `Authenticate`) are opaque, SHA-256-hashed, optionally
  expiring, revocable by ID (`RevokeAPIKey`) — a real, working credential lifecycle, but structurally
  a single flat secret per session, not a scoped token with a catalog, a project, and a role list
  the way a Keystone token is.
- **The workload/runtime model is exactly one thing: a Docker container, run via bollard.**
  `agent-executor`'s `ContainerSpec` carries `memory_bytes`/`nano_cpus`/`pids_limit`/(as of ADR-025)
  a `tc` egress ceiling into Docker's `HostConfig`. `grep -n "Volume\|Mount"` across
  `agent-executor/src/lib.rs` returns **zero matches** — there is no persistent volume/mount support
  at any layer of the protocol or the executor today. `DeployRequest` (`agent.proto`) carries
  `workload_id`, `lease_id`, `image`, `limits`, `lease_end` — nothing resembling a VM flavor, a
  console, or a boot volume.
- **Container images are already digest-pinned and validated, the closest thing to a Glance
  precedent that exists.** `workloadapi.digestImage` (`service.go:30`) is a regexp requiring
  `name@sha256:<64 hex>` and `validateSubmission` rejects any `SubmitWorkloadRequest.Image` that
  doesn't match it — enforced today, not aspirational. Issue #154 (found and fixed live this
  quarter, PR #155, merged) was specifically about the Agent not pulling an image before deploy;
  the fix pulls the exact pinned digest from the registry named in the reference before
  `create_container`. There is no OpenInfra-hosted image store; the registry is always external
  (Docker Hub, a private registry, etc.), addressed by content hash.
- **Networking is real but ephemeral and Control-Plane-mediated, not a persistent tenant-owned
  object.** ADR-010's `internal/wireguard` allocates a short-lived UDP port and a peer *per lease*,
  attached only after finalized on-chain lease confirmation and Agent `RUNNING` confirmation, torn
  down on stop/revoke. There is no "network" or "subnet" resource a tenant creates once and attaches
  many workloads to, no port resource independent of a lease, and no security-group mechanism of any
  kind — a workload's network exposure today is entirely defined by whether it holds a lease, not by
  any per-workload or per-network ACL. ADR-025 adds bandwidth QoS (`tc` token-bucket egress shaping,
  keyed by workload) and ADR-026 adds a flat, exact-match availability-zone placement constraint
  (`ResourceCapability.zone` / `WorkloadConstraints.required_zone`) — both real, both narrow.
- **Internal IDs are not uniformly UUID-shaped.** `provider_id = sha256(public_key)` hex-encoded, 64
  characters (`providerjoin/service.go:249,424`) — not an RFC 4122 UUID. `lease_id` is a **on-chain
  `u64` sequence number**, parsed with `strconv.ParseUint(item.LeaseID, 10, 64)`
  (`orchestrator/worker.go:219,239,290`) — a small integer, not a UUID either. `workload_id` is the
  one ID that is already UUID-shaped in practice (client/dashboard-generated via `google/uuid`).
  Any OpenStack-compatible surface that returns these as `id` fields in a Nova/Cinder/Glance-shaped
  JSON body needs an explicit, stated ID-mapping policy — the three internal ID types cannot be
  passed through uniformly and are not source-compatible with OpenStack's own ID assumptions.
- **`AGENTS.md`'s frozen-architecture rule and ADR-012 §6's gate table govern everything below.**
  Component-boundary changes need their own ADR (`AGENTS.md:15`). Kubernetes stays prohibited under
  ADR-006 until its own accepted ADR (`AGENTS.md:43`). ADR-012 §5 states plainly: "Milestone v2.0
  (OpenStack compatibility, #22-#27) is an API-surface track. It is orthogonal to \[the
  decentralization] roadmap and is neither blocked by it nor a prerequisite for it, provided it
  introduces no new central authority." That proviso is load-bearing for §2 below.

## Decision

### 1. Compatibility strategy: a genuine, curated, wire-compatible REST subset — not a conceptual
mapping only

This is the single most consequential choice in this ADR, so it is made explicitly rather than by
default.

**Rejected: conceptual mapping only** (OpenInfra-native APIs that borrow OpenStack's resource
vocabulary — "project," "flavor," "network" — with no wire compatibility). This would be simpler to
build and would satisfy the plain-English part of issue #22's title ("service mapping"), but it
fails the issue's own acceptance criteria on its face: "evaluate SDK and Tempest interoperability"
and "list supported API microversions" are both meaningless questions to ask about an API that was
never wire-compatible in the first place — you cannot run Tempest, or the real `openstack` CLI, or
Terraform's `openstack` provider, against an endpoint that only *resembles* OpenStack's resource
model. If OpenInfra's own dashboard and CLI are the only intended clients, this ADR would not be
needed at all — `internal/dashboard` and a native CLI already exist and already work. The entire
premise of milestone v2.0, read against its own acceptance criteria, is that *existing, unmodified
OpenStack tooling* should be able to point at OpenInfra and do useful, bounded things.

**Decision: real OpenStack REST API compatibility, for an explicitly curated and honestly-scoped
subset of each service's operations, at named supported microversions, with an explicit non-goal
list per service.** Concretely: a client speaking the real Keystone v3, Nova (2.1 baseline
microversion), Neutron v2.0, Glance v2, and Cinder v3 wire protocols — real request/response JSON
shapes, real HTTP status codes and error-body format, a real Keystone service catalog — can perform
the *supported* subset of operations against OpenInfra and get the *actual* OpenStack-documented
behavior back, not an OpenInfra-flavored approximation of it. Every operation this ADR (or its
follow-ups, §7) does not implement returns the correct OpenStack "not implemented"/404/501 shape,
not a silent success, a made-up field, or a different error format — an unsupported operation must
fail exactly the way a real OpenStack deployment with that extension disabled fails, so a client
program can distinguish "this cloud doesn't have that feature" from "this isn't really OpenStack."

Why this is right for this project specifically, not compatibility for its own sake: OpenInfra's own
goal (per `AGENTS.md`'s Vision) is a decentralized provider cloud competing for workloads against
incumbent providers. The overwhelming majority of that addressable audience already has OpenStack
(or OpenStack-tooling-compatible: Terraform, Ansible OpenStack modules, `openstack` CLI, Horizon
muscle memory) integration built into their existing pipelines. A conceptual-only mapping asks every
such user to write new integration code before they can try OpenInfra; a genuine, if partial, wire
compatibility surface asks them to point existing tooling at a new `auth_url` and see how far it
gets. The "how far it gets" is exactly what §2-§6 below scope out, service by service, rather than
promising full parity this system's actual data model (§ Context) cannot support without further,
separately-gated work.

### 2. Component boundary: a new `internal/openstackapi` HTTP surface inside the existing Control
Plane binary — not a new service

**This is not a new component boundary**, and this ADR is explicit about why, following the same
reasoning ADR-027 used to reject a separate CA service:

- The Control Plane already terminates and serves more than one wire protocol from the same process
  today (`ControlPlaneService` over gRPC+mTLS, `internal/dashboard`'s HTTP/JSON API on a second
  listener). Adding a third HTTP surface — OpenStack-shaped REST/JSON on its own listener/port,
  structured as `internal/openstackapi/{keystone,nova,neutron,glance,cinder}` packages registering
  routes the same way `dashboard.go:209-236` does — extends a responsibility the Control Plane
  already has (serving tenant-facing HTTP APIs translated into internal calls), rather than creating
  one it doesn't.
- Every one of these packages is a **translation layer**, not a new source of truth: it converts an
  OpenStack-shaped HTTP request into the *same* internal Go calls `internal/dashboard` and the gRPC
  `ControlPlaneService` handlers already make against `internal/workloadapi`, `internal/scheduler`,
  `internal/orchestrator`, `internal/userauth`, and (new, §3) a projects/quota package. No new
  authoritative store is introduced beyond what §3-§6 name explicitly (new Postgres tables under the
  existing single Postgres instance — not "another database" under `AGENTS.md`'s prohibited-changes
  list, the same reasoning ADR-027 §4 used for its own new `providers.status` value).
  PostgreSQL remains the sole off-chain authority; nothing here writes to the chain that the existing
  `blockchainbridge` package doesn't already write.
  Redis usage, if any (e.g. Keystone token revocation lookups, mirroring ADR-027 §4's
  `openinfra:revoked:*` pattern), stays reconstructible from Postgres, never authoritative on its
  own.
- ADR-012 §5's own proviso — "provided it introduces no new central authority" — is satisfied: this
  surface adds no new party who must be trusted, only a new *shape* through which the same Control
  Plane that is already trusted is addressed.

**Consequence, stated plainly:** because this fits inside the existing component boundary, this ADR
does **not** need to be read as a boundary-change proposal the way the task briefing anticipated it
might have to be. If a future slice needs the OpenStack surface's request volume, latency isolation,
or dependency footprint (e.g. a Tempest-conformance test harness) to live in a genuinely separate
deployable, *that* is a new decision requiring its own ADR at that time — not something this ADR
pre-authorizes.

### 3. Identity mapping (Keystone, issue #23)

**Projects, not a bolt-on to the existing role column.** A new `projects` table
(`project_id`, `name`, `description`, `enabled`, `created_at`) and a new `project_memberships`
table (`project_id`, `user_id`, `role`) — genuinely new schema, because Keystone's model
(domain → project → user, with roles assignable per project) has no representation today: the
existing `users.role` column is a single, global, Control-Plane-operator-visibility tier (ADR-16),
answering "what can this person see across the whole system," not "what can this person do within
this specific project." These are different questions and this ADR does not try to collapse them —
`users.role` stays exactly as ADR-016 defined it (dashboard RBAC tier); a new, separate
project-scoped role (`project_member` / `project_admin` — the two OpenStack itself distinguishes for
the common case, deliberately not attempting Keystone's full custom-policy engine) governs what a
user may do to resources *within a project*. `workloads.owner_id` is extended, not replaced: a
workload gains a `project_id` column (nullable during migration, required for any workload created
through the OpenStack surface), and every OpenStack-facing query scopes by `project_id` the same
literal way `internal/workloadapi` already scopes by `owner_id` — reusing the exact "ownership
check via the query itself, never a separate authorization branch" pattern ADR-016 established,
because that pattern is precisely what keeps a tenant-isolation bug from being introduced as a
one-off mistake in a new code path.

**Domains:** a single implicit `default` domain for the first slice, matching Keystone v3's own
default and every real-world single-domain deployment. Multi-domain (a second layer of tenant
grouping above projects) is named explicitly as deferred (§8) — nothing in the current tenant model
needs it, and inventing the authority structure for who can create a domain is exactly the kind of
speculative complexity this repository's other ADRs (e.g. ADR-026 §3's zone-allowlist reasoning)
have consistently declined to build ahead of a real need.

**Quotas:** a new `project_quotas` table (`project_id`, `max_cpu_millicores`, `max_ram_mb`,
`max_storage_gb`, `max_workloads`, ...) enforced at the same commit-time check
`internal/workloadapi`'s existing `ProviderCapacity` ceiling already runs (`service.go`'s
reservation-ledger pattern) — a **second**, independent ceiling per project, checked alongside the
existing per-provider one, not a replacement for it. A project with no quota row is treated as
unbounded (fail-open on the *quota* dimension specifically, not on capacity or auth) matching how a
provider that hasn't operator-configured bandwidth is already treated as zero-capacity-for-that-
dimension elsewhere in this codebase (ADR-025) — the precedent differs per dimension because the
consequence differs: an absent bandwidth number means "cannot schedule here" (safe default), while
an absent quota means "grandfather existing/ungoverned projects rather than silently locking every
project that predates quotas out of the system" — stated explicitly as a deliberate choice, not
copied blindly from a different ADR's default.

**Token format: bridge, not reimplementation.** Keystone's real token formats (Fernet, PKI) are an
internal implementation detail — no client-visible contract depends on the token's *internal* byte
format, only on its *external* behavior: an opaque bearer string in `X-Subject-Token`, presented on
every subsequent call in the same header, expires, is revocable, and (for a scoped token) carries an
implicit project/role context the server resolves server-side. This ADR bridges Keystone's token
*API* (`POST /v3/auth/tokens` — accepts a password or an existing-token re-scope request, returns
`X-Subject-Token` plus a body containing the resolved project, roles, and service catalog) onto
`internal/userauth`'s **existing** `oiu_`-prefixed API key mechanism underneath: a Keystone token
*is*, internally, one more `userauth.APIKey` row, with `CreateAPIKeyWithExpiry` supplying the
"unscoped credential becomes a scoped token" step and an added `project_id` column on the API-key
row recording its scope. **No Fernet encryption, no PKI-signed tokens, no separate token-signing key
material is implemented** — this is a deliberate, scoped-down choice: it satisfies every
wire-visible Keystone client expectation (revoke, expire, scope, catalog) using a credential
mechanism this repository already operates, tests, and trusts, rather than standing up a second,
parallel credential-issuance system whose only purpose would be producing bytes in a specific
internal format no client actually inspects. If a specific client library is later found to validate
token *shape* (not just opaque-bearer behavior) client-side, that is a compatibility gap to record
against the non-goal list (§7), not a reason to build Fernet pre-emptively.

**Service catalog:** a static, Control-Plane-config-driven catalog (one entry per implemented service
— identity, compute, network, image, volumev3 — each pointing at this Control Plane's own
`internal/openstackapi` base URL) rather than a dynamically registered `endpoint`/`service` schema —
there is exactly one deployment topology (one Control Plane) this needs to describe today, and a
dynamic multi-region/multi-endpoint catalog is meaningless until ADR-012 Stage 1's multi-Control-
Plane work (ADR-017, not yet written) exists to register more than one endpoint into it.

### 4. Compute mapping (Nova/Placement, issue #24) — the ADR-006 boundary, addressed head-on

This is the second most consequential decision, and this ADR is deliberately conservative rather
than silently assuming ADR-006 is superseded.

**What issue #24 actually asks for, read literally:** "a production-safe VM execution backend
alongside Docker" and "hardware virtualization capability discovery" are unambiguous — they mean
real virtual machines (the issue names libvirt/KVM as an example), not a container dressed up in
Nova's vocabulary. ADR-006 fixes Docker as *the* MVP workload runtime and explicitly defers
"Kubernetes, VM orchestration, and alternative runtimes." A VM backend is squarely "alternative
runtime" — a real execution-model addition, and per `AGENTS.md`'s frozen-architecture rule
("Do not change a language, framework, database, or component boundary without an accepted ADR"),
this needs its own accepted ADR extending (not silently overriding) ADR-006, the same way ADR-012 §6
already gates every other frozen-architecture lift by name. **This ADR does not lift that gate and
does not decide whether a VM backend is added.** It is out of scope here, deliberately, for the same
reason ADR-030 declined to fold in issue #120's treasury-custody design: bundling a genuinely new
execution-model decision (hypervisor choice, host resource isolation model, image format, migration
story, its own threat model) into an already-large API-surface ADR would make this ADR responsible
for two separable, both-large decisions, harder to review or accept incrementally than either alone.

**What this ADR does settle:** the Nova/Placement **API surface** can be built now, against the
**existing Docker-container execution model**, as a "Nova-shaped API, container reality underneath"
compatibility layer — explicitly, honestly scoped to the subset of Nova's operations that a
container workload can actually satisfy:

| Nova concept | Backed by (today, Docker-only) | Status |
|---|---|---|
| `POST /v2.1/servers` (create) | `workloadapi.SubmitWorkload` via `internal/openstackapi/nova` translation (image ref → digest-pinned OCI reference, §5's Glance mapping; flavor → `ResourceRequirements`) | Supported |
| `GET/DELETE /v2.1/servers/{id}` (show/delete) | `workloadapi.Get`/`RequestStop` | Supported |
| `POST .../action` `{reboot}` (soft) | `Stop` + re-`Deploy` against the same `lease_id` — an approximation, not a true in-place reboot (a container restart, not a guest OS reboot) | Supported, with the approximation stated in the response's own semantics, never silently claimed as a real reboot |
| Flavors (`GET /v2.1/flavors`) | A static, operator-configured list mapping flavor name → `ResourceRequirements` preset, mirroring how `WorkloadConstraints`/`ResourceRequirements` are already expressed | Supported |
| Placement (`GET /resource_providers`, `allocations`) | `internal/scheduler`'s `Candidate`/`ProviderCapacity` ledger (§ Context) already tracks exactly this: a resource provider's total/reserved/available CPU/RAM/storage/bandwidth. Placement's API is a **read/translation shim** over data this system already computes, not a new ledger | Supported, read-focused; direct allocation-writing via Placement's own API (bypassing Nova) is a non-goal (§7) — allocations remain Nova-driven, as most real deployments already run them |
| Console access (`os-getConsoleOutput`, VNC/serial) | **Nothing** — no VM, no hypervisor console, no equivalent Docker concept (`docker logs`/`exec` are structurally different: interactive host access, not a boot-time console stream) | **Not implemented.** Named explicitly as a non-goal until/unless a VM backend exists |
| Live migration, resize (changing flavor in place), snapshots-as-images, nested-virtualization capability discovery | **Nothing** — all presuppose a real hypervisor | **Not implemented**, explicit non-goal for the container-backed slice |
| `hw:*` extra-specs, CPU pinning, NUMA topology | **Nothing** — Docker's resource model doesn't expose this | **Not implemented** |

This gives issue #24's API-compatibility acceptance criteria (flavors, server lifecycle, scheduling
allocations, metadata, quotas) a real, buildable, honestly-scoped answer **without** touching ADR-006
at all — every operation above maps onto the *existing* Docker-container execution path,
`agent-executor`, and `bollard`. The VM-backend half of issue #24 (a real libvirt/KVM backend,
hardware virtualization capability discovery, true console/migration/resize) is **explicitly
deferred to its own follow-up ADR** that must be written, reviewed, and accepted before any of that
work starts — named as such in §7's sequencing, not silently assumed to happen automatically once
this ADR is accepted.

### 5. Networking mapping (Neutron, issue #25)

Unlike compute, this is mostly **net-new schema and mechanism sitting above an existing, narrower
primitive** — ADR-010's WireGuard overlay is ephemeral and per-lease, not a persistent, tenant-owned
network object, and there is no security-group concept anywhere today.

- **Networks/subnets/ports:** new Postgres tables (`neutron_networks`, `neutron_subnets`,
  `neutron_ports`, each `project_id`-scoped per §3) representing what a tenant *intends* — a
  persistent object a tenant creates once and attaches many workloads' ports to over time. This is
  genuinely new orchestration state, not a compatibility shim: today's overlay has no concept of
  "the same network across two different leases." ADR-010's `Backend` interface (already abstracted
  specifically so unit tests don't need `CAP_NET_ADMIN`) is the mechanism this new layer drives —
  the *interface* is reused, the *lifecycle model* above it is new.
- **IPAM:** subnet CIDR allocation and per-port IP assignment is new bookkeeping this system has
  never needed (today's overlay allocates a UDP port and a WireGuard peer, not a tenant-visible
  IP address in a tenant-chosen CIDR) — a real, bounded new mechanism, not a reuse of anything.
- **Security groups — the security-critical new mechanism, called out explicitly:** issue #25's own
  acceptance criteria demand "security groups enforced fail-closed." Nothing today enforces any
  per-workload network ACL; exposure is currently binary (has a lease-gated overlay attachment, or
  doesn't). A security-group implementation bug here does not just leak Neutron-API-surface data —
  it can **defeat the actual security property ADR-010 was written to guarantee** ("a peer is
  authorized by a finalized Lease... must disappear when the workload stops or the lease is
  revoked"). This is precisely the kind of surface named in the Threat model section below as
  needing dedicated security review before implementation, not a routine feature slice.
- **QoS/bandwidth (Neutron's `qos-policies` extension):** direct mapping onto **already-shipped**
  mechanism — ADR-025's `tc` token-bucket egress ceiling and ADR-026's zone constraint are exactly
  what Neutron's QoS/AZ-adjacent concepts ask for. This is the one piece of the Neutron mapping that
  is a genuine compatibility *shim* over existing primitives, not new mechanism, and is
  correspondingly lower-risk to build directly.
- **Floating IPs / NAT / public ingress:** **no equivalent exists at all.** ADR-012 §5 names
  "Gateway node" as Stage 2 (v4.0) decentralization-roadmap work — a node that terminates public
  ingress and routes into the private workload mesh — that does not exist today at any stage. This
  ADR's Neutron slice stays Stage-0-scoped (a single, Control-Plane-mediated overlay, matching
  ADR-010 exactly): floating IPs, if built at all under this milestone, would need their own
  narrower design for a Stage-0-appropriate ingress path (e.g. a Control-Plane-fronted reverse
  proxy per floating IP, not decentralized gateway routing) — explicitly **not** the same thing as
  ADR-012 Stage 2's eventual gateway-node work, and this ADR does not attempt to pre-design that
  convergence. Named as deferred (§7/§8), not solved here.
- **DHCP/metadata policy:** OpenStack's metadata service (`169.254.169.254`) has no analog; a
  workload today receives configuration exclusively through its `WorkloadDefinition` at deploy time,
  not a runtime-queried metadata endpoint. A compatible metadata service, if built, is new surface
  serving tenant-supplied data to a running container — itself worth a security look (it would be a
  new, un-authenticated-by-IP-alone endpoint reachable from inside every workload's network
  namespace) rather than assumed safe by precedent.

Given how much of this section is genuinely new, security-relevant mechanism (not a shim), §7
recommends this needs its own narrower follow-up ADR before implementation — the same posture
ADR-025 took for its own smaller `CAP_NET_ADMIN` privilege increase, scaled up for a bigger new
surface.

### 6. Storage mapping (Glance/Cinder, issue #26)

The two halves of this issue are architecturally very different in how much new work they need, and
this ADR treats them separately rather than as one unit.

**Glance (images): mostly already satisfied, thin catalog layer on top.** § Context already
confirmed digest-pinned OCI references (`name@sha256:<64 hex>`) are enforced today, at submission
time, by `workloadapi.digestImage` — this **is** Glance's core promise (immutable, content-addressed,
integrity-verified artifacts) already, just without a Glance-shaped API in front of it. This ADR's
Glance mapping is therefore a genuinely thin layer: a new `glance_images` table
(`image_id` [UUID, freshly minted — the first genuinely new UUID-shaped ID this ADR introduces],
`project_id`, `name`, `oci_reference` [the same `name@sha256:...` string, revalidated with the
existing regexp], `visibility` [`private`/`public`, scoped to the owning project unless public],
`created_at`) that **registers a reference to an image that already exists in some external OCI
registry** — it does not store, proxy, or cache image bytes. `POST /v2/images` (Glance's
create-then-upload two-step) is satisfied only for the "create with `location`/reference" variant;
Glance's raw-bytes `PUT /v2/images/{id}/file` upload endpoint is an **explicit non-goal** (§7) —
OpenInfra has no artifact store to receive those bytes into and building one would be new
infrastructure this issue's acceptance criteria don't actually require (they ask for "immutable
digest-verified images with provenance and access controls," all satisfiable by the reference model
above). A client that only ever pushes to Docker Hub/a private registry and then references the
digest — the existing, working OpenInfra flow — sees full Glance-API-compatible behavior for that
flow; a client that expects to `glance image-create --file` directly does not, and gets Glance's own
"upload not permitted for this store" response shape, not a silent failure.

**Cinder (block storage): a genuine gap, needs its own follow-up ADR.** § Context already confirmed
`agent-executor` has zero volume/mount support today — not a Docker limitation (Docker volumes are a
normal, well-understood Docker feature within ADR-006's existing runtime, not a runtime change), but
a genuine absence in this codebase's current executor and protocol. Building Cinder compatibility
needs, at minimum: (a) `agent-executor` gaining Docker named-volume create/attach/detach support
(itself bounded, additive work inside the existing Docker-only runtime — does not touch ADR-006);
(b) a durable volume-lifecycle model in Postgres (`cinder_volumes`: create/attach/detach/
snapshot/delete, `project_id`-scoped, with explicit attachment state so double-attachment is
structurally prevented, matching this issue's own acceptance criterion); (c) an encryption-at-rest
and secure-deletion policy for volume contents, since a deleted tenant volume containing tenant data
is exactly the class of "tenant-private, must be erasable" data ADR-012 §4 already names as a
cross-cutting requirement ("Tenant-private classes... must be erasable on request... encrypted with
tenant-held keys rather than merely access-controlled"). This is real, new, security-relevant design
work (data durability across provider restarts/crashes, orphaned-volume reconciliation after a
partition, secure deletion) — issue #26 is tagged `type:security` precisely because of this half, not
the Glance half. §7 recommends Cinder gets its own narrower follow-up ADR before implementation; the
Glance half does not need one and can proceed directly under this ADR's mapping.

### 7. Kubernetes (issue #27) — explicitly not decided here

`AGENTS.md` keeps Kubernetes prohibited under ADR-006 until its own accepted ADR
(`AGENTS.md:43`), and ADR-012 §6's gate table has no entry for it at all — it is not
decentralization-stage work, it is a runtime-boundary question exactly like §4's VM backend, gated
the same way. **This ADR does not attempt to lift that prohibition.** Issue #27's own text already
says the quiet part explicitly ("Kubernetes remains explicitly outside the MVP," sequenced "after
VM, identity, network, image, and storage foundations are stable") — this ADR agrees with that
framing and defers everything about it to a dedicated follow-up ADR specifically scoped to the
Kubernetes runtime-boundary question, the same way §4 defers the VM-backend question. That follow-up
ADR needs to settle, at minimum, exactly what issue #27 names: cluster-lifecycle API choice (it
names Magnum-compatible as one option, not a decision), tenant-isolated control-plane/worker-node
trust boundaries, CNI/CSI within this system's existing WireGuard-based networking (§5, once that
itself is settled), and — critically — "no direct Kubernetes-to-chain authority," which is really a
restatement of this repository's existing "the Provider Agent never talks to the chain directly"
rule applied to a new component.

**Sketch only, not a decision, for how it *might* eventually fit if that gate is separately
cleared:** a Magnum-compatible cluster API translating a "create cluster" request into a set of
Nova-compatible `server` resources (§4) — worker nodes as either containers-standing-in-for-nodes
(if never escaping the Docker-only runtime, a real but limited approximation, likely too weak for a
real conformant Kubernetes cluster) or real VM-backed nodes (if §4's VM-backend ADR is separately
accepted first) — consuming the same lease/scheduler primitives every other workload type already
does, per issue #27's own acceptance criterion. This sketch resolves nothing; it exists only so §8's
sequencing table has something concrete to point at as "blocked on two separate gates," not to
pre-commit to a design.

### 8. Sequencing across #23-27, and which need their own follow-up ADR

| Issue | Can proceed directly under this ADR's mapping? | Reasoning |
|---|---|---|
| **#23 Identity** | **No — needs its own narrower follow-up ADR** before implementation | Everything downstream needs it (auth/tenancy is the foundation every other service's `project_id` scoping depends on), it is `type:security`-tagged, and it introduces a genuinely new schema layer (projects, project roles, quotas) plus a token-bridging design (§3) that is exactly the class of decision ADR-016 held for explicit owner sign-off ("it decides who can see which tenant's data: a real security boundary"). Sequenced **first** — nothing else in #24-26 can be built project-scoped without it. |
| **#24 Compute — API layer (container-backed, §4's table)** | **Yes, directly** | Confined to translating existing Docker-workload operations into Nova/Placement shape; no new privilege, no new data class, no new trust boundary beyond what identity (#23) already gates. |
| **#24 Compute — VM backend** | **No — hard-blocked on its own separate ADR** extending ADR-006 | Not sequenced relative to the others at all; it's an independent gate that may never be pulled, per §4. |
| **#25 Networking — QoS/AZ mapping (existing ADR-025/026 mechanisms)** | **Yes, directly** | Pure compatibility shim over already-accepted, already-shipped mechanism. |
| **#25 Networking — networks/subnets/ports/security-groups** | **No — needs its own narrower follow-up ADR** | Genuinely new, security-relevant mechanism (§5) whose failure mode is defeating ADR-010's actual security guarantee, not merely leaking API-surface data. |
| **#26 Storage — Glance (image reference catalog)** | **Yes, directly** | Thin layer over an already-enforced invariant (§6). |
| **#26 Storage — Cinder (block volumes)** | **No — needs its own narrower follow-up ADR** | Genuine new mechanism: durability, encryption, secure deletion, double-attachment prevention (§6) — the actual reason issue #26 is `type:security`-tagged. |
| **#27 Kubernetes** | **No — needs its own dedicated ADR**, sequenced last, additionally gated on #24's VM-backend decision if that path is chosen | Explicit non-goal of this ADR (§7); ADR-006's Kubernetes prohibition is not touched here. |

**Recommended implementation order:** #23 (its own ADR, then implementation) → #24's API layer and
#26's Glance half (can proceed in parallel once #23 lands, both low-risk direct implementations under
this ADR) → #25's QoS/AZ shim (direct, low-risk, can also proceed once #23 lands) → #25's
networks/security-groups (its own ADR) and #26's Cinder half (its own ADR) — these two can be
designed in parallel, both security-relevant, both genuinely new mechanism → #24's VM-backend
decision, whenever it is pursued, entirely independent of the above → #27, last, gated on both its
own ADR and (if the VM path is chosen for Kubernetes worker nodes) #24's VM-backend ADR.

## Threat model / security note

Per this session's established caution around real security-relevant surfaces (matching how
ADR-016, ADR-025, and ADR-027 were each held for explicit owner sign-off rather than
self-accepted), naming the obvious risk surfaces this ADR's decisions create, directly:

- **Identity/token bridging (#23, §3).** The single highest-value bug class: a scoping error in the
  Keystone-token-to-`userauth`-API-key bridge that lets a token minted for project A resolve, act on,
  or enumerate resources in project B. This is structurally the same class of bug ADR-016 §6 already
  worried about for the dashboard's tenant-isolation boundary, applied to a second, parallel
  authorization surface (the OpenStack API) that must independently get the same answer right — two
  authorization code paths reading the same `project_id` column are two chances to get the check
  wrong in only one of them. Needs dedicated security review before implementation, specifically:
  cross-tenant denial tests (already named in #23's own acceptance criteria) run against **both**
  the dashboard's existing authorization path and this new one, not just the new one in isolation.
- **Security-group enforcement (#25, §5).** A fail-open bug here does not merely leak data the way a
  dashboard authorization bug would — it can put a workload's network exposure in a state ADR-010
  was specifically designed to make impossible ("a peer is authorized by a finalized Lease... must
  disappear when the workload stops or the lease is revoked"). Needs dedicated security review before
  implementation, and needs its own follow-up ADR (§8) rather than being folded into a general
  networking implementation PR.
- **Kubernetes (#27), when eventually pursued.** Not designed here at all (§7); flagged only so the
  eventual follow-up ADR inherits this note rather than starting from zero: "no direct
  Kubernetes-to-chain authority" (the issue's own acceptance criterion) is this repository's existing
  Agent-never-talks-to-chain-directly rule, and any cluster-credential-rotation design needs the same
  bounded-blast-radius reasoning ADR-027 already applied to Provider Agent leaf certificates.
- **Cinder secure deletion (#26, §6), when eventually pursued.** A volume-deletion bug that leaves
  tenant data recoverable on a provider's disk after a tenant believes it deleted the volume is a
  direct violation of ADR-012 §4's erasure guarantee for tenant-private data. Named for the eventual
  follow-up ADR, not solved here.

## Consequences

- Confirms milestone v2.0 is plannable and gives #23-27 a coherent shape, per issue #22's own job.
- **New Postgres schema across three services**, all under the existing single Postgres instance
  (no new database, per §2): `projects`, `project_memberships`, `project_quotas` (§3);
  `neutron_networks`/`neutron_subnets`/`neutron_ports` and a security-groups table (§5, deferred to
  its own ADR); `glance_images` (§6, direct) and `cinder_volumes` (§6, deferred to its own ADR).
  `workloads` gains a `project_id` column.
- **A new HTTP surface inside the existing Control Plane binary** (`internal/openstackapi`, §2) —
  no new deployable, no new ADR-012 §6 gate lifted, per §2's reasoning.
- **Two ADR-006-adjacent decisions explicitly deferred, not made:** whether a VM execution backend is
  added alongside Docker (§4), and whether Kubernetes is added as an optional workload service (§7).
  Neither is authorized by this ADR's acceptance; each needs its own separately accepted ADR before
  any implementation.
- **Three narrower follow-up ADRs are now named as owed** before their respective implementation
  work starts (§8): identity/projects (#23), networks/security-groups (#25's harder half), and
  Cinder block storage (#26's harder half). This ADR's acceptance does not authorize skipping any of
  them.
- **`protocol/proto` is not changed by this ADR.** Every mapping above translates at the
  `internal/openstackapi` HTTP boundary into calls against the *existing* gRPC/internal Go surface
  (`workloadapi`, `scheduler`, `orchestrator`, `userauth`) — no new field on `DeployRequest`,
  `WorkloadDefinition`, or any other `.proto` message is proposed here. A future Cinder-volume ADR
  (§6/§8) will need a real `DeployRequest`/`ResourceRequirements` proto change (volume attachment
  has to reach `agent-executor` somehow) — named as that follow-up ADR's responsibility, not
  pre-designed here.
- `ROADMAP.md`'s v2.0 milestone description should be read alongside this ADR once accepted; no text
  change to `ROADMAP.md` is proposed as part of this ADR itself.

## Out of scope (this ADR, all services)

- Any implementation. Docs only, as directed.
- Full parity with any OpenStack service — every section above names its own non-goal list
  explicitly rather than leaving "full compatibility" as an implied, unbounded promise.
- Glance raw-bytes image upload (§6); Cinder implementation itself (§6, its own ADR); Neutron
  networks/subnets/ports/security-groups implementation itself (§5, its own ADR); any VM execution
  backend (§4, its own ADR); Kubernetes in any form (§7, its own ADR).
- Multi-domain Keystone hierarchy (§3) and a dynamic, multi-endpoint service catalog (§3) — both
  named as meaningless until real multi-tenancy-beyond-projects and multi-Control-Plane deployment
  (ADR-017, not yet written) respectively exist.
- Regions, in OpenStack's own sense (a region is a fully independent deployment with its own
  endpoint catalog entry) — there is one Control Plane; "region" as a concept is not meaningfully
  different from "the one deployment that exists" until ADR-012 Stage 1 multi-Control-Plane work
  lands. Availability zones (already real, ADR-026) are not the same concept as OpenStack regions
  and this ADR does not conflate them.
- A Tempest conformance test suite itself — issue #22 asks this ADR to "evaluate SDK and Tempest
  interoperability," which §1's strategy answers at the architecture level (real wire compatibility
  makes Tempest evaluation *possible*); actually running Tempest against an implementation is
  necessarily downstream of #23-26 shipping something to run it against, not something this ADR can
  do today.

## Open questions for the accepting reviewer

- **Is real wire-level OpenStack compatibility (§1) actually the right investment for this project's
  current stage**, versus a smaller conceptual mapping that satisfies less of issue #22's letter but
  costs a fraction of the engineering effort this ADR's full scope implies? This ADR argues yes,
  based on the issue's own acceptance criteria and the stated goal of tooling interoperability, but
  it is a real resource-allocation choice against everything else in the roadmap (ADR-012's Stage 1-4
  decentralization work), not a free decision, and is worth the repository owner's explicit
  weigh-in rather than this ADR's own justification being taken as sufficient on its own.
- **Whether a VM execution backend (§4) is wanted at all**, independent of the OpenStack-compatibility
  question — issue #24 asks for one, but this ADR does not evaluate whether the operational cost
  (a second execution model, hypervisor security surface, host resource isolation model) is worth it
  for this project's actual users, versus staying container-only indefinitely and accepting that the
  Nova-compatible surface never grows past §4's container-backed subset.
- **Whether Cinder (§6) and the Neutron networks/security-groups slice (§5) should be sequenced
  before or after #24's VM-backend question**, since real block-attached-volume and real
  tenant-network use cases arguably matter more for VM workloads than for the container workloads
  this ADR's direct-implementation slices cover — this ADR sequences them independently (§8) but the
  reviewer may reasonably want them coupled instead.

## Verification

Checked against source before writing: `AGENTS.md` (full file — frozen architecture, prohibited
changes, ADR-012 §6 gate table reference); `docs/adr/012-decentralization-roadmap-and-trust-
boundaries.md` (full file, especially §5's "orthogonal to the roadmap" proviso and §6's gate table,
confirmed no gate names OpenStack, VMs, or Kubernetes as a Stage 1-4 item); `docs/adr/006-docker-
runtime.md` (full file); `docs/adr/010-wireguard-workload-overlay.md` (full file); `docs/adr/016-
dashboard-rbac-and-tenant-isolation.md` (full file — role model, `requireRole`, ownership-via-query
pattern, break-glass grant precedent); `docs/adr/025-bandwidth-usage-reporting-and-rate-limit-
enforcement.md` and `docs/adr/026-availability-zone-selection.md` (full files — QoS/zone mechanisms
this ADR's Neutron mapping reuses); `docs/adr/027-mtls-pki-enrollment-rotation-revocation.md` (full
file — the "extends an existing responsibility, no new component boundary" reasoning this ADR's §2
mirrors); `docs/adr/030-protocol-usage-fee.md` (full file — the "don't fold a second large trust
boundary into one ADR" reasoning this ADR's §4 mirrors for the VM-backend deferral); `docs/adr/`
directory listing (`001`-`030` plus two `legacy-*` and a duplicate `009` pair, confirmed `031` is the
next free number, confirmed via `gh pr list --state open` that no open PR claims it);
`protocol/proto/openinfra/{shared,agent,controlplane}/v1/*.proto` (full files — confirmed no
project/flavor/network/volume concept exists anywhere on the wire today, confirmed `DeployRequest`'s
exact field list); `control-plane/internal/workloadapi/service.go` (full file — `digestImage` regexp,
`Workload`/`ProviderCapacity` struct fields, `owner_id` scoping pattern, `SubmitWorkload`);
`control-plane/internal/userauth/userauth.go` (full file — API key mechanism, role model, `roleRank`);
`control-plane/internal/dashboard/dashboard.go` (`Server.Handler()`'s route table, confirmed the
existing multi-surface-from-one-binary precedent); `control-plane/internal/orchestrator/worker.go`
(confirmed `lease_id` is a `strconv.ParseUint`-parsed on-chain `u64`, not a UUID); `control-plane/
internal/providerjoin/service.go` (confirmed `provider_id = sha256(public_key)` hex, not a UUID);
`provider-agent/crates/agent-executor/src/lib.rs` (`grep -n "Volume\|Mount"`, zero matches — confirmed
no volume/mount support exists); `control-plane/migrations/` directory listing (`000001`-`000016`,
confirmed current schema has no `projects`/`network`/`volume`/`image` table); `architecture.md`,
`architecture_review.md`, `ROADMAP.md` (grepped for every OpenStack service name — confirmed no
aspirational design exists to reconcile against beyond `ROADMAP.md`'s one-paragraph milestone
summary); `gh issue view 22/23/24/25/26/27` (full text, every acceptance criterion addressed above by
section); issue #154 and its fix (PR #155, merged — the digest-pinned-image-pull precedent cited in
§6); `git log`/`git branch -a` (confirmed no other in-flight branch touches `docs/adr/031-*` or an
OpenStack-compatibility proposal; this session's other active work is on `blockchain/pallets/escrow`,
confirmed unrelated by file path).

Refs #22. Related: ADR-006 (Docker-only runtime — not superseded by this ADR; §4 and §7 both
explicitly defer any change to it to their own future ADRs), ADR-010 (WireGuard overlay — the
primitive §5's Neutron mapping builds on), ADR-012 (decentralization roadmap — §5's "orthogonal
track" framing this ADR operates under), ADR-016 (dashboard RBAC — the tenant-isolation and
break-glass-grant precedents §3 and §5 reuse), ADR-025/ADR-026 (bandwidth QoS and availability zones
— the mechanisms §5's QoS/AZ mapping reuses directly), ADR-027 (mTLS PKI — the "extends an existing
responsibility, not a new component" precedent §2 follows), ADR-030 (protocol usage fee — the
"defer a second large trust boundary to its own ADR" precedent §4 follows for the VM-backend
question).
