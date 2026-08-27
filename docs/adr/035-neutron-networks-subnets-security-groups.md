# ADR-035: Neutron-compatible networks, subnets, ports, and security groups

## Status

Accepted (by the repository owner, explicitly, relayed in-session — after reviewing a full summary
of this ADR's decisions and their reasoning, then confirming to proceed with implementation).

Originally written by Claude Code, autonomously, in response to issue #170 (split off issue #25 per
ADR-031 §5/§8, which named this exact slice as needing its own narrower follow-up ADR before
implementation). Issue #25 is `type:security`-tagged specifically because of the security-group half
of this design, and ADR-031 §8 already flagged this as needing dedicated security review — the same
posture ADR-016, ADR-025, and ADR-027 were each held to before acceptance. Nothing here is
implemented yet by this ADR itself; issue #25's hard half is unblocked by this acceptance and now
carries the implementation work, including the dedicated security review its `type:security` tag
calls for.

## Context

ADR-031 §5 settled the easy quarter of issue #25 directly (QoS/AZ mapping is a pure compatibility
shim over already-shipped ADR-025/026 mechanism) and explicitly deferred the rest — networks,
subnets, ports, IPAM, and security groups — to this follow-up ADR, because it is "mostly net-new
schema and mechanism sitting above an existing, narrower primitive," not a shim. This ADR is that
follow-up. It does not revisit the QoS/AZ mapping (ADR-031 §5's third bullet, "the one piece of the
Neutron mapping that is a genuine compatibility shim... lower-risk to build directly" stands as
written) and does not decide anything about identity/projects (issue #23, ADR-031 §3) beyond
depending on it, per ADR-031 §8's sequencing table, which names #23 as a hard prerequisite for
everything else in the Neutron mapping.

**What exists today, verified against source before writing anything below:**

- **ADR-010's overlay is per-workload, not per-network.** `control-plane/internal/wireguard.Manager`
  keeps one process-wide `peers map[string]peerState` keyed by `workloadID` — there is no concept of
  "these five peers belong to the same network" anywhere in this package. `Allocate` derives each
  peer's address deterministically from its allocated port: `overlayAddress(port) =
  "10.254.<(port/250)%250>.<port%250+1>/32"` (`wireguard.go:209-211`), always a single `/32`, always
  carved from one fixed `10.254.0.0/16`-shaped space. `AllowedIPs` defaults to exactly that one `/32`
  when the caller doesn't override it (`Allocate`, `wireguard.go:126-129`; `Attach`,
  `wireguard.go:152-155`, which always passes exactly one address). This is the mechanism this ADR's
  network/subnet/port layer sits on top of, not something this ADR replaces.
- **`AllowedIPs` is WireGuard's own cryptokey-routing ACL, already doing real enforcement.**
  `CommandBackend.Configure` programs `wg set <iface> ... peer <pubkey> allowed-ips <list>`
  (`wireguard.go:262`) — WireGuard rejects any packet from a peer whose source address isn't in that
  peer's `AllowedIPs`, and refuses to route outbound traffic to a destination outside it. Today this
  already restricts a peer to exactly its own single address; nothing about this ADR's design may
  widen that per-peer ceiling (§3 below is explicit about this).
- **The peer lifecycle is already correctly lease-gated, and this ADR does not touch that gate.**
  `Attach` is called by the orchestrator "only after finalized on-chain lease confirmation and Agent
  Docker RUNNING confirmation" (ADR-010's own Decision text, unchanged); `Revoke` tears down namespace
  attachment before the Lease is completed. This ADR's new mechanism (security groups, §3) must
  compose with this ordering, never bypass it — verified as the central design constraint below.
- **Every workload container runs on Docker's default bridge with no inter-container isolation
  configured anywhere.** `grep -n "NetworkMode\|bridge\|EndpointsConfig\|internal.*true"` across
  `provider-agent/crates/agent-executor/src/lib.rs` returns zero matches — `agent-executor` never
  sets a custom `NetworkMode` or a per-workload isolated Docker network; every container gets Docker's
  ordinary default-bridge networking. **This is a pre-existing gap this ADR did not create but must
  design around**: two workload containers scheduled onto the *same* provider host can already reach
  each other directly over `docker0` today, entirely bypassing WireGuard and lease-gating, because
  nothing currently prevents same-host, same-bridge container-to-container traffic. §3 below treats
  this as part of the enforcement-point decision, not a separate problem, because the correct fix
  (enforcing at the veth, not at the WireGuard peer) closes both gaps with one mechanism.
- **`agent-executor` already has a working, tested precedent for exactly this kind of host-level
  enforcement, using a privilege it already holds.** ADR-025 §3's `rate_limit.rs` applies a `tc`
  token-bucket qdisc to the *host-side* end of each workload's veth pair (resolved via
  `resolve_veth_name`, shared with `bandwidth.rs`'s counter-reading), at container start, torn down
  implicitly and atomically when Docker destroys the veth pair on container stop — no separate cleanup
  call needed, because "destroying either end of a veth pair — along with every qdisc attached to it —
  is atomic kernel behavior" (`rate_limit.rs`'s own doc comment). This already required, and already
  has, `CAP_NET_ADMIN` on the Agent process (ADR-025 §3, the reason that ADR was held for explicit
  sign-off). Testability is solved the same way on both sides of the wire already:
  `wireguard.CommandBackend`'s injectable `Runner` on the Go side, `rate_limit.rs`'s `CommandRunner`
  trait with a `FakeCommandRunner` on the Rust side — neither needs real privilege or a real interface
  in tests.
- **No network/subnet/port/security-group concept, and no real IPAM, exists anywhere today.**
  Confirmed via `control-plane/migrations/` (no `neutron_*` table) and
  `protocol/proto/openinfra/{shared,agent,controlplane}/v1/*.proto` (no such message). This is
  genuinely new schema and mechanism, exactly as ADR-031 §5 said.
- **Multi-tenancy has no `project_id` yet in the shipped schema.** Issue #23 (ADR-031 §3) is the
  source of truth for `projects`/`project_memberships`/`workloads.project_id`. Per ADR-031 §8's
  sequencing table, #23 is a hard prerequisite for this slice ("nothing else in #24-26 can be built
  project-scoped without it") — this ADR is written to compose with #23's design as summarized in
  ADR-031 §3, referenced rather than re-litigated, and does not block on that issue's exact final
  column names.

## Decision

### 1. Resource model: network and subnet are new grouping concepts; a port is ADR-010's existing
peer allocation, promoted from implicit to an explicit, precreated resource

**A Neutron "network" does not map 1:1 onto anything that exists today.** There is no existing
concept of "these peers belong together" in `internal/wireguard` — inventing one is unavoidable, not
a shim. New Postgres tables, all `project_id`-scoped (§4):

- `neutron_networks` (`network_id` uuid, `project_id`, `name`, `shared` bool default false,
  `created_at`).
- `neutron_subnets` (`subnet_id` uuid, `network_id`, `project_id`, `cidr`, `gateway_ip` nullable,
  `created_at`) — one network may have more than one subnet (real Neutron allows this; this ADR does
  not restrict it, since nothing about the underlying mechanism requires a 1:1 relationship).
- `neutron_ports` (`port_id` uuid, `network_id`, `subnet_id`, `project_id`, `fixed_ip`,
  `mac_address` nullable — not meaningful for a WireGuard-backed port, kept only for wire-shape
  compatibility with clients that read it, `workload_id` nullable, `created_at`).

**A "port" is the one piece of this model that maps closely onto existing mechanism**: it is
ADR-010's per-workload `wireguard.Allocation`, promoted from "implicitly created at `Attach` time,
address derived from an allocated port number" to "explicitly created ahead of time via
`POST /v2.0/ports`, address reserved from a real tenant-chosen subnet CIDR (§2), independent of the
workload that will eventually attach to it" — matching real Neutron/Nova semantics, where a port is
typically created (and gets its fixed IP) before a server boots into it. Concretely:

- Creating a port reserves `fixed_ip` from its subnet's pool (§2) and inserts a `neutron_ports` row.
  This is Control-Plane-only bookkeeping — **no WireGuard peer exists yet, no `Backend` call is made,
  no privileged operation happens.** A port with no workload attached is inert.
- A workload submitted with a `port_id` records that binding (`neutron_ports.workload_id`). The
  **actual WireGuard peer allocation is unchanged from ADR-010**: it still only happens when the
  orchestrator calls `Attach` after finalized lease confirmation and Agent `RUNNING` confirmation
  (§ Context, unchanged trigger, unchanged ordering). The only change is what address `Attach` passes
  as `AllowedIPs` — instead of `wireguard.go`'s current `overlayAddress(0)` placeholder-derived
  address, it passes the port's IPAM-reserved `fixed_ip`. This is a small, mechanical change to one
  call site (`Manager.Attach`'s caller in the orchestrator), not a change to `Manager`, `Backend`, or
  any of ADR-010's lifecycle guarantees.
- A workload submitted with **no** `port_id` (today's only path, and every existing test/workload)
  is completely unaffected: it keeps exactly today's behavior — an implicit, ADR-010-derived `/32`
  from the `10.254.0.0/16` legacy range, no `neutron_ports` row, no network/subnet involved at all.
  Backward compatibility is structural, not a special case: the orchestrator only consults
  `neutron_ports` when a workload names a `port_id`.

**Reachability is honestly scoped, not assumed.** ADR-010's `Backend` operates against a single
workload's namespace on the single provider host that workload lands on; nothing in this codebase
today gives two peers on *different* provider hosts a path to reach each other (there is no
cross-provider relay, gateway, or shared WireGuard hub — confirmed by `internal/wireguard`'s
complete lack of any multi-host concept). **A Neutron network in this MVP is therefore a shared
address space and a shared security-policy scope, not a real L2/L3 fabric spanning providers.** Two
ports in the same network whose workloads land on different provider hosts cannot reach each other
over this overlay in this slice — named explicitly in Out of scope, not silently promised. Two ports
in the same network on the **same** provider host are reachable only insofar as §3's enforcement
explicitly allows it (never by default — see §3's fail-closed default).

### 2. IPAM: tenant-chosen subnet CIDRs, disjoint from ADR-010's legacy `10.254.0.0/16` range,
allocated within a subnet's own pool

- **Collision avoidance with ADR-010's existing scheme**: `10.254.0.0/16` stays permanently reserved
  for the legacy, implicit, no-`port_id` path (§1's backward-compatible default). Subnet creation is
  rejected if the tenant-chosen CIDR overlaps `10.254.0.0/16` — a single, explicit, mechanical check
  at `POST /v2.0/subnets`, not a new allocation scheme of its own. This is the entire collision-
  avoidance mechanism; no other coordination with the legacy path is needed because the two address
  spaces are disjoint by construction.
- **Per-port allocation**: a `fixed_ip` is drawn from the subnet's CIDR at port-create time
  (sequential, lowest-available-first — simplest correct policy, no operator-visible behavior to get
  wrong), excluding the network/broadcast addresses and, if set, `gateway_ip`. Released back to the
  pool when the port is deleted. Enforced unique per subnet via a Postgres unique constraint on
  `(subnet_id, fixed_ip)` — the ordinary, boring way to prevent double-allocation, not a new
  mechanism.
- **What this ADR does NOT resolve, flagged honestly rather than asserted past**: whether two
  *different* subnets (in different networks, different projects) may reuse the same CIDR (e.g. both
  choosing `10.0.0.0/24`). Real Neutron allows this freely, because a tenant network is a genuinely
  isolated L2 segment. Here, because the ultimate `AllowedIPs` value is programmed onto a shared
  `wireguard.Manager` process state (§ Context — one `peers` map, keyed by `workloadID` process-wide,
  not partitioned by provider host in the code as written), whether two ports in different tenants'
  subnets can safely reuse the same `fixed_ip` without colliding depends on infrastructure this ADR
  does not have full visibility into (specifically: whether `CommandBackend`'s `wg`/
  `openinfra-wireguard-attach` invocations are scoped per-provider-host or share one global namespace
  in production — ADR-010's own text is silent on this, and nothing in `wireguard.go` itself resolves
  it). This ADR's conservative, safe-by-construction first slice therefore requires **subnet CIDRs to
  be globally unique across all projects and networks**, not just within one tenant's account —
  strictly more restrictive than real Neutron, named explicitly as a first-slice simplification and
  as an open question for the accepting reviewer (below), not a confident design claim on ground this
  ADR cannot fully verify.

### 3. Security-group enforcement — the security-critical decision

**Fail-safe default, stated as the load-bearing rule first:** a port with no security group attached,
or a security group with zero rules, denies **all** traffic, both directions. This is a deliberate
divergence from real OpenStack Neutron's own default (which auto-creates a permissive `default`
security group allowing all egress and ingress from the same group) — issue #25's acceptance
criteria say "security groups enforced fail-closed" in so many words, and a wire-compatible *shape*
copied from upstream's permissive default would satisfy the API surface while failing the actual
requirement. Where this ADR wants Neutron's convenience default (e.g. "let this workload send
outbound traffic without the tenant needing to remember an explicit rule"), it is delivered as an
**explicit, auditable, removable rule row** inserted at network-create time — never as implicit
"absence of rules means allow" behavior. The distinction is the entire point: an explicit rule can be
listed, reasoned about, and revoked; an implicit fallback cannot, and is exactly the failure mode
this issue is tagged `type:security` to prevent.

**Enforcement point: the Agent, nftables, against the workload's own veth — the same interface
`rate_limit.rs` already attaches `tc` to, using the `CAP_NET_ADMIN` privilege ADR-025 already
granted.** Three concrete alternatives were weighed:

- **WireGuard `AllowedIPs`** (widen/narrow the peer's own ACL). Rejected as the primary mechanism:
  `AllowedIPs` is a flat list of CIDRs with no protocol/port granularity — Neutron security-group
  rules need `(direction, protocol, port_range_min/max, remote_ip_prefix)`, which `AllowedIPs` cannot
  express at all. It also only governs traffic that reaches the WireGuard interface — it says
  nothing about same-host `docker0` bridge traffic (§ Context's pre-existing gap), so it would leave
  the same-host case completely unenforced even if it could express port-level rules.
- **A Control-Plane-side proxy/firewall.** Rejected: nothing routes workload traffic through the
  Control Plane today (ADR-010's peers attach directly into the provider host's namespace), so this
  would require inventing a new data-plane hop this system doesn't have, a much larger change than
  this ADR's scope.
- **Decision: host-level nftables on the Agent, applied to the workload's host-side veth, at
  `AttachNamespace` time, torn down implicitly when the veth is destroyed.** This is the same
  interface `resolve_veth_name` already resolves for `rate_limit.rs`/`bandwidth.rs` — every packet
  the workload sends or receives, whether bound for the same-host Docker bridge or for the WireGuard
  overlay, crosses this one veth. A ruleset here is therefore the single correct enforcement point
  for **both** the WireGuard-mediated path Neutron's security groups are nominally about *and* the
  pre-existing same-host container-to-container gap named in § Context — one mechanism closes both,
  which is a genuine, incidental security improvement this ADR's implementation should claim
  explicitly, not a side effect to bury.

**Concrete mechanics, mirroring `rate_limit.rs`'s existing pattern exactly:**

1. At container start (same point `rate_limit.rs`'s `tc` qdisc is applied, and — for a
   Neutron-attached port — the same `AttachNamespace` call ADR-010 already gates on finalized lease +
   Agent RUNNING confirmation), the Agent installs an nftables base chain on the workload's veth with
   a **default-drop policy**, before any allow rule is added. There is no window where the interface
   exists with an implicit allow.
2. For each active rule on each security group attached to the port, the Agent adds one `accept`
   rule (`direction`, `protocol`, `port_range_min/max`, `remote_ip_prefix`) to the chain. Multiple
   security groups on one port are unioned (matching Neutron), never intersected.
3. Teardown is atomic and implicit, exactly as `rate_limit.rs`'s doc comment already establishes for
   `tc`: destroying a veth pair destroys every qdisc *and* every nftables rule scoped to it, so
   `DetachNamespace`/`Revoke` need no separate nftables cleanup call — the same "no window to leak"
   reasoning ADR-025 already relies on applies unchanged here.
4. Testability follows the existing seam exactly: a `CommandRunner`/`FakeCommandRunner` pair
   (Rust) or an injectable `Runner` (Go, if the rule-set computation lives Control-Plane-side and is
   only *applied* Agent-side) records the exact `nft` invocations against a fake, no real interface or
   `CAP_NET_ADMIN` needed in unit tests — matching both `wireguard.CommandBackend` and
   `rate_limit.rs`'s existing precedent.

**Why this can never weaken ADR-010's lease-gating guarantee — reasoned explicitly, per the task
briefing's own instruction:**

- The nftables base chain is installed in the **same** `AttachNamespace` call ADR-010 already gates
  on finalized lease confirmation and Agent `RUNNING` confirmation. There is no code path that
  installs security-group state before that gate fires, and no code path that installs it
  independent of a lease at all — a port with no attached workload has no veth to attach rules to,
  full stop.
- Teardown is coupled to the same veth-destruction event `Revoke`/`Detach` already trigger (§ point 3
  above) — security-group state cannot outlive the lease-gated attachment, because it has no
  existence independent of the interface the attachment creates.
- **Security-group rules only ever narrow, never widen, what the underlying attachment already
  permits.** WireGuard's `AllowedIPs` continues to be programmed to exactly the port's single
  `fixed_ip` (§1 — unchanged from ADR-010's own single-`/32`-per-peer model), regardless of how
  permissive a security group's rules are. A maximally permissive security group (e.g. an `accept
  0.0.0.0/0` egress rule) still cannot cause the peer to accept or route packets for any address
  WireGuard's own cryptokey routing doesn't already restrict it to — the `AllowedIPs` ceiling is
  structurally outside and above anything a security-group rule can express, because it is enforced
  by a different layer (the kernel WireGuard module's own packet filtering) that this ADR's nftables
  rules do not touch and cannot override.
- Consequently, the worst a security-group misconfiguration (in the *permissive* direction — too
  many rules, not too few) can do is fail to add a restriction ADR-010 didn't already provide; it can
  never *remove* one ADR-010 does provide. The fail-closed default (this section's opening rule)
  means the more likely and more dangerous misconfiguration — an empty or missing security group —
  fails safe by construction, denying everything, rather than failing open.

**Non-goal for this slice, named explicitly: `remote_group_id` (a rule referencing another security
group's members rather than a static CIDR).** Real Neutron supports this; it requires re-evaluating
every dependent rule whenever group membership changes (a port joins/leaves a group), a genuinely
stateful mechanism this ADR does not design. `remote_ip_prefix`-only rules (static CIDR match) are
this slice's complete rule vocabulary — the same "smallest mechanism that satisfies the actual ask"
posture ADR-026 §2/§3 already took for zone matching. `remote_group_id` is named in Out of scope.

### 4. Multi-tenancy: `project_id` gates every create/attach, reusing the established
ownership-via-query pattern

Every `neutron_networks`/`neutron_subnets`/`neutron_ports`/`neutron_security_groups`/
`neutron_security_group_rules` row carries `project_id`. Every query scoping — "list my networks,"
"attach this port," "add this security-group rule" — filters by `project_id` **in the query itself**,
the identical pattern ADR-031 §3 established for `workloads.project_id` and ADR-016 established for
dashboard tenant isolation ("ownership check via the query itself, never a separate authorization
branch... keeps a tenant-isolation bug from being introduced as a one-off mistake in a new code
path"). Concretely:

- A port can only be attached to a workload whose `project_id` matches the port's network's
  `project_id`. Cross-project port attachment is rejected at the same validation layer that already
  checks `workloads.owner_id`/`project_id` today.
- A security group can only be attached to a port within the same project that owns the security
  group. `shared` networks (§1's `neutron_networks.shared` column) are the one deliberate exception,
  matching real Neutron: a shared network can be attached to by other projects' ports, but its
  subnets/security-groups remain owned and mutable only by the creating project — read-attach,
  not co-write.
- **This ADR is sequenced after #23, not concurrent with it**, per ADR-031 §8's own sequencing table.
  It is written against #23's design as summarized in ADR-031 §3 (a `project_id` column, a
  `project_member`/`project_admin` role pair) rather than blocking on #23's exact final shape, per the
  task briefing's instruction — if #23 lands with materially different column names or a different
  role model, this ADR's `project_id`-scoping *pattern* still applies unchanged; only the literal
  column/table names would need updating in the implementing PR.

### 5. QoS/AZ and everything ADR-031 §5 already settled: unchanged, not revisited here

ADR-031 §5's third bullet already disposed of Neutron's `qos-policies` extension and AZ-adjacent
concepts as a direct shim over ADR-025 (`tc` egress ceiling) and ADR-026 (zone constraint) — "the one
piece of the Neutron mapping that is a genuine compatibility shim over existing primitives," per that
ADR's own words, and explicitly in scope for #25's *direct* implementation, not this follow-up. This
ADR does not re-decide it. The one place it touches this ADR's scope at all: a `neutron_ports` row
*may* optionally carry a QoS policy reference for wire-shape completeness (`GET /v2.0/ports/{id}`
clients expect a `qos_policy_id` field to exist, even if null), but the actual rate-limit mechanism
underneath remains exactly ADR-025 §3's existing `tc` implementation, unchanged, keyed by workload as
it already is today — not re-keyed by port.

## Consequences

- **New Postgres schema**, under the existing single Postgres instance (no new database, matching
  ADR-031 §2's reasoning): `neutron_networks`, `neutron_subnets`, `neutron_ports`,
  `neutron_security_groups`, `neutron_security_group_rules`, `neutron_port_security_groups` (the
  many-to-many join, since Neutron allows multiple security groups per port).
- **A proto change is owed to the implementing PR**: the orchestrator's Agent-facing attach/deploy
  path needs to carry a port's resolved security-group rule set (direction, protocol, port range,
  remote CIDR) to the Agent so it can build the nftables ruleset described in §3. This ADR names the
  shape (a repeated `SecurityGroupRule`-like message) but does not pin the exact field numbers/RPC —
  that is real implementation work requiring the full consumer analysis `AGENTS.md` demands (every
  Agent build, every Control Plane build), not resolved here.
- **The Agent process's existing `CAP_NET_ADMIN` grant (ADR-025 §3) now also backs nftables rule
  application, not just `tc`.** No *new* standing privilege is requested — this is the same capability
  already granted and already documented in `deployments/` and the README's trust model per ADR-025's
  own Consequences — but the scope of what that capability is used for grows, worth a one-line update
  to that existing documentation when implemented, not a new sign-off event for the capability grant
  itself (the sign-off event is *this ADR*, for the new mechanism built on top of it).
- **`internal/wireguard`'s `Manager`/`Backend` interface is extended, not replaced.** `Allocate`'s
  `AllowedIPs` parameter, already present on `Request`, is populated from a port's IPAM-reserved
  `fixed_ip` instead of the placeholder derivation, when a `port_id` is present — a small, additive
  change to one call site.
- **Closes a pre-existing gap incidentally**: today, two workload containers on the same provider
  host can reach each other over Docker's default bridge with zero enforcement of any kind. §3's
  veth-level nftables placement closes this as a side effect of solving the security-group
  requirement correctly, for *any* port with at least one attached security group — worth calling
  out to the reviewer as a genuine, additional security improvement this design delivers, not
  originally asked for by issue #25's letter but implied by doing enforcement in the structurally
  correct place.
- Sequenced after #23 (identity/projects) per ADR-031 §8; this ADR's implementation should not start
  before #23 lands, for the same reason ADR-031 §8 gives.

## Out of scope for this ADR / this MVP slice

- **Cross-provider L2/L3 connectivity within one Neutron network.** §1 states plainly that two ports
  in the same network on different provider hosts cannot reach each other over this mechanism today
  — there is no cross-provider relay or shared hub anywhere in this codebase. A real fix is
  ADR-012 §5's Stage 2 Gateway-node work, not this ADR.
- **Floating IPs, routers, NAT, public ingress.** Matching ADR-031 §5's own deferral: "no equivalent
  exists at all" today; any floating-IP design needs its own Stage-0-appropriate narrower design (a
  Control-Plane-fronted reverse proxy per floating IP was ADR-031's own sketch, not built here
  either), explicitly distinct from the eventual Gateway-node convergence.
- **DHCP/metadata service** (`169.254.169.254`-style runtime-queried configuration). A workload
  today, and after this ADR, still receives configuration exclusively via its `WorkloadDefinition` at
  deploy time. Building a metadata service is new, unauthenticated-by-IP-alone attack surface
  reachable from inside every workload's network namespace — its own security review, not folded in
  here.
- **`remote_group_id` security-group rules** (§3) — static `remote_ip_prefix` only, for this slice.
- **IPv6.** Every address in this design is IPv4, matching ADR-010's existing `10.254.0.0/16` scheme.
- **Per-project or global network/subnet/port quotas.** Deferred to #23's `project_quotas` mechanism
  (ADR-031 §3) growing new columns, or a future ADR, if and when it's a real problem — not designed
  here, matching ADR-031 §3's own "revisit only if a real use case shows up" posture for comparable
  deferrals.
- **A formal default security group auto-created per project.** Whether/how a convenience default
  ships is implementation detail for the implementing PR to settle within §3's fail-closed
  constraint (any default must be an explicit, listed rule, never implicit), not a design decision
  this ADR needs to make.
- **Global CIDR-reuse across tenants** (§2) — this slice requires subnet CIDRs to be globally unique,
  stricter than real Neutron, pending resolution of the open question below.
- **Any implementation.** Docs only, as directed.

## Open questions for the accepting reviewer

- **§2's IPAM conservatism (globally unique subnet CIDRs, not per-tenant-unique).** This ADR could
  not fully verify from `internal/wireguard`'s current code whether `CommandBackend`'s `wg`/
  `openinfra-wireguard-attach` invocations are scoped per-provider-host in production or share one
  global address/peer namespace the way the Go-level `Manager.peers` map (unpartitioned by provider
  host) suggests. If the reviewer can confirm the production topology partitions by provider host,
  §2's global-uniqueness constraint is stricter than necessary and could be relaxed to
  per-provider-host uniqueness (closer to real Neutron's per-tenant-isolated CIDR reuse) in the
  implementing PR — flagged rather than guessed at, since guessing wrong here would either produce an
  unnecessarily restrictive design or, worse, a real collision risk.
- **The security-group enforcement point (§3) is the single most consequential decision in this ADR**
  and is exactly the part issue #170 called out as needing dedicated security review. This ADR's
  reasoning (host-side nftables on the workload veth, fail-closed default, coupled lifecycle with
  ADR-010's existing attach/detach gating) is a considered proposal, not a foregone conclusion — the
  repository owner's live review of this specific section, including the "narrows never widens"
  argument and the pre-existing same-host-bridge gap it incidentally closes, is the primary thing
  this ADR is asking for before any implementation starts.
- **Whether promoting a port to an explicit, precreated resource (§1) is worth the added complexity**
  versus keeping port creation implicit-at-deploy-time (closer to today's ADR-010 behavior, simpler,
  but a weaker match to real Neutron/Nova's "create port, then boot into it" semantics that tools like
  Terraform's `openstack` provider actually rely on). This ADR takes the explicit-port path because
  ADR-031 §1 already committed this project to genuine wire compatibility, not a conceptual mapping —
  but it is a real added-surface cost worth the reviewer's explicit weigh-in, not a free choice.

## Verification

Checked against source before writing: `docs/adr/031-openstack-compatibility-architecture.md` (full
file, especially §5 and §8's sequencing table — the direct mandate and scope boundary for this ADR);
`docs/adr/010-wireguard-workload-overlay.md` (full file — the lease-gating guarantee this ADR must
not weaken); `docs/adr/025-bandwidth-usage-reporting-and-rate-limit-enforcement.md` (full file — the
`CAP_NET_ADMIN`/host-level-enforcement/veth-scoped-teardown precedent §3 follows directly);
`docs/adr/026-availability-zone-selection.md` (full file — the "smallest mechanism," free-form-string,
and ownership-via-query precedents this ADR reuses for security-group rules and project scoping);
`control-plane/internal/wireguard/wireguard.go` (full file — `Manager`, `Backend`, `Allocate`,
`Attach`, `Revoke`, `overlayAddress`, `CommandBackend`, confirmed no network/subnet/security-group
concept exists, confirmed `AllowedIPs` defaults to a single `/32`, confirmed `peers` map is
process-wide and not visibly partitioned by provider host); `control-plane/internal/
wireguard/wireguard_test.go` (confirmed existing test shape, the seam this ADR's new mechanism should
follow); `provider-agent/crates/agent-executor/src/rate_limit.rs` (full doc comment and structure —
the `tc`/veth/`CAP_NET_ADMIN`/atomic-teardown precedent §3 mirrors exactly) and `bandwidth.rs`
(`resolve_veth_name`, confirmed the same veth resolution is shared and reusable); `grep -n
"NetworkMode|bridge|EndpointsConfig|internal.*true" provider-agent/crates/agent-executor/src/lib.rs`
(zero matches — confirmed the pre-existing same-host container-isolation gap named in § Context and
addressed by §3's enforcement-point choice); `control-plane/migrations/` directory listing (confirmed
no `neutron_*`/`projects` table exists yet); `protocol/proto/openinfra/{shared,agent,controlplane}/
v1/*.proto` (confirmed no network/subnet/port/security-group message exists); `gh issue view 170`
(full text — this ADR's direct scope, confirms the four bullet points this Decision section
addresses in order); `gh issue view 25` (full text — the parent issue's acceptance criteria,
"security groups enforced fail-closed" quoted verbatim in §3); `gh issue view 23` (full text —
confirmed identity/projects is the referenced-not-blocked-on dependency per the task briefing);
`docs/adr/` directory listing and `gh pr list --state open` (confirmed `034` is the next free ADR
number and no open PR claims it).

Refs #170. Refs #25.
