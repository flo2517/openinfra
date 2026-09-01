# ADR-038: On-chain workload scheduling and deployment authorization

## Status

Accepted (by the repository owner, explicitly, relayed in-session — after reviewing a full summary
of this ADR's decisions and their reasoning, then confirming to proceed with implementation).
Nothing here is implemented yet by this ADR itself; issue #50 (and #62's provider-reselection slice)
is unblocked by this acceptance and now carries the implementation work.

**Numbering note.** ADR-012 §6's gate table reserves this design as "ADR-019 — on-chain
orchestration," unblocking #50 and #62. `038` is the actual next-free ADR number at the time this
draft was written (`git ls-tree` against fresh `origin/main` shows `037` as the highest existing
number, content-addressed frontend distribution; no open PR claims `038`) — not `019`, for the
identical reason ADR-036 arrived as `036` instead of its own reserved `018`: ADR-012 §6's
"Consequences" policy is "an unplanned ADR always takes the next integer," not "gates are claimed
in table order," and four unplanned ADRs (`013`–`016`, then `030`–`037` in sequence) have landed
between ADR-012's reservation and this document. Every reference below to "the ADR-019 gate" means
*this* document fulfills that gate's obligation; every reference to "ADR-019" by number, if it ever
appears elsewhere, means whatever this table's *reservation* pointed at, not a document that exists.

**A second, narrower numbering note, about issue #50 itself.** Issue #50's own "Blocked by" line
reads "ADR-016 (see ADR-012 §6)". This predates ADR-012's own two numbering corrections (see
ADR-012 "Consequences," the two renumbering entries): the gate issue #50 actually depends on was
`ADR-013` at genesis, renumbered to `ADR-016` in the first correction, then to `ADR-019` in the
second correction when `ADR-016` itself was independently claimed by dashboard RBAC
(`docs/adr/016-dashboard-rbac-and-tenant-isolation.md`). Issue #50's text was never updated after
that second shift. ADR-012 §6 is the authoritative source; it names this gate `ADR-019`, arriving
here as `038`. Anyone reading issue #50's body in isolation should not go looking for a document
called `ADR-016` — it exists, and it is unrelated (dashboard RBAC, not scheduling).

## Context

Issue #50 ("Move workload scheduling and deployment authorization from the central Go Control
Plane into on-chain logic") is, in its own words, "the largest single removal of central authority
in the roadmap." It directly conflicts with `AGENTS.md`'s "runtime orchestration" prohibition,
liftable only by this gate. Issue #62 ("Add auto-healing and automatic workload migration") is
named as a second consumer of the same gate in ADR-012 §6's table; it is addressed in Decision §9
below, following the partial-gate-fulfillment precedent ADR-037 set for #58/#59 under the ADR-021
gate — this ADR fulfills one piece of #62's dependency, not all of it, stated explicitly rather
than left ambiguous.

### What actually happens today, read directly from source, not from the architecture docs

**Scheduling is Go-side integer-basis-point arithmetic, not a stub.**
`control-plane/internal/scheduler/rank.go` (472 lines) computes, per candidate provider: a resource
fit score (CPU/RAM/storage — and, if requested, bandwidth — each clamped to 0..10,000 basis points
via `fitBps`, an honest ratio of available-to-required, never inventing a live-usage number where
none exists) and a reputation score (`weightedReputationBps`, a fixed per-workload-profile weighted
sum over `pallet-reputation`'s five dimensions, read live from chain via
`ReputationSource.LatestReputationVector`). These combine via `ProfileWeights` (also fixed,
committed-to-source-control basis-point constants, one table per `WorkloadProfile`) into a single
`TotalBps` per candidate. Hard exclusions (not scored, just dropped) apply for: no advertised
endpoint, insufficient CPU/RAM/storage/bandwidth, a declared-zone mismatch against
`constraints.RequiredZone` (ADR-026 §4), `constraints.RequiresVm` without
`VirtualizationCapable` (ADR-033 §7), and `constraints.MinReputation`. Ranking sorts descending by
`TotalBps`, ties broken lexicographically by `ProviderID` — already a deterministic total order,
already integer-only, already reproducible given the same inputs. `constraints.MaxLatencyMs` and
`constraints.MaxPrice` are accepted on the wire but never enforced anywhere in this codebase
(`rank.go`'s own comment: *"there is no latency measurement or pricing signal anywhere yet... 
inventing a number to compare against would be worse than the honest gap"*).

**The inputs that feed that computation are not all on-chain today**, and this is the central
tension this ADR must resolve, not gloss over:

| Input `rank.go` uses | On-chain today? | Source today |
|---|---|---|
| Reputation vector (5 dimensions) | **Yes** — `pallet-reputation::ReputationVectors` | Chain read via `blockchainbridge` |
| Provider's *declared total* CPU/RAM/storage | **Partially** — `pallet-resource-market::Offers` has `cpu: u32, ram: u64, storage: u64`, but no bandwidth, no zone, no VM-capability | Chain (totals only) + live heartbeat (everything else) |
| Provider's *currently available* CPU/RAM/storage (total minus what's already committed to active leases) | **No** — no on-chain capacity ledger exists at all | `workloadapi.ProviderCapacity`, a Postgres-only running ledger `AssignLease` checks atomically (`internal/workloadapi/postgres.go`) |
| Declared bandwidth (ingress/egress Mbps) | **No** | Live heartbeat only (`ResourceCapability.Bandwidth`) |
| Availability zone (ADR-026) | **No** | Live heartbeat only (`ResourceCapability.zone`) |
| VM-capability (ADR-033 §7) | **No** | Live heartbeat only (`ResourceCapability.virtualization_capable`) |
| Liveness / "is this provider's Agent actually reachable right now" | **No, and cannot be** — see Decision §1 | Redis-cached heartbeat freshness, 15s cadence |

Only the reputation vector and the *declared total* offer are consensus facts today. Everything else
that makes `rank.go`'s output non-trivial — available capacity net of active leases, bandwidth,
zone, VM-capability, and liveness — is Go-side, off-chain, and in several cases (liveness) cannot
become a consensus fact at all without changing what "consensus" means. Decision §1 draws the line
precisely instead of assuming everything `rank.go` touches can simply move on-chain unchanged.

**Lease creation is already chain-anchored, but the *provider choice* it records is asserted, not
verified.** `internal/orchestrator/worker.go`'s `SCHEDULING` state calls `w.ranker.Rank(...)`
(Go-side, as above), then `w.store.AssignLease` (a Postgres atomic capacity check), then hands the
winning `ProviderID` to `LeaseRegistrar.EnsureLeaseActive`
(`control-plane/internal/blockchainbridge/registrar.go:200`). `EnsureLeaseActive` submits
`pallet_lease::create_lease(lease_id, provider, resource_hash, duration)` **signed directly by the
Control Plane's bridge account** (`registrar.go:246`, not wrapped in `Sudo` — the bridge account
*is* `ensure_signed(origin)`'s caller, i.e. `create_lease`'s `consumer`), then a second, `Sudo`-wrapped
call transitions the lease to `Active` (`registrar.go:251-256`, `T::LeaseOrigin::ensure_origin` is
`EnsureRoot`). `pallet-lease::create_lease` (`blockchain/pallets/lease/src/lib.rs:117-162`) checks
only that `provider` is lease-eligible per `T::ProviderLookup` (wired to
`pallet-provider-registry::is_active`, ADR-036 §1's bonded-and-Active gate) — it accepts *whatever*
`provider` the caller names, with no on-chain check that this was "the best" provider by any
definition. This confirms ADR-029's own finding verbatim (*"every `pallet-lease::create_lease` call
today is signed by the bridge account as `consumer`"*) from the scheduling side: the chain today
faithfully records a decision it never made and cannot verify, made entirely off-chain by one
operator's Go process. This is precisely the gap issue #50 names.

**Deployment dispatch is, and must remain, off-chain.** `worker.go`'s `DEPLOYING` state builds an
`agentv1.DeployRequest` and calls `AgentDispatcher.DeployAndConfirm`, a real gRPC round trip over
mTLS to a specific Agent process, waiting for the Agent's own confirmation before
`w.store.MarkRunning` — `AGENTS.md`'s "never report `RUNNING`... before authoritative confirmation"
rule, already enforced. No runtime pallet can perform this step: it requires a live network
connection to an off-chain process, which is exactly what `AGENTS.md`'s "no network/system access"
rule for Substrate code forbids, permanently, no ADR lifts it. The known unbounded-retry gap
(`retry()`'s `RetryPolicy.MaxAttempts`, actually already bounded since issue #138 landed —
`CLAUDE.md`'s "known gaps" note is stale on this specific point, reconfirmed by reading
`worker.go:459-480` directly: `MaxAttempts` is enforced and `MarkFailed` is the terminal state) is
otherwise correctly diagnosed: a workload whose provider died retries dispatch to that same,
chain-named provider up to `MaxAttempts` times, then gives up. This ADR's design must not change
that shape — Decision §7 says precisely what changes and what does not.

**Escrow/settlement (ADR-029, Accepted) is orthogonal by design and needs no change.** `pallet-escrow`
correlates to a lease only by `lease_id`, decoupled from `pallet-lease::consumer` specifically
*because* that field is the bridge account (ADR-029 §3). This ADR does not touch `pallet-escrow`,
does not change how `fund_escrow`/`complete_and_payout` work, and does not change what `lease_id`
means to escrow. A scheduling decision produces a `lease_id` exactly as it does today; everything
downstream of that ID is unaffected.

### What already exists in this codebase for "deterministic, bounded selection from an on-chain set" — the load-bearing precedent

`pallet-network-validator::committee` (`blockchain/pallets/network-validator/src/lib.rs:972-1005`)
already solves a structurally similar problem: select up to `TargetCommitteeSize` distinct accounts
from `ActiveValidatorSet` (a `BoundedVec<AccountId, T::MaxValidators>`, `MaxValidators = 256` in
this runtime — chosen specifically because `Validators`, the underlying `StorageMap`, "cannot be
iterated within a bounded weight," so a second, bounded, enumerable mirror is kept in step with it
on every status transition). Selection is `blake2_256((provider, round, nth))` reduced modulo the
remaining candidate count, drawing without replacement — a pure function of committed state, no
external randomness, publicly computable by any node. Its own doc comment names this as
*intentionally predictable* (no VRF exists in this codebase — confirmed by grep: no
`pallet-insecure-randomness-collective-flip` or any randomness pallet is actually wired into
`blockchain/runtime/src/lib.rs`, only present transitively in `Cargo.lock`), because committee
assignment's security rests on quorum and bonded stake, not on secrecy. This ADR reuses both halves
of that precedent directly: the bounded-enumerable-mirror-of-an-unbounded-map pattern (Decision §3)
and the "determinism is a feature here, not a limitation" reasoning (Decision §1) — inverted,
because scheduling's actual requirement (issue #50: "reproducible by any observer... no privileged
input") is the *opposite* of committee assignment's unpredictability goal. No randomness primitive,
verifiable or otherwise, is needed anywhere in this design; §1 explains why.

## Decision

### 1. What is deterministic and bounded enough for the runtime, and what stays off-chain

**On-chain, as a pure function of finalized state, no exceptions:**

- Provider eligibility: `ProviderStatus::Active` (bonded per ADR-036, not suspended,
  `pallet-provider-registry`).
- Provider's declared total capacity: `pallet-resource-market::Offers` (existing, extended — §4).
- Provider's *available* capacity: declared total minus a new on-chain running commitment ledger
  (§4) — not a live heartbeat number, a chain-committed one.
- Reputation vector: `pallet-reputation::ReputationVectors` (existing, unchanged).
- Declared zone and VM-capability: moved on-chain as part of the offer (§4) — today they are
  heartbeat-only and therefore not verifiable by an independent observer at all; a scheduling
  decision that depends on them without them being on-chain would fail "reproducible... from
  finalized chain state alone" by construction.
- The scoring function itself: `rank.go`'s exact resource-fit/reputation-weighted basis-point
  formula, reimplemented in the runtime as integer-only SCALE/`u32` arithmetic (it already is
  integer-only in Go — no float ever participates, per `rank.go`'s own header comment — so this is
  a port, not a redesign). `ProfileWeights` becomes `parameter_types!` constants, mirroring how
  `DefaultReputation`/`MaxReputation` already are runtime constants both `rank.go` and the runtime
  independently reference (`rank.go:88-97`'s own comment already names this exact
  keep-in-sync-by-hand risk for the two existing constants; this ADR does not introduce a new
  category of risk, it extends an existing one that already has no better answer in this codebase).

**Deliberately never on-chain, named explicitly rather than left to be discovered by omission:**

- **Liveness.** "Is this provider's Agent reachable right now" is not a consensus fact and cannot
  become one: it changes on a ~15s heartbeat cadence, and a chain node has no network path to a
  Provider Agent to check it directly even if it wanted to (`AGENTS.md`'s no-network-access rule for
  runtime code, permanent, no ADR lifts it). Eligibility on-chain is `ProviderStatus::Active`, a
  much coarser, slower-changing fact (bonded, not suspended) — **not** "heartbeated in the last N
  seconds." A provider whose Agent process died 10 seconds ago but has not yet been suspended
  on-chain is still `Active` and can still be selected. This is a real, accepted gap, not solved
  here: it is exactly the "provider disappearing between decision and deployment" scenario the
  acceptance criteria name a test for (§8), and it is exactly why liveness/failure-detection is
  named as its own follow-up concern for issue #62 (§9), not folded into this ADR.
- **`MaxLatencyMs`/`MaxPrice`.** Unenforced today for the same reason `rank.go` already gives — no
  signal source exists anywhere in this codebase — and moving them on-chain would not fix that; a
  chain node has no more ability to measure real network latency between an arbitrary tenant and an
  arbitrary provider than a Go process does. This ADR does not invent a proxy metric to fill the gap
  dishonestly. They stay accepted-but-inert on the wire, unchanged from today.
- **A live-usage figure for bandwidth beyond the declared total.** `rank.go`'s own doc comment
  already states there is no live-usage signal on the wire for bandwidth, only a declared ceiling;
  this ADR does not change that, and the on-chain scoring function uses the same
  declared-total-as-available convention `rank.go` already uses, honestly inheriting the same
  limitation rather than inventing a number.
- **Anything requiring the runtime to iterate an unbounded set.** Addressed structurally, not by
  exclusion — see §3.

**No verifiable randomness of any kind is needed.** The task this ADR answers requires the *opposite*
of unpredictability: "provider selection is reproducible by any observer from finalized chain state
alone." A pure, deterministic function of on-chain state already satisfies that; injecting VRF-style
entropy would make the outcome *harder* to reproduce off a given block, not easier, and would solve
a problem (unpredictability, useful for committee assignment's collusion-resistance) this design
does not have. Tie-breaking uses the same deterministic total order `rank.go` already uses today —
lexicographic ordering over `AccountId`'s SCALE-encoded bytes — ported unchanged.

### 2. Extends, replaces, or sits alongside `pallet-lease`?

**Alongside, as a new pallet, `pallet-scheduling`** (runtime index 19, next free after
`pallet-provider-slashing` at 18). `pallet-lease` is **not** extended and **not** replaced:
`create_lease`/`update_lease_state`'s signatures, storage, and every existing caller (Network
Validator flows, any manual/test lease) are untouched. This follows the exact precedent ADR-029 and
ADR-036 both set for their own new pallets, single-responsibility reasoning restated, not
re-derived: `pallet-scheduling` reads `pallet-resource-market` (capacity, zone, VM-capability, via a
new narrow trait — see §4) and `pallet-reputation` (via the existing pattern every other pallet in
this workspace already uses to avoid a hard compile dependency), and **internally** calls
`pallet_lease::Pallet::<T>::create_lease`-equivalent logic (not via the public extrinsic — a new,
non-extrinsic entry point mirroring `pallet-reputation::set_dimension_score`'s "internal-only, not a
`#[pallet::call]`" pattern, so `pallet-lease` remains the only writer of `Leases` regardless of what
triggers a new one) atomically inside its own single extrinsic. Atomicity is load-bearing: the
scheduling decision and the lease's existence must commit in the same dispatch, or a race exists
between "the chain decided provider P" and a second, concurrent `schedule_workload` call (or a
racing direct `create_lease` call) claiming P's capacity first.

**The one new extrinsic:**

```rust
pub fn schedule_workload(
    origin: OriginFor<T>,
    workload_id_hash: [u8; 32],     // sha256("openinfra-resource-v1\0" || definition || 0 || image),
                                     // the exact canonicalResourceHash worker.go already computes —
                                     // reused unchanged as the binding commitment, not reinvented
    requirements: BoundedRequirements,   // new, integer-only shape — see below
    constraints: BoundedConstraints,     // new, integer-only shape — see below
    duration: BlockNumberFor<T>,
) -> DispatchResult
```

`ensure_signed`, **permissionless** — any account, not a privileged origin. This is the load-bearing
decentralization mechanism, stated plainly: the caller supplies *inputs* (what the workload needs);
the runtime computes the *output* (which provider) as a pure function of those inputs plus already
finalized state. No argument lets a caller name, bias toward, or exclude a specific provider. The
Control Plane's bridge account remains the *only relayer that exists today*, but it is no longer the
only relayer *possible* — a second Control Plane replica (#34, still gated), a tenant with its own
key (ADR-029 already names this as required future work for escrow anyway), or any third-party
watchdog could call this extrinsic and get the identical answer, because the chain — not the caller
— picks the provider.

**Idempotency (the "replay of a stale decision" acceptance criterion):**
`ScheduledWorkloads: StorageMap<[u8; 32] /* workload_id_hash */, LeaseId, OptionQuery>`. A second
`schedule_workload` call for a `workload_id_hash` that already has an entry is a no-op that returns
the existing `lease_id` (`Ok`, not `Error::AlreadyScheduled` — idempotent, not merely rejected, so a
relayer that lost the first call's response and retries gets the same answer instead of an opaque
failure). This directly satisfies "replay of a stale decision" without inventing a new
sequence/nonce scheme: `workload_id_hash` itself is the natural idempotency key, since it is already
a commitment to the exact workload definition, and a workload is scheduled exactly once by
definition.

**Capacity exhaustion:** if no candidate in the bounded set (§3) is `Active`, satisfies every hard
constraint, and has sufficient available capacity, `schedule_workload` returns
`Error::NoEligibleProvider` and commits nothing — the direct on-chain analog of today's `NO_CAPACITY`
retry path, now computed identically by every observer instead of asserted by one Go process.

**Provider disappearing between decision and deployment (the on-chain half):** `schedule_workload`
commits capacity atomically at decision time (§4); nothing about a provider going dark *after* that
point changes on-chain state by itself. The residual gap — a lease that is `Active`, has committed
capacity, but never reaches a running deployment because the Agent is unreachable — already exists
today (worker.go's `MarkFailed` after `RetryPolicy.MaxAttempts` is Postgres-only; it does not touch
chain state at all, so an abandoned lease and its committed capacity currently persist forever with
no release path, on-chain or off). This ADR does not silently inherit that gap: `pallet-scheduling`
adds `abandon_unstarted_lease(origin, lease_id)`, **permissionless**, callable once
`DeploymentTimeout` blocks (a new governed constant) have elapsed since scheduling with the lease
still short of a deploy-confirmed marker (§7 defines exactly what marks it confirmed), releasing the
committed capacity back via the same internal call §4's `release_capacity` exposes. The orchestrator's
existing `MarkFailed` path (§7) is the intended caller once `MaxAttempts` is exhausted, closing the
capacity leak this design would otherwise reproduce, not merely avoid extending.

### 3. Weight-boundedness: a bounded linear scan, not an off-chain-worker

**The concrete shape:** `schedule_workload`'s dispatch iterates a bounded candidate set,
`SchedulableProviders: StorageValue<_, BoundedVec<T::AccountId, T::MaxSchedulableProviders>,
ValueQuery>` — a second, bounded, enumerable mirror of `pallet-resource-market::Offers` (a
`StorageMap`, unbounded, cannot be iterated within a bounded weight — the exact same reason
`ActiveValidatorSet` exists as a mirror of `Validators` today), kept in step on every
`announce_offer`/`remove_offer`/status change touching eligibility, mirroring `leave_active_set`'s
existing maintenance pattern (`network-validator/src/lib.rs:961-970`) verbatim. Cost is `O(N)` where
`N = MaxSchedulableProviders` in the worst case (every registered offer present, all eligible),
benchmarked (not stubbed — see below) as `base_weight + N * per_candidate_weight`, the same shape
`frame_benchmarking` already produces for any bounded-iteration extrinsic in this ecosystem.

**Why a bounded linear scan, not an off-chain-worker-computed-then-verified result:** the task this
ADR must answer specifically raises OCW+verification as the alternative for "pick the best from N"
when N is unbounded. It does not help here, for a concrete reason: verifying "this is really the
argmax over the real candidate set" requires re-scanning the same candidate set on-chain anyway — an
OCW cannot submit a result the chain accepts on faith (that would reopen exactly the "trust the
relayer" pattern ADR-029 §4.2 deliberately broke from for money, and this ADR should not reintroduce
it for scheduling). Verification cost for an argmax is not asymptotically cheaper than computing it
directly. An OCW would only help if N were unbounded and a *sampled* or *probabilistic* answer were
acceptable — it is not: the acceptance criteria demand an exact, reproducible answer. A bounded
linear scan is therefore strictly simpler, already the established idiom in this codebase
(`committee`'s own bound, `MaxValidators = 256`), and correct.

**Concrete `MaxSchedulableProviders` proposal: `1024`.** Grounded, not arbitrary: this runtime's only
existing precedent for "how many independently-operated accounts do we expect to enumerate on-chain
in one call" is `MaxValidators = 256` (network-validator); the local dev stack
(`deployments/docker-compose.yml`) runs exactly 3 provider agents today, the actual current
provider-count reality. `1024` is a deliberately generous multiple of the validator precedent — a
placeholder proportionate to "more providers than validators, by design, since every validator scores
many providers," not a calibrated capacity-planning figure, and named as an open question below.
**What happens past the bound is explicitly out of scope for this ADR**: a network that grows past
`MaxSchedulableProviders` needs either sharding (candidate subsets windowed by
block-number-derived indexing, the same `blake2_256`-modulo idiom `committee` already uses, applied
to *which slice* of providers a given call considers rather than to selecting one) or genuinely a
different mechanism (DHT-based discovery, #56, Stage 3) — named as real follow-up work, not solved
here, matching this ADR's own discipline of not silently overreaching into a later stage's scope.

**Weights must be benchmarked, not stubbed — stated as a hard requirement because two sibling
pallets currently fail it.** Read directly from source: `pallet-lease::WeightInfo for ()` returns
`Weight::zero()` for both extrinsics (`blockchain/pallets/lease/src/lib.rs:16-23`);
`pallet-resource-market::WeightInfo for ()` returns a flat `Weight::from_parts(10_000, 0)` for all
four (`blockchain/pallets/resource-market/src/lib.rs:14-27`) — neither is a real benchmark, both are
placeholder `impl`s used only because no `runtime-benchmarks`-gated `WeightInfo` has been generated
for either pallet yet. This ADR does not repeat that pattern for its own, more consequential surface:
`pallet-scheduling` must ship a real `benchmarks.rs` (the standard `frame_benchmarking` macro,
already available in this workspace's dependency tree) producing an honest `base + N *
per_candidate` formula for `schedule_workload`, checked into the crate the same way this workspace
already checks in every other generated artifact (protocol bindings, per `AGENTS.md`). Issue #50's
own acceptance criterion — "weights are benchmarked, not stubbed" — is treated here as inviolable
for new code, independent of whether it retroactively also flags an existing gap in `pallet-lease`/
`pallet-resource-market` (it does, but fixing pre-existing sibling pallets' stubbed weights is not
in scope for this ADR and is named separately below, not silently folded in).

### 4. Extending `pallet-resource-market`: capacity, zone, VM-capability move on-chain

`ResourceOffer<T>` (`blockchain/pallets/resource-market/src/lib.rs:59-64`) gains two fields,
additively:

```rust
pub struct ResourceOffer<T: Config> {
    pub cpu: u32,
    pub ram: u64,
    pub storage: u64,
    pub capabilities: BoundedVec<u8, T::MaxCapabilitiesLen>,
    pub zone: BoundedVec<u8, T::MaxZoneLen>,           // new; empty = undeclared, matching
                                                         // Candidate.Zone's existing "" convention
    pub virtualization_capable: bool,                   // new; false-by-default, matching
                                                         // ResourceCapability's existing
                                                         // fail-closed proto3-default convention
}
```

a genuine, if small, storage-value schema change requiring an `OnRuntimeUpgrade` migration —
flagged explicitly, the same way ADR-029 §10 flags `EscrowRecord`'s own future-field-addition
requirement, not silently assumed free. `MaxZoneLen` is a new `parameter_types!` constant (proposed
`64`, matching typical zone-name lengths, no existing bound to mirror since zone has been
heartbeat-only until now).

**New on-chain capacity ledger**, alongside `Offers` in the same pallet (natural home: it is the
"how much is left" complement to "how much is offered," and keeps `pallet-scheduling` itself free of
capacity-accounting responsibility, matching this codebase's narrow-trait-per-concern discipline):

```rust
pub struct CapacityCommitment {
    pub cpu: u32,
    pub ram: u64,
    pub storage: u64,
}
#[pallet::storage]
pub type Committed<T: Config> =
    StorageMap<_, Blake2_128Concat, T::AccountId, CapacityCommitment, ValueQuery>;
```

Two new, non-extrinsic entry points (mirroring `pallet-reputation::set_dimension_score`'s
internal-only shape): `reserve_capacity(provider, amounts) -> DispatchResult` (checked-add against
`Offers`'s totals, erroring — not saturating — on would-exceed, since silently under-reserving
capacity is a correctness bug, not a bounded display value like reputation) and
`release_capacity(provider, amounts)` (saturating-sub, since a release can never legitimately exceed
what was reserved but must not panic if bookkeeping ever drifts). `pallet-scheduling` calls
`reserve_capacity` inside `schedule_workload`'s same atomic dispatch, and `release_capacity` inside
`abandon_unstarted_lease` and (new, required) a hook on `pallet-lease`'s existing
`Active -> Completed`/`Active -> Expired` transitions — today `update_lease_state` has no such hook
at all; this ADR adds one, the minimal touch to `pallet-lease` this design needs (a call to
`pallet_resource_market::Pallet::<T>::release_capacity` from inside `update_lease_state`'s existing
match arms, gated by a new narrow trait, not a change to `update_lease_state`'s signature or its
existing transition table). Available capacity is then `Offers[p].{cpu,ram,storage} -
Committed[p].{cpu,ram,storage}` — a pure, checked-subtraction function of two already-on-chain
values, computed fresh on every `schedule_workload` call, never cached, never drifting from
finalized state the way Postgres's `ProviderCapacity` ledger structurally can (a second writer, a
second source of truth, reconciled only by convention).

**Bandwidth is deliberately not moved on-chain by this ADR.** `rank.go`'s bandwidth fit-scoring
(including its WireGuard-overhead adjustment, `WireGuardEffectiveMbps`) is real and used, but folding
it into this design would also require moving `IngressTotalMbps`/`EgressTotalMbps` on-chain and
deciding how the overlay-enabled/disabled toggle (a per-deployment Control Plane setting today, not
a chain fact) participates in a supposedly deployment-agnostic on-chain function — a second,
separable design question this ADR does not need to answer to satisfy issue #50's acceptance
criteria, none of which mention bandwidth specifically. Bandwidth-aware placement stays off-chain,
folded into the same rollback-flag "off-chain scheduler" path (§8) for any workload that requests it,
until a follow-up narrows this gap — named honestly as a real, scoped-out limitation, not hidden.

### 5. Converting the wire protocol's floats to the runtime's integers

`shared.proto`'s `ResourceRequirements.cpu` (`float`) and `WorkloadConstraints.min_reputation`/
`max_price` (`float`) can never cross into an extrinsic argument — `AGENTS.md`'s no-floats rule for
runtime code is permanent, no ADR lifts it, and this ADR does not attempt to. This is not a new
problem: ADR-029 §1 already established the precedent this ADR follows unchanged —
*"`ResourceRequirements.cpu` stays a float for scheduling fit, off-chain; billing always
integerizes."* The Control Plane, not the runtime, performs this conversion, exactly where `rank.go`'s
own `cpuMillicores()` already does it today (float32 cores → integer millicores, `int64(cores*1000 +
0.5)`). `schedule_workload`'s `BoundedRequirements`/`BoundedConstraints` arguments are:

```rust
pub struct BoundedRequirements { pub cpu_millicores: u32, pub ram_mb: u64, pub storage_gb: u64 }
pub struct BoundedConstraints {
    pub required_zone: BoundedVec<u8, T::MaxZoneLen>,   // empty = no zone constraint
    pub min_reputation_bps: u16,                         // 0..=10_000, 0 = no floor; same basis-point
                                                          // convention globalBps already uses
    pub requires_vm: bool,
}
```

`WorkloadDefinition`/`WorkloadConstraints` themselves are **not** changed — the tenant-facing proto
stays exactly as it is; this is a purely internal Control Plane conversion at the point it builds the
extrinsic call, the same boundary `rank.go`'s `cpuMillicores` already sits at today, moved one layer
lower. `max_latency_ms`/`max_price` are dropped at this boundary (never enforced anywhere, §1) —
not silently renamed, simply not passed through, consistent with their existing inert status.

### 6. The hardest question: how does an Agent — which never talks to chain — trust a scheduling decision it did not make?

Stated precisely, because hand-waving it is exactly what the task instructions forbid: once
`schedule_workload` finalizes, naming provider P for `lease_id` L, the Control Plane's orchestrator
still relays a `DeployRequest` to P's Agent over the existing gRPC/mTLS channel — nothing about that
transport changes. The question is what stops a compromised, censoring, or merely buggy Control
Plane from dispatching that `DeployRequest` to a *different* provider than the one chain state
actually names, and whether an Agent (or anyone) can catch it.

**This ADR does not grant the Provider Agent direct chain access.** `AGENTS.md`'s prohibited-list
names "direct Agent-to-chain access" as its own, separately gated item — `ADR-020`, not this one
(ADR-012 §6: *"ADR-020 — P2P mesh and DHT discovery... Must settle: peer authentication without a
central introducer"*). A narrow, single-purpose carve-out ("the Agent may read only
`pallet-lease`/`pallet-scheduling` storage, nothing else") is still a real instance of the
prohibited class, not a smaller, different one — the Agent would still need a chain connection (a
light client verifying finality, or a trusted RPC endpoint) it does not have today, and inventing
that machinery inside *this* ADR would be scope creep into a gate this document is not the accepted
door for. This ADR explicitly declines to smuggle that exception in, even though it would make the
strongest possible answer to this question.

**What this ADR does instead: the decision becomes independently reproducible and post-hoc
falsifiable by any third party, even though the Agent itself still cannot check it in real time.**
Concretely:

1. **The decision layer is fully decentralized already, per §2** — any observer with read access to
   a chain node (a second Control Plane replica, a tenant's own client, a block explorer, an
   independent auditor — anyone but the Agent, which still has none) can recompute
   `schedule_workload`'s pure function against the same finalized block and get the identical answer.
   The Control Plane is no longer a *required* source of truth for "who should run this workload" —
   it is one of arbitrarily many possible relayers of an *already-decided* fact, and it has zero
   ability to bias that fact regardless of how many replicas exist or how they behave.
2. **The *transport* leg (chain-decided provider → actual `DeployRequest` recipient) is made
   auditable, not unforgeable, by construction plus one new field.** `worker.go`'s existing state
   machine already enforces `item.ProviderID` is set exactly once (in `SCHEDULING`) and never
   mutated afterward through `LEASE_PENDING`/`LEASED`/`DEPLOYING` — so under this design, any
   legitimate execution path dispatches to the exact provider `schedule_workload` named, by
   construction, not by a check that could be bypassed. What this ADR adds: `DeployRequest` gains a
   new field, `scheduling_block_hash` (the finalized block hash `schedule_workload`'s result was read
   from — a genuine, if small, `protocol/proto` change requiring its own consumer analysis at
   implementation time, per `AGENTS.md`), purely for **audit correlation**. It does not let the Agent
   verify anything new — the Agent still has no chain access and cannot check this field itself — but
   it upgrades what an *external* auditor can do from "trust that the Control Plane's dashboard
   correctly reflects what it read from chain" to "independently re-run the same deterministic
   function against this exact, named block and compare." A divergence (the dispatched provider does
   not match what that block's finalized state names) becomes a falsifiable, reproducible claim
   anyone can check, not an assertion resting on the operator's word.
3. **`control-plane/internal/dashboard`** (already read-only, already reads finalized chain state per
   the existing README/`CLAUDE.md` health-check convention) is extended to show, per lease, both the
   on-chain-named provider (read from `pallet-scheduling::ScheduledWorkloads` → `pallet-lease::Leases`)
   and the provider Postgres records as actually dispatched — the same invariant §2 above already
   makes structurally true, now made visible for a human or automated monitor to catch the one case
   it should never diverge: a bug or compromise in the orchestrator itself.

**What this explicitly does not solve, named rather than implied by omission:** a Control Plane that
is compromised *between* reading the finalized decision and dispatching the `DeployRequest` can, in
principle, dispatch to the wrong provider (or a right provider with a tampered `Image`/resource
spec) in that one window, and no Agent-side check in this design prevents that dispatch from being
attempted — only detects it after the fact, via §6.3's audit surface. Closing that gap for real needs
either the Agent verifying independently (ADR-020's job, not this one) or a signed, block-pinned
`DeployRequest` the Agent can check against a key it already trusts without needing chain access at
all — a real, narrower alternative worth the accepting reviewer's attention, raised in Open Questions
below rather than assumed away.

### 7. What `internal/scheduler` and `internal/orchestrator` become

**`internal/scheduler/rank.go` is not deleted.** It becomes the off-chain fallback path (§8) and,
independent of that, stays the exact algorithm the runtime's `schedule_workload` ports — the two
must be kept in step by hand the same way `DefaultReputation`/`MaxReputation` already are (§1), a
real, ongoing maintenance obligation named here rather than assumed automatic. A contract test
(new, required for this ADR's implementation) asserting the Go and Rust implementations agree on a
shared table of inputs is the concrete mechanism that keeps them from silently drifting — the same
category of guard `protocolcontract` already provides for wire types, applied here to scoring logic
instead.

**`internal/orchestrator/worker.go`'s `SCHEDULING` state changes shape, `DEPLOYING`
does not.** Today: `SCHEDULING` calls `w.ranker.Rank` (Go-side decision) then
`w.store.AssignLease` (Postgres capacity check) then, in `LEASE_PENDING`, asserts that decision onto
chain via `EnsureLeaseActive`. Under this design: `SCHEDULING` instead calls a new
`SchedulingRegistrar.ScheduleWorkload(ctx, workloadIDHash, requirements, constraints, duration) ->
(leaseID, providerID, err)` — a single chain call that *is* the decision, replacing both the Go-side
`Rank` call and the separate `EnsureLeaseActive` call in `LEASE_PENDING` (which collapses into
`SCHEDULING`, since the chain call already produces an `Active`-bound lease atomically — `LEASE_PENDING`
as a distinct state may become vestigial; final state-machine shape is implementation detail, not
fixed by this ADR). `w.store.AssignLease`'s Postgres capacity check becomes redundant with §4's
on-chain ledger and is removed for the on-chain path specifically (kept, unchanged, for the
off-chain fallback path, §8) — Postgres remains authoritative for workload *lifecycle* state
(`REQUESTED`/`SCHEDULING`/.../`RUNNING`, per `AGENTS.md`'s unchanged Postgres-authoritative rule) but
is no longer the arbiter of *which provider* runs a workload once on-chain scheduling is active.
`DEPLOYING` is **completely unchanged**: it dispatches to whatever `item.ProviderID` was set to,
regardless of which path set it, exactly the "Control Plane becomes an executor of decisions the
chain already made" framing issue #50 asks for, made literal — the same function, the same retry
policy, the same `AGENT_DEPLOY_FAILED` handling, the same authoritative-confirmation-before-`RUNNING`
rule, unmodified.

### 8. Rollback: two flags, chain-side authoritative, Control-Plane-side operational

Per ADR-012 §7 ("every stage must keep its predecessor operable for one release"), the off-chain
`rank.go` path is not deleted, not deprecated in code, and stays fully tested for at least one
release after on-chain scheduling ships — the same "keep the predecessor operable" discipline
`EscrowPaused` (ADR-029 §10) already establishes for a different pallet, mirrored here structurally,
not reinvented:

- **Chain-side, authoritative:** a new governed boolean, `OnChainSchedulingEnabled: bool`
  (`pallet-scheduling`), toggled by `T::SchedulingModeOrigin = EnsureRoot` — the same reused-origin
  choice every governed toggle in this codebase already makes (`EscrowPaused`'s `PauseOrigin`,
  `SuspensionOrigin`). While disabled, `schedule_workload` returns `Error::OnChainSchedulingDisabled`
  outright — fails closed, matching `EscrowPaused`'s "no new escrow can be funded" precedent exactly.
  This is the real kill switch: if a fault in the on-chain scoring logic is discovered network-wide,
  governance halts it in one call, without redeploying any Control Plane replica.
- **Control-Plane-side, operational:** a new environment variable (this codebase's established
  opt-in convention, matching `WIREGUARD_INTERFACE`'s existing shape — `SetOverlay`/`SetWireGuardOverlayEnabled`'s
  own doc comments describe exactly this idiom), e.g.
  `OPENINFRA_ORCHESTRATOR_ONCHAIN_SCHEDULING_ENABLED`, selecting which code path `SCHEDULING`
  actually takes for a given `Worker` instance — lets one operator opt out locally (a suspected
  runtime bug affecting only their deployment, a staged rollout across Control Plane replicas once
  #34 exists) without needing a governance action.
- **Both must agree for the on-chain path to run**; either flag being "off" falls back to the
  existing `rank.go` path, never to a hard failure — matching `AGENTS.md`'s "no silent mocks, no
  placeholder success paths" instinct in the opposite direction: better to keep serving workloads on
  the proven path than to block scheduling entirely while one switch is in an unexpected state.

### 9. Interaction with issue #62 — partially fulfilled, matching the ADR-037 precedent

ADR-012 §6 names this gate as unblocking both #50 and #62. This ADR **fulfills only the
provider-*reselection* sub-piece of #62's acceptance criteria** — explicitly, following the same
partial-gate-fulfillment shape ADR-037 set for #58/#59 under the ADR-021 gate, restated here rather
than left implicit:

- **Fulfilled:** #62's "the decision to migrate is reproducible from finalized chain state...
  no privileged Control Plane input" — once *something* (#62's own future mechanism) decides a
  migration must happen, *choosing the new provider* is exactly `schedule_workload`, called again
  with the same workload's requirements. No new scheduling logic is needed for that step; this ADR's
  function is directly reusable.
- **Not fulfilled, needs #62's own follow-up ADR:** failure detection distinguishing a genuinely dead
  provider from a partitioned observer (this ADR's §1 explicitly keeps liveness off-chain and
  unaddressed); fencing (proving the old instance stopped before the new one is reported `RUNNING`);
  bounded, idempotent migration retries; persistent-volume reattachment ordering (#59); lease/payment/
  reputation consequences of a migration; and anti-gaming (a migration cannot be induced as an
  attack). None of these are scheduling problems — they are liveness-consensus, fencing, and
  lifecycle problems this ADR does not attempt to solve by extension. A pointer, not a decision: this
  codebase already has an attributable, quorum-based, on-chain-recorded liveness signal
  (`pallet-network-validator`'s availability-round machinery, ADR-011) that #62's own ADR may find a
  more natural foundation for failure detection than inventing a new one — named here as a hint for
  whoever writes that document, not a design this ADR makes on its behalf.

## Threat model

Enumerated concretely, per this codebase's own established convention (ADR-029 §9, ADR-036 §7), not
gestured at:

- **A Control Plane names a different provider than the chain decided (censorship/tampering at
  dispatch).** Not prevented in real time (§6) — detected after the fact via the audit surface §6.3
  describes. This is the primary residual risk this ADR carries forward, stated as such, not
  minimized.
- **A Control Plane withholds `schedule_workload` entirely for a specific tenant (censorship by
  omission).** Mitigated structurally, not just detected: `schedule_workload` is permissionless
  (§2) — any other relayer holding the same workload definition can submit it. A tenant with no
  alternative relayer today (no second Control Plane replica exists yet, #34 is still gated) has no
  practical alternative in the *current* topology, but the mechanism does not itself require the
  Control Plane specifically, unlike today's design where only the bridge account's signature is
  ever accepted.
- **Replay of a stale scheduling decision.** Closed by `ScheduledWorkloads`'s idempotency key (§2) —
  a second submission for an already-scheduled `workload_id_hash` returns the existing answer,
  never re-decides or double-leases.
- **Capacity exhaustion, including a race between two concurrent `schedule_workload` calls for
  different workloads.** Closed by §4's atomic `reserve_capacity` inside the same dispatch that
  selects the provider — a second call reading stale pre-reservation state simply sees reduced
  availability and, if genuinely exhausted, returns `NoEligibleProvider` rather than
  over-committing; no float, no saturating arithmetic on the reservation itself (checked, per §4).
- **A provider disappearing between decision and deployment.** Not prevented (liveness is
  structurally off-chain, §1) — bounded by the existing `RetryPolicy.MaxAttempts` at dispatch time
  (unchanged, §7) plus this ADR's new `abandon_unstarted_lease` (§2) closing the capacity-leak gap
  that path did not previously close.
- **A malicious relayer submitting a workload's requirements that do not match what the tenant
  actually authorized off-chain (e.g. understating requirements to game placement).** Out of scope
  for this ADR, same as the existing off-chain path: nothing in this codebase today cryptographically
  binds a tenant's workload submission to the resource requirements a relayer later asserts on its
  behalf (the tenant has no on-chain identity, per ADR-012 §2's own vocabulary table, restated
  unchanged by ADR-029 §3) — this ADR does not widen that gap, and closing it needs the same
  tenant-signed-key work ADR-029 §3/§12 already names as required future work for escrow, not
  something this ADR should duplicate or presuppose.
- **Weight-exhaustion / block-stuffing via many `schedule_workload` calls.** Bounded per-call cost
  (§3's benchmarked `O(N)` weight) is the standard Substrate transaction-fee/weight-limit defense
  already applicable to every extrinsic in this runtime; this ADR adds no new class of risk beyond
  what already exists for any bounded-iteration call.
- **Operator-level collusion / Sybil.** Out of scope, inherited unchanged from ADR-012 §2's
  already-accepted gap, same as every other ADR in this roadmap states for itself rather than
  claiming to solve.

## Tests required (mapping directly to issue #50's named scenarios)

1. **Success.** A `schedule_workload` call with a satisfiable candidate set selects the highest-scoring
   eligible provider, matching `rank.go`'s output for the identical input table (the contract test
   named in §7).
2. **Censorship by a Control Plane.** A second relayer (test harness account, not the bridge account)
   successfully calls `schedule_workload` for a workload the "primary" relayer never submitted,
   proving no privileged origin is required.
3. **Replay of a stale decision.** Two `schedule_workload` calls for the same `workload_id_hash`
   return the same `lease_id`/provider, and capacity is reserved exactly once, not twice.
4. **Capacity exhaustion.** A candidate set with insufficient available capacity across every
   candidate returns `NoEligibleProvider`, reserves nothing, and — a specific regression this ADR's
   own design must guard — a subsequent `schedule_workload` for a *different*, satisfiable workload
   still succeeds (exhaustion is per-candidate-availability, not a stuck pallet state).
5. **A provider disappearing between decision and deployment.** `schedule_workload` succeeds,
   commits capacity; the off-chain `DEPLOYING` dispatch fails every `RetryPolicy.MaxAttempts` attempt;
   `MarkFailed` fires; `abandon_unstarted_lease` (called from the `MarkFailed` path) releases the
   committed capacity, verified by a subsequent `schedule_workload` for a workload that now fits only
   if that capacity was actually released.

Plus, not named in the issue but required by this ADR's own design: a weight-benchmark regression
test (bounded `O(N)` cost does not silently degrade to unbounded as `MaxSchedulableProviders`
changes), and the Go/Rust scoring-parity contract test (§7).

## Out of scope

- Direct Agent-to-chain access of any kind, including a narrow, single-pallet-scoped exception —
  ADR-020's gate, not this one (§6).
- Verifiable randomness / VRF — not needed (§1), and this codebase has none wired in today regardless.
- Bandwidth-aware on-chain placement (§4) — stays off-chain, folded into the rollback path.
- `MaxLatencyMs`/`MaxPrice` enforcement — inert on the wire before this ADR, inert after it, for the
  same reason (§1, §5).
- Any change to `pallet-escrow`, `fund_escrow`, or `complete_and_payout` — orthogonal, correlated
  only by `lease_id`, unchanged (Context).
- Fixing `pallet-lease`/`pallet-resource-market`'s existing stubbed (`Weight::zero()`/flat)
  `WeightInfo for ()` implementations — a real, pre-existing gap this ADR's own review surfaced (§3),
  but not this ADR's to fix retroactively; named as follow-up hardening, not bundled in.
- Issue #62's failure detection, fencing, migration retries, volume reattachment, and anti-gaming —
  needs its own ADR (§9).
- Sharding/paginating scheduling beyond `MaxSchedulableProviders` — needs #56 (DHT discovery, Stage
  3) or its own mechanism (§3).
- A signed, Agent-checkable `DeployRequest` that would strengthen §6 without granting chain access —
  raised as an open question, not designed here.
- Changing `pallet-lease::create_lease`'s public extrinsic or removing it — it remains available for
  non-scheduling-originated leases (manual/test flows); this ADR adds a second, chain-computed path
  to reach `Active`, it does not remove the existing one.

## Consequences

- A new pallet, `pallet-scheduling`, at runtime index 19, with a new `Config` (narrow read traits
  into `pallet-resource-market`/`pallet-reputation`/`pallet-provider-registry`, a new
  `SchedulingModeOrigin = EnsureRoot`, `MaxSchedulableProviders`/`DeploymentTimeout` governed
  constants), one primary extrinsic plus `abandon_unstarted_lease`, new storage
  (`ScheduledWorkloads`, `SchedulableProviders`, `OnChainSchedulingEnabled`), and a real,
  benchmarked `WeightInfo` — sized comparably to `pallet-escrow`, this codebase's largest existing
  new-pallet precedent.
- `pallet-resource-market::ResourceOffer` gains two fields (`zone`, `virtualization_capable`),
  requiring a genuine storage migration, plus a new `Committed` capacity ledger and two internal
  entry points (`reserve_capacity`/`release_capacity`) — every existing caller
  (`announce_offer`/`remove_offer`/`announce_offer_for`/`remove_offer_for`) keeps its exact
  signature.
- `pallet-lease::update_lease_state` gains one internal hook (a call into
  `pallet-resource-market::release_capacity` on `Active -> Completed`/`Active -> Expired`) — its
  public signature and existing transition table are unchanged.
- `internal/orchestrator/worker.go`'s `SCHEDULING` state gains a second code path
  (`SchedulingRegistrar.ScheduleWorkload`) selected by a two-flag rollback mechanism (§8);
  `internal/scheduler/rank.go` is retained as both the off-chain fallback and the Go-side half of a
  new required scoring-parity contract test; `DEPLOYING` is unchanged.
- `protocol/proto`'s `agent.proto` gains one new field on `DeployRequest`
  (`scheduling_block_hash`), a real change requiring its own consumer analysis at implementation
  time, per `AGENTS.md`.
- `control-plane/internal/dashboard` gains a per-lease "on-chain-named provider vs. actually
  dispatched provider" view — new, read-only, no change to its existing authority model.
- `AGENTS.md`'s "runtime orchestration" prohibition is lifted **only** for the specific mechanism
  this ADR describes (bounded, deterministic, integer-only provider selection over already-on-chain
  state) — it does not authorize a broader class of on-chain orchestration logic, and any future
  extension (e.g. moving bandwidth-aware placement on-chain, per §4's explicit deferral) needs its
  own review against this ADR's reasoning, not an assumption that the door is now fully open.

## Open questions for the accepting reviewer

- **Is post-hoc, third-party-auditable detection (§6) an acceptable answer to the censorship/
  tampering-at-dispatch question, or does the reviewer want a stronger, real-time Agent-side check
  pulled forward** — e.g. a signed, block-pinned `DeployRequest` the Agent can verify against a key
  it already trusts (the Control Plane's mTLS cert, or a governance-published key) without needing
  chain access at all? This ADR judged that narrower mechanism as a real, separable design question
  worth its own scrutiny rather than folding it in here, but it is the single largest residual gap
  this document leaves open, and the reviewer may weigh it differently.
- **Is `MaxSchedulableProviders = 1024` the right bound**, or should it be smaller (tighter weight
  budget, matching the dev stack's actual 3-provider reality more conservatively) or explicitly
  tied to `MaxValidators` by some ratio rather than picked independently? This ADR proposes a
  round, generous placeholder, not a calibrated figure (§3).
- **Should `pallet-lease::create_lease`'s public extrinsic be restricted (e.g. to a new, narrower
  origin) once on-chain scheduling is the primary path, to prevent a lease being created outside
  `schedule_workload`'s capacity-accounting entirely** — bypassing `Committed` bookkeeping via the
  older, still-open path? This ADR leaves `create_lease` exactly as it is (§2's "out of scope") on
  the reasoning that removing/restricting it is itself a breaking change to an already-accepted
  pallet's existing consumers, but the reviewer may judge the resulting two-path capacity-tracking
  gap unacceptable even during the rollback window.
- **Should the fixing of `pallet-lease`/`pallet-resource-market`'s existing stubbed `WeightInfo for
  ()` implementations (§3, discovered incidentally while grounding this ADR) be folded into this
  ADR's implementation work, or filed as its own separate, smaller issue?** Named as a real, if
  minor, pre-existing gap this review surfaced, explicitly not this ADR's decision to make
  unilaterally.
- **Is extending `pallet-resource-market::ResourceOffer` (rather than a wholly separate storage
  item) the right home for `zone`/`virtualization_capable`, given it requires a live-pallet storage
  migration** — versus a parallel `StorageMap` in the new `pallet-scheduling` that avoids touching
  an already-shipped pallet's storage shape at all, at the cost of a second place capacity-adjacent
  facts about a provider can live? This ADR chose the smaller-surface-area option (one pallet knows
  "what a provider offers," full stop) but the migration cost is real and worth the reviewer's
  explicit weighing.

## Verification

Checked against source before writing, every file named below read in full unless noted:
`AGENTS.md` (permanent prohibitions, frozen architecture, ADR-gate framing, in full); `docs/adr/
012-decentralization-roadmap-and-trust-boundaries.md` (full file — §2 trust/threat table, §4
replay-protection convention, §6 gate table's exact "ADR-019... Unblocks #50, #62" row and both
renumbering-policy "Consequences" entries, §7 rollback rule); `gh issue view 50` and `gh issue view
62` (full text, every acceptance-criterion bullet cross-checked against a specific Decision
subsection above); `control-plane/internal/scheduler/rank.go` (full file, 472 lines — exact
fit-scoring/reputation-weighting formulas, `ProfileWeights`, exclusion reasons, the
`cpuMillicores`/basis-point-only-arithmetic convention this ADR's §5 conversion follows); `control-
plane/internal/orchestrator/worker.go` (full file, 803 lines — `processOne`'s full state machine,
`retry`/`backoffFor`'s actually-bounded shape correcting `CLAUDE.md`'s stale note, `rankableCandidates`,
`canonicalResourceHash`); `control-plane/internal/blockchainbridge/registrar.go` (`EnsureLeaseActive`/
`EnsureLeaseCompleted` in full, lines 1-260+ — confirmed the bridge account is `create_lease`'s
direct signer, not `Sudo`-wrapped, and `update_lease_state` is); `blockchain/pallets/lease/src/lib.rs`
(full file, 206 lines — `create_lease`/`update_lease_state`'s exact bodies, transition table,
`ProviderLookup` trait, stubbed `WeightInfo for ()`); `blockchain/pallets/resource-market/src/lib.rs`
(full file, 178 lines — `ResourceOffer`'s exact fields confirming no zone/VM-capability/availability
tracking exists, stubbed `WeightInfo for ()`); `blockchain/pallets/provider-registry/src/lib.rs`
(full file, 625 lines — ADR-036's bonding/`ProviderStatus::Active` gate this ADR's eligibility check
reuses unchanged); `blockchain/pallets/reputation/src/lib.rs` (full file, 404 lines — `ReputationVector`'s
exact shape, `set_dimension_score`'s internal-only pattern this ADR's own internal entry points
mirror); `blockchain/pallets/network-validator/src/lib.rs` (module doc, `Config`, `ActiveValidatorSet`
lines 290-296, `committee`/`is_assigned`/`leave_active_set` lines 960-1010 read in full — the
bounded-deterministic-selection precedent this ADR's §1/§3 build on directly); `blockchain/runtime/
src/lib.rs` (pallet index list lines 143-190 confirming next-free index 19, every relevant
`parameter_types!` constant including `MaxValidators = 256`/`MaxCapabilitiesLen = 256`, confirmed no
randomness pallet is actually wired into `construct_runtime` despite an indirect `Cargo.lock`
dependency); `docs/adr/029-metering-billing-escrow-settlement.md` (full file — the bridge-account-
is-`consumer` finding this ADR's Context reconfirms from the scheduling side, the float-to-integer
conversion precedent §5 follows, the `EscrowPaused` rollback-flag precedent §8 follows, its own
"Verification"/"Open questions" section format this ADR follows); `docs/adr/
036-provider-slashing-economics.md` (full file — the numbering-note precedent this document's own
numbering note follows, the new-pallet-not-extension reasoning §2 follows, its own threat-model and
open-questions format); `docs/adr/037-content-addressed-frontend-distribution.md` (partial-gate-
fulfillment precedent §9 follows for #62); `protocol/proto/openinfra/shared/v1/shared.proto`
(`ResourceCapability`/`ReputationVector`/`WorkloadDefinition`/`ResourceRequirements`/
`WorkloadConstraints`/`Lease`/`EventEnvelope` message definitions — confirmed every float field this
ADR's §5 must convert around, confirmed `Lease`/`EventEnvelope` have no fields this ADR needs to
change); `deployments/docker-compose.yml` (grepped — confirmed 3 provider-agent instances in the
local dev stack, the actual current provider-count reality §3 cites); `CLAUDE.md` (full file, the
task's own binding context, including its "known gaps" section whose unbounded-retry claim this
ADR's Context corrects against direct source reading).

Refs #50. Related: #62 (auto-healing — partially unblocked, §9), ADR-012 (§6 gate table — this
document is the ADR that gate names, arriving as `038` rather than `019`), ADR-011 (Network Validator
committee-selection precedent this ADR's determinism argument and bounded-iteration mechanism both
reuse directly), ADR-026 (availability zones — the trust boundary `required_zone` moving on-chain
inherits unchanged: still a self-declared, unverified fact, same class as bandwidth and price),
ADR-029 (escrow/settlement — orthogonal, unchanged, correlated only by `lease_id`; also the direct
precedent for §5's float-to-integer conversion and §8's rollback-flag mechanism), ADR-033 (VM
execution backend — `virtualization_capable`'s existing fail-closed convention, preserved moving
on-chain), ADR-036 (provider bonding/`ProviderStatus::Active` — the eligibility gate this ADR's
on-chain scheduling reuses unchanged, and the new-pallet/numbering-note precedent this document's
own structure follows), ADR-037 (partial-gate-fulfillment precedent for #62, §9).
