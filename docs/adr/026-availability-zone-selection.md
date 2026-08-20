# ADR-026: Availability zone selection for workload placement

## Status

Accepted (by the repository owner, explicitly, relayed in-session — after reviewing a full summary
of this ADR's decisions and their reasoning, then confirming to proceed with implementation).

## Context

Issue #73's original acceptance criteria listed "regional endpoint selection" as one of five
remaining gaps in bandwidth/network handling. ADR-025 §4 settled four of the five (multi-point
probing, signed usage summaries, `tc` rate-limit enforcement, WireGuard overhead) and disposed of
"regional endpoint selection" as a parameter-level fix: feed the Network Validator's
already-measured RTT into the scheduler's existing fit-scoring, no new wire field. A PR built
exactly that (#127, closed without merging): a new `submit_network_latency` extrinsic pair, trimmed
mean aggregation, a `LatestNetworkLatency` running value, `MaxLatencyMs` becoming a hard exclusion
when latency is known. It was rejected because it solves the wrong problem. "Regional endpoint
selection" in an infrastructure-scheduling context is the ordinary AWS/GCP/Azure feature: a
workload names an availability zone or region and is placed only on a provider in that zone. It is
a **placement constraint the requester declares**, not a network-quality signal a validator
measures. RTT-based latency-awareness is a real, separate, still-open idea (routing toward a
*faster* provider), but it is not what "select a region" means anywhere else in cloud
infrastructure, and it is not what was being asked for here.

This ADR supersedes ADR-025 §4's "regional endpoint selection" paragraph with the correct framing
and builds it. ADR-025 §4's WireGuard-overhead paragraph is unaffected and remains as-is. RTT-based
latency-awareness (what PR #127 built) is named explicitly in "Out of scope" below as a distinct,
possible future ADR — not resurrected here under a different name.

Verified before writing, to ground every decision below in what actually exists rather than
assumption:

- **Nothing on the wire carries a zone/region today.** `protocol/proto/openinfra/shared/v1/
  shared.proto`'s `ResourceCapability`, `ResourceRequirements`, and `WorkloadConstraints`
  (`max_latency_ms`, `min_reputation`, `max_price`) have no such field. `agent-core::AgentSettings`
  has no such field either. This is a genuine new wire-protocol addition, not wiring up something
  already declared but unused.
- **The bandwidth precedent is the closest analog, and it resolves cleanly to a heartbeat-carried
  field.** `AgentSettings::bandwidth_ingress_mbps`/`bandwidth_egress_mbps` are operator-configured,
  with this exact reasoning in their doc comment: *"real link speed generally isn't
  auto-detectable in virtualized/cloud environments... this is operator-configured, the same trust
  boundary as the price/reputation claims a provider already self-declares."* A zone/region is even
  less auto-detectable/verifiable than link speed. Tracing the actual data flow:
  `agent-cli`'s `resource_capability()` (`provider-agent/crates/agent-cli/src/main.rs`) builds a
  fresh `ResourceCapability` — cpu/ram/storage from live inventory, bandwidth from config — on
  **both** `CompleteJoin` and **every** `ReportHeartbeat`, so the two call sites can never drift.
  On the Control Plane side, `agentmanager.Directory.ListSchedulableProviders`
  (`control-plane/internal/agentmanager/directory.go`) builds each `SchedulableProvider.Capabilities`
  from the **most recent Redis heartbeat payload**, not from the `Capabilities` blob persisted to
  Postgres at join time (that Postgres copy is written once, at `CompleteJoin`, and never read again
  for scheduling — confirmed in `control-plane/internal/providerjoin/service.go`). So
  `ResourceCapability` is, in practice, a live, redeclarable-every-heartbeat structure, not a
  fixed-at-registration one, for every field already on it including bandwidth.
- **`ResourceCapability` has no env-var override; it is config-file only.**
  `apply_executor_env_overrides` in `agent-cli/src/main.rs` only overrides the four `ExecutorSettings`
  fields (`max_workloads`, `max_cpu_cores`, `max_memory_mb`, `pids_limit`, `max_egress_mbps`) plus
  itself; `bandwidth_ingress_mbps`/`bandwidth_egress_mbps` (on `AgentSettings`, the same struct a
  zone field would join) have no `OPENINFRA_AGENT_*` equivalent — an operator edits `config.yaml`
  and restarts, or waits for the next config reload if one exists. There is no established
  precedent to break here by not adding an env override for zone either.
- **The scheduler's hard-exclusion shape already exists and is the right template.**
  `internal/scheduler/rank.go`'s `scoreOne` hard-excludes on `constraints.MinReputation` (a
  workload's floor) and on insufficient CPU/RAM/storage/bandwidth (a workload's requirement) by
  returning `(Score{}, true, reason)` before any score is computed — never a soft penalty. It
  explicitly does *not* yet enforce `MaxLatencyMs`/`MaxPrice`, with a comment pointing future
  implementers at exactly this spot: *"constraints.MaxLatencyMs and constraints.MaxPrice are
  accepted but not enforced... inventing a number to compare against would be worse than the
  honest gap. They are wired through the constructor and this comment specifically so the next
  person adding either signal has one place to look."* Zone is the first of these three
  currently-inert constraint fields to actually get enforced, and follows the same shape as the
  already-enforced `MinReputation` check, not the still-deferred latency/price ones.
- **`Candidate.HasReputation` is the established "field genuinely absent, not zero" convention**:
  a provider with no on-chain reputation record is treated as neutral-default, not
  zero-and-penalized. The zone case is different in kind, reasoned about explicitly in Decision §4
  below, because unlike reputation (which a provider cannot self-declare before the chain assigns
  it), zone is entirely provider-declared, available from the provider's very first heartbeat, at
  zero cost to declare.
- **Nothing on-chain carries this either.** `blockchain/pallets/provider-registry/src/lib.rs`'s
  `Provider<T>` struct has no region/zone field, and this ADR does not propose adding one —
  consistent with bandwidth capacity, which also never went on-chain.
- **Exclusion reasons are already collected but not surfaced to the requester today.**
  `scheduler.Decision.Excluded` carries a per-candidate `Reason` string, but
  `orchestrator.Worker.processOne` (`control-plane/internal/orchestrator/worker.go`) only surfaces
  the *count* on a `NO_CAPACITY` failure (`"no eligible provider (%d candidates excluded)"`), never
  the individual reasons. Better zone-mismatch error messaging is therefore not just "add a field"
  — it needs this existing gap closed too, noted honestly in Decision §3 rather than assumed away.

## Decision

### 1. The provider declares its zone on `ResourceCapability`, re-sent every heartbeat

Add a field to `ResourceCapability`:

```protobuf
message ResourceCapability {
  float cpu_total = 1;
  float cpu_available = 2;
  int64 ram_total_mb = 3;
  int64 ram_available_mb = 4;
  int64 storage_total_gb = 5;
  int64 storage_available_gb = 6;
  GPUCapability gpu = 7;
  Bandwidth bandwidth = 8;
  string zone = 9;
}
```

Mirrored on `agent-core::AgentSettings` as `pub zone: String` (`#[serde(default)]`, default `""`),
following `bandwidth_ingress_mbps`'s exact pattern: operator-configured in `config.yaml`, no env-var
override (matching bandwidth, not the `ExecutorSettings` fields that do have one), read into
`resource_capability()` on every `CompleteJoin`/`ReportHeartbeat` call.

**Why `ResourceCapability`, not identity-adjacent data fixed at Join:** the alternative — zone set
once at `CompleteJoin`, immutable afterward, next to `NodeIdentity` — was seriously considered,
since a zone conceptually feels more like "where this machine is" than "what it can currently do."
It was rejected for two reasons specific to this codebase, not in the abstract:

1. **It fights the grain of how `ResourceCapability` already works.** Every other field on this
   message — including the one architecturally closest to zone, bandwidth — is already
   redeclared every heartbeat and read live from Redis, never from the Postgres join-time copy.
   Making zone the one field on this message that is instead fixed-at-Join and immutable would be
   a special case future maintainers have to remember, for no benefit this ADR can identify: the
   heartbeat-carried field already gets everything the identity-fixed version would, at zero extra
   mechanism.
2. **An operator legitimately needs to correct a wrong zone declaration**, and the two realistic
   cases split differently: a data-entry mistake at first setup (should be fixable immediately, not
   worth a leave/rejoin cycle) and a provider that physically relocates (rare, but the same
   "worth explaining in an audit log" property a mistake fix has, and there is no `UpdateProvider`
   RPC or config-mutation audit trail anywhere in this codebase today for *any* field — including
   bandwidth — to attach that to). Making zone Join-fixed would not solve the audit-trail gap
   (bandwidth has the identical gap already and nobody has needed to solve it yet); it would only
   add friction to the common case (typo fix) without buying anything for the rare one
   (relocation). If provider-identity change auditing becomes a real need later, it is a
   cross-cutting concern for every self-declared field (price, bandwidth, zone, reputation-adjacent
   claims), not a reason to special-case zone alone.

Consequence, stated plainly: a provider can change its declared zone between one heartbeat and the
next, and the scheduler will honor the new value on its very next ranking pass (heartbeats land
every ~15s). This is the same trust boundary bandwidth already has — nothing about zone makes a
provider more likely to lie about it than about price, reputation, or bandwidth, and this ADR does
not attempt to change that trust boundary.

### 2. The workload requests a zone via a new `WorkloadConstraints` field, flat and exact-match

```protobuf
message WorkloadConstraints {
  int32 max_latency_ms = 1;
  float min_reputation = 2;
  float max_price = 3;
  string required_zone = 4;
}
```

Semantics: `required_zone == ""` (the proto3 default, unset) means "no zone constraint, any zone —
including a provider with no declared zone — is fine," matching how `max_latency_ms == 0` already
means "unset" on this same message. A non-empty `required_zone` is matched against the candidate's
`ResourceCapability.zone` by **exact string equality**, case-sensitive, no normalization, no
hierarchy. `"us-east"` does not match `"us-east-1a"`; they are different opaque strings.

This is deliberately the simplest thing that satisfies "let a workload choose a zone." A hierarchy
(region containing zones containing racks, `"us-east"` matching `"us-east-1a"` via prefix or a
parent/child table) was considered and set aside: it requires a taxonomy decision (who defines the
tree, where it's stored, how a provider or workload picks a level) that nothing in this codebase
needs yet — there is exactly one caller of zone matching today (this ADR's own scheduler rule), no
existing multi-level location data anywhere in the schema, and no workload use case in front of
this ADR that a flat string doesn't already satisfy. Named explicitly as future work in "Out of
scope," not solved speculatively here.

### 3. Validation: free-form string, not a Control-Plane-enforced allowlist — for this first slice

Two options were weighed:

- **A small operator-configured allowlist**, validated by the Control Plane at heartbeat/submission
  time (reject an unrecognized zone outright). Cleaner UX in principle (a typo is caught
  immediately, at the source, with a clear error) but requires new config surface (where does the
  allowlist live — an env var, a config file, a chain-governed list?), a migration path for adding a
  new zone name later, and — critically — a decision about *who* is authoritative for the set of
  valid zones in a network of independent, permissionless providers. That authority question is
  exactly the kind of new governance surface `AGENTS.md` requires its own ADR for, and doesn't have
  an obvious answer yet (unlike, say, `EnsureRoot` governance, which ADR-023 is explicitly gated for
  future work — zone-allowlist governance would be a smaller instance of the same open question).
- **A free-form, opaque, operator-defined string**, exactly matched. Simplest possible mechanism,
  zero new governance surface, consistent with how price and bandwidth are already free-form
  operator declarations with no Control-Plane-side allowlist. The known cost: a typo (`"us-eas"` vs
  `"us-east"`) on either the provider or the workload side silently produces "no eligible provider,"
  with no signal of *why*.

This ADR takes the free-form string, for the same reason §2 took the flat/exact-match structure:
it's the smallest mechanism that satisfies the actual ask, and a permissionless network of
independently-operated providers has no natural single authority to own an allowlist yet. The typo
risk is real, not hand-waved, so this ADR pairs it with a mitigation that is honest about being
partial:

**Error messaging.** `orchestrator.Worker.processOne`'s `NO_CAPACITY` path
(`control-plane/internal/orchestrator/worker.go`) today only reports *how many* candidates were
excluded, discarding `scheduler.Decision.Excluded[i].Reason` entirely — this predates zone and
affects every existing exclusion reason (insufficient CPU, below-minimum reputation, etc.), not
something this ADR introduces. This ADR's implementation should extend that failure path to
include the *distinct* `Reason` strings actually seen (bounded — e.g. deduplicated, capped) rather
than only the count, and specifically: when every exclusion reason is a zone mismatch, surface the
**set of zones actually declared among the excluded candidates** (e.g. `"no eligible provider: 3
candidates excluded — requested zone \"us-eas\" matched none; zones present: us-east, us-west,
eu-central"`). This directly answers "why did my request fail" without a Control-Plane-owned
allowlist. It is a small, mechanical extension of data the ranker already collects — not a new
subsystem — but it is real implementation work this ADR is naming explicitly rather than assuming
away, since today's `NO_CAPACITY` message would otherwise give a zone typo zero signal beyond "some
candidates were excluded."

### 4. Scheduler: hard exclusion, same shape as `MinReputation`, no neutral-default for zone

In `scoreOne` (`internal/scheduler/rank.go`), add a check ahead of (or alongside) the existing
`MinReputation` check:

```go
if constraints != nil && constraints.RequiredZone != "" && candidate.Zone != constraints.RequiredZone {
    return Score{}, true, "zone mismatch"
}
```

with `Candidate` gaining a `Zone string` field, populated in `rankableCandidates`
(`control-plane/internal/orchestrator/worker.go`) from `p.Capabilities.Zone`, alongside the existing
CPU/RAM/storage/bandwidth extraction.

**A provider with no declared zone (`Zone == ""`), when a workload requests a specific zone: is
excluded.** This is the one place this ADR's reasoning diverges from the superficially similar
`HasReputation` neutral-default convention, and the divergence is deliberate, confirmed against the
actual heartbeat/registration flow rather than assumed:

- `HasReputation` is neutral-default because reputation is *chain-assigned*, not
  provider-declared — a brand-new provider has a real timing gap (chain hasn't scored it yet)
  between "joined" and "has a reputation record," through no choice of the provider's own. Treating
  that gap as a penalty would punish newness, not dishonesty.
- Zone has no equivalent timing gap. It is available, at zero cost, from a provider's very first
  heartbeat — the same config-file field bandwidth already is. A provider with `zone == ""` made
  that choice (or its operator never filled it in), not something the system withheld from it. It
  cannot satisfy an explicit "run this in zone X" request it has no answer for, and treating that as
  "neutral, matches anything" would silently place a workload somewhere the requester explicitly
  did not ask for — the opposite of what "let a workload choose a zone" means. Excluding it is the
  only reading consistent with the feature actually being requested.
- This also means: a workload that does **not** set `required_zone` is completely unaffected —
  every candidate, zoned or not, is eligible exactly as today. The exclusion only activates when a
  workload makes an explicit request, matching the `max_latency_ms == 0` / `MinReputation == 0`
  "unset means no constraint" convention already established on this same message.

### 5. Consumer analysis (proto change, `AGENTS.md` requirement)

Two independent skew directions, both proto3 default-value forward-compatible:

- **New wire field, old binary reading it:** an old Agent build that has never heard of `zone`
  simply never sets it; the Control Plane reads it as `""` (proto3's unset-string default,
  indistinguishable on the wire from an explicit empty string — the same ambiguity `max_latency_ms
  == 0` already lives with, not a new class of problem). A workload with no `required_zone` is
  unaffected. A workload that *does* request a zone will exclude every old-build provider (correct:
  it declared no zone, per §4's reasoning) — this is the intended behavior, not a compatibility
  bug, and it degrades gracefully: existing deployments with no zone-requesting workloads see zero
  behavior change.
- **New field sent, old binary not reading it:** a new Agent build reporting a real zone value,
  talking to an old Control Plane binary that has not been rebuilt against the updated `.proto` —
  proto3 unknown fields are preserved-but-ignored by the generated code in both Go and Rust
  (neither language's generated bindings reject an unrecognized field number by default), so the
  old Control Plane keeps scheduling exactly as it does today, with no `required_zone` constraint
  available to enforce because the corresponding scheduler code doesn't exist yet either. No crash,
  no behavior change beyond "the new field is inert until both sides are upgraded" — the same
  posture ADR-025 §2 documented for its own heartbeat field addition.

Every consumer of `ResourceCapability`/`WorkloadConstraints` identified and accounted for above:
`agent-cli::resource_capability()` (producer), `providerjoin.validateCapabilities`/
`validateCompleteJoin`/`validateHeartbeat` (Control Plane ingestion — needs no new validation logic
beyond accepting the field; a free-form string has no format to reject per §3), `agentmanager.
Directory.ListSchedulableProviders` (pass-through), `orchestrator.rankableCandidates` (new
`Candidate.Zone` extraction), `scheduler.scoreOne` (new hard-exclusion rule), and
`internal/protocolcontract` (contract-conformance tests — needs a new case, per existing pattern).

### 6. Out of scope for this first slice

- **A formal zone/region taxonomy or hierarchy** (region containing zones, prefix or parent/child
  matching such as `"us-east"` matching `"us-east-1a"`). §2 explains why a flat opaque string is
  sufficient today; revisit only if a real multi-level use case shows up.
- **Multi-zone provider declarations** (a provider spanning or serving more than one zone). Today's
  `zone` is a single string; a provider that genuinely operates across zones would need either
  multiple registrations or a repeated field — not designed here, no evidence yet that any real
  provider needs this.
- **A Control-Plane-owned or chain-governed zone allowlist.** §3 explains why free-form is this
  slice's answer; an allowlist is a governance question (who is authoritative for valid zone names
  in a permissionless network) deserving its own ADR if it becomes a real problem, not a default
  reached for preemptively.
- **Zone-aware pricing.** Nothing here changes `max_price`/pricing logic; a provider is free to
  price by zone already (zone is just another operator-declared fact), but no mechanism here
  reads zone for pricing purposes.
- **RTT-based/latency-aware scheduling** (what PR #127 built and this ADR's Context section
  explains was the wrong reading of "regional endpoint selection"). Choosing the *fastest* provider
  via validator-measured RTT is a real, different, still-open idea — it answers "which provider is
  closest to me," not "run this in the zone I named" — and would need its own ADR if pursued. This
  ADR does not build any part of it, and does not repurpose `MaxLatencyMs` (still explicitly
  unenforced, per the comment in `scoreOne` this ADR leaves untouched).
- **Zone-based reputation or Reward Points weighting.** Zone is a placement constraint only; it
  does not feed `pallet-reputation` or `pallet-rewards` in any way.
- **Cross-zone latency estimation.** Distinct from both the above — estimating the network cost of
  a workload's *dependencies* being in a different zone than the workload itself. Not attempted;
  no cross-workload topology model exists anywhere in this codebase today.

## Consequences

- `ResourceCapability` and `WorkloadConstraints` both gain a new field — a proto change, consumer
  analysis is above; `buf generate` output (`protocol/generated/go`, and the Rust bindings built at
  `provider-agent` build time) must be regenerated and committed as part of the implementing PR,
  with `git diff --exit-code -- protocol/generated` passing in CI per the existing protocol job.
- `agent-core::AgentSettings` gains a `zone: String` field (config-file only, no env override,
  matching bandwidth) — a `config.yaml` schema change, non-breaking (`#[serde(default)]`, an
  existing config file with no `zone` key continues to parse and defaults to `""`, i.e. "no zone
  declared").
- `scheduler.Candidate` gains a `Zone` field and `scoreOne` gains a new hard-exclusion branch —
  behavior change only for workloads that set `required_zone`; every existing workload/test that
  never sets it is unaffected (proto3 default `""` short-circuits the new branch immediately).
- `orchestrator.Worker.processOne`'s `NO_CAPACITY` error path should be extended to surface
  distinct exclusion reasons (not just a count) as part of implementing §3's error-messaging
  mitigation — a small, real piece of implementation work this ADR calls out explicitly rather than
  leaving implicit.
- ADR-025 §4's "regional endpoint selection" paragraph is superseded by this ADR; its
  WireGuard-overhead paragraph is unaffected. This ADR should be cross-linked from ADR-025 (a
  one-line "superseded by ADR-026, see there" note) when this ADR is accepted, so a reader of
  ADR-025 alone is not misled into thinking the RTT-based design is still the plan.
- Closes issue #73's last remaining acceptance-criteria item, once implemented.

## Verification

Checked against source before writing: `protocol/proto/openinfra/shared/v1/shared.proto`
(`ResourceCapability`, `ResourceRequirements`, `WorkloadConstraints`, `NodeIdentity` — full text);
`provider-agent/crates/agent-core/src/lib.rs` (full file — `AgentSettings`, `ExecutorSettings`,
`Default` impls, doc comments); `provider-agent/crates/agent-cli/src/main.rs`
(`resource_capability()`, `apply_executor_env_overrides`, `parse_env`, `load_config`);
`control-plane/internal/providerjoin/service.go` (`CompleteJoin`, `ReportHeartbeat`,
`validateHeartbeat`, `validateCompleteJoin`, `validateCapabilities` — confirms Postgres
`Capabilities` is write-once-at-join, never re-read for scheduling); `control-plane/internal/
agentmanager/directory.go` (`SchedulableProvider`, `ListSchedulableProviders` — confirms live
Redis-heartbeat sourcing, not Postgres); `control-plane/internal/scheduler/rank.go` (full file —
`Candidate`, `scoreOne`, the `MinReputation`/`HasReputation` patterns, the
`MaxLatencyMs`/`MaxPrice` "accepted but not enforced" comment); `control-plane/internal/
orchestrator/worker.go` (`processOne`, `rankableCandidates` — confirms `Decision.Excluded` reasons
are collected but not surfaced today); `blockchain/pallets/provider-registry/src/lib.rs`
(`Provider<T>` — confirms no region/zone field on-chain); `docs/adr/025-bandwidth-usage-reporting-
and-rate-limit-enforcement.md` (full text, the ADR whose §4 this supersedes); `docs/adr/
015-bandwidth-throughput-measurement.md` (full text, structural precedent); PR #127 (closed,
unmerged — the rejected RTT-based reading) and issue #73's comment history (confirms "regional
endpoint selection" is the sole remaining item).

Refs #73. Related: ADR-025 (§4's regional-endpoint-selection paragraph superseded by this ADR;
§4's WireGuard-overhead paragraph unaffected), ADR-015 (bandwidth measurement, the closest
structural precedent for a provider self-declared, unverified capability field).
