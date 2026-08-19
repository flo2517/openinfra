# ADR-026: Network latency evidence and scheduler latency-awareness

## Status

Proposed.

## Context

Issue #73's last remaining acceptance criterion is ADR-025 §4's "regional endpoint selection."
ADR-025 §4 assumed the plumbing to get a validator-observed round-trip time (RTT) from a
`MeasureBandwidth` probe to the Control Plane's scheduler already existed, and that closing the
gap was "a parameter on an existing mechanism." Re-checking against the real code (this ADR's own
research, and a prior same-session investigation) shows neither half of that assumption holds:

- **The RTT is computed and thrown away.** `control-plane/internal/networkvalidator/bandwidth.go`'s
  `callMeasureBandwidth` returns a real `elapsed time.Duration` per probe. It is used only inside
  `runOneBandwidthProbe` to compute `estimateThroughputMbps` (splitting elapsed time between
  ingress/egress proportionally to byte count) and is never returned, stored, or carried into
  `bandwidthProbeOutcome`, `ChallengeResult`, or `submit_evidence`. There is no RTT anywhere
  on-chain today, for any dimension.
- **There is no channel from validator to scheduler except the chain.** ADR-013 §1 states
  `cmd/networkvalidator` "needs no Postgres/Redis" as a deliberate property: it is an independently
  operated binary with its own chain-signing key, not part of the Control Plane's process or
  database boundary. A validator writing latency data to Postgres/Redis directly would break that
  already-accepted invariant, not just add a mechanism alongside it.
- **`submit_evidence` is shared by all five `ScoreDimension`s**, not Network-specific
  (`blockchain/pallets/network-validator/src/lib.rs`). `Submission { validator, score_bps,
  sample_count, payload_hash }` and `RoundResult { score_bps, previous_score_bps, submissions,
  committee_target, closed_at, status }` have no field for a raw millisecond figure — a
  `0..10_000` basis-point score means something different from a latency measurement, and neither
  type has room to add one without a decision about what Compute/Storage/Availability/Reliability
  submissions do with it.
- **`internal/scheduler/rank.go` already has a `constraints.MaxLatencyMs` field wired through and
  explicitly unused.** Its own comment: *"this system has no latency measurement or pricing signal
  anywhere yet... inventing a number would be worse than the honest gap. They are wired through the
  constructor and this comment specifically so the next person adding either signal has one place
  to look."* This ADR is that follow-up for the latency half.
- **There is no cheap "current RTT for provider X" lookup today**, and the existing precedent for
  "cheap current value" vs. "expensive history scan" matters for this decision (§4 below).

**A scope correction found while researching, stated plainly:** ADR-025 §4 calls this "regional
endpoint selection," but nothing in this codebase carries a *region* anywhere — not on
`ResourceCapability`, not on `WorkloadRequirements`, not on a validator's own identity, not
anywhere on the wire. A validator's committee assignment (`committee(provider, round)`) is drawn
from the single global `ActiveValidatorSet`, with no geographic dimension. Building true regional
selection — routing a workload to the provider *closest to that specific workload's origin* —
would require a wire-protocol change to carry a requester/workload region and a
provider-region tag, a materially larger feature than "feed a validator-observed RTT into scoring."
This ADR does **not** build regional endpoint selection. It builds the substantially smaller thing
ADR-025 §4's own decision text actually described doing — "feed the most recent measured RTT into
the scheduler's existing scoring inputs" — as a general, single-scalar network-quality signal
observed by whichever validators happen to be assigned to a provider, not a per-requester regional
match. True region-aware routing is named explicitly as future work in "Out of scope" below, and
would need a further ADR of its own (a new committee-assignment dimension, a wire-protocol region
tag, and a very different scoring model) — it is not a smaller version of what follows.

## Decision

### 1. Where RTT is recorded on-chain: a new, Network-only mechanism, not an extension of `submit_evidence`

Two options were weighed:

**A. Extend the shared envelope** (`Submission`/`RoundResult` gain an `Option<u32> rtt_ms` field,
`submit_evidence` gains a parameter). `Option<u32>` is `MaxEncodedLen`-compatible (frame_support's
blanket impl), so non-Network dimensions could cleanly submit `None` rather than needing an
in-band sentinel — this resolves §5's "distinguish never-measured from measured-as-zero" concern
correctly. But it still touches: `submit_evidence`'s signature and every one of its ~10 existing
call-site tests in `tests.rs`; `trimmed()`'s aggregation (a second reduction is needed since
`Option<u32>` values can't feed the same `u32` sum `score_bps` uses); `RoundResult`'s fixed byte
width and `decodeRoundResult`'s length check; `encodeSubmitEvidenceCall`'s pinned byte layout and
its test; and `roundresult_test.go`. That is real, broad surface for a field that is meaningful for
exactly one of five dimensions.

**B. A new, Network-only extrinsic and storage, alongside `submit_evidence`.** Duplicates some
logic (an active-validator check, an assignment check, a duplicate-submission check, a bounded
quorum-gated close) but touches **zero** existing types, call indices, or tests. Critically, the
duplication is smaller than it first appears: `committee(provider, round)` is already
**dimension-independent** — the same committee scores all five dimensions for a given
(provider, round), so `is_assigned` is one direct call to existing pallet logic, not a
reimplementation. What's new is genuinely new (bounded temp storage, a close call, a running
"latest" value) rather than a copy of something that already exists.

**Decision: B.** The deciding factor is that A's added surface is proportional to how *shared* a
mechanism is, and this data point is not shared — it is meaningful for one dimension only. Paying
A's cost (touching every dimension's existing, already-tested call path) to serve one dimension's
need is a worse trade than B's cost (new, additive, fully isolated surface). B also composes
better with §6's scope cut: because it is not entangled with `submit_evidence`/`close_round`,
leaving out disputes/slashing for this first slice (see "Out of scope") does not create any
inconsistency with how the existing five dimensions behave — it is simply a smaller pallet feature
that hasn't grown disputes yet, the same shape ADR-013 itself shipped in slices.

Concretely, in `pallet-network-validator`:

```rust
/// One validator's raw round-trip-time observation for a provider in a
/// round, in whole milliseconds. Not a score -- no 0..10_000 basis-point
/// scale, no reputation effect. Populated only from a validator's own
/// wall-clock measurement (the `elapsed` already computed in
/// runOneBandwidthProbe), never from anything the provider self-reports.
#[pallet::storage]
pub type LatencySubmissions<T: Config> = StorageNMap<
    _,
    (NMapKey<Blake2_128Concat, T::AccountId>, NMapKey<Twox64Concat, u64>),
    BoundedVec<(T::AccountId, u32), T::MaxSubmissionsPerRound>, // (validator, rtt_ms)
    ValueQuery,
>;

/// The current, aggregated latency figure for a provider -- the only
/// thing the scheduler ever reads (see Decision §4). OptionQuery: absent
/// means "never aggregated," never a zero/sentinel value standing in for
/// "unknown" (see Decision §5).
#[pallet::storage]
pub type LatestNetworkLatency<T: Config> = StorageMap<
    _, Blake2_128Concat, T::AccountId,
    LatencyRecord<BlockNumberFor<T>>, OptionQuery,
>;

pub struct LatencyRecord<BlockNumber> {
    pub rtt_ms: u32,
    pub round: u64,
    pub submissions: u32,
    pub updated_at: BlockNumber,
}
```

Two new calls, appended after the existing nine (`call_index(9)`, `call_index(10)` — existing
indices 0-8 are untouched, so nothing already deployed or tested needs renumbering):

- `submit_network_latency(origin, provider, round, rtt_ms: u32)`: `ensure_signed`, `is_active`,
  `validator != provider`, `is_assigned(provider, round, validator)` (reusing `committee()`
  directly), reject a duplicate submission from the same validator for the same
  `(provider, round)`, push into `LatencySubmissions`. No `payload_hash`/copied-evidence check in
  this first slice — see "Out of scope."
- `close_network_latency(origin, provider, round)`: callable by any active validator once
  `LatencySubmissions` for `(provider, round)` reaches `MinQuorum` (reusing the existing constant,
  currently 3 in this runtime), same as `close_round`. Aggregates (§3 below), writes
  `LatestNetworkLatency`, clears `LatencySubmissions`.

Both reuse the **same** `round: u64` numbering already used for the Network `ScoreDimension` (no
new round-numbering scheme): a validator assigned to score a provider's Network dimension this
round is exactly the validator eligible to also report latency this round.

### 2. What non-Network dimensions do with it

Nothing — this is the direct payoff of Decision §1. Because `LatencySubmissions`/
`submit_network_latency` are entirely separate from `Evidence`/`submit_evidence`,
Compute/Storage/Availability/Reliability submissions are never asked about latency at all. There is
no sentinel, no `Option` field on a shared struct, no new decision for those four dimensions to
make. This is the concrete gap that made Option A structurally more expensive than Option B, not
just larger in line count.

### 3. Aggregation rule at `close_network_latency`: trimmed mean, same rule as `score_bps` — not minimum

The task framing this ADR started from suggested a *minimum*-across-validators rule, reasoning that
RTT is genuinely path-dependent (different validators, different vantage points, all "true" for
their own path) unlike `score_bps`, where disagreement implies someone is wrong. That framing is
right about *why* RTT is statistically different from `score_bps` — but the conclusion doesn't
follow, once the concrete mechanism is considered: **who submits the number.**

RTT here is the *validator's own wall-clock measurement* (the `elapsed` `runOneBandwidthProbe`
already computes), never anything the provider self-reports. A provider cannot inflate or deflate
it. The only party that can misreport it is a validator itself — and a **minimum** rule is exactly
the wrong aggregation against that risk: a single dishonest or badly-configured validator claiming
an implausibly low RTT (e.g. 0-1ms) wins the round outright, permanently, every time, with no other
validator able to outvote it. A **trimmed mean** (drop the lowest and highest of 3+ submissions,
average what remains — literally reusing `trimmed()`'s existing logic, generalized from `u16` to
`u32`) requires *at least two* validators to collude toward the same extreme to move the result,
matching the same abuse-resistance property `score_bps` already relies on.

The genuine path-dependence the original framing raised is a real and honest limitation, but it is
a **precision** limitation, not a **security** one: a trimmed mean of three different validators'
real RTTs to the same provider is a number that doesn't correspond to any one of their actual
paths. That is acceptable here specifically because of what this number is used for (§4 gives it
a coarse, single scalar role in ranking — a general "how good does this provider's network path
look from wherever validators happen to be" signal, not a promise of the RTT a specific future
workload's own traffic will see from its own origin). Given the scope correction in Context (this
is not true regional/requester-relative routing), a coarse committee-trimmed-mean is a defensible
match for the actual claim being made, and reusing an existing, already-tested aggregation
primitive is a real implementation-cost saving over inventing and testing a second one.

**Decision: reuse `trimmed()`'s exact rule** (generalized over `u32`), for abuse-resistance and
implementation reuse. `close_network_latency` does not reward `PointsPerAcceptedSubmission` for
this first slice — see "Out of scope."

### 4. How the scheduler actually reads it: a single point-read, mirroring `LatestReputationVector`, not a round scan

There is precedent for two different read shapes against this pallet family, and picking the right
one matters:

- **Dashboard reads (`internal/dashboard/validatorscores.go`, `validatorrounds.go`)** scan a
  bounded lookback window (12 rounds, 3 rounds) of the `Rounds`/`Evidence` `StorageNMap`s, because
  that pallet-level API is genuinely history-shaped (`Rounds` is keyed by
  `(provider, round, dimension)`, has no "give me the latest" query, and the safe RPC allowlist
  this node runs under has no key-enumeration call available) — several sequential RPC round trips
  per request, acceptable for a human-facing dashboard page load, not for a scheduler hot path.
- **`pallet-reputation::ReputationVectors`** is not history-shaped: it's a running value the
  pallet itself keeps current (`record_dimension_score` updates it at every `close_round`), keyed
  only by `provider`. `blockchainbridge.LatestReputationVector` is a *single* storage read, and
  `internal/orchestrator/worker.go` already calls it live, per candidate, on every ranking pass —
  an already-accepted performance characteristic for this exact hot path.

`LatestNetworkLatency` (§1) is deliberately built in the second shape, not the first, for exactly
this reason: it is a running "latest known" value the pallet maintains itself
(`close_network_latency` writes it), keyed only by `provider`, so the scheduler's read is one
point-read per candidate, not a lookback scan. Concretely:

- `blockchainbridge` gains `LatestNetworkLatencyMs(ctx, provider) (rttMs uint32, found bool, err
  error)`, decoding `LatestNetworkLatency` at the finalized head — same shape as
  `LatestReputationVector`, same file layout convention (`networklatency.go` alongside
  `reputation.go`).
- `internal/orchestrator/worker.go`'s `rankableCandidates` calls it alongside the existing
  `LatestReputationVector` call, populating a new `Candidate.NetworkLatencyMs uint32` /
  `Candidate.HasNetworkLatency bool` pair (see §5 for why this is a pair, not a single field).

This closes the "no simple current-round lookup" gap noted in Context — not by building a new
lookup primitive, but by recognizing the pallet should maintain the derived "latest" value itself
(as it already does for reputation), rather than pushing history-reconstruction work onto every
reader.

### 5. The neutral/unknown-latency case

`LatestNetworkLatency` is `OptionQuery`: a provider that has never had `close_network_latency`
succeed for it simply has no entry — absence, not a zero or a sentinel `u32::MAX`. This is the same
pattern `Candidate.HasReputation bool` already uses in `rank.go` for "no on-chain reputation record
yet," and the same convention #29 established ("explicit unavailable state, never false success").
`Candidate.HasNetworkLatency` carries that bit through to the scheduler; `NetworkLatencyMs` is only
meaningful when it's `true`.

In `scoreOne` (`internal/scheduler/rank.go`), the existing comment already names the landing spot:
*"constraints.MaxLatencyMs and constraints.MaxPrice are accepted but not enforced... They are wired
through the constructor and this comment specifically so the next person adding either signal has
one place to look."* This ADR's implementation removes that comment's latency half and adds:

- When `constraints.MaxLatencyMs > 0` **and** `candidate.HasNetworkLatency` is true: exclude the
  candidate if `candidate.NetworkLatencyMs > constraints.MaxLatencyMs`, mirroring the existing
  `MinReputation` hard-exclusion pattern exactly (`Score{}, true, "network latency exceeds
  workload's maximum"`).
- When `constraints.MaxLatencyMs > 0` **and** `HasNetworkLatency` is false: **not excluded** — an
  unmeasured provider is treated as neutral, never penalized, per #29's convention, carried forward
  explicitly from ADR-025 §4's own text ("a provider that never had a probe run simply scores as
  unknown latency, treated as neutral, not penalized"). A workload with a latency constraint still
  gets to consider a never-measured provider; it just cannot be excluded on a signal that doesn't
  exist yet.
- When `constraints.MaxLatencyMs == 0` (unset, the common case today — nothing populates it):
  behavior is unchanged from today, latency plays no role.

A weighted "prefer lower latency among passing candidates" scoring term (folding `NetworkLatencyMs`
into `resourceFitBps` the way bandwidth fit is already conditionally included) is a natural, small
follow-up once the hard-constraint path is live and real `MaxLatencyMs` values exist to validate
against — deliberately not attempted in this same slice; see "Out of scope."

### 6. Out of scope for this ADR / first slice

- **True region-aware/requester-relative endpoint selection** (see Context's scope correction) —
  needs a wire-protocol region tag and a different committee-assignment model, not a smaller
  version of this.
- **Disputes and slashing for latency evidence.** `submit_network_latency`/`close_network_latency`
  have no `dispute_round`/`resolve_dispute` equivalent and no `RoundSubmitters`-style
  slashing-attribution storage. Latency does not feed `pallet-reputation` and has no economic
  consequence for a provider today, so the stakes that justify `Rounds`'s dispute machinery
  (ADR-018) don't yet apply. If a future ADR decides latency should affect reputation or rewards,
  disputes become necessary at that point, not before.
- **Reward Points for latency submissions.** `close_network_latency` does not call
  `T::ValidatorRewards::accrue`. Whether reporting latency should be an incentivized validator duty
  like the five `ScoreDimension`s is a real economics question, deliberately deferred rather than
  answered as a side effect of this ADR.
- **Anti-collusion `payload_hash`-style duplicate-evidence detection** for latency submissions.
  `submit_evidence`'s `CopiedEvidence` check exists because `score_bps` is a summary of a specific
  off-chain probe payload; RTT already has a much weaker incentive to copy (see Decision §3 — the
  provider cannot influence it, and colluding validators gain less by copying a number that isn't
  supposed to match across vantage points anyway). Left as a documented gap, not a silent one.
- **A weighted (soft) latency scoring term** in `resourceFitBps`/`ReputationBps` beyond the hard
  `MaxLatencyMs` exclusion — noted in Decision §5 as a natural, small follow-up, not built here.
- **WireGuard overhead's effect on measured RTT.** ADR-025 §4 already settled WireGuard overhead as
  a separate, already-implemented bandwidth-tolerance adjustment (`WireGuardOverheadBps`); this ADR
  does not add an equivalent adjustment to the new RTT figure. `MeasureBandwidth` probes run
  directly against the Agent's mTLS listener, not through a workload's WireGuard tunnel, so the
  measured RTT is already the un-tunneled figure — consistent with, not contradicting, the existing
  bandwidth adjustment's scope.
- **Per-workload historical latency trend / dashboard surface.** This ADR gives the scheduler a
  live point-read; a dashboard page showing latency history over time (the same shape
  `validatorscores.go` already gives `score_bps`) is a natural, separate follow-up, not required to
  close #73.

## Consequences

- `pallet-network-validator` gains two new storage items and two new calls (`call_index(9)`,
  `call_index(10)`) — additive only; every existing call index, storage item, and test is
  untouched.
- `internal/blockchainbridge` gains a new file (`networklatency.go`, mirroring `reputation.go`'s
  shape) plus two new `Registrar` methods (`SubmitNetworkLatency`, `CloseNetworkLatency`) and their
  pinned-byte-layout encode functions, each needing their own tests — but no existing
  `blockchainbridge` file changes.
- `internal/networkvalidator`'s challenge loop (ADR-013 §3 step 4) gains one more call per round
  per assigned provider (`submit_network_latency`, using the `elapsed` value
  `runOneBandwidthProbe` already computes and currently discards) plus participation in
  `close_network_latency` the same way it already participates in `close_round` — a small, bounded
  addition to the same loop, not a new loop.
- `internal/scheduler/rank.go`'s `Candidate` gains two fields (`NetworkLatencyMs`,
  `HasNetworkLatency`); `scoreOne` gains one new hard-exclusion branch. `constraints.MaxLatencyMs`
  goes from documented-but-inert to enforced.
- `internal/orchestrator/worker.go`'s `rankableCandidates` gains one more live chain read per
  candidate per ranking pass, the same cost `LatestReputationVector` already pays today (a second
  point-read of the same shape, not a scan).
- Issue #73's last acceptance criterion, correctly scoped (see Context), is closed by this ADR's
  implementation, once accepted — not by the literal "regional endpoint selection" wording, which
  this ADR argues is not actually buildable with today's wire protocol.

## Verification

Checked against source before writing: `control-plane/internal/networkvalidator/bandwidth.go` (full
file, confirming `elapsed` is computed and discarded); `blockchain/pallets/network-validator/
src/lib.rs` (full `submit_evidence`/`close_round`/`trimmed`/`committee`/`is_assigned` bodies, and
every storage/type declaration — confirming `committee()` is dimension-independent and `Submission`/
`RoundResult` have no latency room); `control-plane/internal/blockchainbridge/roundresult.go` (full
file, `RoundResult`'s pinned decode); `control-plane/internal/blockchainbridge/
networkvalidatorregistrar.go` (call indices 0-8, `encodeSubmitEvidenceCall`'s pinned layout);
`control-plane/internal/blockchainbridge/reputation.go` (`LatestReputationVector`'s single-point-read
shape); `control-plane/internal/orchestrator/worker.go` (confirming this exact call is already made
live per ranking pass); `control-plane/internal/scheduler/rank.go` (full file, `MaxLatencyMs`'s
existing dead-wiring and comment, `HasReputation`'s neutral-default pattern,
`fitBps`/`resourceFitCount`'s conditional-inclusion pattern for optional bandwidth scoring);
`control-plane/internal/dashboard/validatorscores.go` and `validatorrounds.go` (full lookback-scan
mechanism and the safe-RPC-allowlist reason it exists); `control-plane/internal/networkvalidator/
round.go` (confirming round-number derivation is a pure function of finalized block number, and
that `round` is an off-chain convention the pallet never derives itself); `docs/adr/
013-network-validator-daemon.md` (full text — "needs no Postgres/Redis," slice precedent);
`docs/adr/025-bandwidth-usage-reporting-and-rate-limit-enforcement.md` (full text, §4's literal
claims checked against the above); `docs/adr/018-slashing-and-economic-penalties.md` (dispute/slash
mechanism this ADR deliberately does not replicate); `blockchain/runtime/src/lib.rs`
(`ValidatorMinQuorum = 3`, `ValidatorTargetCommitteeSize = 5`, confirming `trimmed()`'s 3+
drop-high-drop-low behavior against real configured values).

Refs #73. Related: ADR-011 (Network Validator protocol, `submit_evidence`/`close_round`/
`committee` this ADR extends alongside, not inside), ADR-013 (daemon architecture and the
"needs no Postgres/Redis" invariant this ADR's on-chain-only channel preserves), ADR-015 (the
`MeasureBandwidth` probe whose already-computed `elapsed` this ADR finally uses), ADR-018
(slashing/dispute mechanism this ADR's first slice deliberately does not extend to latency), ADR-025
§4 (the decision this ADR replaces with a narrower, honestly-scoped one).
