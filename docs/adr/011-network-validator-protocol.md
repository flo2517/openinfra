# ADR-011: Decentralized Network Validator and worker scoring protocol

## Status

Accepted.

## Context

Every number that currently feeds a provider's on-chain reputation is produced
and submitted by one party: the Control Plane. `availability::submit_proof`,
`availability::record_availability`, and `reputation::update_vector` are all
gated by `frame_system::EnsureRoot` bound to the Control Plane's bridge
account (`blockchain/runtime/src/lib.rs:185,202-203`). The bridge verifies a
provider's Ed25519 signature off-chain and is the only party allowed to call
the Agent's `SolveChallenge` RPC. This was the correct MVP shortcut — it let
Proof of Availability and reputation ship end-to-end (#7) — but it means a
provider's reputation is only as trustworthy as the single operator running
its Control Plane. There is no independent party that can catch a Control
Plane under-reporting or over-reporting its own providers, and nothing stops
one operator from running both the provider and the party that scores it.

OpenInfra's Bittensor-inspired design calls for a **Network Validator**: an
independently operated role that challenges Workers (providers), evaluates
delivered service, and submits attributable weights. This is a distinct
concept from a **Chain Authority** (the Aura block producer / GRANDPA finality
voter that keeps the chain itself live — see ADR-009). Adding Network
Validators means adding a new component and a new trust boundary
(non-Control-Plane parties writing to the chain, and a new class of client
the Provider Agent must authenticate), which `AGENTS.md`'s frozen-architecture
rule requires an accepted ADR for before implementation.

## Decision

### 1. Identity, registration, authorization, stake, selection, lifecycle

Add a new pallet, `pallet-network-validator`, following the same shape as
`pallet-provider-registry`:

- **Identity**: a Network Validator is a Substrate `AccountId` (its own key,
  distinct from any provider's or the Control Plane bridge's). No new PKI
  system — the account that signs extrinsics *is* the identity.
- **Registration**: `register_validator(origin)` — signed, self-service,
  bonds a minimum stake (`T::MinValidatorStake`, via the runtime's existing
  balances/`fungible` trait) into a reserved lock. Bonding is the primary
  Sybil deterrent for the MVP; a validator with no economic stake gets no
  weight.
- **Lifecycle**: `Candidate -> Active` once stake clears the minimum,
  `Active -> Suspended` on a governance/root call (dispute resolution, see
  §4), `-> Exited` after an unbonding period (`T::UnbondingPeriod` blocks)
  with no pending assignments. Mirrors the `ProviderInspector` trait: expose
  `NetworkValidatorInspector::is_active(&AccountId) -> bool` for other
  pallets to check without a hard dependency.
- **Authorization boundary this ADR adds**: Network Validators submit their
  own signed extrinsics directly to the chain — they do **not** go through
  the Control Plane's bridge. `availability::ProofOrigin` and
  `reputation::UpdateOrigin` change from `EnsureRoot` to `ensure_signed`
  gated by `NetworkValidatorInspector::is_active`. `EnsureRoot` is kept only
  for emergency admin overrides (suspension, parameter changes), not for
  routine scoring. The Control Plane keeps its existing root-origin calls
  for provider registration and lease management — nothing there changes.
- **Selection**: for each challenge round, assign a bounded committee of
  `T::CommitteeSize` active validators per provider, derived from
  `blake2(parent_hash, provider, round)`. This repo's dev chain uses Aura,
  not BABE (contrary to `architecture.md`'s claim — flagging that doc/code
  gap here), so there is no VRF-grade unpredictability available; assignment
  is pseudo-random but not secret once the block is known. We accept that
  for the MVP and rely on the deadline window (§2) plus quorum/aggregation
  (§4) — not secrecy of assignment — as the real anti-collusion property. A
  validator may never be assigned to a provider whose `AccountId` it also
  controls (trivial self-assignment check); detecting *operator-level*
  relationships beyond shared keys is out of scope for the MVP and is called
  out as an accepted gap in §3.

### 2. Randomized bounded challenges

Extend the existing `SolveChallengeRequest.Type` enum in
`protocol/proto/openinfra/agent/v1/agent.proto` with `TYPE_NETWORK` and
`TYPE_RELIABILITY` (compute/storage/availability already exist). Assigned
Network Validators call `SolveChallenge` **directly** against the Provider
Agent's existing gRPC/mTLS surface — this is the one new data-plane edge this
ADR introduces. The Agent still never talks to the chain directly (that rule
is unchanged); it now also accepts a second class of authenticated client
besides its Control Plane. Trust bootstrap: the Control Plane continues to be
the Agent's certificate introducer and pushes the current active-validator
allowlist to the Agent (extending the existing heartbeat/config channel), so
no separate validator PKI is needed for the MVP. Each challenge carries a
nonce and a block-number deadline, mirroring `pallets/availability`'s
existing `Challenge { expected_response, deadline }` — a response after the
deadline is rejected the same way `ChallengeTimeout` already works.

### 3. Signed evidence envelopes, replay resistance, bounded retention

A validator's evidence never lands on-chain in full. The Agent's
`SolveChallengeResponse` (already `result` + `signature`) is evaluated
locally by the validator, which then submits a bounded, integer-only summary
on-chain — generalizing the existing `AvailabilitySummary` shape
(`pallets/availability/src/lib.rs:116-125`) per dimension:

```
EvidenceSummary {
    round: u64,
    provider: AccountId,
    validator: AccountId,      // implicit: the extrinsic's signer
    dimension: enum { Compute, Storage, Network, Availability, Reliability },
    score_bps: u16,             // 0..=10_000, never a float
    sample_count: u32,
    observed_at: BlockNumber,
    payload_hash: [u8; 32],     // hash of the full off-chain evidence
}
```

Replay resistance reuses the pattern already proven in
`LastProofSequence`/`sequence > last`: track `(provider, round, validator)`
and reject a repeat. Bounded retention: only the latest aggregated result per
provider per dimension is kept in consensus state (as today); raw evidence —
challenge payloads, timing traces, signed responses — stays off-chain,
addressable only by `payload_hash`, exactly like the current
`payload_hash` field. Nothing changes about keeping detailed telemetry out of
the runtime.

### 4. Threats and mitigations

| Threat | Mitigation |
|---|---|
| Collusion / weight-copying | Aggregation requires a quorum of independent validator submissions per round (§5); a single validator (or a colluding minority under the quorum threshold) cannot move a provider's score. |
| Sybil | Bonded minimum stake per validator identity; no free registration. |
| Self-validation | Validator cannot be assigned to, and its extrinsic is rejected for, a provider `AccountId` it also controls. Operator-level (off-chain) collusion is **not** solved by this ADR — flagged as an accepted MVP gap, to be closed by future reputation-weighted stake slashing. |
| Bribery / false reporting | Submissions are attributable (signed, non-repudiable) and retained by `payload_hash`; a provable false report is groundwork for slashing (§5), which this ADR scopes but does not fully specify economically. |
| Withholding (validator goes silent) | Quorum requirement means a round with too few submissions is marked low-confidence (§5) rather than silently accepted; it does not corrupt the aggregate. |
| Replay | `(provider, round, validator)` uniqueness, same mechanism as the existing `LastProofSequence` check. |

### 5. Multi-validator aggregation, confidence, disputes, incentives

- **Aggregation**: when a round's deadline passes (or quorum is reached,
  whichever first), `pallet-network-validator` closes the round and computes
  a **trimmed mean** (drop the highest and lowest submission before
  averaging, integer division, `saturating_*` throughout — no floats,
  matching `AGENTS.md`) over the committee's `score_bps` for each dimension.
  This is a small, bounded, deterministic computation over at most
  `T::CommitteeSize` values, safe to run in the runtime.
- **Writing the result**: aggregation calls into `pallet-reputation` through
  a new cross-pallet trait (`ReputationUpdater`, same shape as
  `ProviderInspector`) rather than validators calling
  `reputation::update_vector` directly — this keeps `reputation` the single
  writer of `ReputationVectors` and lets it enforce `MaxDelta`/`MaxScore`
  bounds regardless of who triggered the update.
- **Confidence**: store `submissions_received / committee_size` and
  `round_closed_at` alongside each dimension's score so the Control Plane and
  dashboard can distinguish a well-attested score from a thin one, and flag
  degraded quorum instead of reporting false success — directly answering the
  dashboard acceptance criterion in #29.
- **Disputes**: a provider (or another committee validator) may call
  `dispute_round(round, provider, dimension)` within a short bounded window
  after closure. For the MVP this suspends that dimension's update
  (reputation stays at its prior value) pending a root/governance
  resolution; a fully on-chain adjudication mechanism is deferred.
  Called out explicitly as scoped out of this ADR.
- **Incentives**: extend `pallet-rewards` to accrue Reward Points to
  validators whose submission survived trimming (i.e., was not an outlier)
  for a closed round. Slashing stake for provably bad submissions is the
  intended long-term deterrent but its economic parameters need their own
  analysis — **out of scope for this ADR**, tracked as follow-up work before
  #29 can consider incentives "done."

### What #29 (implementation) still owns

This ADR fixes the shape of the protocol, the origin/trust model, and the
pallet boundaries. It deliberately leaves to implementation: exact storage
layout and weights, the Control Plane's validator-allowlist push mechanism to
Agents, the `dispute_round` resolution path, and slashing economics.

## Consequences

- The Provider Agent gains a second authenticated gRPC client type
  (Network Validators), authorized via a Control-Plane-pushed allowlist
  rather than a new PKI — a real, if bounded, increase in the Agent's attack
  surface that must be covered by tests (unauthorized validator rejected,
  expired allowlist entry rejected, self-assignment rejected).
- `reputation` and `availability` origins move from a single `EnsureRoot`
  bridge account to `ensure_signed` + registry checks — any future change to
  who may score a provider must go through `pallet-network-validator`, not a
  runtime config constant.
- The Control Plane stops being the sole source of a provider's reputation,
  which is the point, but it also stops being able to unilaterally guarantee
  a score for its own providers — operators who relied on that (even
  informally) will see scores become quorum-dependent and possibly
  low-confidence during the validator set's bootstrap period.
- Operator-level Sybil/collusion resistance beyond bonded stake and
  quorum-of-independent-accounts is explicitly not solved here; a follow-up
  ADR is needed before any slashing goes live.
- `architecture.md` claims BABE/GRANDPA consensus; the actual dev chain runs
  Aura/GRANDPA (ADR-009). This ADR's selection mechanism (§1) is designed
  around that reality, not the aspirational doc — worth reconciling
  `architecture.md` separately.
