# ADR-036: Provider slashing economics

## Status

Accepted (by the repository owner, explicitly, relayed in-session — after reviewing a full summary
of this ADR's decisions and their reasoning, then confirming to proceed with implementation).
Nothing here is implemented yet by this ADR itself; issue #52 is unblocked by this acceptance and
now carries the implementation work.

**Numbering note.** ADR-012 §6's gate table reserves this design as "ADR-018 — slashing and
economic penalties." That number was claimed first by validator-side slashing
(`docs/adr/018-slashing-and-economic-penalties.md`, Accepted, scoped explicitly to issue #29 and
explicitly *not* to provider slashing — see its §5), because ADR-012's own numbering policy
(§6, "Consequences," second correction) settled on "an unplanned ADR always takes the next
integer; if that collides with a reserved gate, only that one gate moves." This document is the
gate ADR-012 §6 actually meant, arriving under `036` — the next free number at the time this draft
was written (`034`/`035` reserved-but-unmerged for unrelated storage/security-group proposals on
other branches) — not `018`. Every reference below to "the ADR-018 gate" means *this* document
fulfills that gate's obligation; every reference to "ADR-018" by number means the validator-slashing
ADR that already exists and is already Accepted.

## Context

Issue #52 ("Add provider slashing to back availability commitments") asks for exactly what ADR-011
§5 deferred when it shipped Network Validator rewards: *"Slashing stake for provably bad
submissions is the intended long-term deterrent but its economic parameters need their own
analysis — out of scope for this ADR."* ADR-018 answered that deferral for **validators** —
slashing a Network Validator's own bonded stake when `resolve_dispute(uphold: true)` confirms its
submission fed a wrong aggregate. ADR-018 §5 is explicit that it does not answer the question for
**providers**, and names the reason: *"Providers have no bonded stake to slash yet
(`pallet-provider-registry` has no `Currency` association at all: confirmed by grep, no `Currency`,
stake, bond, or collateral of any kind)."* That finding still holds — reconfirmed here by reading
`blockchain/pallets/provider-registry/src/lib.rs` in full (206 lines: `ProviderStatus`, `Provider<T>`
with `owner`/`public_key`/`status`, `register_provider`/`register_provider_for`/`set_status`, no
`Currency`, no `ReservableCurrency`, no balance-shaped field of any kind). Every other pallet this
ADR touches was re-read in full for this draft (see Verification).

This is therefore two designs, not one: (1) a bonding mechanism for providers, which does not exist
today, and (2) the slashing mechanism issue #52 actually asks for, which depends on (1). ADR-029
(Accepted, escrow/settlement) already anticipated this gap explicitly and left a named seam for it:
its own module doc in `blockchain/pallets/escrow/src/lib.rs:184-206` states *"Issue #52 (provider
stake slashing) is not implemented anywhere in this codebase and is blocked on its own not-yet-
accepted ADR... If a future, separately-ADR'd slashing mechanism needs to claw back a specific
period's payout after the fact, it must act on the provider's own bonded stake... not on this
escrow's already-released reservation."* This ADR is that "future, separately-ADR'd" document. It
does **not** claw back escrow payouts — consistent with the seam's own boundary, a slash here only
ever touches a provider's bonded stake, never funds already repatriated through `pallet-escrow`.

### What already exists that this design must not duplicate or endanger

- **The trimmed-mean, quorum-gated, disputable aggregate** (`pallet-network-validator::close_round`,
  `dispute_round`, `resolve_dispute` — `blockchain/pallets/network-validator/src/lib.rs:749-927`) is
  already this codebase's accepted source of truth for "a provider's availability score for round
  R, attributable to a quorum of independent validators, not any single validator's word." This ADR
  reuses it as-is. It does not add new challenge/evidence machinery, for the same reason ADR-018 §
  gave: `submit_evidence`'s `DuplicateSubmission`/`CopiedEvidence` checks and the trimmed mean
  already make the aggregate the strongest attributable signal available; inventing a second one
  would fork "what counts as provably bad service" into two disagreeing definitions.
- **The reserve-balance contamination class**, found and fixed twice this session
  (`EscrowPayerInspector` in `pallet-network-validator`, `ValidatorRegistrationInspector` in
  `pallet-escrow`, both citing the same root cause: `pallet_balances`'s reserved balance is
  untagged per-account, so `slash_reserved`/`repatriate_reserved` cannot distinguish "this
  pallet's own reservation" from "an unrelated reservation held by the same account for a
  different role"). Provider bonding is a **third** reservation against that same untagged pool.
  §5 below is this ADR's answer; it is not optional, and it follows the exact pattern the two
  existing fixes already established rather than inventing a fourth shape.
- **`pallet-rewards::calculate_reward`** (`blockchain/pallets/rewards/src/lib.rs:95-151`) already
  scales a provider's Reward Points linearly by `availability_percent` (`scaled = base *
  (1000 + reputation) * availability_percent / 100_000`). A provider at 50% delivered availability
  already earns roughly half the Reward Points of a provider at 100% — mild, continuous economic
  pressure exists today for *any* availability shortfall. Slashing bonded stake is a categorically
  different, discrete, irreversible-per-incident penalty; §3 below sizes it deliberately high enough
  to matter but keeps the trigger threshold deliberately far below "any shortfall" so the two
  mechanisms do not double-punish the same ordinary variance.
- **`pallet-escrow`'s dispute discipline** (Verification cites the exact lines): `disputed_once`
  making a resolved state genuinely terminal, escrow-scoped (not account-scoped) shortfall
  accounting, and money moving at most once, only after every avenue to contest it is exhausted.
  §4 below follows the same discipline: a provider slash executes only after both the round-level
  `DisputeWindow` (network-validator) and this ADR's own appeal window have closed unused, so
  there is never a need to "un-burn" already-destroyed funds — the two "reversed" scenarios in
  issue #52's test list are both satisfied by *preventing* execution, never by refunding after it.

## Decision

### 1. Provider bonding (new, in `pallet-provider-registry`)

Bonding is added to the existing lifecycle pallet, not a new pallet, because it gates the existing
`ProviderStatus::Active` transition and nothing else — folding it into `pallet-provider-registry`
is a smaller, more legible change than adding a cross-pallet trait purely to read a status enum
that pallet already owns.

- **New `Config` items**: `Currency: ReservableCurrency<AccountId>` (the same `pallet_balances`
  instance `pallet-network-validator` and `pallet-escrow` already use), `MinStake: Get<Balance>`,
  `UnbondingPeriod: Get<BlockNumber>`.
- **New storage**: `ProviderBonds<T>: StorageMap<AccountId, BondRecord<Balance, BlockNumber>>`,
  `BondRecord { stake: Balance, status: BondStatus }`, `BondStatus` mirroring
  `network-validator::ValidatorStatus`: `Active`, `Exiting { available_at: BlockNumber }`.
- **New calls, all self-service (`ensure_signed`, no privileged origin)**, deliberately decoupled
  from `register_provider`/`register_provider_for` rather than folded into them:
  - `bond_stake(origin, amount)` — reserves `amount` from the caller's own free balance, requires
    `caller` to already be `Providers::<T>::contains_key`, requires `amount >= MinStake` on first
    bond (top-ups above the minimum are unrestricted), and — critically — requires
    `!EscrowInspector::has_open_escrow(&caller) && !ValidatorRegistrationInspector::is_registered
    (&caller)` (§5).
  - `request_unbond(origin)` — begins unbonding, `available_at = now + UnbondingPeriod`, fails if
    a `PendingSlash` exists for the caller in any dimension (§4, §6).
  - `withdraw_unbonded(origin)` — releases the reservation once `available_at` has passed,
    **re-checks** the no-pending-slash condition (not just at `request_unbond` time — see §6),
    removes the `BondRecord`.
- **Why decoupled from registration.** `register_provider_for` is called today exclusively by the
  Control Plane's bridge account (`RegistrationOrigin = EnsureRoot`, per ADR-009) on behalf of a
  provider whose off-chain identity it has already verified. Coupling bonding to that call would
  require the bridge account to front provider collateral — making the bridge the custodian of
  provider funds, exactly the anti-pattern ADR-029 §3 already rejected for tenant escrow funding
  ("This ADR treats that as unacceptable for a design handling real value"). Self-service bonding
  by the provider's own key, decoupled from registration, is the smaller change and the correct
  custody model, following ADR-029's own precedent for the identical shape of problem.
- **Gating `Active`.** `set_status`'s `valid_transition` table gains one additional condition,
  checked only for the `Verified -> Active` edge: `ProviderBonds::<T>::get(&provider).map(|b|
  b.stake).unwrap_or_default() >= T::MinStake::get()`. A provider with no bond, or a bond that has
  fallen below `MinStake` (via a slash, see §3), cannot be `Active` and therefore cannot be
  scheduled a new lease — bonding has real teeth without touching `register_provider_for`'s
  signature or any existing consumer of it.
- **Symmetric contamination guard, exposed outward.** `pallet-provider-registry` exposes a new
  narrow trait, `ProviderBondInspector<AccountId> { fn has_open_bond(&AccountId) -> bool; }`,
  mirroring `EscrowPayerInspector`/`ValidatorRegistrationInspector`'s existing shape exactly. This
  ADR does **not** implement the two call sites that must consume it
  (`pallet-network-validator::register_validator`, `pallet-escrow::fund_escrow`) — that is
  implementation work for whoever picks up this ADR — but it specifies the obligation precisely so
  it is not missed: without those two additional checks, the three-way guard (§5) is only
  two-thirds closed and the exact contamination class already fixed twice this session reopens
  through the third, unguarded edge.

### 2. What counts as slashable evidence

A **breach round** for provider `P`, dimension `Availability`, round `R` is a `RoundResult` in
`pallet-network-validator::Rounds` such that all of the following hold, read directly off that
existing storage item — no new evidence type, no new signature scheme:

1. `status ∈ {Final, DisputeRejected}` — never `Disputed` (still contestable) or `DisputeUpheld`
   (already reversed; see §4).
2. `now >= closed_at + T::DisputeWindow::get()` (network-validator's own dispute window, read via
   the oracle trait below) — a round cannot be counted while it could still be disputed.
3. `score_bps < T::AvailabilityBreachThresholdBps::get()`.
4. `submissions * 10_000 / committee_target >= T::SlashConfidenceThresholdBps::get()` — a
   materially **higher** bar than the `MinQuorum` needed merely to close the round and update
   reputation. This is the direct mechanism for issue #52's "degraded quorum reduces confidence
   rather than producing a slash": a round that closes on the bare minimum (e.g. 3 of a 5-target
   committee, 60%) is fully valid for reputation purposes but, by itself, can never satisfy
   condition 4 at the proposed 80% threshold (§3) — it simply never becomes slash-eligible,
   silently, no error, no event; it just never appears in a breach streak.

A new pallet, `pallet-provider-slashing`, reads this through a narrow read-only trait —
`AvailabilityRoundOracle<AccountId> { fn round(provider: &AccountId, round: u64) ->
Option<RoundView>; }`, `RoundView` exposing exactly the four fields condition 1-4 need — rather than
depending on `pallet-network-validator` directly, the same pattern every cross-pallet dependency in
this workspace already uses (`ProviderInspector`, `NetworkValidatorInspector`, `ReputationUpdater`,
`ValidatorRewards`, `EscrowPayerInspector`, `ValidatorRegistrationInspector`,
`ReputationPenalty`). This directly satisfies issue #52's "slashing triggers only on evidence that
is attributable, non-repudiable, and already on-chain" — the oracle can only ever return an
already-committed `RoundResult`, never a raw `Evidence` submission (which `close_round` deletes on
closing anyway, per `network-validator/src/lib.rs:805-808`) and never "a single validator's
unaggregated word."

### 3. Trigger, amount, and window — the concrete numbers

| Constant | Proposed value | Why |
|---|---|---|
| `MinProviderStake` | 1,000 (same `Balance` unit as `MinValidatorStake`) | Symmetric order of magnitude with the existing validator bond. Neither this ADR nor ADR-029 pegs `Balance` to a real-world unit (ADR-029 §12 leaves that open); this is a placeholder ratio, not a calibrated economic figure, and is called out as an open question below. |
| `AvailabilityBreachThresholdBps` | 5,000 (50%) | Deliberately generous to the provider. `pallet-rewards::calculate_reward` already scales rewards linearly by `availability_percent`, so anything above 50% is already self-correcting through reduced pay — slashing is reserved for delivery so degraded it is closer to "not delivering" than "delivering poorly." |
| `SlashConfidenceThresholdBps` | 8,000 (80% of `TargetCommitteeSize`, i.e. ≥4 of 5 committee members at today's genesis parameters) | Strictly higher than `MinQuorum`'s 60% (3 of 5) needed merely to close a round. A slash needs the network's strongest available attestation, not its minimum viable one. |
| `BreachRounds` | 3, and **consecutive round numbers** (`R, R+1, R+2`, not "3 of the last N") | Mirrors `MinQuorum = 3` and ADR-018 §5's own forward note: *"one bad round never slashes over a consecutive-rounds window."* Strict consecutiveness (rather than "3 of the last 10") is the simpler, more auditable rule and is explicitly named as a tunable, not a proof, below. |
| `ProviderSlashAmount` | 150 (flat, 15% of `MinProviderStake`) | A **flat amount**, not a percentage of current stake, matching `ValidatorSlashAmount`'s own shape (`100`, flat, 10% of `MinValidatorStake = 1,000`) — deliberately higher than the validator figure. A validator's upheld-wrong submission is a scoring-integrity failure; a provider's confirmed availability breach is a failure of the actual paid-for service, directly harming a tenant. The higher rate reflects that difference in kind, while staying well short of a full-bond wipeout on one incident, for the identical single-key-governance-risk reason ADR-018 §3 gives (`EnsureRoot` should not be trusted to destroy 100% of a bond on one adjudicated incident). At 150/1,000, a provider needs on the order of six to seven independent, fully-attested, undisputed, unappealed 3-round breach streaks to exhaust a minimum bond — a high bar given how many independent conditions (§2's four, plus §4's two windows) must each fail to protect the provider before even one execution occurs. |
| `SlashAppealWindow` | 14,400 blocks (~1 day at 6s blocks) | Matches `ValidatorUnbondingPeriod`'s existing "~1 day" magnitude — long enough for a provider to assemble off-chain counter-evidence (independent uptime logs, an ISP incident report) for a human-reviewed appeal, short enough to keep `PendingSlash` state bounded and give timely finality. |

Slashed funds are **burned** — `T::Currency::slash_reserved` with the resulting negative
imbalance dropped, never `resolve`d into any account — for the identical reasoning ADR-018 §4
already gives and this ADR does not re-derive: paying the disputer manufactures an incentive to
fabricate a breach claim; paying the tenant/provider-that-reported-it makes every observer a
financial beneficiary of an unrelated provider's penalty. A treasury-redirect alternative was
considered and rejected for the same reason: this codebase has no `pallet-treasury`, and inventing
one purely to hold slashed funds is a second, larger, unrelated architecture decision this ADR
should not smuggle in.

### 4. Interaction with `dispute_round` / `resolve_dispute` — no execution before every window closes

This ADR adds **no new dispute mechanism for an individual round's score.** `dispute_round` and
`resolve_dispute` (`network-validator/src/lib.rs:840-927`) are reused exactly as they exist today,
for the same reason ADR-018 reused them for validator slashing: the round-level dispute is already
this codebase's accepted adjudication path for "was this aggregate wrong," and provider slashing
must never diverge from validators on that question. Concretely:

- Condition 1 in §2 (`status ∈ {Final, DisputeRejected}`) means a round that is currently
  `Disputed` cannot count toward a breach streak at all — `record_breach` (§6) simply finds no
  eligible round and does nothing. This directly satisfies issue #52's "a slash cannot be
  finalized while the round that justifies it is disputed": there is no path from an open dispute
  to a `PendingSlash` in the first place, not a check that races against one.
- If a round that *was* provisionally counted toward a breach streak (i.e., still within its own
  `DisputeWindow`, not yet consumed by `execute_slash`) is subsequently disputed and the dispute
  is **upheld** (`RoundStatus::DisputeUpheld`), that round's status condition 1 fails retroactively
  the next time `record_breach`/`execute_slash` reads it — the breach streak it was part of can
  never complete. This is issue #52's "an upheld dispute reverses it," achieved by **exclusion**,
  never by refunding an already-executed slash: because `execute_slash` (§6) additionally requires
  every contributing round's own `DisputeWindow` to have elapsed (condition 2), no round can ever
  be consumed by an executed slash while it could still flip to `DisputeUpheld`. Money moves at
  most once, only after both the round-level window and this ADR's own appeal window (§6) have
  closed unused — the same "exactly-once, no re-arming" discipline `pallet-escrow`'s
  `disputed_once` already established for this codebase, applied here to a multi-round streak
  instead of a single escrow.
- `dispute_round`'s existing standing rule — callable by "the scored provider or a validator that
  was on the round's committee" (`network-validator/src/lib.rs:856-859`) — already gives the
  provider itself a first, free opportunity to contest any individual round before it can ever
  become breach evidence. This ADR's own appeal (§6) is a **second, later** layer, over the
  aggregated multi-round decision rather than any single round's score — the two are not
  redundant: the first lets the provider stop a bad round before it counts; the second lets the
  provider contest the *pattern* even after every individual round survived its own window.

### 5. Closing the reserved-balance contamination class a third way

`pallet_balances`'s reserved balance is untagged per account (this codebase predates
`fungible::MutateHold`/`HoldReason`, per both existing fixes' own doc comments). Provider bonding
is a third role reserving into that same pool, alongside Network Validator stake and escrow
`payer` `max_charge`. Left unguarded, `pallet-provider-slashing::execute_slash`'s `slash_reserved`
call would be exactly as dangerous as the two already-fixed cases: an account that is
simultaneously a bonded provider and a registered validator (or an open escrow's payer) would have
a provider-availability slash silently consume funds actually backing an unrelated validator bond
or escrow `max_charge`, corrupting that other pallet's accounting with no reconciliation path —
the identical failure mode `EscrowPayerInspector` and `ValidatorRegistrationInspector` already
exist to prevent for the other two role-pairs.

This ADR closes the third edge the same way the first two were closed, not with a new shape:

- `pallet-provider-registry::bond_stake` (§1) refuses an account that
  `EscrowInspector::has_open_escrow` or `ValidatorRegistrationInspector::is_registered` — reusing
  both existing traits unchanged, wired the same way `pallet-network-validator::register_validator`
  and `pallet-escrow::fund_escrow` already consume them.
- `pallet-provider-registry` exposes `ProviderBondInspector` (§1) for the other two pallets to
  consume symmetrically. **This ADR specifies but does not implement** the two call-site changes
  (`register_validator` and `fund_escrow` each gaining one more `ensure!`) — flagged explicitly so
  implementation does not treat the guard as optional or forget the third edge while wiring the
  first two.
- Net result once all three edges are wired: an `AccountId` may hold **at most one** of
  {Network Validator, escrow payer, bonded provider} at a time. This is a real constraint on
  account reuse, stated plainly as a consequence, not hidden in a trait's doc comment alone.

### 6. Mechanics: detection, appeal, execution — new `pallet-provider-slashing`

A new pallet, not an extension of `pallet-network-validator` or `pallet-provider-registry`, for
the same single-responsibility reasoning every other cross-cutting concern in this workspace
already follows: it reads from network-validator (via `AvailabilityRoundOracle`, §2) and mutates
provider-registry's bond (via a new, non-extrinsic `ProviderStakeSlasher` entry point — mirrors
`pallet-reputation::set_dimension_score`'s and `pallet-rewards::accrue_points`'s existing
"internal-only, not a `#[pallet::call]`" pattern precisely, so `pallet-provider-registry` stays the
only writer of `ProviderBonds` regardless of which pallet triggers a change).

- **Storage**: `PendingSlashes<T>: StorageMap<(AccountId, ScoreDimension) ->
  PendingSlash<BlockNumber>>` (`PendingSlash { first_round: u64, created_at: BlockNumber, state:
  Proposed | Appealed }`); `LastSlashedRound<T>: StorageMap<(AccountId, ScoreDimension) -> u64>` —
  a watermark, never re-decreased, recording the highest round number already consumed by an
  *executed* slash (whether or not a later appeal on a different streak succeeds), so the same
  round can never be counted into two different breach streaks. This directly answers issue #52's
  "double-slash for the same round" test: `record_breach` requires every round in a candidate
  streak to be `> LastSlashedRound`, unconditionally.
- **`record_breach(origin, provider, dimension, first_round)`** — permissionless (`ensure_signed`,
  any caller; no privileged origin needed, mirroring `close_round`'s own "deterministic function of
  already-committed state needs no privileged origin" reasoning), checks §2's four conditions for
  `first_round, first_round+1, first_round+2` via the oracle, checks all three exceed
  `LastSlashedRound`, checks no `PendingSlashes` entry already exists for `(provider, dimension)`,
  and inserts one if every condition holds. Emits `BreachRecorded`.
- **`appeal_slash(origin, provider, dimension)`** — `ensure_signed`, only the provider itself
  (`who == provider`) may open its own appeal, only while `PendingSlashes` is `Proposed` and within
  `SlashAppealWindow` of `created_at`. Moves state to `Appealed`, blocking `execute_slash` until
  resolved. Emits `SlashAppealed`.
- **`resolve_slash_appeal(origin, provider, dimension, uphold: bool)`** —
  `T::SlashAppealOrigin::ensure_origin` (`EnsureRoot` for the MVP, the same reused-origin choice
  every dispute/suspension path in this codebase already makes — `SuspensionOrigin`,
  `DisputeOrigin`, `PauseOrigin`, all `EnsureRoot` today). `uphold = true` **removes**
  `PendingSlashes` without ever calling `slash_reserved` — no funds moved, nothing to reverse,
  because none were ever taken; this is issue #52's "appeals path... bounded window and a defined
  resolution origin," and the second of the two "reversed" scenarios named in its test list.
  `uphold = false` proceeds directly to the same execution path `execute_slash` uses. Either way,
  `LastSlashedRound` advances past the streak's rounds so it cannot be re-litigated by a fresh
  `record_breach` call. Emits `SlashAppealResolved`.
- **`execute_slash(origin, provider, dimension)`** — permissionless, same reasoning as
  `record_breach`; requires `PendingSlashes` to be `Proposed` (never `Appealed` — an open appeal
  blocks execution outright) and `now >= created_at + SlashAppealWindow`. Calls
  `ProviderStakeSlasher::slash(&provider, T::ProviderSlashAmount::get())`, which internally mirrors
  `network-validator::slash_round_submitters`'s existing saturating pattern exactly: `slash_reserved`
  is capped at whatever is actually reserved, the returned shortfall is subtracted from the
  requested amount to get what was really removed, `ProviderBonds`'s bookkeeping is
  `saturating_sub`'d by that real amount (never underflows, never exceeds the bond — issue #52's
  arithmetic requirement, satisfied the same way the existing validator path already satisfies it).
  If the post-slash stake falls below `MinStake`, calls provider-registry's internal
  (non-extrinsic) force-transition to `Suspended` — reusing the `Active -> Suspended` edge
  `valid_transition` already allows, exactly as `slash_round_submitters` reuses
  `leave_active_set`/`Suspended` for validators. Removes `PendingSlashes`, advances
  `LastSlashedRound`, burns the imbalance (§3), emits `ProviderSlashed { provider, dimension,
  first_round, amount, force_suspended }`.
- **Slash-then-exit race (§1, `request_unbond`/`withdraw_unbonded`)**: both calls check for a live
  `PendingSlashes` entry for the caller (any dimension) and fail (`SlashPending`) if one exists.
  The check is repeated at `withdraw_unbonded`, not only at `request_unbond`, because a breach can
  be detected *after* unbonding has already begun (the underlying rounds closed before the exit
  request, but `record_breach` is only called afterward) — stake stays reserved throughout
  `Exiting` exactly as it already does for validators (`ValidatorStatus::Exiting` keeps
  `is_active` false but the reservation live), so `execute_slash` can still act on it, and
  `withdraw_unbonded` re-checking closes the window a provider would otherwise have to race an
  exit through between breach detection and slash execution.

### 7. False-positive protection, quantified

Two distinct failure modes issue #52 names, answered separately because they need different
answers:

- **A colluding validator committee (or minority) manufacturing a breach.** A single colluding
  validator (1 of a 5-target committee) cannot move the trimmed mean at all — it is the exact
  value the trim discards. A colluding minority under `MinQuorum` cannot even close the round.
  A colluding minority *above* `MinQuorum` but below `SlashConfidenceThreshold` (e.g. exactly 3 of
  5) can close a low-scoring round, but that round fails condition 4 in §2 outright — it is
  confidence-gated out of breach eligibility regardless of its score. Only a colluding **majority**
  (≥4 of 5, i.e. enough to also clear the 80% confidence bar) sustained across **three consecutive
  rounds**, with none of them successfully disputed within their own window, can produce an
  executable breach — and even then, the provider retains both `dispute_round` (per round, before
  the streak completes) and `appeal_slash` (after) as backstops. This ADR does not claim to solve
  operator-level collusion at that scale; it is the same accepted MVP gap ADR-011 §4 and ADR-012 §2
  already name (*"Operator-level collusion... needs the slashing ADR (§6) and, ultimately,
  attestation (#60, #61)"*) — this ADR is that named slashing ADR, and it bounds the **damage** a
  successful collusion can do (one `ProviderSlashAmount` per streak, appealable, never more than
  the bond) rather than claiming to prevent the collusion itself, which is explicitly Stage 4 work
  (#60/#61) this ADR does not attempt.
- **A genuine network partition, not an actual outage.** This is not solvable by more on-chain
  logic: the availability challenge protocol (ADR-007, ADR-011) cannot distinguish "the provider is
  down" from "the provider is up but unreachable from the validators that happened to be assigned
  to it" at the protocol level — both produce an identical low `score_bps`. ADR-012 §2's own
  trust table already states a provider is *"never trusted for... its own availability."* This
  ADR's only answer, and the honest one, is procedural rather than algorithmic: `appeal_slash`
  exists precisely so a provider with independent, off-chain evidence of a partition (upstream ISP
  incident reports, independent uptime monitoring) can put that evidence in front of
  `SlashAppealOrigin` before any fund actually moves. No on-chain mechanism in this design, or
  plausibly in any design at this layer, can make that distinction automatically.

## Consequences

- `pallet-provider-registry` gains a `Currency` dependency and three new self-service calls — a
  real, if narrow, change to a pallet every existing consumer (`register_provider_for` via the
  Control Plane bridge, `set_status` via the same) already depends on. Every existing call keeps
  its exact signature; only `Verified -> Active` gains one additional precondition.
  `genesis`/dev-chain endowments (`deployments/`) will need enough free balance minted for
  providers to bond, on top of what they already need for validator stake and escrow funding — a
  dev-environment concern for implementation, not a consensus-rule change (same note ADR-029 §9
  already made for its own `Currency` consumer).
- A new pallet (`pallet-provider-slashing`) and its cross-pallet wiring
  (`AvailabilityRoundOracle`, `ProviderStakeSlasher`, `ProviderBondInspector`) are owed by whoever
  implements this ADR, plus the two symmetric guard call-sites named in §5. None of this is
  implemented by this document itself.
- A provider that never bonds can never reach `Active` and therefore can never be scheduled a new
  lease under the gate this ADR adds — existing providers already `Active` under today's
  bond-free rule are grandfathered only until their next `set_status` transition attempt; this ADR
  does not retroactively suspend anyone, but implementation must decide (and this ADR flags as an
  open question below) whether already-`Active` providers get a bonding grace period.
- An `AccountId` may now hold at most one of {Network Validator, escrow payer, bonded provider} —
  a real new constraint on account/key reuse across roles, stated plainly rather than left implicit
  in a trait doc comment, per §5.
- Two independent, human-reviewable backstops exist before any provider slash executes
  (round-level `dispute_round`, streak-level `appeal_slash`), both currently resolved by
  `EnsureRoot` — the same single-key governance risk ADR-018 §9 and ADR-029's own open questions
  already accept for the MVP and explicitly hand off to ADR-023/#36. This ADR does not change that
  risk; it adds one more `EnsureRoot`-gated surface to the set already carrying it.
- Operator-level collusion above the confidence threshold, sustained across a full breach streak,
  remains unsolved by this ADR, as stated plainly in §7 rather than implied only by omission.

## Open questions for the accepting reviewer

- **Is `MinProviderStake = 1,000` (matching `MinValidatorStake` 1:1) the right ratio**, or should a
  provider's bond scale with its advertised resource capacity (a provider offering 10x the compute
  of another arguably needs 10x the collateral to back an equivalently sized commitment)? This ADR
  proposes the flat figure as the smaller change and explicitly does not attempt capacity-scaled
  bonding — flagging it as a real design axis left undecided, not an oversight.
- **Should already-`Active` providers (bonded under today's zero-collateral rule) get an explicit
  grace period** before `set_status`'s new precondition can knock them back to `Verified` on their
  next transition attempt, or is "bond before your next transition" acceptable disruption for an
  MVP-stage network with a small existing provider set? This ADR does not decide it.
- **Is `BreachRounds = 3` *strictly consecutive* round numbers the right rule**, versus "3 of the
  last N" (more forgiving of an irregular round cadence, but a materially more complex, less
  auditable computation)? §3 names this as a deliberately simple starting rule, not a proven
  optimum.
- **Is 15% (`ProviderSlashAmount` relative to `MinProviderStake`) actually calibrated to real
  economic harm**, or is it — like ADR-029 §12's currency-peg questions — fundamentally
  unanswerable until `Balance` is pegged to something real? This ADR reasons only about the ratio
  to `MinValidatorStake`, not about absolute value, because nothing in this codebase pegs `Balance`
  to a real-world unit yet.
- **Should a successful `appeal_slash` carry any consequence for whoever called `record_breach`**
  (today: none — permissionless callers bear no cost for a breach report that is later appealed
  successfully) — a griefing vector where a party could spam `record_breach` calls against a
  provider hoping one sticks, though each is a bounded, cheap, deterministic read with no funds at
  risk until `execute_slash`, so the blast radius of spam is limited to chain-space noise, not
  provider funds. This ADR does not propose a bond-and-slash-the-reporter mechanism, judging it
  disproportionate to the risk, but flags the trade-off for the reviewer rather than assuming it.

## Verification

Citations checked against source before writing, every file read in full unless noted:
`docs/adr/012-decentralization-roadmap-and-trust-boundaries.md` (§2 trust/threat table incl. the
"Operator-level collusion" cross-cutting threat citing "the slashing ADR (§6)"; §6 gate table's
literal "ADR-018 — slashing and economic penalties | Unblocks #52" row and its renumbering-policy
"Consequences" entries; §3 data classification); `docs/adr/011-network-validator-protocol.md` (§5
"Slashing stake for provably bad submissions... out of scope for this ADR"); `docs/adr/
018-slashing-and-economic-penalties.md` (full file — Accepted status, §5's explicit "#52... stays
out of scope here," the bounded-per-incident/burn-not-redistribute/reused-EnsureRoot precedent this
ADR follows throughout); `blockchain/pallets/network-validator/src/lib.rs` (full file, 1099 lines —
module doc's reserve-contamination guard section; `Config`'s `SlashAmount`/`MinStake`/
`UnbondingPeriod`/`DisputeWindow`/`MinQuorum`/`TargetCommitteeSize`; `RoundResult`/`RoundStatus`/
`RoundSubmitters` shapes; `close_round` lines 756-830; `dispute_round` lines 840-878;
`resolve_dispute` lines 888-927; `slash_round_submitters` lines 1052-1088; `EscrowPayerInspector`
trait and its doc comment lines 123-142); `blockchain/pallets/provider-registry/src/lib.rs` (full
file, 206 lines — confirmed no `Currency`/stake/bond of any kind; `ProviderStatus`/`Provider<T>`
shape; `set_status`/`valid_transition`'s exact transition table; `register_provider_for`'s
`RegistrationOrigin`-gated, bridge-driven shape); `blockchain/pallets/reputation/src/lib.rs` (full
file, 403 lines — `set_dimension_score`'s "not an extrinsic... internal entry point" pattern this
ADR's `ProviderStakeSlasher`/oracle traits follow); `blockchain/pallets/rewards/src/lib.rs` (full
file, 201 lines — `calculate_reward`'s `availability_percent` linear scaling at lines 126-137;
`accrue_points`'s identical "not an extrinsic" pattern); `blockchain/pallets/escrow/src/lib.rs`
(module doc in full, lines 1-340 read directly, remainder grepped for structure — the
"reserve-balance contamination fix" and "dispute re-arming / double-payment fix" sections lines
26-68; the "slashing seam (issue #52), explicit and undecided by design" section lines 184-206
this ADR directly answers; `ValidatorRegistrationInspector`/`ReputationPenalty` trait shapes lines
267-313; `DisputeOutcome`/`disputed_once`/`EscrowShortfallWrittenOff` terminal-state discipline);
`blockchain/runtime/src/lib.rs` (grepped for every relevant origin/constant — `MinValidatorStake =
1_000`, `ValidatorSlashAmount = 100`, `ValidatorUnbondingPeriod = 14_400`, `ValidatorDisputeWindow =
300`, `EscrowDisputeWindow = 300`, `SuspensionOrigin`/`DisputeOrigin`/`RegistrationOrigin`/
`StatusOrigin` all `EnsureRoot`; pallet index list confirming `ProviderRegistry`/`NetworkValidator`/
`Escrow` as siblings); `docs/adr/029-metering-billing-escrow-settlement.md` (§3's "unacceptable for
a design handling real value" reasoning against bridge-account custody, directly reused in this
ADR's §1; the ADR-018 precedent summary in its own Context; its own "Open questions for the
accepting reviewer" section, whose format this ADR follows); `AGENTS.md` (permanent prohibitions,
frozen architecture, in full); `gh issue view 52` (full text, every acceptance-criterion bullet
cross-checked against a specific Decision subsection above).

Refs #52. Related: ADR-011 (§5's original deferral), ADR-012 (§6 gate table — this document is the
ADR that gate names, arriving as `036` rather than `018` per the numbering note above), ADR-018
(validator-slashing precedent this ADR follows throughout and is symmetric with — a bonded
provider and a bonded validator are now slashable by structurally parallel, independently governed
mechanisms), ADR-029 (the escrow pallet whose own module doc named this exact seam and whose
dispute discipline this ADR's appeal/execution sequencing follows).
