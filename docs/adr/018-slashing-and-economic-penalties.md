# ADR-018: Slashing and economic penalties (Network Validator scope)

## Status

Proposed (left unaccepted by Claude Code, deliberately — like ADR-016, this decides when the
protocol may destroy a participant's bonded funds: a real, partly irreversible economic boundary,
not a narrower technical decision. Needs the repository owner's explicit acceptance before
implementation starts, exactly as ADR-016 §Status describes for its own case).

**Scope note:** this ADR only settles the piece issue #29 needs: slashing a Network Validator's
own bonded stake for a provably wrong submission. It deliberately does **not** attempt provider
slashing for missed availability commitments (issue #52, milestone v3.0) — see §5.

## Context

`pallet-network-validator` bonds real stake (`ReservableCurrency`, `MinStake` = 1,000, reserved in
`register_validator`, released after `UnbondingPeriod` in `withdraw_unbonded`) but today a
dishonest or wrong submission only costs the submitter the round's reward — never the stake. The
pallet's own module doc says so directly: *"Still open per ADR-011: slashing (penalties beyond
earning nothing for a round)."* ADR-011 §5 defers the same point explicitly: *"Slashing stake for
provably bad submissions is the intended long-term deterrent but its economic parameters need
their own analysis — out of scope for this ADR, tracked as follow-up work before #29 can consider
incentives 'done.'"* Issue #29's acceptance criteria repeat it: *"governed rewards/penalties
incentivize honest Workers and Network Validators."*

ADR-012 §6's gate table names this ADR-018 and lists it as unblocking issue #52 (provider
slashing), with prohibition "none (new mechanism)" — no existing `AGENTS.md` prohibition needs
lifting, this is new ground. That table is accurate for #52's half. It undersells what #29 itself
already needs: **validator**-side slashing for provably wrong evidence, which — unlike #52 — has
no missing precondition. Providers have no bonded stake to slash yet (`pallet-provider-registry`
has no `Currency` association at all: confirmed by grep, no `Currency`, stake, bond, or collateral
of any kind), which is why #52 needs provider bonding built first and stays out of scope here.
Validators already bond stake today. There is something to slash right now.

### What's provably wrong, without inventing new proof machinery

Two designs were considered:

1. **Equivocation reports** (the classic Substrate pattern: two independently signed messages by
   the same key disagreeing with each other, submitted as proof by anyone). This needs a new
   canonical signable message format for evidence separate from the `submit_evidence` extrinsic
   itself, and a new permissionless `report_equivocation` call that verifies two signatures. It's
   also mostly moot here: `submit_evidence`'s `Evidence::try_mutate` already rejects a second
   submission from the same validator for the same `(provider, round, dimension)` outright
   (`Error::DuplicateSubmission`) — a validator cannot get two conflicting values committed
   on-chain in the first place, so there is no second on-chain record to compare against without
   the validator separately signing an off-chain message, which nothing today produces or asks for.
2. **Slash on upheld dispute.** `dispute_round` / `resolve_dispute` already exist, already require
   a governed origin (`T::SuspensionOrigin`, configured as `EnsureRoot` — see
   `runtime/src/lib.rs:319`) to decide whether a challenged round's result was wrong, and already
   distinguish "upheld" (the disputed score was wrong; rolled back to `previous_score_bps`) from
   "rejected" (the disputed score stands). This is already the MVP's accepted source of truth for
   "provably wrong" — reusing it for slashing adds a consequence to an existing, already-governed
   decision instead of inventing a second one.

Design 2 is chosen: it needs no new proof format, no new signature verification in the pallet, and
no new trust assumption beyond the one the pallet already asks the network to accept for dispute
resolution itself.

## Decision

1. **Trigger.** `resolve_dispute(uphold: true)` is the sole slash trigger for this ADR. A round
   closes, someone disputes it within `DisputeWindow`, and `T::SuspensionOrigin` (`EnsureRoot`)
   upholds the dispute — meaning the round's aggregate score was wrong. `resolve_dispute` currently
   only rolls the reputation dimension back; this ADR adds a slash of the validators responsible.

2. **Who is slashed.** The validators whose submission survived outlier trimming and fed the wrong
   aggregate (`Pallet::trimmed`'s `considered` set at close time) — not validators trimmed as
   outliers, since the trimmed-mean already discards them from the result and ADR-011 §5 already
   distinguishes "persistent outlier" from "dishonest": *"the trimmed mean... discards the highest
   and lowest submission by construction, so an honest validator seeing a genuine edge case is
   trimmed exactly like a liar... Persistent outlier status may inform selection or rewards; it may
   never slash on its own."* This ADR does not relitigate that — it only slashes validators whose
   values were actually counted into a result that governance then upheld as wrong. `close_round`
   needs to persist the considered set (or their identities) into `Rounds` so `resolve_dispute` can
   read it later; today `Rounds` stores the aggregate, not the per-validator membership behind it.

3. **Amount.** A governed runtime constant, `SlashAmount`, applied per responsible validator per
   upheld dispute — not the validator's full stake. A single governance call destroying 100% of a
   participant's bond on one adjudicated incident is a harsher irreversible outcome than this MVP's
   single-key (`EnsureRoot`) governance should be trusted with; a bounded per-incident amount lets
   repeated incidents compound instead. `slash_reserved` is capped (`saturating`) at whatever the
   validator currently has reserved — it can never underflow or slash unreserved funds. If a slash
   brings a validator's reserved stake to zero, the validator is force-suspended in the same call
   (reusing the existing `Suspended` status and `leave_active_set`), so a zero-stake validator
   cannot keep collecting round assignments while a normal `suspend` governance action is pending.

4. **Slashed funds are burned**, not paid to the disputer or the provider — carried over unchanged
   from the earlier (closed, unmerged) draft of this ADR: paying the disputer manufactures an
   incentive to fabricate breaches; paying the provider makes every tenant a beneficiary of a
   validator dispute unrelated to their own lease. `ReservableCurrency::slash_reserved` returns a
   negative imbalance; this ADR drops it (no `resolves` call), which reduces total issuance —
   Substrate's standard burn.

5. **What stays explicitly out of scope.** Provider slashing for missed availability commitments
   (#52) needs a bonding mechanism in `pallet-provider-registry` that does not exist yet — a
   substantially larger, separate change (new `Currency` association, changed registration
   semantics for every existing caller including the Control Plane's `register_provider_for` path
   per ADR-009) that #29 does not need and this ADR does not design. #52 is milestone v3.0; when
   it's picked up, it needs its own ADR revision or a follow-up ADR, informed by whatever this
   ADR's validator-slashing implementation teaches in production. `BreachRounds` /
   "one bad round never slashes over a consecutive-rounds window" — relevant to #52's
   availability-commitment framing, not to this ADR's upheld-dispute framing — is likewise left for
   that later ADR.

6. **No clawback of rewards.** Consistent with `pallet-rewards`'s existing documented behavior
   (*"Crediting is one-way: an upheld dispute does **not** currently claw back points already
   accrued for that round"*) — this ADR does not change that. Slashing stake and clawing back
   Reward Points are separate mechanisms; only the former is in scope here.

7. **No new governance primitive.** `EnsureRoot` via `T::SuspensionOrigin` already adjudicates
   `resolve_dispute` today, uncontroversially (already merged, already the MVP's accepted pattern
   per the pallet's own doc: *"final adjudication is deferred (ADR-011 §5), so for the MVP a
   governance origin decides"*). This ADR does not wait on ADR-023 (decentralized governance) —
   nothing here asks `EnsureRoot` to do a new kind of thing, only to have a heavier consequence for
   the same kind of decision it already makes.

## Consequences

- A validator whose evidence is proven wrong through the existing dispute path now has bonded
  funds at stake, not just a round's rewards — closes the incentive gap ADR-011 §5 flagged.
- `close_round` must persist per-round submitter identity (today only the aggregate persists in
  `Rounds`), a storage-shape change to `pallet-network-validator` — bounded by
  `MaxSubmissionsPerRound`, so no unbounded growth.
- A false-positive risk exists: `EnsureRoot` is one key. A wrongly-upheld dispute now costs an
  honest validator real funds, not just a rolled-back score. This ADR accepts that risk for the
  MVP on the same terms the pallet already accepted it for score correctness, and does not widen
  it — the amount is bounded per incident specifically so a single bad governance call is not
  catastrophic. Decentralizing this origin remains ADR-023's job, not this ADR's.
- Colluding-committee risk (ADR-011 §4, ADR-012 §2's already-accepted gap) is unchanged: a
  colluding majority can still get its own wrong aggregate upheld by disputing nothing. This ADR
  does not claim to fix that.
- `#52` (provider slashing) remains blocked on provider bonding, tracked separately, not by this
  ADR's acceptance.

## Verification

Citations checked against source before writing: `blockchain/pallets/network-validator/src/lib.rs`
(module doc lines 19–21 "Still open per ADR-011: slashing"; `submit_evidence` at 568–626,
`DuplicateSubmission` check at 602–605; `resolve_dispute` at 750–790; `trimmed` at ~805–860;
`ReservableCurrency`/`MinStake`/`register_validator` at 161, 173, 441, 449); `runtime/src/lib.rs`
(`SuspensionOrigin = EnsureRoot` at 319, `MinValidatorStake`/`ValidatorUnbondingPeriod`/
`ValidatorDisputeWindow` at 106–115); `pallets/rewards/src/lib.rs` (one-way crediting note at
~178–180); confirmed by grep that `pallet-provider-registry` and `pallet-lease` define no
`Currency`, stake, bond, or collateral of any kind.

Refs #29. Related: #52 (out of scope here, see §5), ADR-011, ADR-012 §6.
