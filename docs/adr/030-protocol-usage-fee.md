# ADR-030: Protocol usage fee (take-rate)

## Status

Proposed. Written by Claude Code, autonomously, in response to issue #120, following the same
convention established by ADR-016/018/025/026/027/028/029: this is a proposal, not yet reviewed.
It becomes Accepted only after the repository owner reviews a summary of this ADR's decisions and
their reasoning and confirms acceptance in an interactive session. Nothing here is implemented by
this ADR itself.

## Context

Issue #120 asks for a protocol-level usage fee — a small, governance-configurable cut of
settlement value routed to a protocol treasury/dev-fund account rather than the provider — so the
network can be self-sustaining from actual usage rather than relying solely on outside funding.

Issue #19's own ADR, **ADR-029 (Metering, billing, escrow, and settlement architecture)**,
explicitly considered folding #120 in and declined, deferring it to a follow-up ADR (ADR-029 §8).
Its stated reasoning, quoted because this ADR builds directly on it rather than re-deciding it:

> 1. This ADR's own custody and evidence-verification design (§3-§6) is already the largest,
>    highest-stakes surface this repository has designed to date. Folding in a second, independent
>    custody problem — a protocol treasury account, with its own governance/multisig design ... —
>    would make one ADR responsible for two separable trust boundaries, harder to review as a unit
>    and harder to accept incrementally.
> 2. A fee is a strictly additive extension of `complete_and_payout`'s already-checked arithmetic
>    (`fee = charged_amount.checked_mul(fee_bps).and_then(|v| v.checked_div(10_000))`,
>    `provider_amount = charged_amount.checked_sub(fee)`, repatriate `fee` to a treasury account
>    instead of burning or folding it into the provider's amount) — it does not change this ADR's
>    state machine, evidence model, or dispute flow. Deferring it costs nothing architecturally.
> 3. The transparency requirement #120 names ... is naturally satisfied by `fund_escrow`'s
>    `max_charge` argument regardless of whether a fee exists — if a follow-up ADR adds one,
>    `max_charge` continues to be the payer's hard authorized ceiling, fee included.

This ADR is that follow-up. It takes ADR-029's escrow lifecycle, custody model, and governance
pattern as settled and adds the fee mechanism on top, exactly along the seam ADR-029 §8 already
sketched.

**State of `pallet-escrow` at the time of writing:** ADR-029 is Accepted but not yet merged to
`main` (open as PR #144); `blockchain/pallets/` in this worktree contains seven pallets
(`provider-registry`, `resource-market`, `lease`, `reputation`, `rewards`, `availability`,
`network-validator`) and **no `pallet-escrow` yet** — confirmed by listing `blockchain/pallets/`
directly. Per this task's own briefing, `pallet-escrow` may be landing in a parallel branch
(`feat/pallet-escrow`); no such branch exists in this repository's remotes at the time of writing
either (checked `git branch -a`). This ADR therefore designs its fee mechanism as **a set of
additive amendments to `pallet-escrow` as specified by ADR-029** (its `EscrowRecord`, `Config`,
extrinsics, and events, quoted and cited by section below) rather than against an implementation
that does not yet exist in this tree. Whoever implements this ADR should re-verify these amendments
against `pallet-escrow`'s actual code once it lands, and reconcile any drift from ADR-029's spec
before proceeding.

**Governed-constant precedent checked directly**, per this task's brief:

- `pallet-rewards` (`blockchain/pallets/rewards/src/lib.rs`) uses `#[pallet::constant] type
  MaxResourceUnits: Get<u64>` / `MaxDuration: Get<u64>` / `MaxReputation: Get<u32>` — compile-time
  constants, changeable only by runtime upgrade, no governed *storage* item for any of them.
- `pallet-network-validator` (`blockchain/pallets/network-validator/src/lib.rs:174-212`) is the
  richer precedent: eight `#[pallet::constant]` compile-time bounds (`MinStake`,
  `UnbondingPeriod`, `MaxSubmissionsPerRound`, `MinQuorum`, `TargetCommitteeSize`, `MaxValidators`,
  `DisputeWindow`, `PointsPerAcceptedSubmission`, `SlashAmount`) plus a runtime-adjustable
  `SuspensionOrigin: EnsureOrigin<Self::RuntimeOrigin>`, wired to `EnsureRoot` in the runtime (per
  ADR-018 §3-4) for dispute resolution.
- Neither existing pallet has a **governed storage value** (something changeable by a plain
  signed-and-checked extrinsic, not a runtime upgrade) — ADR-029 §7 is the first to introduce this
  shape implicitly by naming `EscrowPaused: bool` as a governed boolean toggled by
  `T::PauseOrigin = EnsureRoot`. This ADR's `FeeBasisPoints` and `TreasuryAccount` follow that same
  shape: a `StorageValue` mutated only via an `EnsureRoot`-gated extrinsic, not a compile-time
  `Get<...>` constant — because issue #120 explicitly asks for the rate to be adjustable "so the
  rate isn't a redeploy-required constant," which a `#[pallet::constant]` cannot satisfy (it is
  fixed at compile time, only changeable by a runtime upgrade). This is a deliberate, small
  divergence from the `MaxResourceUnits`-style precedent, justified by #120's own requirement, not
  an inconsistency.

**Where a payer would see this fee, checked directly:** `control-plane/internal/workloadapi/`'s
`SubmitWorkload` (`service.go:113`) returns `SubmitWorkloadResponse{WorkloadId, State, CreatedAt}`
(`protocol/proto/openinfra/controlplane/v1/control_plane.proto:155-159`) — no price or fee field
exists, and none is a natural fit: per ADR-029 §1/§3, pricing (`PriceSchedule`) and escrow funding
happen **later and separately** from `SubmitWorkload`, via a tenant-signed `fund_escrow` extrinsic
the payer constructs themselves (most likely relayed unmodified by the dashboard, per ADR-029 §3),
correlated to the workload only by `lease_id`. `SubmitWorkload` does not know the price, the
provider, or whether escrow will ever be funded for a given workload — it precedes all of that.
Decision §5 below addresses this directly rather than proposing a `SubmitWorkloadResponse` field
that would be premature.

## Decision

### 1. Rate model: flat percentage, in basis points

A single flat percentage of the **settled** amount (`charged_amount`, ADR-029 §4.2), stored as
`u16` basis points (0–10,000, where 10,000 = 100%). This is exactly the shape ADR-029 §8 already
sketched as the natural extension of `complete_and_payout`'s checked arithmetic.

Per-unit (a flat fee per CPU-core-second / MB / GB-second, independent of price) and tiered
(rate varies with volume) were both considered and rejected for v1:

- **Per-unit** would need its own schedule alongside `PriceSchedule`'s four rates (ADR-029 §1),
  doubling that struct's surface for no benefit this issue names, and raises an unresolved question
  ADR-029 deliberately left open — whether the reserved-but-unpriced `gpu_seconds` dimension
  (priced at 0, not billed in v1) should also accrue a per-unit fee despite carrying zero settled
  value. A percentage of `charged_amount` sidesteps this entirely: zero settled value on a
  dimension trivially yields zero fee on it, with no special case.
- **Tiered** (rate depends on cumulative volume, e.g. per payer or per provider over time) requires
  stateful accumulation this system has nowhere today — no per-account running total exists on any
  economic pallet — and the issue's own text names this as "added complexity for unclear benefit at
  MVP stage." Building that accumulator is a strictly bigger, separable piece of work with no
  named requirement driving it yet.

A flat percentage is stateless per settlement call, uniform regardless of which billable dimension
produced `charged_amount`, and requires no new state beyond the rate itself.

### 2. Collection point: only at successful `complete_and_payout` (and `resolve_dispute`'s
`PayProvider` outcome), never at funding or on a full refund

Tied explicitly to `pallet-escrow`'s four lifecycle calls as specified in ADR-029 §4:

| Call | Fee deducted? | Reasoning |
|---|---|---|
| `fund_escrow` | **No.** | `max_charge` is reserved from the payer's own account, untouched by this ADR (§2's Consequences point 3, ADR-029). Fee is only ever computed against the *actual settled* `charged_amount`, which does not exist yet at funding time — deducting anything here would mean a payer is charged a fee even in a scenario that ends in total under-delivery or a full refund, which this ADR treats as unacceptable (see the row below). |
| `complete_and_payout` | **Yes**, from `charged_amount`. | This is the only call in the entire lifecycle that certifies real, verified, signed delivery of service (ADR-029 §4.2's Ed25519-verified `MeteringSummary`). It is the one point where "value was actually delivered and settled" is true, checked on-chain, not asserted. |
| `refund_escrow` | **No.** | Per ADR-029 §4.3, this path returns the full `max_charge` to the payer when nothing was ever settled (silence, non-delivery). No value was delivered, so no fee is owed on it — a fee here would mean the protocol takes a cut of a transaction that produced nothing, which is not the "usage fee" issue #120 asks for. |
| `dispute_escrow` | **N/A** (no value movement). | Freezes state only; §4's rows above/below apply once resolved. |
| `resolve_dispute`, outcome `RefundPayer` | **No.** | Same reasoning as `refund_escrow`: this outcome affirms the provider did *not* deliver as claimed (ADR-029 §5 also withholds the reputation penalty's opposite — a `PayProvider` outcome — from this branch, for the same "no fee/penalty when nothing legitimate happened" logic). No fee on a transaction the adjudicator determined did not legitimately settle. |
| `resolve_dispute`, outcome `PayProvider(amount)` | **Yes**, from `amount`. | This outcome affirms the provider *is* owed for delivered service, adjudicated rather than self-certified — the same "value was actually delivered" condition as `complete_and_payout`, just established by governance instead of on-chain verification. Consistent treatment: same fee computation, factored into one shared internal function both call sites use. |

This is the conservative default the task brief itself named as the safest starting point, and this
ADR adopts it as-is: **no fee on funding, fee only on a call that affirms real settled delivery,
full refund on non-delivery includes no fee deduction.**

Computation, inside `complete_and_payout` (and `resolve_dispute`'s `PayProvider` arm, via a shared
helper) immediately after `charged_amount` is computed and capped at `escrow.max_charge` (ADR-029
§4.2's existing `ChargedAmountExceedsCap` check runs first, unchanged):

```rust
let fee_bps = FeeBasisPoints::<T>::get(); // u16, 0..=MaxFeeBasisPoints::get()
let fee_amount = charged_amount
    .checked_mul(fee_bps.into())
    .and_then(|v| v.checked_div(10_000u32.into()))
    .ok_or(Error::<T>::ArithmeticOverflow)?;
let provider_amount = charged_amount
    .checked_sub(fee_amount)
    .ok_or(Error::<T>::ArithmeticOverflow)?; // fee_amount <= charged_amount by construction
```

followed by two `repatriate_reserved` calls instead of ADR-029 §4.2's single one — `provider_amount`
to `escrow.provider`, `fee_amount` to `TreasuryAccount::<T>::get()` — both from the same `payer`
reservation, using the same `BalanceStatus::Free` semantics ADR-029 §4.2 already specifies.
`T::Currency::unreserve(&payer, escrow.max_charge - charged_amount)` for any unused reservation is
**unaffected** — it is computed from `charged_amount`, not from `provider_amount`, so the fee never
changes how much of the payer's authorized ceiling is returned to them. **The payer's total outlay
is never increased by this fee** — they are charged at most `charged_amount`, exactly as ADR-029
already specifies; the fee only changes how that already-determined amount is *split* on the way
out (§4 below makes this framing explicit).

When `fee_bps == 0` (a valid, governable state, §3), `fee_amount` computes to `0` and the
implementation should skip the zero-value `repatriate_reserved` call to `TreasuryAccount` as a
no-op optimization — a detail for the implementer, not a behavioral difference from a nonzero fee
where the arithmetic degenerates cleanly to "provider receives everything," matching today's
fee-less ADR-029 baseline exactly.

### 3. Destination and custody: a governed treasury account, `EnsureRoot`-controlled for now

A new storage item, `TreasuryAccount: StorageValue<_, T::AccountId, OptionQuery>` (starts unset;
`fund_escrow`... no — `complete_and_payout` with `fee_bps > 0` and no `TreasuryAccount` configured
must fail closed with a new `TreasuryAccountNotConfigured` error, never silently burn or misdirect
the fee), settable only via a new extrinsic:

```rust
fn set_treasury_account(origin: OriginFor<T>, new_account: T::AccountId) -> DispatchResult {
    T::FeeGovernanceOrigin::ensure_origin(origin)?;
    let old = TreasuryAccount::<T>::get();
    TreasuryAccount::<T>::put(&new_account);
    Self::deposit_event(Event::TreasuryAccountUpdated { old, new: new_account });
    Ok(())
}
```

`T::FeeGovernanceOrigin = EnsureRoot<Self::AccountId>` for the MVP — the same choice ADR-029 §4.5
and §10 already made for `DisputeOrigin` and `PauseOrigin`, and the same choice ADR-018 §3-4 made
for `SuspensionOrigin`. This is not a new governance primitive; it is the same single sudo-key
surface this codebase already trusts for every other adjudicated or protocol-parameter decision.

**Explicit, load-bearing caveat, stated as plainly as ADR-029 §12 states its own regulatory
caveats:** `EnsureRoot` naming a single account (today, in practice, the same key behind every
other root-gated call in this runtime) as the fee-rate-setter and the recipient-account-setter is
**not a production custody design**. It does not specify who holds the keys behind `EnsureRoot`,
whether the `TreasuryAccount` itself is a multisig, a DAO-controlled account, or a single EOA, or
what operational controls exist around spending from it once funds accrue there. This ADR
deliberately does **not invent a multisig or DAO scheme** to fill that gap — doing so would be
exactly the kind of unfounded architectural invention the task's own brief warns against. Production
custody and governance of the treasury account is a **non-engineering decision the repository owner
must make separately**, informed by real operational and possibly legal/regulatory input (the same
category of open question ADR-029 §12 already flagged for escrow generally) — this ADR only
specifies that, until that decision is made, the mechanism defaults to the same `EnsureRoot` origin
already governing every other protocol parameter in this runtime, changeable later to a different
origin type by a runtime upgrade with no change to `pallet-escrow`'s call surface.

### 4. Configurability: a governed storage rate with a compile-time cap

```rust
#[pallet::storage]
#[pallet::getter(fn fee_basis_points)]
pub type FeeBasisPoints<T: Config> = StorageValue<_, u16, ValueQuery>; // default via GenesisConfig
```

```rust
fn set_fee_basis_points(origin: OriginFor<T>, new_bps: u16) -> DispatchResult {
    T::FeeGovernanceOrigin::ensure_origin(origin)?;
    ensure!(new_bps <= T::MaxFeeBasisPoints::get(), Error::<T>::FeeExceedsCap);
    let old = FeeBasisPoints::<T>::get();
    FeeBasisPoints::<T>::put(new_bps);
    Self::deposit_event(Event::FeeBasisPointsUpdated { old, new: new_bps });
    Ok(())
}
```

with a new **compile-time** bound, `#[pallet::constant] type MaxFeeBasisPoints: Get<u16>`, matching
the `#[pallet::constant]`-bound-plus-governed-value shape ADR-029 §7 already uses for
`MinEscrowAmount` alongside a runtime value it caps against.

**Sane default and documented cap, as the task requires explicitly:**

- Default `FeeBasisPoints` at genesis: **100 bps (1%)**. Deliberately conservative for an MVP —
  a young network needs provider and payer adoption more than fee revenue, and a fee that is easy
  to justify as negligible against a payer's total cost lowers the bar for using the network at
  all. This is a starting point for governance to raise deliberately as the network matures, not a
  claimed-final number — no different in spirit from any other governed constant's initial value in
  this codebase.
- `MaxFeeBasisPoints`: **2,000 bps (20%)**. Generous enough that governance has real room to adjust
  the rate for years of plausible commission-style pricing without needing a runtime upgrade for an
  ordinary rate change, while hard-blocking a `set_fee_basis_points` call from ever reaching
  anything close to confiscatory (100%, or even a majority split) without a **runtime upgrade** —
  a materially higher-friction, more visible action than a single extrinsic, and the same
  "a single governance call should not be able to destroy/extract everything" instinct
  `SlashAmount`'s own doc comment already states for validator slashing (ADR-018 §3).
  Raising the cap itself is possible later, but only via that same higher-friction path, which is
  the point: an accidental or malicious near-100% fee requires two independent, differently-shaped
  actions (a runtime upgrade to raise the cap, *and* a separate `EnsureRoot` call to set the rate
  within it), not one.
- Every change to either value emits an event (`FeeBasisPointsUpdated`, `TreasuryAccountUpdated`)
  carrying both the old and new value, so a rate or destination change is always visible in the
  on-chain event log, not just in a storage diff a casual observer would need to know to look for.

### 5. Transparency: the fee **rate** is visible before commitment; the fee **amount** cannot be,
and is not claimed to be

Two distinct claims #120 conflates and this ADR separates explicitly:

- **The rate** (`FeeBasisPoints`, currently N%) is knowable in advance — it is a single governed
  number, unrelated to any specific escrow's future usage.
- **The fee amount** for a specific escrow is **not** knowable at funding time, for the same reason
  `charged_amount` itself is not: both depend on actual metered usage over the lease's lifetime,
  which does not exist yet when `fund_escrow` is called. This ADR does not claim otherwise — a
  pre-commitment "estimated fee in currency units" would require estimating usage, which ADR-029 §1
  already declines to do anywhere in this design (`PriceSchedule` is a rate, not a projection).

Given that, and given Context's finding that `SubmitWorkload` precedes and is decoupled from escrow
funding entirely (ADR-029 §3), **this ADR does not add a fee or cost field to
`SubmitWorkloadResponse`** — there is no price, provider, or escrow to compute one against at that
point in the flow, and adding a field here would misleadingly imply a cost estimate exists where
none can yet.

The correct integration point is wherever the payer is about to sign `fund_escrow` — which, per
ADR-029 §3, is necessarily a chain-state-aware moment already (the dashboard/wallet must read
`PriceSchedule`/`max_charge` inputs and construct a real extrinsic for the payer to sign). This ADR
specifies, as **MVP-required**:

1. `FeeBasisPoints` is public on-chain storage — trivially queryable by any RPC caller, indexer, or
   `control-plane/internal/blockchainbridge` read call (the bridge already reads other pallet
   storage the same way; this needs one more read method, not a new mechanism).
2. Whatever UI surface eventually presents the "fund this escrow" action to a payer (built by #20/
   #21, not this ADR) must display the current `FeeBasisPoints` value — e.g. "a N% protocol fee
   (currently N%, governance-adjustable) applies to settled usage, deducted from the provider's
   payout at completion" — **before** the payer signs `fund_escrow`. This satisfies #120's actual
   transparency requirement ("visible to the payer before they commit funds") precisely, without
   requiring a usage estimate this design has no basis for producing.

**Recommended, not required for this ADR to be complete:**

- A dashboard-visible, per-completed-escrow breakdown (settled amount / fee taken / provider net)
  sourced from `EscrowSettled`'s event fields (§6 below adds `fee_amount` to that event
  specifically so this is possible without a second on-chain read). Nice-to-have, post-hoc
  transparency — not pre-commitment transparency, so not required for #120's own stated bar.
- A computed running total ("fees paid to date across all your escrows") in the dashboard. Purely
  additive off-chain aggregation over already-public events; no new on-chain mechanism needed if
  built.

### 6. Provider-facing framing: a revenue split against the provider's payout, not an add-on to
what the payer pays

Per §2's computation, the fee is subtracted from `charged_amount` on the way out to the provider —
the payer's authorized ceiling (`max_charge`) and actual charge (`charged_amount`, capped by
`max_charge`) are **unaffected** by whether a fee exists or what it is set to. This ADR deliberately
rejects the alternative (a fee added *on top of* what the payer authorizes) because that would mean
`max_charge`'s meaning becomes ambiguous — is it the payer's ceiling including or excluding the fee?
— and would require touching ADR-029's already-specified `ChargedAmountExceedsCap` validation
semantics, which this ADR's Consequences section states plainly it does not do.

This makes the fee, in the vocabulary #120's own text used, a **revenue split against the
provider's payout**, not a fee on the payer. Legibility to a provider pricing an offer in
`pallet-resource-market` follows directly and requires **no change to `pallet-resource-market`
itself**: `ResourceOffer` has no price field today (confirmed unchanged, ADR-029's own Context
finding) — pricing is bilateral and off-chain, expressed as `PriceSchedule` at escrow-funding time
(ADR-029 §1). Because `FeeBasisPoints` is public on-chain storage (§5), a provider (or their
tooling) can read the current rate and factor it into the price they negotiate, exactly the way
they would factor in any other bilateral input — e.g. a provider wanting to net a specific
per-core-second rate simply negotiates a `cpu_core_second` value scaled up by
`1 / (1 - fee_bps / 10_000)`. No on-chain gross-up computation, no new pallet-resource-market field,
and no change to how `PriceSchedule` is agreed or stored is needed for this — the same "provider
self-adjusts a bilateral input" pattern this codebase already uses for bandwidth and zone claims
(ADR-015, ADR-026).

## Consequences

- **Amendments to `pallet-escrow` as specified by ADR-029**, once it exists in this tree (§Context):
  two new storage items (`FeeBasisPoints: StorageValue<u16>`, `TreasuryAccount:
  StorageValue<T::AccountId, OptionQuery>`), one new compile-time `Config` constant
  (`MaxFeeBasisPoints: Get<u16>`), one new origin type (`FeeGovernanceOrigin: EnsureOrigin<...>`,
  wired to `EnsureRoot` at the runtime level, matching `DisputeOrigin`/`PauseOrigin`), two new
  extrinsics (`set_fee_basis_points`, `set_treasury_account`), two new events
  (`FeeBasisPointsUpdated`, `TreasuryAccountUpdated`), one new error (`FeeExceedsCap`; plus
  `TreasuryAccountNotConfigured` for the fail-closed case in §2), and a modification to
  `complete_and_payout` and `resolve_dispute`'s `PayProvider` arm to split the settled amount two
  ways instead of paying it out whole. `EscrowSettled`'s existing event (ADR-029 §4.2) gains a new
  `fee_amount: BalanceOf<T>` field alongside its existing `charged_amount`, so the split is
  reconstructable from the event alone (feeds §5's recommended dashboard breakdown and #20's audit
  ledger, matching ADR-029 §10's "reproducible from on-chain events" requirement literally).
- **Zero changes to `fund_escrow`, `refund_escrow`, `dispute_escrow`'s signatures or behavior**, and
  zero changes to `pallet-lease`, `pallet-provider-registry`, `pallet-reputation`, or
  `pallet-resource-market` — this ADR's footprint is confined to `pallet-escrow`'s payout-splitting
  calls and two new governance extrinsics, matching ADR-029's own "deliberately minimal footprint"
  precedent for how it touched already-shipped pallets.
- **A new read path for `control-plane/internal/blockchainbridge`**: exposing `FeeBasisPoints` to
  the dashboard/wallet UI that will eventually construct `fund_escrow` extrinsics (§5) is new,
  small, additive work for whichever future issue builds that UI (#20/#21's territory, same as
  ADR-029's own "not attempted here" carve-outs) — named as required for this ADR's transparency
  requirement to actually be met in practice, not assumed to happen automatically.
- **Genesis/dev-chain concern**: `TreasuryAccount` needs a real, known account configured in
  `deployments/`'s local dev chain (mirroring ADR-029's own note about endowing payer/provider test
  accounts) for `complete_and_payout` with a nonzero default fee to work end-to-end in local dev —
  a dev-environment task for whoever implements this, not a consensus-rule concern.
- This ADR does not close issue #120 by itself; #120 is a design issue, closed by this ADR's
  acceptance (matching ADR-029's own "issue closes only once the ADR is Accepted" convention), with
  the actual `pallet-escrow` amendments implemented alongside or after #21's own implementation
  work, whichever lands `pallet-escrow` first.

## Out of scope

- Any multisig, DAO, or other production custody scheme for `TreasuryAccount` — explicitly declined
  to invent one (§3); this is the repository owner's decision to make, informed by real operational
  and possibly legal input, not this ADR's to prescribe.
- Per-unit or tiered fee models (§1) — flat percentage only, for the reasons given.
- A fee-inclusive cost *estimate* surfaced anywhere pre-usage — only the fee *rate* is claimed
  knowable in advance (§5); this ADR does not attempt to estimate a specific escrow's eventual fee
  before usage occurs.
- Any change to `pallet-resource-market`'s `ResourceOffer` shape, or any on-chain price
  gross-up/negotiation mechanism — pricing legibility for providers is achieved by reading public
  `FeeBasisPoints` state and adjusting a bilateral, off-chain-agreed `PriceSchedule`, not by a new
  on-chain mechanism (§6).
- Spending, budget, or disbursement controls over funds once they reach `TreasuryAccount` — this ADR
  specifies only how funds arrive there, not how they are subsequently spent or governed once held.
- A per-provider or per-payer variable fee rate — one global `FeeBasisPoints` for the whole network,
  matching every other governed constant in this codebase being a single global value, not a
  per-account parameter.

## Verification

Checked against source before writing: `blockchain/pallets/` directory listing (confirmed no
`pallet-escrow` exists in this worktree yet; confirmed the seven pallets that do); `git branch -a`
(confirmed no `feat/pallet-escrow` branch exists in this repository's remotes at time of writing);
`blockchain/pallets/rewards/src/lib.rs` (full file — `#[pallet::constant]` governed-constant shape,
`checked_*` arithmetic convention, `ArithmeticOverflow` error naming); `blockchain/pallets/
network-validator/src/lib.rs` (lines 150-220 — `Config` trait's full constant list, `SuspensionOrigin:
EnsureOrigin` pattern, `SlashAmount`'s bounded-per-incident doc-comment reasoning this ADR's
`MaxFeeBasisPoints` cap mirrors); `blockchain/pallets/lease/src/lib.rs` (grepped for
`#[pallet::constant]`/`Get<`, confirmed `MaxDuration: Get<BlockNumberFor<Self>>` as its only governed
constant); `control-plane/internal/workloadapi/service.go:113-148` (`SubmitWorkload`'s actual return
shape, confirmed no price/fee field); `protocol/proto/openinfra/controlplane/v1/control_plane.proto`
(`SubmitWorkloadRequest`/`SubmitWorkloadResponse` message definitions, confirmed no price field
anywhere in the request either); `docs/adr/` directory listing on `main` (confirmed ADR numbers
001–018, 025, 026 exist; 017, 019–024 do not; 027/028/029 are claimed by open, unmerged PRs #143/
#144, not present on `main` — this ADR is numbered 030, the next number free on `main` and not
claimed by either open PR); `gh pr diff 143 --name-only` / `gh pr diff 144 --name-only` (confirmed
their file lists: `027-mtls-pki-enrollment-rotation-revocation.md`,
`028-provider-agent-disconnected-mode.md`, `029-metering-billing-escrow-settlement.md` respectively
— no overlap with `030-protocol-usage-fee.md`); `git show
origin/docs/adr-settlement-architecture-proposal:docs/adr/029-metering-billing-escrow-settlement.md`
(full file — read in its entirety; every ADR-029 section cited above quoted or paraphrased from this
exact text, not from memory or assumption); `gh issue view 120` (full text, every open question
addressed above by section); `AGENTS.md` (frozen architecture, permanent prohibitions — confirmed
this ADR introduces no new pallet, database, language, or component boundary, only amendments to a
pallet ADR-029 already specifies).

Refs #120. Related: ADR-029 (this ADR's direct prerequisite — its escrow lifecycle, custody model,
and governance pattern are reused, not re-derived; §8 of ADR-029 is the deferral this ADR resolves),
ADR-018 (the `EnsureRoot`-governance and bounded-per-incident precedent this ADR's fee cap follows),
issue #19/#20/#21 (the metering/billing/escrow implementation work this ADR's amendments apply on
top of, once `pallet-escrow` exists in this tree).
