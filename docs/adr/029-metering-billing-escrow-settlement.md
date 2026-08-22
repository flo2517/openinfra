# ADR-029: Metering, billing, escrow, and settlement architecture

## Status

Accepted (by the repository owner, explicitly, relayed in-session — after reviewing a full summary
of this ADR's decisions and their reasoning, then confirming to proceed with implementation).

Originally written by Claude Code, autonomously, in response to issue #19, and held as Proposed
per the convention established by ADR-016/018/025/026/027/028: this is the first design in this
repository to move real, spendable monetary value on-chain, not just reputation numbers, state
records, or bonded stake used purely as a slashing deterrent. Nothing here is implemented yet by
this ADR itself; issues #20 and #21 are unblocked by this acceptance and now carry the
implementation work.

## Context

Issue #19 asks for the architecture that #20 (auditable usage metering / invoice ledger) and #21
(on-chain escrow and provider settlement) will implement, plus #120 (protocol usage fee) folded in
or explicitly deferred. Nothing about payment exists in this codebase today — verified directly,
not assumed:

- **No price is recorded anywhere on-chain.** `pallet-resource-market`'s `ResourceOffer` (`cpu`,
  `ram`, `storage`, `capabilities`) has no price field. `pallet-lease`'s `Lease` (`provider`,
  `consumer`, `resource_hash`, `start`, `end`, `state`) has no price field either. The only place
  "price" appears anywhere in the protocol is `WorkloadConstraints.max_price` — a `float` (proto3
  `shared.proto:119`), a workload's own unenforced ceiling, explicitly called out as inert by
  `internal/scheduler/rank.go`'s own comment (`"constraints.MaxLatencyMs and constraints.MaxPrice are
  accepted but not enforced... inventing a number to compare against would be worse than the honest
  gap"`). This ADR does not reuse that float field for anything on-chain — floats are permanently
  banned from consensus arithmetic (`AGENTS.md`), and this field was never wired to any actual rate
  to begin with.
- **No payment asset moves anywhere today.** `pallet-rewards`'s `RewardBalances` is a plain `u64`
  ledger with no `Currency` trait involved at all — `claim_reward` (`blockchain/pallets/rewards/
  src/lib.rs:158-168`) zeroes the caller's balance and emits an event; it does not call `transfer`,
  `mint`, or touch `pallet_balances` in any way. Reward Points cannot currently be spent, redeemed,
  or converted into anything. This is the starting point this ADR must keep true: Reward Points stay
  reputation-shaped, not payment-shaped.
- **A real `Currency` mechanism already exists and is already used for bonded stake.**
  `blockchain/runtime/src/lib.rs` wires `pallet_balances` in (`Balances = pallet_balances::Pallet
  <Runtime>` at pallet index 3, `AccountData = pallet_balances::AccountData<u64>`), and
  `pallet-network-validator` already depends on it as `type Currency: ReservableCurrency<Self::
  AccountId>` (`blockchain/pallets/network-validator/src/lib.rs:163`), reserving real stake at
  `register_validator` (`T::Currency::reserve`), releasing it at `withdraw_unbonded` (`T::Currency::
  unreserve`), and burning it on an upheld dispute (`T::Currency::slash_reserved`, ADR-018 §3-4).
  `Balance` is `u64` throughout. This is the only real value-bearing mechanism in this codebase
  today, and it is already a FRAME `ReservableCurrency` — the natural foundation to build escrow on
  rather than a new asset class.
- **Every value-bearing extrinsic in this runtime today is submitted by one account, wrapped in
  `Sudo`.** `control-plane/internal/blockchainbridge/registrar.go` (`sudoPalletIndex`/
  `sudoCallIndex`, used for `updateLeaseStateCallIndex`, `setStatusCallIndex`, `registerForCallIndex`
  — every bridge-initiated call) confirms the Control Plane's bridge account is the sole real signer
  behind `RegistrationOrigin`, `StatusOrigin`, `AnnounceOrigin`, `LeaseOrigin`, and `RewardOrigin`,
  every one of which is `frame_system::EnsureRoot<Self::AccountId>` (`runtime/src/lib.rs:165-237`).
  Concretely, **every `pallet-lease::create_lease` call today is signed by the bridge account as
  `consumer`** — `registrar.go:106`'s own check (`"lease %d is not owned by the bridge account"`)
  confirms the bridge account, not a real tenant key, is the `consumer` on every lease that exists.
  This matches ADR-012 §2's vocabulary table verbatim: *"Tenant / User... Has no on-chain identity
  today."* Any escrow design that reserves funds from "the lease's consumer" would, unmodified,
  reserve funds from the **bridge account itself** — i.e. it would make the Control Plane's single
  sudo key the custodian of every tenant's money. This ADR treats that as unacceptable for a design
  handling real value (see Decision §3) and deliberately decouples escrow funding from
  `pallet-lease`'s `consumer` field rather than requiring a change to how leases are created.
- **A provider's Ed25519 public key is already on-chain, keyed by AccountId, today.**
  `pallet-provider-registry`'s `Provider<T>` struct (`blockchain/pallets/provider-registry/src/
  lib.rs:68-73`) stores `public_key: [u8; 32]` directly, populated at registration and indexed a
  second way via `ProviderByKey`. This is the same key `agent-core::identity::Ed25519IdentityManager`
  holds locally and the same key `providerjoin.BeginJoin`/`CompleteJoin` already runs a full,
  tested challenge-response ceremony against. It means a pallet can verify an Agent-signed message
  on-chain, against a public key the chain already trusts, without inventing new key infrastructure
  — a meaningfully stronger option than this codebase's existing pattern of trusting the relayer
  (see `pallet-availability::submit_proof`'s own doc comment: *"Signature verification is
  deliberately performed by the validator bridge before this authorized call"*). Decision §6 uses
  this.
- **The replay-protection pattern this ADR must reuse, not reinvent, is already named by
  ADR-012 §4**: *"Generalize the pattern already proven in `pallet-availability`: a monotonic
  per-subject sequence checked with `sequence > LastProofSequence::<T>::get(&provider)`... plus a
  block-number deadline... Every new signed message introduced by a later stage must carry a
  subject, a sequence or nonce, and a deadline. No new replay scheme is to be invented."*
- **ADR-018 is the closest economic precedent** (validator stake slashing on an upheld dispute) and
  establishes conventions this ADR follows rather than re-derives: bounded per-incident amounts
  rather than all-or-nothing, slashed value is burned rather than redirected (no incentive to
  fabricate a claim), `EnsureRoot` reused rather than inventing a new governance primitive, and the
  explicit, honest statement of what stays out of scope for the MVP.
- **`pallet-provider-registry` still has no `Currency`/stake association** — confirmed unchanged
  since ADR-018 §5 first noted this by grep. Providers cannot be stake-slashed by this ADR either;
  only the softer reputation-dimension penalty pallet-reputation already exposes is available (see
  Decision §5).
- **AGENTS.md's permanent, non-ADR-liftable prohibition** — "Never put detailed metrics on-chain.
  Never put tenant payloads, logs, secrets, or any personal data on-chain: only hashes and
  commitments may cross that line" — and ADR-012 §3's data classification (`Metrics`: "Never
  on-chain"; `Payments / Reward Points`: on-chain, integer, permanent) bound every decision below.
  Bounded integer counters (successful/total samples, CPU-core-seconds) are not "detailed metrics"
  in the sense this rule means — `pallet-availability::AvailabilitySummary` already puts exactly
  this shape of bounded integer summary on-chain today, and this ADR follows that precedent, not a
  new exception to it.

## Decision

### 1. Billable units, integer representation, and where price attaches

Four billable dimensions for v1, matching what's already measured elsewhere in this codebase
(CPU/RAM/storage from `ResourceCapability`/`ResourceRequirements`, network from ADR-025's bandwidth
work) plus a reserved, unpriced fifth:

| Dimension | Unit | Smallest indivisible increment |
|---|---|---|
| CPU | core-seconds | 1 (integer core-seconds, no fractional cores mid-billing — `ResourceRequirements.cpu` stays a float for *scheduling fit*, off-chain; billing always integerizes) |
| RAM | MB-seconds | 1 |
| Storage | GB-seconds | 1 |
| Network | MB (egress + ingress counted separately) | 1 |
| GPU | reserved, `gpu_seconds: u64` field present, **priced at 0 and not billed in v1** | — |

A `metering_schema_version: u16` travels with every metering summary (Decision §6) so a future
schema bump (e.g. real GPU billing, a new dimension) is explicit and old evidence stays
interpretable under the version it was recorded against — the same "explicit version, no silent
reinterpretation" instinct `pallet-network-validator`'s `spec_version`/`transaction_version` guard
(`registrar.go`'s `supportedSpecVersion` check) already enforces for the wire protocol as a whole.

**All values are `u64`, denominated in the settlement `Currency`'s smallest indivisible unit
(Decision §2) per second/MB.** No float crosses into a metering summary or a price at any point —
`WorkloadConstraints.max_price`'s existing float is not reused (Context, above) and this ADR does
not add a second float-typed price field anywhere. All arithmetic combining a rate and a usage count
is `checked_mul`/`checked_add`, erroring (`ArithmeticOverflow`-shaped, matching `pallet-rewards`'s
own error) rather than saturating — unlike `pallet-reputation`'s deliberate use of `saturating_*`
for a bounded score, silently truncating a monetary computation is wrong, not merely imprecise, so
this ADR explicitly does not carry that pattern over.

**Price attaches once, at escrow funding, as an explicit `PriceSchedule`:**

```rust
pub struct PriceSchedule {
    pub cpu_core_second: u64,   // smallest Currency unit per core-second
    pub ram_mb_second: u64,
    pub storage_gb_second: u64,
    pub network_mb: u64,        // same rate applied to egress and ingress MB
}
```

supplied as an argument to `fund_escrow` (Decision §3) and stored immutably inside that escrow's
record. This directly answers "how a price is versioned/attached to a lease": it is not a global
on-chain price list and not a per-provider on-chain rate card — it is a per-escrow commitment,
agreed off-chain between payer and provider (mirroring the already-accepted trust boundary for
bandwidth (ADR-015) and zone (ADR-026): a provider's price is a self-declared, unverified fact, the
same class of claim as its bandwidth or zone, not a new trust boundary). Once funded, a `PriceSchedule`
never changes for that escrow — no retroactive repricing of an in-flight lease, the same "commit
once" discipline `ProcessedLeases`/`LeaseAlreadyRewarded` already enforce for reward calculation.

### 2. Currency/asset model: reuse `pallet_balances`, keep Reward Points untouched

Settlement value moves through the runtime's existing `pallet_balances` (`Balances`), the same
`Currency`/`ReservableCurrency` already backing Network Validator stake. **No new asset pallet
(`pallet-assets` instance or otherwise) for v1.** Reasoning:

- It is already integrated, already a `ReservableCurrency`, already proven for real reserve/
  unreserve/slash flows in this exact runtime (ADR-011/018). Introducing a second asset class would
  mean two independent balance systems, two sets of edge cases, and no consumer in this codebase
  that needs a separate token today.
- The burden of proof for a new mechanism is on diverging from working precedent, and nothing about
  settlement's requirements (integer, checked arithmetic, reservable, transferable between accounts)
  needs anything `pallet_balances` doesn't already provide.
- If a genuinely separate settlement asset (e.g. a stablecoin, a cross-chain asset) becomes a real
  requirement later, introducing `pallet-assets` is a normal, additive pallet addition — nothing
  built on top of this ADR needs to be designed around that possibility in advance, the same
  "don't carry speculative complexity" reasoning ADR-016 §1 used for its own role model.

**Reward Points remain completely distinct, untouched by this ADR.** `pallet-rewards`'s
`RewardBalances` stays a `u64` ledger with no `Currency` involvement. This ADR adds no conversion,
no exchange rate, and no bridge between `RewardBalances` and `pallet_balances::Balance`. A provider
or validator's Reward Points total says nothing about, and has no effect on, its settlement balance.
If a future ADR wants Reward Points to carry real value (a buy-back, a staking yield, a governance
weight), that is a distinct tokenomics decision this ADR does not make and does not presuppose.

**`Balance = u64` headroom, stated honestly:** `u64`'s max (~1.8×10¹⁹) is ample if the smallest unit
is a small fraction of nominal value, but this ADR does not pick or name a real-world currency peg —
doing so would be exactly the kind of regulatory claim §9 explicitly declines to make. If real
fiat-scale value at fine-grained precision is ever handled, `Balance`'s width should be revisited as
part of that work (a runtime-level type change, a genuine migration) — flagged here rather than
silently assumed adequate forever.

### 3. Mechanism: a new FRAME pallet, `pallet-escrow`, not Substrate Contracts

**FRAME pallet, matching every existing economic pallet in this codebase** (`provider-registry`,
`resource-market`, `lease`, `reputation`, `rewards`, `availability`, `network-validator` — all
seven are FRAME pallets, zero exceptions). Substrate Contracts (or any other execution layer) was
considered and rejected:

- Nothing in this workspace depends on `pallet-contracts` today (`blockchain/runtime/Cargo.toml`'s
  `polkadot-sdk` feature list has no `pallet-contracts` entry) — adopting it would itself be a new
  framework/component choice under `AGENTS.md`'s frozen-architecture rule, and unlike on-chain
  orchestration (ADR-019) or P2P mesh (ADR-020), ADR-012 §6's gate table names **no** existing gate
  for a smart-contract execution layer. There is no accepted door for this, and no argument in issue
  #19 or #21 that needs one — a FRAME pallet gets deterministic execution, `no_std`, no floats, and
  bounded storage for free, which is everything this design needs.
- FRAME gives compile-time-checked, benchmarkable dispatch weights out of the box, which is #21's
  own explicit acceptance criterion ("benchmarked weights"); a contracts-based design would need to
  re-derive gas metering discipline this codebase has never used.
- The reviewers, tooling, and test patterns (`#[cfg(test)] mod tests`, `frame_support::pallet!`,
  the `ProviderInspector`/`NetworkValidatorInspector` narrow-trait pattern for cross-pallet wiring)
  already exist and are already exercised by six pallets — a new pallet is the smallest coherent
  change; a new execution model is not.

New pallet `pallet-escrow`, wired at runtime `pallet_index(17)` (the next free index after
`network-validator` at 16). It depends on:

- `type Currency: ReservableCurrency<Self::AccountId>` — bound to `Balances` in the runtime, exactly
  as `pallet-network-validator` already does.
- `type ProviderKeyLookup` — a new narrow trait (`fn public_key(provider: &AccountId) -> Option<
  [u8; 32]>`), redeclared per this pallet the same way `ProviderInspector`/`NetworkValidatorInspector`
  already are (`blockchain/pallets/reputation/src/lib.rs:11-31`, `availability/src/lib.rs:15-38`) so
  `pallet-escrow` carries no hard compile dependency on `pallet-provider-registry`; the runtime wires
  it to `Providers::<Runtime>::get(provider).map(|p| p.public_key)`.
- `type ReputationPenalty` — a new narrow trait for the dispute-loss consequence (Decision §5),
  wired to a new non-extrinsic function on `pallet-reputation` (mirroring how `pallet-network-
  validator` already calls `pallet_reputation::Pallet::<T>::set_dimension_score` internally, not via
  an extrinsic, per `reputation/src/lib.rs:294-340`'s own doc comment: *"Not an extrinsic: this is
  the internal entry point... so `pallet-reputation` remains the only writer"*).
- **No dependency on `pallet-lease` beyond a narrow, read-only `LeaseExists` check** (does
  `lease_id` exist at all, used only to reject funding an escrow against a nonexistent lease id as a
  sanity check) — deliberately **not** a check that `origin == Leases::<T>::get(lease_id).consumer`.
  See §3's Context discussion and the paragraph below for why.

**Escrow's `payer` is decoupled from `pallet-lease`'s `consumer` field.** Because every lease's
`consumer` today is the Control Plane bridge account (Context, above), requiring `fund_escrow`'s
caller to match `Leases::consumer` would make the bridge account the custodian of every tenant's
money — a single key holding everyone's funds, materially worse than today's centralization (which
holds only state records and reputation, nothing spendable). Instead, `fund_escrow`'s `origin`
(`ensure_signed`) becomes the escrow's own, independently tracked `payer: AccountId` field, checked
against nothing but itself for every subsequent call on that escrow. This requires a real, tenant-
held on-chain key funding the escrow directly — the same building block ADR-014's wallet-based
login already establishes (a browser wallet signs a challenge today; this ADR needs that same wallet
to sign and submit a real extrinsic, a genuine extension of ADR-014's scope, not something it
already does — named honestly as new work for #21/#20 to build, most likely via client-side
construction of the raw signed extrinsic that the dashboard then relays unmodified, so the Control
Plane never sees or holds the tenant's private key at any point). This ADR does **not** require
changing how `pallet-lease::create_lease` assigns its `consumer` — that stays exactly as it is
today; escrow tracks its own payer independently, correlated with the lease only by `lease_id`.

### 4. Escrow lifecycle

```rust
pub enum EscrowState { Funded, Completed, Refunded, Disputed }

pub struct EscrowRecord<T: Config> {
    pub payer: T::AccountId,
    pub provider: T::AccountId,
    pub lease_id: LeaseId,           // pallet_lease::LeaseId, no hard dependency (see §3)
    pub max_charge: BalanceOf<T>,
    pub price: PriceSchedule,
    pub metering_schema_version: u16,
    pub last_evidence_sequence: u64, // replay protection, see §6
    pub state: EscrowState,
    pub funded_at: BlockNumberFor<T>,
}
```

Keyed `StorageMap<LeaseId, EscrowRecord<T>>` — one escrow per lease, `lease_id` reused as the
correlation key rather than inventing a separate ID space, matching #21's own acceptance criterion
("idempotent correlation with finalized leases").

1. **`fund_escrow(origin, lease_id, provider, max_charge, price, metering_schema_version)`** —
   `ensure_signed`, permissionless, any account with sufficient free balance. Requires: no existing
   `EscrowRecord` for `lease_id` (`EscrowAlreadyFunded`, matching `create_lease`'s
   `LeaseAlreadyExists` / `calculate_reward`'s `LeaseAlreadyRewarded` precedent of rejecting a
   duplicate outright); `max_charge >= MinEscrowAmount` (governed dust threshold, §7); the lease
   exists (narrow read via `LeaseExists`, §3). Reserves `max_charge` from `payer`'s **own** account
   via `T::Currency::reserve` — funds never leave the payer's account or enter a pooled/omnibus
   account; they are merely earmarked. This is the load-bearing custody choice of this whole design:
   no single account (including the Control Plane bridge account) ever holds more than the funds
   *its own signer* voluntarily reserved. Emits `EscrowFunded`.

2. **`complete_and_payout(origin, lease_id, evidence)`** — `ensure_signed`, **permissionless** (any
   relayer, including but not limited to the Control Plane bridge account or the provider itself).
   `evidence` is the full signed `MeteringSummary` (Decision §6), not just a hash. The pallet:
   - looks up `EscrowRecord`, requires `state == Funded` (`EscrowNotFunded`/`EscrowAlreadySettled`);
   - looks up the provider's registered public key via `ProviderKeyLookup` and verifies
     `evidence.signature` over the canonical encoding of the summary using `sp_io::crypto::
     ed25519_verify` — a standard, deterministic Substrate host function, **new to this codebase**
     (every existing signed-evidence path, e.g. `pallet-availability::submit_proof`, trusts the
     relayer instead; this ADR deliberately breaks from that precedent for money specifically,
     named explicitly as a first, not a silent inconsistency);
   - requires `evidence.sequence > escrow.last_evidence_sequence` (replay protection, ADR-012 §4's
     pattern, reused not reinvented);
   - requires `evidence.period_end - evidence.period_start <= MaxMeteringPeriodSeconds` (bounded,
     matching `MaxProofAge`'s existing shape);
   - computes `charged_amount = cpu_core_seconds * price.cpu_core_second + ram_mb_seconds *
     price.ram_mb_second + storage_gb_seconds * price.storage_gb_second + (network_egress_mb +
     network_ingress_mb) * price.network_mb`, entirely `checked_*`, erroring on overflow rather than
     wrapping or saturating (§1);
   - requires `charged_amount <= escrow.max_charge` (`ChargedAmountExceedsCap` — the pallet computes
     this itself from signed, verified evidence; it is never handed a bare number to trust, closing
     off the "forge completion" threat for the normal path, see §9);
   - `T::Currency::repatriate_reserved(&payer, &provider, charged_amount, BalanceStatus::Free)` moves
     exactly the earned amount from the payer's reserve to the provider's free balance;
   - `T::Currency::unreserve(&payer, escrow.max_charge - charged_amount)` returns any unused
     reservation to the payer automatically — under-delivery (including zero usage) never requires a
     separate refund step;
   - sets `state = Completed`, records `last_evidence_sequence`, emits `EscrowSettled { lease_id,
     provider, charged_amount, evidence_hash }` (a hash of the full evidence, for §10's audit
     correlation with #20's off-chain ledger — the full `MeteringSummary` itself is **not** stored
     on-chain past this call; only its hash and the bounded totals that fed `charged_amount` are).

3. **`refund_escrow(origin, lease_id)`** — `ensure_signed`, restricted to the escrow's own `payer`
   (matched against `escrow.payer`), callable once `RefundWindow` blocks have elapsed since
   `funded_at` with no completion. This is the self-service liveness escape hatch: a payer is never
   permanently stuck if a provider or relayer goes silent, and it needs no governance origin at all
   — the block-height check is itself the authorization. (A governance-triggered refund before
   `RefundWindow` elapses is still reachable, but only via `resolve_dispute`'s `RefundPayer` outcome
   in §4.5 after a `dispute_escrow` call — there is no separate root-gated refund path outside of
   dispute resolution, which keeps `EnsureRoot`'s reach in this pallet to exactly one call.) Requires
   `state == Funded`. `unreserve`s the full `max_charge` back to `payer`. Sets `state = Refunded`.
   This is also the answer to "missing/late/conflicting evidence never becomes silent billable
   success" (#20's own acceptance criterion): the default outcome of *nothing happening* is a full
   refund, enforced by the state machine itself, not by an operator remembering to act.

4. **`dispute_escrow(origin, lease_id, reason_hash)`** — `ensure_signed`, restricted to `escrow.payer`
   or `escrow.provider` (both sides may raise one — a provider disputing an unfairly low
   `charged_amount` is symmetric to a payer disputing an inflated one, though §1's on-chain
   computation from verified evidence makes the latter far harder to manufacture than in a
   trust-the-relayer design). Allowed from `Funded` or, within `DisputeWindow` blocks, `Completed`/
   `Refunded` (a completed payout is not disputable forever). `reason_hash` is a hash-commitment to
   an off-chain dispute filing — never a raw payload on-chain, the same rule §6 applies to metering
   evidence. Sets `state = Disputed`, blocking `complete_and_payout`/`refund_escrow` until resolved.

5. **`resolve_dispute(origin, lease_id, outcome)`**, `outcome: PayProvider(BalanceOf<T>) |
   RefundPayer` — origin `T::DisputeOrigin = EnsureRoot`, the sole remaining sudo-key surface in this
   pallet (§9 explains why the blast radius is now narrower than "every payout"). This directly
   reuses `pallet-network-validator::resolve_dispute`'s already-accepted shape (ADR-018's own
   precedent: *"no new governance primitive... this ADR does not wait on ADR-023"*). `PayProvider`
   repatriates the named amount (bounded by `max_charge`, same as §2) and refunds any remainder;
   `RefundPayer` unreserves the full `max_charge`. **Arbitration beyond this binary choice is
   explicitly out of scope for the MVP** — no partial-split outcome, no independent arbiter role, no
   appeals process. The fallback for "who resolves a dispute" is the same single governed origin
   this codebase already trusts for every other adjudicated decision (`resolve_dispute` in
   `pallet-network-validator`, `SuspensionOrigin` generally) — named explicitly, not hand-waved, per
   the task's own instruction to state this plainly if arbitration is out of scope.

### 5. Interaction with reputation and slashing (#18)

`resolve_dispute`'s `RefundPayer` outcome (the provider was found in the wrong — non-delivery or
rejected evidence) calls the new internal `ReputationPenalty` hook to apply a bounded penalty to the
responsible provider's `Reliability` dimension via `pallet_reputation::set_dimension_score` — the
same "reuse an existing, already-governed decision instead of inventing a second one" reasoning
ADR-018 used for validator slashing, applied to the *consequence* side here. **No stake slashing for
providers**: `pallet-provider-registry` still has no `Currency`/bonding association (confirmed
unchanged from ADR-018 §5), so `slash_reserved` is not available for providers the way it is for
Network Validators. If provider bonding (#52, gated by its own future ADR per ADR-018 §5) ever
lands, wiring real stake-slashing into `resolve_dispute`'s `RefundPayer` branch is natural follow-up
work this ADR does not presuppose or design. `PayProvider` (the payer was found in the wrong, or the
dispute was rejected) applies no reputation penalty to either side — a rejected dispute is not
evidence of provider misconduct any more than an unheld dispute is elsewhere in this codebase.

### 6. Metering evidence: signed, hashed, bounded, replay-resistant

```rust
pub struct MeteringSummary<BlockNumber> {
    pub lease_id: LeaseId,
    pub sequence: u64,                 // monotonic per escrow, see §4.2
    pub period_start: BlockNumber,
    pub period_end: BlockNumber,       // bounded by MaxMeteringPeriodSeconds
    pub cpu_core_seconds: u64,
    pub ram_mb_seconds: u64,
    pub storage_gb_seconds: u64,
    pub network_egress_mb: u64,
    pub network_ingress_mb: u64,
    pub gpu_seconds: u64,              // reserved, priced at 0 in v1 (§1)
    pub metering_schema_version: u16,
    pub signature: [u8; 64],           // Ed25519 over the canonical encoding above
}
```

Signed by the Provider Agent's **existing** `agent-core::identity::Ed25519IdentityManager` key — the
same key `BeginJoin`/`CompleteJoin` already proves possession of and the same key
`pallet-provider-registry::Provider.public_key` already records on-chain. No new keypair, no new
enrollment step. Replay resistance is the `sequence > last_evidence_sequence` check already
described in §4.2 — the same monotonic-sequence pattern `pallet-availability::LastProofSequence`
established and ADR-012 §4 names as the pattern to generalize, not reinvent. Boundedness is
`MaxMeteringPeriodSeconds` (governed, §7) capping `period_end - period_start`, mirroring
`MaxProofAge`'s existing shape.

**What crosses on-chain vs. what stays off-chain, per AGENTS.md's permanent prohibition:** the full
`MeteringSummary` is submitted as a call argument (so the pallet can verify its signature and compute
`charged_amount` from it, §4.2) but is **not persisted** past that call — only `evidence_hash` (in
the `EscrowSettled` event) and the derived `charged_amount` land in permanent storage/events. The
bounded integer counters here (CPU-core-seconds, RAM-MB-seconds, etc.) are the same shape of summary
`pallet-availability::AvailabilitySummary` already puts on-chain (`successful_samples`/
`total_samples`) — this ADR follows that existing precedent for "bounded integer counters are not
'detailed metrics'" rather than carving out a new exception. The full-precision, timestamped,
per-container usage detail #20's Postgres ledger will hold is never sent to the chain at all; the
chain only ever sees one settlement period's four-to-five integers per `complete_and_payout` call.

**Missing/late/conflicting evidence:** "missing" resolves to refund (§4.3). "Late" (evidence past
`MaxMeteringPeriodSeconds` relative to `period_start`, or arriving after `RefundWindow` already let
the payer self-refund) is rejected by the pallet (`ProofTooOld`-shaped error) — the payer's refund,
if already taken, stands; a late relay cannot re-charge a payer who has already been made whole.
"Conflicting" (two different signed summaries with different `sequence` numbers claiming overlapping
periods) is not specially detected on-chain beyond monotonicity — the *second* submission with a
higher sequence simply supersedes correlation-wise for `last_evidence_sequence`, but each
`complete_and_payout` call independently computes and caps its own `charged_amount`, so a
provider cannot re-invoice already-settled usage: `state == Funded` is required for every
`complete_and_payout`, and completion consumes the escrow entirely (moves to `Completed`) — there is
no "top-up" call in this design. Reconciling truly conflicting summaries at the *evidence* level
(e.g. two summaries for the same period with different totals) is a #20 concern (its own signed,
monotonic, replay-resistant Agent report stream) and is intentionally not re-solved on-chain here.

### 7. Governance

Following this codebase's existing convention exactly (`pallet-lease`/`pallet-rewards`/
`pallet-network-validator`'s `#[pallet::constant]` + `parameter_types!` pattern) — "governed" here
means *the same `EnsureRoot`/runtime-upgrade path that already controls every other constant in this
runtime*, not a new voting or proposal mechanism (that is ADR-023's job, still not accepted):

| Constant | Meaning |
|---|---|
| `RefundWindow: BlockNumber` | Blocks after `funded_at` before the payer may self-service refund an uncompleted escrow. |
| `DisputeWindow: BlockNumber` | Mirrors `ValidatorDisputeWindow`. Blocks after `Completed`/`Refunded` during which a dispute may still be raised. |
| `MaxMeteringPeriodSeconds` | Bound on a single evidence record's claimed `period_end - period_start`. |
| `MinEscrowAmount: BalanceOf<T>` | Dust threshold — rejects spam escrows too small to be worth the storage. |

`DisputeOrigin = EnsureRoot` (§4.5) is not itself a governed parameter — it is the origin type, fixed
at compile time same as `SuspensionOrigin`/`LeaseOrigin` elsewhere, changeable only by a runtime
upgrade (i.e. exactly as centralized, and exactly as upgradeable, as every other origin in this
runtime today). `metering_schema_version`'s *meaning* per version is fixed at genesis/by code
deploy, not runtime-governance-adjustable — a schema change is a coordinated upgrade across Agent,
Control Plane, and runtime, not a parameter twiddle.

### 8. Protocol usage fee (#120): explicitly deferred to a follow-up ADR

This ADR does **not** include a fee/take-rate mechanism. Reasoning, as #120 itself invited this ADR
to decide:

1. This ADR's own custody and evidence-verification design (§3-§6) is already the largest,
   highest-stakes surface this repository has designed to date. Folding in a second, independent
   custody problem — a protocol treasury account, with its own governance/multisig design that
   #120's own text says "the sudo-bridge-account precedent... does not answer for production" —
   would make one ADR responsible for two separable trust boundaries, harder to review as a unit and
   harder to accept incrementally.
2. A fee is a strictly additive extension of `complete_and_payout`'s already-checked arithmetic
   (`fee = charged_amount.checked_mul(fee_bps).and_then(|v| v.checked_div(10_000))`, `provider_amount
   = charged_amount.checked_sub(fee)`, repatriate `fee` to a treasury account instead of burning or
   folding it into the provider's amount) — it does not change this ADR's state machine, evidence
   model, or dispute flow. Deferring it costs nothing architecturally; #21 can implement escrow
   completely, end to end, without it, and a follow-up ADR adds the fee as a small, well-scoped
   pallet change plus its own treasury/governance design.
3. The transparency requirement #120 names (fee visible to the payer *before* they commit funds) is
   naturally satisfied by `fund_escrow`'s `max_charge` argument regardless of whether a fee exists —
   if a follow-up ADR adds one, `max_charge` continues to be the payer's hard authorized ceiling, fee
   included, so this ADR's design does not need to anticipate the fee's shape to remain compatible
   with it.

### 9. Threat model

Enumerated concretely, per the task's own instruction not to gesture at "threats exist":

- **Steal/misdirect funds.** Mitigated structurally: no pooled/omnibus account ever holds tenant
  funds (§3); `charged_amount <= max_charge` is enforced on-chain from the payer's own authorized
  cap; `repatriate_reserved` moves funds only to the specific `provider` recorded in the escrow at
  funding time, never an arbitrary address supplied later. Residual risk: a compromised **payer**
  key can only lose funds the payer itself reserved (bounded, not systemic); a compromised
  **provider** key can receive payouts for escrows that name it, same blast radius as any leaked
  signing key in this system today (e.g. a leaked provider Agent key already lets an attacker
  misrepresent that provider's resources).
- **Replay evidence.** Closed by `sequence > last_evidence_sequence`, checked on-chain, §4.2/§6.
- **Forge completion.** Closed for the normal path by on-chain Ed25519 verification against the
  provider's registered `public_key` (§4.2) — a relayer (including the Control Plane bridge account)
  can no longer simply assert a `charged_amount`; it can only relay bytes the provider actually
  signed. **Not closed** for the disputed path: `resolve_dispute`'s `EnsureRoot` can direct
  `PayProvider` or `RefundPayer` for any disputed amount up to `max_charge` without independent
  verification — this is the single largest residual risk this ADR carries forward, named explicitly
  rather than assumed away. It is the same single-sudo-key centralization ADR-012 §2 already flags
  as a general, unsolved gap, inherited here — but the blast radius is now bounded to *disputed*
  escrows only, not every payout, which is a real reduction from a naive design that trusted the
  relayer for `complete_and_payout` too.
- **Grief via disputes.** Either party can freeze an escrow via `dispute_escrow`, forcing manual
  `EnsureRoot` resolution. `DisputeWindow` bounds *when* a dispute may be raised but nothing in this
  ADR rate-limits *how many* escrows one account can dispute — a malicious payer or provider could
  dispute every completion it's party to, delaying funds indefinitely for the counterparty pending
  root's attention. Accepted for the MVP on the same terms ADR-018 §3 accepted its own false-positive
  risk (*"this ADR accepts that risk for the MVP... does not widen it"*); a per-account dispute
  rate-limit is named in §11 as real, deferred hardening, not solved here.
- **Drain the treasury/fee mechanism.** Not applicable — §8 defers the fee entirely; a follow-up ADR
  must threat-model its own treasury custody.
- **Compromised `EnsureRoot`/sudo key.** As above: bounded to disputed escrows, still real, still
  the primary residual risk, inherited from ADR-012 §2, not solved here. A pause (§10) is the
  available circuit breaker if this key is known to be compromised.
- **Overflow/underflow.** All monetary arithmetic is `checked_*`, erroring rather than wrapping or
  saturating (§1) — a deliberate divergence from `pallet-reputation`'s `saturating_*` style, correct
  there for a bounded score, wrong here for money.
- **Under-delivery paid in full.** Closed by evidence-based charging: zero usage computes to a zero
  `charged_amount`, which unreserves the entire `max_charge` back to the payer (§4.2) — there is no
  path where a provider is paid without a signed evidence record backing the amount.
- **Sybil / multi-identity / operator collusion.** Out of scope, inherited unchanged from ADR-012
  §2's already-accepted gap (*"Distinct `AccountId`s controlled by one human are indistinguishable
  on-chain... Nothing below changes that"*) — a colluding payer/provider pair controlled by the same
  operator can move funds to itself in a way this ADR cannot detect, exactly as ADR-012 already says
  is unsolved everywhere else in this system.
- **Censorship of `complete_and_payout` by the Control Plane.** Because completion is
  cryptographically self-verifying and permissionless (§4.2), the Control Plane is **not** a
  required relayer for this specific call the way it is for registration or lease-state changes — a
  provider, a payer, or any third party holding the signed `MeteringSummary` can submit it directly.
  This is a genuine, if narrow, decentralization improvement over this codebase's existing pattern,
  named here as a positive consequence, not assumed automatically as a mitigation for every threat
  above (the Control Plane can still simply choose not to *produce* a signed summary in the first
  place, which is a liveness/withholding risk #20's evidence pipeline must itself address, not
  something this pallet can detect).

### 10. Upgrade, migration, audit, and emergency-pause

- **Runtime upgrade with in-flight escrow.** `Escrows: StorageMap<LeaseId, EscrowRecord<T>>` must
  remain decodable across a `spec_version` bump; any future field addition needs a real
  `OnRuntimeUpgrade` storage migration, not a silent reinterpretation — this matters far more here
  than for a reputation score, because a mis-decoded `EscrowRecord` risks money, not a display value.
  This ADR names the requirement; it does not write the migration (nothing exists yet to migrate).
  The existing `specversion_drift_test.go` discipline (the bridge fails closed on an unrecognized
  `spec_version` rather than guessing) is inherited unchanged, no new mechanism needed.
- **Audit.** Two sources of truth, deliberately not merged into one: PostgreSQL (#20's invoice
  ledger) is authoritative for *usage detail* (per ADR-012 §3, metrics/audit evidence stay off-chain,
  permanently); on-chain `Escrows` storage plus `EscrowFunded`/`EscrowSettled`/`EscrowRefunded`/
  `EscrowDisputed`/`DisputeResolved` events are authoritative for *value movement*. The two
  correlate via `lease_id` and `evidence_hash`/`sequence`. #20's invoices must be reproducible from
  on-chain events plus its own off-chain evidence archive — restating #20's own acceptance criterion
  as a hard constraint this ADR's on-chain shape must not violate (e.g. `evidence_hash` in
  `EscrowSettled` is exactly what lets a Postgres row be checked against the specific evidence that
  produced it).
- **Emergency pause.** A new governed boolean, `EscrowPaused: bool`, toggled by `T::PauseOrigin =
  EnsureRoot`, checked at the top of `fund_escrow`/`complete_and_payout`/`refund_escrow`/
  `dispute_escrow`/`resolve_dispute`. While paused: no new escrow can be funded, and no existing
  escrow can change state at all — **funds already reserved stay reserved, frozen in place**, not
  auto-refunded and not seized. This is the deliberately conservative choice the task asked for:
  auto-refunding during a pause could be wrong if the pause's cause is unrelated to any specific
  escrow (e.g. a runtime bug, not a payer/provider problem), and continuing to allow settlement
  during a known incident is the one behavior a pause exists to prevent. A frozen-in-place state
  is always the honest, inspectable answer regardless of what triggered the pause.
- **Independent security review.** Restated here, not just inherited implicitly: this ADR endorses
  #21's own acceptance criterion verbatim — `pallet-escrow` must not accept real, non-test-network
  value before an independent security review, separate from and in addition to the repository
  owner's ADR acceptance of this document. ADR acceptance authorizes the design; it does not
  substitute for that review before real funds are at risk.

### 11. Out of scope

- Substrate Contracts or any non-FRAME execution mechanism (§3).
- Arbitration beyond `resolve_dispute`'s binary `PayProvider`/`RefundPayer` choice — no partial-split
  outcome, no independent arbiter role, no appeals process, in v1.
- The protocol usage fee (#120) — deferred to a follow-up ADR (§8).
- Provider stake slashing on a lost dispute — needs #52's provider bonding (ADR-018 §5), which does
  not exist; only the reputation-dimension penalty (§5) is available today.
- Real GPU billing enforcement — the field is reserved and carried through the schema (`gpu_seconds`,
  `metering_schema_version`) but priced at 0 and not charged in v1.
- A second asset class (`pallet-assets`, a stablecoin, a cross-chain asset) — single native
  `pallet_balances::Balance` only, per §2.
- Streaming/continuous settlement (#51, ADR-012 §5 Stage 1) — this design is lease-scoped, one
  lump-sum charge at completion, not a payment stream.
- Per-account dispute rate-limiting or other anti-griefing defenses beyond `DisputeWindow` (§9).
- Any change to how `pallet-lease::create_lease` assigns its `consumer` field — this ADR's `payer`
  is deliberately independent of it (§3, §4).
- Automatic price discovery, negotiation, or an on-chain rate card — pricing stays a bilateral,
  off-chain-agreed number committed once at funding time (§1), the same trust boundary bandwidth and
  zone already established.

### 12. Regulatory and tax assumptions — explicit, not authoritative

This ADR is a technical design, not a legal or tax opinion, and does not attempt to be one. What the
*technical* design above depends on, stated plainly so it can be checked against real legal advice
rather than silently assumed:

- **The design assumes settlement is a peer-to-peer value transfer between two on-chain accounts
  (payer, provider), mediated by deterministic, publicly auditable escrow logic that no single party
  — including the Control Plane operator — can unilaterally redirect during normal operation.**
  Under normal completion (§4.2), value only ever moves from the specific payer who reserved it to
  the specific provider named at funding time, gated by a cryptographic check neither party can
  forge. The two exceptions to "no party can unilaterally redirect" are exactly the two flagged as
  the primary residual risks in §9: a disputed escrow's `EnsureRoot` resolution, and an emergency
  pause. If a regulator in the payer's or provider's jurisdiction would consider `EnsureRoot`'s
  dispute-resolution power, or the pause capability, sufficient "control" to constitute money
  transmission or custodial activity, **this design's custody model changes materially** — that is
  not a footnote, it is the load-bearing assumption this whole design rests on.
- **No claim is made about tax treatment** — income timing/recognition for a provider's payout,
  VAT/sales tax or similar on compute services sold across jurisdictions, or any withholding
  obligation, for either providers or payers. This ADR does not and cannot answer those questions.
- **No claim is made about whether `pallet_balances::Balance`, once given real-world value, is a
  security, e-money, or a regulated virtual asset** under any specific jurisdiction's regime.
- These are **non-engineering, open questions for the repository owner** — and very likely outside
  counsel — **not resolved by this ADR**. Implementation (#21) should not proceed to handling real
  (non-test-network) value before they are addressed, independent of and in addition to the
  independent security review named in §10.

## Consequences

- A new pallet, `pallet-escrow`, at runtime index 17, with a new `Config` (`Currency`,
  `ProviderKeyLookup`, `ReputationPenalty`, `FundOrigin = EnsureSigned` in practice via
  `ensure_signed`, `DisputeOrigin = EnsureRoot`, `PauseOrigin = EnsureRoot`, four new governed
  constants per §7), new storage (`Escrows`, `EscrowPaused`), five new extrinsics, five new events,
  and a new error set — sized comparably to `pallet-network-validator`, this codebase's largest
  existing pallet, and should be expected to need similar review depth.
- **Zero changes required to `pallet-lease`, `pallet-provider-registry`, or `pallet-reputation`'s
  existing extrinsics** — only new, narrow, read-only trait implementations against their existing
  storage (`ProviderKeyLookup` reads `Providers`, `LeaseExists` reads `Leases`) and one new
  non-extrinsic function on `pallet-reputation` (mirroring `set_dimension_score`'s existing shape).
  This is a deliberately minimal footprint against already-shipped pallets.
- **A new, genuine dependency for #21's implementation**: a tenant-held on-chain key that can sign
  and submit `fund_escrow`/`dispute_escrow`/self-service `refund_escrow` directly, extending
  ADR-014's wallet-based login (today: HTTP-session signing only) to real extrinsic signing. This is
  named as required, non-optional work for #21, not assumed to already exist.
- **A new protocol/proto surface for #20**: the Provider Agent needs a way to produce and expose a
  signed `MeteringSummary` (§6) that the Control Plane (or any relayer) can submit as
  `complete_and_payout`'s `evidence` argument. This ADR specifies the summary's fields and signing
  key; #20's implementation still owns the actual wire message design, its own `.proto` change, and
  full consumer analysis per `AGENTS.md` — not attempted here.
- `pallet_balances`/`ReservableCurrency` gains a second real consumer beyond Network Validator
  staking — genesis/dev-chain endowment amounts (`deployments/`'s local testnet) will need enough
  balance minted to test payers funding escrows, not just validators bonding stake; a dev-environment
  concern for #21's implementation, not a consensus-rule change.
- Issue #19 closes only once this ADR is **Accepted** (not on this PR's merge); #20 and #21 remain
  blocked until then, per their own stated dependency on #19.

## Open questions for the accepting reviewer

- **Is decoupling `fund_escrow`'s `payer` from `pallet-lease`'s `consumer` (§3) the right call, or
  should lease creation itself move to real tenant-signed keys first (a bigger, more disruptive
  change touching `providerjoin`/orchestrator/dashboard submission) so the two fields can be unified?
  This ADR chose decoupling as the smaller, MVP-compatible change — but it does mean a lease's
  on-chain `consumer` and its escrow's `payer` can name different accounts, which may read as
  confusing to a future implementer who doesn't have this ADR's context.**
- **Is on-chain Ed25519 verification inside `complete_and_payout` (§4.2, §6) an acceptable new
  precedent** — every existing signed-evidence path in this codebase trusts the relayer instead, and
  this ADR deliberately diverges for money specifically. Worth the reviewer's explicit sign-off since
  it's a new category of on-chain computation for this runtime, not just a new pallet.
- **Is `EnsureRoot` for `resolve_dispute` and `EscrowPaused`'s `PauseOrigin` (§4.5, §10) an
  acceptable risk to accept for real value**, given §9 names it as the primary residual risk this
  ADR does not solve? The alternative (waiting for ADR-023's decentralized governance before
  accepting any part of this design) would block #20/#21 indefinitely on a much larger, unrelated
  piece of work — this ADR assumes that trade-off is acceptable for an MVP, matching ADR-018's
  identical assumption for validator slashing, but that assumption is the reviewer's to confirm, not
  this ADR's to declare unilaterally.
- **Is `u64` `Balance` width, and the complete absence of any named real-world currency peg (§2,
  §12), acceptable for the reviewer's actual go-to-market plans for this network?** This ADR
  deliberately declines to pick a peg or a fiat scale — if the reviewer already has a specific answer
  in mind, it should be recorded before #21 starts, since it may affect `Balance`'s type width.
- **All of §12's regulatory/tax questions are, by design, unanswered by this ADR** — they need the
  reviewer's own judgment or outside counsel, not an engineering answer, before real value flows.

## Verification

Checked against source before writing: `blockchain/pallets/resource-market/src/lib.rs` (full file —
confirmed no price field on `ResourceOffer`); `blockchain/pallets/lease/src/lib.rs` (full file —
confirmed no price field on `Lease`, `create_lease`'s `ensure_signed` consumer assignment,
`update_lease_state`'s transition table); `protocol/proto/openinfra/shared/v1/shared.proto`
(`WorkloadConstraints.max_price` at line 119, confirmed `float`, confirmed unused on-chain);
`control-plane/internal/scheduler/rank.go` (confirmed `MaxPrice` "accepted but not enforced" comment
at line 347); `blockchain/pallets/rewards/src/lib.rs` (full file — confirmed `claim_reward` moves no
`Currency`, only zeroes `RewardBalances`); `blockchain/runtime/src/lib.rs` (full file — pallet index
list, every `parameter_types!` constant, every `Config` impl and its origin wiring, `pallet_balances`
integration, `AccountData<u64>`); `blockchain/pallets/network-validator/src/lib.rs` (full file —
`Currency: ReservableCurrency`, `register_validator`'s `reserve`, `withdraw_unbonded`'s `unreserve`,
`slash_round_submitters`'s `slash_reserved`, `EnsureActiveValidator`); `control-plane/internal/
blockchainbridge/registrar.go` (full file — `sudoPalletIndex`/`sudoCallIndex` wrapping every
bridge-initiated call, the `"lease %d is not owned by the bridge account"` check at line 106,
`supportedSpecVersion` drift-guard reasoning); `control-plane/internal/blockchainbridge/bridge.go`,
`rewards.go` (confirmed shape of existing bridge relay code, no escrow/payment path exists today);
`blockchain/pallets/provider-registry/src/lib.rs` (`Provider<T>.public_key: [u8; 32]`,
`ProviderByKey`, confirmed no `Currency`/stake association exists — ADR-018 §5's finding still
holds); `blockchain/pallets/availability/src/lib.rs` (full file — `AvailabilitySummary`,
`LastProofSequence`'s replay pattern, `submit_proof`'s "signature verification... performed by the
bridge before this call" doc comment, the trust-the-relayer precedent this ADR diverges from);
`blockchain/pallets/reputation/src/lib.rs` (full file — `set_dimension_score`'s non-extrinsic,
internal-only shape this ADR's `ReputationPenalty` hook mirrors); `docs/adr/012-decentralization-
roadmap-and-trust-boundaries.md` (§2's trust/threat table, §3's data classification, §4's
replay-protection convention, §6's gate table — confirmed no gate blocks a FRAME-pallet escrow
design); `docs/adr/018-slashing-and-economic-penalties.md` (full file — bounded-per-incident,
burn-not-redistribute, reused-`EnsureRoot`, explicit-scope-limits precedent); `docs/adr/
014-wallet-based-dashboard-login.md` (§1-2 — confirmed today's wallet signing is HTTP-session-scoped
only, not extrinsic-signing); `docs/adr/026-availability-zone-selection.md` and `docs/adr/
015-bandwidth-throughput-measurement.md` (the provider-self-declares-unverified-facts trust boundary
this ADR's `PriceSchedule` follows); `AGENTS.md` (permanent prohibitions, frozen architecture, in
full); `gh issue view 19/20/21/120` (full text, acceptance criteria cross-checked against every
Decision subsection above).

Refs #19. Related: #20 (auditable usage metering / invoice ledger — blocked on this ADR, its
`MeteringSummary` wire format and Postgres ledger design are #20's own work, not fully specified
here), #21 (on-chain escrow implementation — blocked on this ADR, implements `pallet-escrow` as
designed above, subject to independent security review per §10 before real value), #120 (protocol
usage fee — explicitly deferred to a follow-up ADR, §8), ADR-012 (§2 trust/threat model, §3 data
classification, §4 replay-protection convention, §6 gate table — no gate applies), ADR-014
(wallet-based login — extended, not replaced, by this ADR's need for real extrinsic signing),
ADR-018 (slashing precedent this ADR's dispute-consequence design follows).
