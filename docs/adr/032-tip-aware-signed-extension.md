# ADR-032: A tip-aware transaction extension for displacing stuck extrinsics

## Status

Accepted (by the repository owner, explicitly, relayed in-session — after reviewing a full summary
of this ADR's decisions and their reasoning, then confirming to proceed with implementation).

Originally written by Claude Code, autonomously, in response to issue #156, and held as Proposed
per the convention established by ADR-016/018/025/026/027/028/029/030. Nothing here is implemented
yet by this ADR itself; issue #156 is unblocked by this acceptance and now carries the
implementation work (the bespoke `ChargeTip` extension plus the Go-side bounded tip-bump logic).

## Context

Issue #156 is the design half split off from issue #141 (#141's other half — jumping straight to
`MaxBackoff` on a `1012` transaction-ban instead of ramping up to it — already shipped, PR #157,
in `providerjoin.Reconciler.fail`). #141 was itself a deliberately-scoped-out follow-up from #138
(the bounded-retry fix for `orchestrator`/`resourcemarket`'s previously-unbounded reconcile loops).
Three issues, one underlying mechanism gap, investigated end to end for this ADR rather than
assumed:

**This chain has no tip or fee-priority mechanism at all, confirmed by reading both the pinned
`pallet-transaction-payment` source and the pool code that would consume its output.**
`blockchain/runtime/src/lib.rs`'s `TxExtension` is exactly the nine stock `frame_system`
extensions:

```rust
type TxExtension = (
    frame_system::AuthorizeCall<Runtime>,
    frame_system::CheckNonZeroSender<Runtime>,
    frame_system::CheckSpecVersion<Runtime>,
    frame_system::CheckTxVersion<Runtime>,
    frame_system::CheckGenesis<Runtime>,
    frame_system::CheckEra<Runtime>,
    frame_system::CheckNonce<Runtime>,
    frame_system::CheckWeight<Runtime>,
    frame_system::WeightReclaim<Runtime>,
);
```

None of these sets a nonzero `priority` on the `ValidTransaction` they return —
`frame_system::CheckNonce`'s own doc comment states this as a general property of the extensions
around it: *"This extension affects `requires` and `provides` tags of validity, but DOES NOT set
the `priority` field. Make sure that AT LEAST one of the transaction extension sets some kind of
priority upon validating transactions."* Nothing in this runtime's tuple does. Every extrinsic
today validates with `priority: 0` (`ValidTransaction`'s `Default`), full stop, matching the
issue's own claim exactly.

`pallet-transaction-payment` is not a dependency of `blockchain/runtime/Cargo.toml` or
`blockchain/Cargo.toml` directly — confirmed by grepping both — but it *is* present, transitively,
at v49.0.0, pulled in by the `polkadot-sdk = "=2606.0.0"` umbrella crate's `runtime`/bridge-hub test
utilities (`cargo tree -p runtime -i pallet-transaction-payment` shows the path). This means the
exact right pallet version is already resolvable in this workspace's lockfile with zero new
dependency-resolution risk, if it were the right mechanism — it is not (§1 below), but this
removes "would it even resolve against `polkadot-sdk = 2606.0.0`" as an open question.

**A Go-side tip value plumbed into `signCall` today would do nothing but corrupt every extrinsic.**
`control-plane/internal/blockchainbridge/registrar.go`'s `signCall`:

```go
func (r *Registrar) signCall(call []byte, nonce uint64, version RuntimeVersion, genesis [32]byte) ([]byte, [32]byte, error) {
    extra := append([]byte{0}, compactUint(nonce)...)
    ...
```

`extra` is exactly `Era(1 byte, hardcoded Immortal) ++ Compact(nonce)` — the SCALE encoding of the
`CheckEra`/`CheckNonce` extensions' own data, concatenated in tuple order; every other extension in
the tuple above (`AuthorizeCall`, `CheckNonZeroSender`, `CheckSpecVersion`, `CheckTxVersion`,
`CheckGenesis`, `CheckWeight`, `WeightReclaim`) encodes to zero bytes in this runtime, confirmed by
this being the entirety of `extra` in code that passes CI and runs against a live chain today.
Appending a tip byte here with no matching `TransactionExtension` in `TxExtension` would not "fail
to help" — it would shift every subsequent extrinsic's SCALE decode by however many bytes the tip
occupies, hard-failing every extrinsic this bridge submits, not just the ones that set a tip. This
is exactly the risk the issue names, and it is the reason this needs a wire-format decision made
once, centrally, not improvised at a call site.

**The exact mechanics of the collision this ADR needs to fix, read directly from the vendored pool
source** (`sc-transaction-pool-47.0.0/src/graph/ready.rs`, `replace_previous`):

```rust
let old_priority = /* sum of priorities of already-pooled txs providing the same tag, e.g. (account, nonce) */;
if old_priority >= tx.priority {
    return Err(error::Error::TooLowPriority { old: old_priority, new: tx.priority });
}
// otherwise: the old tx(s) are removed, the new one takes the ready slot.
```

and the RPC error code mapping (`sc-rpc-api-0.58.0/src/author/error.rs`): `POOL_INVALID_TX = 1010`,
`POOL_TEMPORARILY_BANNED = 1012`, `POOL_TOO_LOW_PRIORITY = 1014` — confirming the issue's and
`rpc.go`'s references to both codes name two genuinely different pool mechanisms, not two names for
the same thing:

- **`1012` (`IsTemporarilyBanned`, already handled by #157):** the pool has this *exact* extrinsic
  (identical bytes) on a cooldown from a prior submission. Retrying sooner cannot help — the
  bytes are identical either way — which is exactly why #157's fix was "back off longer," not
  "resubmit differently."
- **`1014` (`TooLowPriority`, unhandled today — this ADR's actual subject):** the pool has a
  *different* extrinsic occupying the same `(account, nonce)` slot, and the incoming one's
  `priority` is not strictly greater than the sum of what it would displace. With every extrinsic
  on this chain validating at `priority: 0` today, `old_priority >= tx.priority` is `0 >= 0` —
  **always true** — so a resubmission with genuinely different call bytes but a colliding nonce
  (e.g. because the nonce was computed from *finalized* state that hasn't yet advanced past the
  still-pending entry, as `IsTemporarilyBanned`'s own doc comment already describes for the 1012
  case) can never win today, no matter how many times it's retried. This is the literal mechanism
  by which "a legitimate resubmission cannot displace a stuck entry, only outwait it."

**Contention between callers is already structurally serialized, which simplifies this ADR's
policy question.** `resourcemarket`'s reconciler, `orchestrator`'s worker, `providerjoin`'s
reconciler, and `networkvalidator`'s evidence/dispute calls all sign through **one shared
`*blockchainbridge.Registrar` instance** (constructed once in `control-plane/cmd/controlplane/
main.go:111`, `NewRegistrarFromPKCS8File`, and injected everywhere else) — confirmed by grep, not
assumed. Every method that submits a signed call (`EnsureActive`, `EnsureLeaseActive`,
`EnsureLeaseCompleted`, `AnnounceOfferFor`, `RemoveOfferFor`, `SubmitSudo`, `SubmitDirect`, …) takes
`r.mu.Lock()` first. No two submissions from this process ever race each other in flight; the
collision this ADR addresses arises only *across* separate, mutex-released top-level calls, when
finalization lags behind a still-pending entry and a later call (from the same or a different
caller) computes the same nonce from stale finalized state. §4 below uses this fact directly.

**No spec-version-drift guard exists yet for `transaction_version`,** the one field this ADR is
certain to require changing. `control-plane/internal/blockchainbridge/specversion_drift_test.go`
guards only `spec_version` (filed for issue #123, after #37's spec_version bump silently broke
every registrar call). `transaction_version` has never changed since genesis (`1`, unbumped
through every pallet/extension addition to date, including `AuthorizeCall`/`WeightReclaim`
themselves) and has no equivalent test. §5 below names this as required implementation work.

**Provider Agent is not a consumer of any part of this change**, confirmed against `AGENTS.md`'s
"the Provider Agent never talks directly to the blockchain in the MVP" rule directly: extrinsic
signing lives entirely in `control-plane/internal/blockchainbridge` (Go), talking JSON-RPC to
`blockchain/`'s node; `protocol/proto` governs only the Agent↔Control-Plane gRPC surface and has no
representation of chain extrinsics at all. This is purely a `blockchain/runtime` +
`control-plane/internal/blockchainbridge` change.

## Decision

### 1. Mechanism: a bespoke, minimal `TransactionExtension` — not `pallet-transaction-payment`

`pallet-transaction-payment`'s `ChargeTransactionPayment` extension does not merely *read* a tip;
its `prepare` step unconditionally calls `OnChargeTransaction::withdraw_fee` for
`inclusion_fee + tip` (`inclusion_fee = base_fee + length_fee + weight_fee`, confirmed by reading
`pallet-transaction-payment-49.0.0/src/lib.rs`'s module doc and `withdraw_fee`/`can_withdraw_fee`)
**on every signed extrinsic that carries it in `TxExtension`, tip or no tip.** Wiring it in would
mean every account that ever signs an extrinsic — today, only the one shared bridge/sudo account —
must hold a sufficient free balance and would be debited on every call, a real behavioral change
this chain does not have today and that issue #156 explicitly flags as worth avoiding unless
justified. Nothing about this ADR's actual requirement (let a resubmission win a priority
comparison) needs fee deduction, `WeightToFee`/`LengthToFee` configuration, a `FeeMultiplierUpdate`
schedule, or a `Config::OnChargeTransaction` implementation — all mandatory surface
`pallet-transaction-payment` brings whether or not it is used for its stated purpose. Zeroing
`WeightToFee`/`LengthToFee` down to nothing would avoid *changing the amount charged* but would not
avoid the pallet unconditionally exercising the withdrawal/existential-deposit code path on every
call, which is exactly the kind of side-channel behavior change this dev/MVP chain has no reason to
take on for a problem that doesn't require it.

This ADR instead adds a small, standalone `TransactionExtension` — no new pallet, no `Config`
trait, no storage — implemented directly against `Runtime`'s `RuntimeCall` in
`blockchain/runtime/src/lib.rs` (or a `runtime/src/extensions.rs` submodule if that keeps
`lib.rs` more readable):

```rust
/// Carries an optional tip, used only to influence transaction-pool `priority`
/// (ADR-032). Deducts nothing from any account -- this chain has no fee
/// mechanism, and this extension does not introduce one.
#[derive(Encode, Decode, DecodeWithMemTracking, Clone, Eq, PartialEq, TypeInfo, Debug)]
pub struct ChargeTip(#[codec(compact)] pub Balance); // Balance = u64, this runtime's Balance type

impl TransactionExtension<RuntimeCall> for ChargeTip {
    const IDENTIFIER: &'static str = "ChargeTip";
    type Implicit = ();
    type Val = ();
    type Pre = ();

    fn weight(&self, _: &RuntimeCall) -> Weight {
        Weight::zero() // pure function of self, no storage reads
    }

    fn validate(
        &self,
        origin: RuntimeOrigin,
        _call: &RuntimeCall,
        _info: &DispatchInfoOf<RuntimeCall>,
        _len: usize,
        _implicit: Self::Implicit,
        _inherited_implication: &impl Encode,
        _source: TransactionSource,
    ) -> ValidateResult<Self::Val, RuntimeCall> {
        // +1 tie-breaks two zero-tip transactions, matching
        // pallet-transaction-payment's own convention for the same reason.
        let priority = self.0.saturating_add(1) as TransactionPriority;
        Ok((ValidTransaction { priority, ..Default::default() }, (), origin))
    }

    fn prepare(self, _: Self::Val, _: &RuntimeOrigin, _: &RuntimeCall, _: &DispatchInfoOf<RuntimeCall>, _: usize)
        -> Result<Self::Pre, TransactionValidityError> {
        Ok(())
    }
}
```

This is strictly additive to the wire format (§3) and to the runtime's behavior: no account is ever
debited, no existential-deposit requirement is introduced for any caller, and every extrinsic that
sets `tip = 0` behaves byte-for-byte identically in every way except the one new trailing `extra`
byte and the resulting `priority = 1` instead of `priority = 0` (harmless — still the lowest
possible nonzero priority, changes nothing about which zero-tip transactions win against each
other, see §2).

### 2. Priority semantics: raw tip value is the entire signal, appended last in the tuple

Because nothing else in this runtime contributes to `priority` today (§Context), the
`max_tx_per_block`-scaled formula `pallet-transaction-payment::get_priority` uses (to keep a small
tip meaningful relative to a block's weight/length capacity when *other* extrinsics are also
carrying weight-based fees) is solving a problem this chain does not have. A direct
`priority = tip + 1` is the entire mechanism, and it's sufficient by construction: pool code's own
displacement rule (`sc-transaction-pool`'s `replace_previous`, quoted in Context) is
`old_priority >= tx.priority ⇒ reject as 1014; else ⇒ evict old, admit new`. Any resubmission whose
tip is **strictly greater** than the tip of whatever it collides with wins the slot outright, no
scaling needed — the two entries in question are, in this chain's actual failure mode, always
competing for the exact same `(account, nonce)` `provides` tag on the one shared bridge account, so
there is no cross-account priority-ordering fairness question to reason about yet (§4's "future
work" note addresses what would need re-examining if that stops being true).

`ChargeTip` is appended as the **tenth and last** element of `TxExtension`, after `WeightReclaim` —
matching where `ChargeTransactionPayment` conventionally sits in every stock Substrate
runtime template, and, more concretely, meaning **every extension ahead of it keeps encoding
exactly the bytes it does today; nothing about the first nine extensions' `extra` contribution
changes.** This is the smallest-blast-radius placement: existing `extra` bytes are a strict prefix
of the new `extra` bytes, not reshuffled.

### 3. Wire format: `signCall`'s `extra` gains one trailing `Compact<u64>`, control-plane-only

```go
func (r *Registrar) signCall(call []byte, nonce uint64, tip uint64, version RuntimeVersion, genesis [32]byte) ([]byte, [32]byte, error) {
    extra := append([]byte{0}, compactUint(nonce)...)
    extra = append(extra, compactUint(tip)...) // new: ChargeTip's Compact<Balance>
    ...
```

Every existing caller of `signCall`/`signSudo`/`submitSigned` passes `tip: 0` unless it is
specifically retrying after a `1014` (§4) — so this is additive at every call site except the one
new bounded retry path #156's implementation adds. This is confirmed to be **purely a
control-plane-side concern**: no `.proto` message changes, no `agent-api`/generated-code awareness
needed anywhere, per Context's confirmation that the Provider Agent never constructs or signs an
extrinsic. `Balance` in this runtime is `u64` (`ExistentialDeposit = ConstU64<1>` on
`pallet_balances::Config`, confirmed directly), matching `compactUint`'s existing `uint64` signature
in `registrar.go` with no new encoding helper needed — `compactUint(tip)` reuses the exact function
already used for the nonce.

### 4. Bounded tip-bump policy: inside `Registrar.submitSigned`, shared state, not per-caller

Given Context's finding that every caller already funnels through one mutex-serialized
`*Registrar`, and that the collision this ADR fixes is specifically same-account/same-nonce
contention, the bump logic belongs **inside `Registrar.submitSigned` itself**, not duplicated in
each of `resourcemarket`, `orchestrator`, and `providerjoin`'s own retry loops. One implementation
point, automatically shared by every caller through the mutex that already exists — no new
cross-caller coordination primitive needed, and no risk of two callers independently guessing tips
that collide with each other instead of resolving the real fight.

Concretely, for #156's eventual implementation (not built by this ADR):

- Add `IsPriorityTooLow(err error) bool` to `blockchainbridge/rpc.go`, sibling to
  `IsTemporarilyBanned`, checking `rpcErr.Code == 1014`.
- `submitSigned` retries the *same logical call* with a strictly increasing tip on a `1014`
  specifically (never on any other error, matching `IsTemporarilyBanned`'s existing precedent of
  being triggered by one exact error code, not "any failure"): tip sequence `1, 2, 4` (doubling,
  matching this codebase's existing exponential-backoff style in `providerjoin.Reconciler`/
  `orchestrator.Worker`) over **`MaxTipBumpAttempts = 3`** attempts, capped at **`MaxTip = 100`**
  (u64). Because `priority = tip + 1` and the pool's rule is strict-greater-than, a step of `1` is
  already sufficient to win against a same-value stuck entry — doubling is a hygiene/predictability
  choice matching existing style, not a requirement the priority formula imposes.
- **`MaxTip` is not a spend limit** — `ChargeTip` never debits any account (§1) — it exists only to
  keep the retry state small and predictable, not to bound anyone's exposure. This distinction is
  worth stating explicitly because every other "max" in this codebase's economic pallets (e.g.
  ADR-030's `MaxFeeBasisPoints`) *is* a spend/exposure cap; this one is not, and conflating the two
  would misstate what's being bounded.
- If `MaxTipBumpAttempts` is exhausted without success, **fall through to the exact behavior #157
  already established for `1012`**: the caller's own outer bounded-retry loop (`providerjoin.
  Reconciler`'s backoff, `orchestrator.Worker`'s `RetryPolicy`, `resourcemarket`'s
  `MaxWithdrawAttempts`) takes over unchanged. This ADR's tip-bump is a fast inner mechanism nested
  inside one submission attempt, not a replacement for the bounded-retry architecture #138/#157
  already built.
- Because `Registrar.mu` already serializes every submission across every caller, no per-caller tip
  state is needed at all — a single "current bump attempt for the call in flight" lives as a local
  variable inside the (now slightly longer) `submitSigned`, reset to `0`/no-tip at the start of
  every top-level call. Contention between `resourcemarket` and `providerjoin` is resolved by the
  mutex making their submissions strictly sequential, not by anything tip-related; the tip only
  needs to beat whatever specific entry is *already pooled* from an earlier, not-yet-finalized
  submission, which by construction was submitted through this same serialized path.
- **Explicitly out of scope for this bump policy, named so it isn't silently assumed away later:**
  today's single-shared-bridge-account trust model (Context) means a large tip can never starve a
  *different* legitimate signer, because there isn't one yet. If a later ADR under ADR-012's
  decentralization roadmap introduces additional independent signers competing for block space,
  `MaxTip`'s role would need re-examination as a pool-fairness question, not just a retry-hygiene
  one — this ADR does not attempt to design for that case now.

### 5. Spec/transaction version: bump `transaction_version`, and `spec_version` alongside it; no
migration path needed for this MVP stage

Adding a new element to `TxExtension` changes the SCALE-decoded shape of every extrinsic's `extra`
field — this is precisely what `transaction_version` exists to signal, per standard Substrate
practice, independent of whether any pallet call/dispatch logic changed. This repository's own
history confirms the distinction is taken seriously here already: `transaction_version` has never
changed since genesis (still `1`), while `spec_version` bumped once, `2 → 3`, specifically for #37's
consensus-mechanism change (manual sealing → Aura/GRANDPA) — not for any of the six pallets added
since (including `pallet-escrow`, present in this tree at `pallet_index(17)` without a further
`spec_version` bump). This ADR's change is exactly the kind `transaction_version` is for: **bump
both** `spec_version` (`3 → 4`) and `transaction_version` (`1 → 2`) together, matching standard
practice for a runtime change that alters transaction validity/extrinsic format, and update
`registrar.go`'s `supportedSpecVersion`/`supportedTransactionVersion` constants in the same PR — the
exact drift this repo has already been burned by once (issue #123, #37's spec_version bump breaking
every registrar call silently). **Required additional implementation work, named explicitly:**
extend (or add a sibling to) `specversion_drift_test.go` to also guard `transaction_version` against
`registrar.go`'s constant, since this is the first time that field has ever needed to change and no
guard exists for it today.

**No runtime-upgrade/migration path is needed.** This repository has never performed a live runtime
upgrade against a running chain for any of the structural additions since #37 (six pallets landed
without one); the established, repeatedly-exercised pattern for a breaking runtime change at this
MVP stage is a fresh chain — `make dev-clean` wipes postgres/redis/substrate data, exercised
routinely this session alone. This ADR's implementation should assume the same: a fresh dev chain
after this lands, not a migration. If a genuinely persistent chain with real accumulated state ever
exists before this ships, that would be a reason to revisit this specific point, but nothing in this
repository's current practice suggests that's the case yet.

## Non-goals

- **No general-purpose fee market.** `ChargeTip` does not compute or charge `base_fee`,
  `length_fee`, or `weight_fee`; no account's balance is ever touched by it. This ADR is scoped
  entirely to §2's priority mechanism.
- **No behavior change for any extrinsic that never collides.** An extrinsic submitted with
  `tip = 0` (every call site, until #156's retry path specifically needs otherwise) behaves exactly
  as it does today in every way that matters for correctness — the only observable difference is
  `priority: 1` instead of `priority: 0`, which changes nothing about relative ordering among the
  many other zero-tip extrinsics still validating at that same value.
- **No economic/spend cap design.** `MaxTip` (§4) bounds retry-state size and predictability, not
  exposure — there is no exposure, because nothing is ever withdrawn (§1's central point, repeated
  here because it is easy to misread `MaxTip` as ADR-030's `MaxFeeBasisPoints`-style spend cap, and
  it is not that).
- **No multi-signer pool-fairness design.** §4's last bullet names this explicitly: today's
  single-shared-bridge-account model means this is not yet a real question. A future ADR would need
  to revisit it if that changes.
- **No implementation in this ADR.** The `ChargeTip` extension, the `TxExtension` tuple change, the
  `signCall`/`submitSigned` wire-format and retry changes, the version-bump, and the drift-test
  extension are all issue #156's follow-on implementation work, unblocked by acceptance of this
  document, not built by it.

## Consequences

- `blockchain/runtime/src/lib.rs`: one new ~40-line `TransactionExtension` impl (no new pallet, no
  new `Config` trait, no new storage), `TxExtension`'s tuple gains a tenth element appended last,
  `spec_version` and `transaction_version` both bump.
- `control-plane/internal/blockchainbridge/registrar.go`: `signCall` gains a `tip uint64`
  parameter and one appended `compactUint(tip)` call; `submitSigned` gains the bounded tip-bump
  retry loop described in §4; `supportedSpecVersion`/`supportedTransactionVersion` both update to
  match.
- `control-plane/internal/blockchainbridge/rpc.go`: one new `IsPriorityTooLow` predicate, sibling
  to the existing `IsTemporarilyBanned`.
- `control-plane/internal/blockchainbridge/specversion_drift_test.go`: extended (or a sibling test
  added) to also guard `transaction_version`, closing the gap named in §5 before it can repeat
  issue #123's failure mode for the field this ADR is the first to ever change.
- Zero changes to `protocol/proto`, `provider-agent/`, or any generated bindings — confirmed
  out of scope per Context's direct check against `AGENTS.md`.
- Zero changes to `resourcemarket`, `orchestrator`, or `providerjoin`'s own reconcile-loop code
  beyond what already flows through `Registrar.submitSigned` today — the tip-bump lives in one
  shared place, not duplicated across callers, per §4.
- This ADR does not close issue #156 by itself; #156 is a design issue, closed by this ADR's
  acceptance (matching the convention ADR-029/030 already established), with the actual
  implementation work — `ChargeTip`, the version bump, `signCall`'s new parameter, the bounded
  retry loop, and the drift-test extension — carried out afterward, once accepted.

## Verification

Checked against source before writing: `blockchain/runtime/src/lib.rs` (full file — `TxExtension`,
`VERSION`/`spec_version`/`transaction_version`, `construct_runtime!`'s pallet list including
`Escrow` at index 17, `pallet_balances::Config`'s `ExistentialDeposit = ConstU64<1>` confirming
`Balance = u64`); `blockchain/Cargo.toml` / `blockchain/runtime/Cargo.toml` (confirmed
`pallet-transaction-payment` is not a direct dependency of either; confirmed `polkadot-sdk =
"=2606.0.0"` pin); `cargo tree -p runtime -i pallet-transaction-payment` (confirmed
`pallet-transaction-payment` v49.0.0 is resolvable transitively through `polkadot-sdk`'s bridge-hub
test-utility path, at the exact version matching this workspace's pin); `~/.cargo/registry/src/
.../pallet-transaction-payment-49.0.0/src/lib.rs` (full module doc, `Config` trait, `get_priority`
— read and quoted directly, not recalled from memory — confirming both the `final_fee =
inclusion_fee + tip` unconditional-withdrawal behavior and the `max_tx_per_block`-scaled priority
formula this ADR deliberately does not replicate); `~/.cargo/registry/src/.../frame-system-48.0.0/
src/extensions/check_nonce.rs` (full file, confirming `TransactionExtension`'s exact trait shape
used by this pinned SDK version — `Implicit`/`Val`/`Pre` associated types, `validate`/`prepare`
signatures — used as the template for `ChargeTip`, and confirming via its own doc comment that no
extension in this runtime's tuple sets `priority` today); `~/.cargo/registry/src/.../sc-transaction-
pool-47.0.0/src/graph/ready.rs` (`replace_previous`, full function — the exact
`old_priority >= tx.priority` displacement/rejection rule this ADR's entire mechanism depends on);
`~/.cargo/registry/src/.../sc-rpc-api-0.58.0/src/author/error.rs` (`POOL_TEMPORARILY_BANNED = 1012`,
`POOL_TOO_LOW_PRIORITY = 1014` constants, confirming the two error codes referenced across issues
#138/#141/#156 and `rpc.go`'s own comments map to two distinct pool mechanisms, not one);
`control-plane/internal/blockchainbridge/registrar.go` (full file — `signCall`'s exact current
`extra` construction, every `submitSigned`/`signSudo` call site, `Registrar.mu`'s use in every
write method); `control-plane/internal/blockchainbridge/rpc.go` (`IsTemporarilyBanned`, its doc
comment's account of the finalized-nonce race); `control-plane/internal/blockchainbridge/
resourcemarket.go` / `networkvalidatorregistrar.go` (confirmed every write method takes `r.mu.Lock()`
first); `control-plane/cmd/controlplane/main.go:111` (confirmed exactly one `*Registrar` is
constructed and shared across `resourcemarket`, `orchestrator`, `providerjoin`, and
`networkvalidator`); `control-plane/internal/blockchainbridge/specversion_drift_test.go` (full file
— confirmed it guards only `spec_version`, filed for issue #123, no `transaction_version`
equivalent exists); `control-plane/internal/providerjoin/reconciler.go` /
`control-plane/internal/orchestrator/worker.go` (confirmed #157's exact `IsTemporarilyBanned →
jump to MaxBackoff` shape, and the existing exponential-backoff style this ADR's tip-doubling
matches); `control-plane/internal/resourcemarket/reconciler.go` (`MaxWithdrawAttempts`, and its own
comment already citing the live `1014` collision this ADR addresses); `AGENTS.md` (frozen
architecture, "Provider Agent never talks directly to the blockchain" — confirmed this ADR
introduces no Agent-side or protocol-level change); `docs/adr/` directory listing on this branch's
base (confirmed ADR numbers 001–030 exist on `main`; 031 is claimed by a separate, unmerged
OpenStack-compatibility ADR in a parallel worktree at the time of writing, confirmed by direct
inspection — this ADR is therefore numbered 032, the next number free and not claimed by any other
in-flight work); `gh issue view 156` / `gh issue view 141` (full text, every open question addressed
above by section).

Refs #156. Related: issue #141 (the original ask, split into this ADR's design half and #157's
already-shipped `MaxBackoff` half), issue #138 (the bounded-retry architecture this ADR's tip-bump
nests inside, not replaces), ADR-030 (the precedent for a governed numeric bound in this codebase —
explicitly distinguished from `MaxTip` in Non-goals, since ADR-030's bound caps real spend and this
one does not).
