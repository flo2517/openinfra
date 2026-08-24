#![cfg_attr(not(feature = "std"), no_std)]

//! On-chain escrow, metering-evidence-gated settlement, dispute, and
//! emergency-pause for lease payouts (ADR-029).
//!
//! Implements ADR-029's `pallet-escrow`: a payer reserves `max_charge` from
//! their **own** account (never a pooled/omnibus account -- ADR-029 Sec3-4),
//! a permissionless relayer later submits an Agent-signed [`MeteringSummary`]
//! that this pallet verifies on-chain (`sp_io::crypto::ed25519_verify`
//! against the provider's already-registered `pallet-provider-registry`
//! public key -- new to this codebase, every other signed-evidence path here
//! trusts the relayer instead, see ADR-029 Sec4.2/Sec6/Sec9), computes the
//! charge itself from the verified evidence, and repatriates exactly that
//! amount to the provider while returning the rest to the payer. A payer can
//! self-service refund an uncompleted escrow after `RefundWindow`; either
//! party can freeze an escrow via `dispute_escrow`, resolved only by
//! `EnsureRoot` (the one remaining sudo-key surface in this pallet -- ADR-029
//! Sec4.5/Sec9). Reward Points (`pallet-rewards`) are entirely untouched by
//! this pallet -- settlement value moves through `pallet_balances`
//! (`ReservableCurrency`) only, per ADR-029 Sec2.
//!
//! **This pallet moves real, spendable monetary value. It must not accept
//! non-test-network funds before an independent security review, separate
//! from the ADR's own acceptance -- ADR-029 Sec10.**
//!
//! **Reserve-balance contamination fix.** This pallet and
//! `pallet-network-validator` both reserve funds against the same untagged,
//! per-account `pallet_balances` reserved balance (this codebase predates
//! `fungible::MutateHold`/`HoldReason`). An account holding both roles --
//! escrow `payer` and Network Validator -- let a validator slash
//! (`slash_reserved`, scoped only to the account, not to any one pallet's
//! bookkeeping) consume an unrelated escrow's reserved `max_charge`,
//! permanently stranding that escrow (`complete_and_payout`/
//! `refund_escrow` fail closed, by design, on any such inconsistency, with
//! no other extrinsic able to reconcile it). Two changes close this: (1)
//! [`Pallet::fund_escrow`] rejects a payer who is currently a registered
//! Network Validator ([`ValidatorRegistrationInspector`]), and the runtime
//! symmetrically rejects `pallet-network-validator::register_validator` for
//! an account with funds locked in an open escrow as payer
//! ([`PayerOpenEscrowCount`]); (2) [`Pallet::resolve_dispute`] -- and only
//! that root-gated call, never the two self-service/permissionless paths --
//! can write off a confirmed, irrecoverable shortfall instead of leaving an
//! already-contaminated escrow stuck forever (see
//! [`Event::EscrowShortfallWrittenOff`]).

extern crate alloc;

pub use pallet::*;

use frame_support::{
    traits::{BalanceStatus, Currency, EnsureOrigin, Get, ReservableCurrency},
    weights::Weight,
    Hashable,
};

/// Reused from `pallet-lease` as a plain type alias (not a crate
/// dependency): ADR-029 Sec3 deliberately gives this pallet no hard
/// dependency on `pallet-lease` beyond the narrow, read-only
/// [`LeaseExists`] check below.
pub type LeaseId = u64;

/// Narrow, read-only interface for looking up a registered provider's
/// Ed25519 public key -- redeclared here rather than depending on
/// `pallet-provider-registry` directly, the same
/// `ProviderInspector`/`NetworkValidatorInspector` pattern every other
/// pallet in this workspace already uses for cross-pallet wiring. `None`
/// (the deny-by-default impl for `()`) makes `complete_and_payout` reject
/// signature verification for an unknown provider rather than silently
/// treating it as valid.
pub trait ProviderKeyLookup<AccountId> {
    fn public_key(provider: &AccountId) -> Option<[u8; 32]>;
}

impl<AccountId> ProviderKeyLookup<AccountId> for () {
    fn public_key(_: &AccountId) -> Option<[u8; 32]> {
        None
    }
}

/// Narrow, read-only sanity check that a lease id exists at all --
/// deliberately **not** a check that the caller matches
/// `pallet-lease::Leases::consumer` (ADR-029 Sec3: every lease's consumer
/// today is the Control Plane bridge account, so that check would make the
/// bridge account the custodian of every tenant's escrow). Advisory only,
/// like `ProviderInspector`'s permissive default elsewhere in this
/// workspace, so a runtime that hasn't wired this yet (e.g. this pallet's
/// own unit tests) still exercises every other check.
pub trait LeaseExists {
    fn exists(lease_id: LeaseId) -> bool;
}

impl LeaseExists for () {
    fn exists(_: LeaseId) -> bool {
        true
    }
}

/// Applies a bounded reliability penalty to the provider found in the wrong
/// by a resolved dispute (ADR-029 Sec5). Mirrors
/// `pallet-network-validator`'s `ReputationUpdater`/ADR-018's slashing
/// consequence pattern: `pallet-reputation` stays the only writer of the
/// reputation vector, this pallet only ever calls its existing non-extrinsic
/// `set_dimension_score` entry point through this hook. No stake slashing is
/// available for providers (`pallet-provider-registry` still has no
/// `Currency`/bonding association, confirmed unchanged since ADR-018 Sec5) --
/// this reputation-dimension penalty is the only consequence available today.
pub trait ReputationPenalty<AccountId> {
    fn apply(provider: &AccountId, penalty_bps: u16) -> frame_support::dispatch::DispatchResult;
}

impl<AccountId> ReputationPenalty<AccountId> for () {
    fn apply(_: &AccountId, _: u16) -> frame_support::dispatch::DispatchResult {
        Ok(())
    }
}

/// Narrow, read-only check for whether an account is currently a
/// registered Network Validator, **regardless of status** (`Active`,
/// `Suspended`, or `Exiting` all still hold real bonded stake in
/// `pallet_balances`'s reserved balance until `withdraw_unbonded` actually
/// releases it -- unlike `NetworkValidatorInspector::is_active` elsewhere in
/// this workspace, which deliberately excludes `Suspended`/`Exiting` for a
/// different purpose, gating submission rights).
///
/// This backs [`Pallet::fund_escrow`]'s guard against reserve-balance
/// contamination: `pallet-escrow` and `pallet-network-validator` both call
/// `ReservableCurrency` against the same untagged, per-account `reserved`
/// balance (this codebase predates `fungible::MutateHold`/`HoldReason`).
/// `pallet-network-validator::slash_round_submitters` slashes a flat,
/// validator-scoped amount from that shared pool, unconditionally --
/// nothing in `slash_reserved` distinguishes "this validator's own bonded
/// stake" from "an unrelated escrow's `max_charge` reserved by the same
/// `AccountId` as `payer`". The smallest closure of that precondition is
/// refusing to let one account hold both roles: a registered Network
/// Validator may not also become an escrow `payer`.
pub trait ValidatorRegistrationInspector<AccountId> {
    fn is_registered(account: &AccountId) -> bool;
}

impl<AccountId> ValidatorRegistrationInspector<AccountId> for () {
    fn is_registered(_: &AccountId) -> bool {
        false
    }
}

pub trait WeightInfo {
    fn fund_escrow() -> Weight;
    fn complete_and_payout() -> Weight;
    fn refund_escrow() -> Weight;
    fn dispute_escrow() -> Weight;
    fn resolve_dispute() -> Weight;
    fn set_paused() -> Weight;
    fn set_fee_basis_points() -> Weight;
    fn set_treasury_account() -> Weight;
}

impl WeightInfo for () {
    fn fund_escrow() -> Weight {
        Weight::from_parts(10_000, 0)
    }
    fn complete_and_payout() -> Weight {
        Weight::from_parts(10_000, 0)
    }
    fn refund_escrow() -> Weight {
        Weight::from_parts(10_000, 0)
    }
    fn dispute_escrow() -> Weight {
        Weight::from_parts(10_000, 0)
    }
    fn resolve_dispute() -> Weight {
        Weight::from_parts(10_000, 0)
    }
    fn set_paused() -> Weight {
        Weight::from_parts(10_000, 0)
    }
    fn set_fee_basis_points() -> Weight {
        Weight::from_parts(10_000, 0)
    }
    fn set_treasury_account() -> Weight {
        Weight::from_parts(10_000, 0)
    }
}

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use sp_runtime::traits::{Saturating, Zero};

    pub type BalanceOf<T> =
        <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

    /// `(provider_amount, fee_amount, treasury_account)`, [`Pallet::split_fee`]'s
    /// return shape (ADR-030 Sec2) -- named so clippy's `type_complexity`
    /// lint doesn't need silencing.
    type FeeSplit<T> = (
        BalanceOf<T>,
        BalanceOf<T>,
        Option<<T as frame_system::Config>::AccountId>,
    );

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::config]
    pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
        /// Reused, not reinvented (ADR-029 Sec2): the same
        /// `ReservableCurrency` already backing Network Validator stake.
        /// No new asset pallet for v1.
        type Currency: ReservableCurrency<Self::AccountId>;
        /// Backs signature verification in [`Pallet::complete_and_payout`];
        /// the runtime wires this to `pallet-provider-registry::Providers`.
        type ProviderKeyLookup: ProviderKeyLookup<Self::AccountId>;
        /// Backs the sanity check in [`Pallet::fund_escrow`]; the runtime
        /// wires this to `pallet-lease::Leases`.
        type LeaseExists: LeaseExists;
        /// Backs the dispute-loss consequence in
        /// [`Pallet::resolve_dispute`]; the runtime wires this to
        /// `pallet-reputation`.
        type ReputationPenalty: ReputationPenalty<Self::AccountId>;
        /// Backs [`Pallet::fund_escrow`]'s reserve-contamination guard; the
        /// runtime wires this to `pallet-network-validator::Validators`.
        type ValidatorInspector: ValidatorRegistrationInspector<Self::AccountId>;
        /// Sole remaining sudo-key surface in this pallet (ADR-029 Sec4.5):
        /// resolves a frozen, disputed escrow. `EnsureRoot` for the MVP,
        /// same as every other adjudicated decision in this codebase
        /// (`pallet-network-validator::resolve_dispute`).
        type DisputeOrigin: EnsureOrigin<Self::RuntimeOrigin>;
        /// Governs the emergency pause (ADR-029 Sec10). `EnsureRoot` for
        /// the MVP.
        type PauseOrigin: EnsureOrigin<Self::RuntimeOrigin>;
        /// Governs `set_fee_basis_points`/`set_treasury_account` (ADR-030
        /// Sec3). `EnsureRoot` for the MVP, the same choice already made
        /// for `DisputeOrigin`/`PauseOrigin` above -- not a new governance
        /// primitive, the same single sudo-key surface this runtime
        /// already trusts for every other protocol parameter.
        type FeeGovernanceOrigin: EnsureOrigin<Self::RuntimeOrigin>;
        /// Blocks after `funded_at` before the payer may self-service
        /// refund an uncompleted escrow.
        #[pallet::constant]
        type RefundWindow: Get<BlockNumberFor<Self>>;
        /// Blocks after an escrow settles (`Completed`/`Refunded`) during
        /// which it may still be disputed. Mirrors
        /// `pallet-network-validator::DisputeWindow`.
        #[pallet::constant]
        type DisputeWindow: Get<BlockNumberFor<Self>>;
        /// Bound on a single evidence record's claimed
        /// `period_end - period_start`, mirroring
        /// `pallet-availability::MaxProofAge`'s shape.
        #[pallet::constant]
        type MaxMeteringPeriodSeconds: Get<BlockNumberFor<Self>>;
        /// Dust threshold: rejects an escrow too small to be worth the
        /// storage.
        #[pallet::constant]
        type MinEscrowAmount: Get<BalanceOf<Self>>;
        /// Bounded per-incident reliability penalty applied to a provider
        /// found in the wrong by `resolve_dispute`'s `RefundPayer` outcome
        /// (ADR-029 Sec5), basis points (0..=10_000).
        #[pallet::constant]
        type ReliabilityPenaltyBps: Get<u16>;
        /// Compile-time hard cap on `FeeBasisPoints` (ADR-030 Sec4): only a
        /// runtime upgrade can raise it, so a single `set_fee_basis_points`
        /// call can never reach anything close to confiscatory without a
        /// materially higher-friction, more visible second action.
        #[pallet::constant]
        type MaxFeeBasisPoints: Get<u16>;
        type WeightInfo: WeightInfo;
    }

    /// Per-escrow, integer, `u64`-denominated rate card, agreed off-chain
    /// between payer and provider and committed once at [`Pallet::fund_escrow`]
    /// time -- never a global on-chain price list, never repriced after
    /// funding (ADR-029 Sec1).
    #[derive(
        Clone,
        Copy,
        Decode,
        DecodeWithMemTracking,
        Encode,
        Eq,
        MaxEncodedLen,
        PartialEq,
        Debug,
        TypeInfo,
    )]
    pub struct PriceSchedule {
        /// Smallest `Currency` unit per CPU core-second.
        pub cpu_core_second: u64,
        /// Smallest `Currency` unit per RAM MB-second.
        pub ram_mb_second: u64,
        /// Smallest `Currency` unit per storage GB-second.
        pub storage_gb_second: u64,
        /// Smallest `Currency` unit per network MB; the same rate applies
        /// to egress and ingress (ADR-029 Sec4.2).
        pub network_mb: u64,
    }

    #[derive(
        Clone,
        Copy,
        Decode,
        DecodeWithMemTracking,
        Encode,
        Eq,
        MaxEncodedLen,
        PartialEq,
        Debug,
        TypeInfo,
    )]
    pub enum EscrowState {
        Funded,
        Completed,
        Refunded,
        Disputed,
    }

    #[derive(
        Clone, Decode, DecodeWithMemTracking, Encode, Eq, MaxEncodedLen, PartialEq, Debug, TypeInfo,
    )]
    #[scale_info(skip_type_params(T))]
    pub struct EscrowRecord<T: Config> {
        pub payer: T::AccountId,
        pub provider: T::AccountId,
        pub lease_id: LeaseId,
        pub max_charge: BalanceOf<T>,
        pub price: PriceSchedule,
        pub metering_schema_version: u16,
        /// Replay protection: the highest `MeteringSummary.sequence`
        /// already accepted for this escrow (ADR-029 Sec4.2/Sec6).
        pub last_evidence_sequence: u64,
        pub state: EscrowState,
        pub funded_at: BlockNumberFor<T>,
        /// The block this escrow left `Funded` (`Completed` or
        /// `Refunded`), if it has. Not part of ADR-029's own
        /// `EscrowRecord` sketch -- added because Sec4.4's dispute window
        /// ("within `DisputeWindow` blocks" of settling) has no other
        /// anchor to measure from once an escrow is no longer `Funded`.
        pub settled_at: Option<BlockNumberFor<T>>,
    }

    /// Signed, hashed, bounded, replay-resistant usage evidence (ADR-029
    /// Sec6). Submitted as a call argument to [`Pallet::complete_and_payout`]
    /// so the pallet can verify its signature and compute the charge
    /// on-chain; it is **not** persisted past that call -- only its hash
    /// (in [`Event::EscrowSettled`]) and the derived `charged_amount` land
    /// in permanent storage/events, per `AGENTS.md`'s permanent
    /// prohibition on detailed metrics on-chain.
    #[derive(
        Clone, Decode, DecodeWithMemTracking, Encode, Eq, MaxEncodedLen, PartialEq, Debug, TypeInfo,
    )]
    pub struct MeteringSummary<BlockNumber> {
        pub lease_id: LeaseId,
        /// Monotonic per escrow; replay resistance, ADR-012 Sec4's pattern
        /// reused, not reinvented.
        pub sequence: u64,
        pub period_start: BlockNumber,
        pub period_end: BlockNumber,
        pub cpu_core_seconds: u64,
        pub ram_mb_seconds: u64,
        pub storage_gb_seconds: u64,
        pub network_egress_mb: u64,
        pub network_ingress_mb: u64,
        /// Reserved; priced at 0 and not charged in v1 (ADR-029 Sec1/Sec11).
        pub gpu_seconds: u64,
        pub metering_schema_version: u16,
        /// Ed25519 signature over [`Pallet::metering_signing_payload`] of
        /// every field above, by the Provider Agent's existing
        /// `agent-core::identity::Ed25519IdentityManager` key -- the same
        /// key `pallet-provider-registry::Provider.public_key` already
        /// records on-chain.
        pub signature: [u8; 64],
    }

    /// The binary outcome `resolve_dispute` may direct (ADR-029 Sec4.5).
    /// Arbitration beyond this choice -- partial splits, an independent
    /// arbiter, an appeals process -- is explicitly out of scope for v1
    /// (ADR-029 Sec11).
    #[derive(
        Clone,
        Copy,
        Decode,
        DecodeWithMemTracking,
        Encode,
        Eq,
        MaxEncodedLen,
        PartialEq,
        Debug,
        TypeInfo,
    )]
    pub enum DisputeOutcome<Balance> {
        /// Pay the provider the named amount (bounded by `max_charge`,
        /// same cap as ordinary completion); any remainder is refunded to
        /// the payer.
        PayProvider(Balance),
        /// Refund the payer the full `max_charge`; applies the bounded
        /// reliability penalty to the provider (ADR-029 Sec5).
        RefundPayer,
    }

    /// One escrow per lease, keyed by `lease_id` (`pallet-lease`'s own id
    /// space, reused rather than inventing a separate one -- ADR-029 Sec4,
    /// #21's own "idempotent correlation with finalized leases" criterion).
    #[pallet::storage]
    #[pallet::getter(fn escrows)]
    pub type Escrows<T: Config> =
        StorageMap<_, Blake2_128Concat, LeaseId, EscrowRecord<T>, OptionQuery>;

    /// Emergency circuit breaker (ADR-029 Sec10). While `true`, no new
    /// escrow can be funded and no existing escrow can change state --
    /// funds already reserved stay reserved, frozen in place, never
    /// auto-refunded and never seized.
    #[pallet::storage]
    pub type EscrowPaused<T: Config> = StorageValue<_, bool, ValueQuery>;

    /// Count of this account's escrows currently holding reserved funds as
    /// `payer` (state `Funded`, or `Disputed` reached directly from
    /// `Funded` -- i.e. an escrow whose `max_charge` is still actually
    /// reserved on-chain, not yet repatriated/unreserved/written off).
    /// Backs the reverse half of the reserve-contamination guard: the
    /// runtime's `pallet-network-validator::register_validator` reads this
    /// directly (`PayerOpenEscrowCount::<Runtime>::get(who) > 0`) to refuse
    /// registering an account that currently has escrow funds locked as
    /// payer. Bounded per account (a `u32` counter, not an unbounded list),
    /// so no new unbounded storage is introduced.
    #[pallet::storage]
    pub type PayerOpenEscrowCount<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, u32, ValueQuery>;

    /// ADR-030 Sec4: 100 bps (1%), a deliberately conservative MVP
    /// default -- easy to justify as negligible against a payer's total
    /// cost, a starting point for governance to raise deliberately as the
    /// network matures.
    #[pallet::type_value]
    pub fn DefaultFeeBasisPoints<T: Config>() -> u16 {
        100
    }

    /// Governed protocol usage fee rate, in basis points (0..=10_000,
    /// further bounded by `MaxFeeBasisPoints`). Deducted from the settled
    /// amount only at `complete_and_payout` / `resolve_dispute`'s
    /// `PayProvider` outcome (ADR-030 Sec2) -- never at `fund_escrow`,
    /// `refund_escrow`, or `resolve_dispute`'s `RefundPayer` outcome, all
    /// of which move zero fee regardless of this value.
    #[pallet::storage]
    #[pallet::getter(fn fee_basis_points)]
    pub type FeeBasisPoints<T: Config> = StorageValue<_, u16, ValueQuery, DefaultFeeBasisPoints<T>>;

    /// Governed destination for the protocol usage fee (ADR-030 Sec3).
    /// Starts unset (`OptionQuery`, no default) so a payout with a
    /// nonzero `FeeBasisPoints` and no configured treasury fails closed
    /// (`Error::TreasuryAccountNotConfigured`) rather than silently
    /// skipping the fee or crediting it nowhere.
    #[pallet::storage]
    #[pallet::getter(fn treasury_account)]
    pub type TreasuryAccount<T: Config> = StorageValue<_, T::AccountId, OptionQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        EscrowFunded {
            lease_id: LeaseId,
            payer: T::AccountId,
            provider: T::AccountId,
            max_charge: BalanceOf<T>,
            metering_schema_version: u16,
        },
        /// `evidence_hash` is a hash of the full submitted evidence, for
        /// #20's off-chain invoice ledger to correlate against -- the
        /// `MeteringSummary` itself is never stored past this call.
        EscrowSettled {
            lease_id: LeaseId,
            provider: T::AccountId,
            charged_amount: BalanceOf<T>,
            evidence_hash: [u8; 32],
        },
        EscrowRefunded {
            lease_id: LeaseId,
            payer: T::AccountId,
            amount: BalanceOf<T>,
        },
        EscrowDisputed {
            lease_id: LeaseId,
            disputed_by: T::AccountId,
            reason_hash: [u8; 32],
        },
        DisputeResolved {
            lease_id: LeaseId,
            outcome: DisputeOutcome<BalanceOf<T>>,
            provider_amount: BalanceOf<T>,
            payer_amount: BalanceOf<T>,
        },
        EscrowPausedSet {
            paused: bool,
        },
        /// A confirmed, irrecoverable shortfall between this escrow's own
        /// `max_charge` bookkeeping and what is actually reserved on-chain
        /// for `payer` was written off by [`Pallet::resolve_dispute`]
        /// rather than left permanently stuck. Only ever emitted from that
        /// root-gated path -- `complete_and_payout`/`refund_escrow` still
        /// fail closed (`Error::ReserveAccountingInconsistent`) on any such
        /// inconsistency, by design; this event exists specifically for the
        /// case that guard cannot self-resolve. `provider_amount`/
        /// `payer_amount` are what was actually moved from what was
        /// actually available (in the same priority order the outcome
        /// already implies -- `PayProvider` pays the provider first, any
        /// leftover reservation returns to the payer; `RefundPayer` returns
        /// whatever remains to the payer); `shortfall` is the portion of
        /// `expected_total` (`max_charge`) that could not be recovered at
        /// all, e.g. because it was already moved or burned elsewhere
        /// against the same shared reserved balance. No protocol fee
        /// (ADR-030) is ever taken on a write-off -- see
        /// [`Pallet::resolve_dispute`]'s doc comment.
        EscrowShortfallWrittenOff {
            lease_id: LeaseId,
            payer: T::AccountId,
            provider: T::AccountId,
            expected_total: BalanceOf<T>,
            provider_amount: BalanceOf<T>,
            payer_amount: BalanceOf<T>,
            shortfall: BalanceOf<T>,
        },
        /// Emitted by `set_fee_basis_points` on every change, carrying both
        /// the old and new rate so a rate change is always visible in the
        /// on-chain event log (ADR-030 Sec4).
        FeeBasisPointsUpdated {
            old: u16,
            new: u16,
        },
        /// Emitted by `set_treasury_account` on every change.
        TreasuryAccountUpdated {
            old: Option<T::AccountId>,
            new: T::AccountId,
        },
        /// The protocol usage fee portion actually transferred to
        /// `treasury_account`, alongside `EscrowSettled` /
        /// `DisputeResolved`'s `PayProvider` outcome -- a dedicated event,
        /// not a silently-added field on either of those, so the fee
        /// split is visible without needing to know to look for it.
        /// Never emitted for a zero fee (ADR-030 Sec2/Sec4): a `$0`
        /// "fee collected" event carries no information, matching this
        /// pallet's existing skip-the-zero-value-transfer behavior. Also
        /// never emitted alongside [`Event::EscrowShortfallWrittenOff`] --
        /// see [`Pallet::resolve_dispute`]'s doc comment.
        ProtocolFeeCollected {
            lease_id: LeaseId,
            fee_amount: BalanceOf<T>,
            treasury_account: T::AccountId,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        /// `EscrowPaused` is set; no escrow may fund or change state.
        Paused,
        /// An escrow already exists for this `lease_id`.
        EscrowAlreadyFunded,
        /// `max_charge` is below `MinEscrowAmount`.
        EscrowBelowMinimum,
        /// `LeaseExists` reports no such lease.
        LeaseDoesNotExist,
        /// The payer's free balance could not cover `max_charge`.
        InsufficientFreeBalance,
        /// No `EscrowRecord` exists for this `lease_id`.
        EscrowNotFound,
        /// The escrow is not in `Funded` state (already completed,
        /// refunded, or under dispute).
        EscrowNotFunded,
        /// The evidence's own `lease_id` field does not match the
        /// `lease_id` this call names -- closes a cross-escrow replay
        /// where evidence signed for one lease is submitted against a
        /// different one.
        LeaseIdMismatch,
        /// `evidence.metering_schema_version` does not match the version
        /// committed at funding time.
        MeteringSchemaVersionMismatch,
        /// `ProviderKeyLookup` has no public key for this escrow's
        /// provider.
        ProviderKeyNotFound,
        /// `sp_io::crypto::ed25519_verify` rejected the evidence's
        /// signature.
        InvalidSignature,
        /// `evidence.sequence` is not strictly greater than
        /// `last_evidence_sequence`.
        EvidenceSequenceReplay,
        /// `period_end` precedes `period_start`.
        InvalidMeteringPeriod,
        /// `period_end - period_start` exceeds `MaxMeteringPeriodSeconds`.
        MeteringPeriodTooLong,
        /// A checked arithmetic operation over usage x price overflowed.
        ArithmeticOverflow,
        /// The computed `charged_amount` exceeds `max_charge`.
        ChargedAmountExceedsCap,
        /// A `ReservableCurrency` reserve/unreserve/repatriate call moved
        /// less than expected -- the reserved balance this pallet tracks
        /// no longer matches what is actually reserved on-chain for this
        /// account. Failing closed rather than silently under-crediting
        /// either party.
        ReserveAccountingInconsistent,
        /// `RefundWindow` blocks have not yet elapsed since `funded_at`.
        RefundWindowNotElapsed,
        /// The caller is not this escrow's `payer`.
        NotPayer,
        /// The caller is neither this escrow's `payer` nor its `provider`.
        NotPartyToEscrow,
        /// The escrow is already `Disputed`.
        AlreadyDisputed,
        /// `DisputeWindow` blocks have elapsed since the escrow settled.
        DisputeWindowElapsed,
        /// The escrow is not currently `Disputed`.
        NotDisputed,
        /// `resolve_dispute`'s `PayProvider(amount)` exceeds `max_charge`.
        PayoutExceedsCap,
        /// `payer` is currently a registered Network Validator (any
        /// status -- `Active`, `Suspended`, or `Exiting` all still hold
        /// reserved stake). Rejected because `pallet-escrow` and
        /// `pallet-network-validator` share one untagged, per-account
        /// `ReservableCurrency` reserved balance: a validator slash is not
        /// scoped to the validator's own stake, so an account holding both
        /// roles risks an unrelated slash consuming this escrow's reserved
        /// `max_charge`. See [`ValidatorRegistrationInspector`].
        PayerIsRegisteredValidator,
        /// `set_fee_basis_points`'s `new_bps` exceeds `MaxFeeBasisPoints`.
        FeeExceedsCap,
        /// A payout with `FeeBasisPoints > 0` was attempted with no
        /// `TreasuryAccount` configured. Fails closed rather than silently
        /// skipping the fee or crediting it nowhere (ADR-030 Sec3).
        TreasuryAccountNotConfigured,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Reserve `max_charge` from the caller's **own** free balance and
        /// open an escrow for `lease_id`. Permissionless: any signed
        /// account with sufficient free balance may fund an escrow, and
        /// that account -- not `pallet-lease`'s `consumer` -- becomes this
        /// escrow's `payer` (ADR-029 Sec3). Funds never leave the payer's
        /// account or enter a pooled account; they are merely earmarked.
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::fund_escrow())]
        pub fn fund_escrow(
            origin: OriginFor<T>,
            lease_id: LeaseId,
            provider: T::AccountId,
            max_charge: BalanceOf<T>,
            price: PriceSchedule,
            metering_schema_version: u16,
        ) -> DispatchResult {
            let payer = ensure_signed(origin)?;
            ensure!(!EscrowPaused::<T>::get(), Error::<T>::Paused);
            ensure!(
                !Escrows::<T>::contains_key(lease_id),
                Error::<T>::EscrowAlreadyFunded
            );
            ensure!(
                max_charge >= T::MinEscrowAmount::get(),
                Error::<T>::EscrowBelowMinimum
            );
            ensure!(
                T::LeaseExists::exists(lease_id),
                Error::<T>::LeaseDoesNotExist
            );
            // Reserve-contamination guard: a registered Network Validator
            // (any status) may not also become an escrow payer, since both
            // pallets reserve against the same untagged per-account balance
            // (see `ValidatorRegistrationInspector`'s doc comment).
            ensure!(
                !T::ValidatorInspector::is_registered(&payer),
                Error::<T>::PayerIsRegisteredValidator
            );

            T::Currency::reserve(&payer, max_charge)
                .map_err(|_| Error::<T>::InsufficientFreeBalance)?;

            let funded_at = frame_system::Pallet::<T>::block_number();
            Escrows::<T>::insert(
                lease_id,
                EscrowRecord {
                    payer: payer.clone(),
                    provider: provider.clone(),
                    lease_id,
                    max_charge,
                    price,
                    metering_schema_version,
                    last_evidence_sequence: 0,
                    state: EscrowState::Funded,
                    funded_at,
                    settled_at: None,
                },
            );
            PayerOpenEscrowCount::<T>::mutate(&payer, |count| *count = count.saturating_add(1));

            Self::deposit_event(Event::EscrowFunded {
                lease_id,
                payer,
                provider,
                max_charge,
                metering_schema_version,
            });
            Ok(())
        }

        /// Verify a provider-signed [`MeteringSummary`] on-chain and pay
        /// out exactly the charge it computes to, capped by `max_charge`.
        /// Permissionless: any relayer holding the signed evidence --
        /// including but not limited to the Control Plane bridge account or
        /// the provider itself -- may submit it (ADR-029 Sec4.2/Sec9).
        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::complete_and_payout())]
        pub fn complete_and_payout(
            origin: OriginFor<T>,
            lease_id: LeaseId,
            evidence: MeteringSummary<BlockNumberFor<T>>,
        ) -> DispatchResult {
            let _submitter = ensure_signed(origin)?;
            ensure!(!EscrowPaused::<T>::get(), Error::<T>::Paused);
            ensure!(evidence.lease_id == lease_id, Error::<T>::LeaseIdMismatch);

            let mut escrow = Escrows::<T>::get(lease_id).ok_or(Error::<T>::EscrowNotFound)?;
            ensure!(
                escrow.state == EscrowState::Funded,
                Error::<T>::EscrowNotFunded
            );
            ensure!(
                evidence.metering_schema_version == escrow.metering_schema_version,
                Error::<T>::MeteringSchemaVersionMismatch
            );

            let public_key = T::ProviderKeyLookup::public_key(&escrow.provider)
                .ok_or(Error::<T>::ProviderKeyNotFound)?;
            let message = Self::metering_signing_payload(&evidence);
            let signature = sp_core::ed25519::Signature::from_raw(evidence.signature);
            let public = sp_core::ed25519::Public::from_raw(public_key);
            ensure!(
                sp_io::crypto::ed25519_verify(&signature, &message, &public),
                Error::<T>::InvalidSignature
            );

            ensure!(
                evidence.sequence > escrow.last_evidence_sequence,
                Error::<T>::EvidenceSequenceReplay
            );
            ensure!(
                evidence.period_end >= evidence.period_start,
                Error::<T>::InvalidMeteringPeriod
            );
            let period_len = evidence.period_end.saturating_sub(evidence.period_start);
            ensure!(
                period_len <= T::MaxMeteringPeriodSeconds::get(),
                Error::<T>::MeteringPeriodTooLong
            );

            let charged_amount = Self::compute_charge(&escrow.price, &evidence)?;
            ensure!(
                charged_amount <= escrow.max_charge,
                Error::<T>::ChargedAmountExceedsCap
            );

            let (provider_amount, fee_amount, treasury_account) = Self::split_fee(charged_amount)?;
            if !provider_amount.is_zero() {
                let shortfall = T::Currency::repatriate_reserved(
                    &escrow.payer,
                    &escrow.provider,
                    provider_amount,
                    BalanceStatus::Free,
                )
                .map_err(|_| Error::<T>::ReserveAccountingInconsistent)?;
                ensure!(
                    shortfall.is_zero(),
                    Error::<T>::ReserveAccountingInconsistent
                );
            }
            if !fee_amount.is_zero() {
                // `split_fee` only ever returns a nonzero `fee_amount`
                // alongside `Some(treasury_account)` -- see its own
                // doc comment.
                let treasury = treasury_account.ok_or(Error::<T>::TreasuryAccountNotConfigured)?;
                let shortfall = T::Currency::repatriate_reserved(
                    &escrow.payer,
                    &treasury,
                    fee_amount,
                    BalanceStatus::Free,
                )
                .map_err(|_| Error::<T>::ReserveAccountingInconsistent)?;
                ensure!(
                    shortfall.is_zero(),
                    Error::<T>::ReserveAccountingInconsistent
                );
                Self::deposit_event(Event::ProtocolFeeCollected {
                    lease_id,
                    fee_amount,
                    treasury_account: treasury,
                });
            }
            let remainder = escrow.max_charge.saturating_sub(charged_amount);
            if !remainder.is_zero() {
                let unreleased = T::Currency::unreserve(&escrow.payer, remainder);
                ensure!(
                    unreleased.is_zero(),
                    Error::<T>::ReserveAccountingInconsistent
                );
            }

            let evidence_hash = evidence.blake2_256();
            escrow.state = EscrowState::Completed;
            escrow.last_evidence_sequence = evidence.sequence;
            let now = frame_system::Pallet::<T>::block_number();
            escrow.settled_at = Some(now);
            let provider = escrow.provider.clone();
            Self::decrement_payer_open_count(&escrow.payer);
            Escrows::<T>::insert(lease_id, escrow);

            Self::deposit_event(Event::EscrowSettled {
                lease_id,
                provider,
                charged_amount,
                evidence_hash,
            });
            Ok(())
        }

        /// Self-service refund. Restricted to this escrow's own `payer`,
        /// callable once `RefundWindow` blocks have elapsed since
        /// `funded_at` with no completion -- needs no governance origin at
        /// all, the block-height check is itself the authorization
        /// (ADR-029 Sec4.3).
        #[pallet::call_index(2)]
        #[pallet::weight(T::WeightInfo::refund_escrow())]
        pub fn refund_escrow(origin: OriginFor<T>, lease_id: LeaseId) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(!EscrowPaused::<T>::get(), Error::<T>::Paused);
            let mut escrow = Escrows::<T>::get(lease_id).ok_or(Error::<T>::EscrowNotFound)?;
            ensure!(who == escrow.payer, Error::<T>::NotPayer);
            ensure!(
                escrow.state == EscrowState::Funded,
                Error::<T>::EscrowNotFunded
            );
            let now = frame_system::Pallet::<T>::block_number();
            let unlock_at = escrow.funded_at.saturating_add(T::RefundWindow::get());
            ensure!(now >= unlock_at, Error::<T>::RefundWindowNotElapsed);

            let unreleased = T::Currency::unreserve(&escrow.payer, escrow.max_charge);
            ensure!(
                unreleased.is_zero(),
                Error::<T>::ReserveAccountingInconsistent
            );

            escrow.state = EscrowState::Refunded;
            escrow.settled_at = Some(now);
            let amount = escrow.max_charge;
            let payer = escrow.payer.clone();
            Self::decrement_payer_open_count(&escrow.payer);
            Escrows::<T>::insert(lease_id, escrow);

            Self::deposit_event(Event::EscrowRefunded {
                lease_id,
                payer,
                amount,
            });
            Ok(())
        }

        /// Freeze an escrow pending governance resolution. Callable by
        /// either the payer or the provider, from `Funded` at any time, or
        /// from `Completed`/`Refunded` within `DisputeWindow` blocks of
        /// settling (ADR-029 Sec4.4).
        #[pallet::call_index(3)]
        #[pallet::weight(T::WeightInfo::dispute_escrow())]
        pub fn dispute_escrow(
            origin: OriginFor<T>,
            lease_id: LeaseId,
            reason_hash: [u8; 32],
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(!EscrowPaused::<T>::get(), Error::<T>::Paused);
            let mut escrow = Escrows::<T>::get(lease_id).ok_or(Error::<T>::EscrowNotFound)?;
            ensure!(
                who == escrow.payer || who == escrow.provider,
                Error::<T>::NotPartyToEscrow
            );

            match escrow.state {
                EscrowState::Funded => {}
                EscrowState::Completed | EscrowState::Refunded => {
                    let settled_at = escrow.settled_at.unwrap_or(escrow.funded_at);
                    let now = frame_system::Pallet::<T>::block_number();
                    let deadline = settled_at.saturating_add(T::DisputeWindow::get());
                    ensure!(now <= deadline, Error::<T>::DisputeWindowElapsed);
                }
                EscrowState::Disputed => return Err(Error::<T>::AlreadyDisputed.into()),
            }

            escrow.state = EscrowState::Disputed;
            Escrows::<T>::insert(lease_id, escrow);

            Self::deposit_event(Event::EscrowDisputed {
                lease_id,
                disputed_by: who,
                reason_hash,
            });
            Ok(())
        }

        /// Settle a disputed escrow. `DisputeOrigin`-gated -- the sole
        /// remaining sudo-key surface in this pallet (ADR-029 Sec4.5/Sec9).
        #[pallet::call_index(4)]
        #[pallet::weight(T::WeightInfo::resolve_dispute())]
        pub fn resolve_dispute(
            origin: OriginFor<T>,
            lease_id: LeaseId,
            outcome: DisputeOutcome<BalanceOf<T>>,
        ) -> DispatchResult {
            T::DisputeOrigin::ensure_origin(origin)?;
            ensure!(!EscrowPaused::<T>::get(), Error::<T>::Paused);
            let mut escrow = Escrows::<T>::get(lease_id).ok_or(Error::<T>::EscrowNotFound)?;
            ensure!(
                escrow.state == EscrowState::Disputed,
                Error::<T>::NotDisputed
            );
            // Whether this escrow's `max_charge` is still actually reserved
            // for `payer` (never yet released by complete_and_payout/
            // refund_escrow): decided before any mutation below, since this
            // call itself sets `settled_at` at the end and it's the only
            // signal left once a `Completed`/`Refunded` escrow is disputed
            // again within `DisputeWindow` (ADR-029 Sec4.4) -- that path's
            // funds were already released the first time it settled, so
            // `PayerOpenEscrowCount` must not be decremented a second time
            // for it here.
            let funds_still_reserved = escrow.settled_at.is_none();
            let max_charge = escrow.max_charge;

            // Fail-safe for a confirmed, irrecoverable reserve shortfall
            // (see the PR description for the mechanism): unlike
            // `complete_and_payout`/`refund_escrow`, which still fail
            // closed (`Error::ReserveAccountingInconsistent`) on *any*
            // inconsistency between this escrow's own `max_charge`
            // bookkeeping and what is actually reserved on-chain for
            // `payer`, this root-gated path tolerates it: it pays out
            // whatever is actually available, in the same priority order
            // the normal path already uses (`PayProvider` pays the
            // provider first, any leftover reservation returns to the
            // payer; `RefundPayer` returns whatever remains to the payer),
            // and reports the unrecoverable remainder as `shortfall` rather
            // than erroring the whole call. When nothing is actually short
            // -- every case any test before this fix could ever reach --
            // `paid`/`returned` are numerically identical to the nominal
            // `amount`/`remainder` this call always produced before, so
            // this is a strict superset of the previous behavior, not a
            // change to it.
            let (provider_amount, payer_amount, final_state, shortfall) = match outcome {
                DisputeOutcome::PayProvider(amount) => {
                    ensure!(amount <= max_charge, Error::<T>::PayoutExceedsCap);
                    // AMBIGUOUS INTERACTION, RESOLVED CONSERVATIVELY (see
                    // the merge report): ADR-030's protocol fee and the
                    // reserve-contamination write-off fail-safe were
                    // developed independently and neither PR specifies how
                    // they interact when both could apply to the same
                    // dispute. This resolution takes the reading spelled
                    // out in the merge instructions -- a write-off is a
                    // degraded recovery of a contaminated escrow, not a
                    // normal successful settlement, so it must never also
                    // carry a protocol-fee deduction on funds that were
                    // never actually fully available.
                    //
                    // Whether this escrow's reserved funds are still fully
                    // intact is decided once, up front, via a read-only
                    // balance check -- before any transfer below -- so the
                    // fee-vs-write-off choice is deterministic rather than
                    // inferred from a partial transfer's own shortfall.
                    // This pallet has no per-escrow tag on the reserved
                    // balance (that's the root cause of the contamination
                    // bug itself, see the module doc comment), so an
                    // account-level check against this escrow's own
                    // `max_charge` is the finest precision actually
                    // available on-chain -- consistent with, not an
                    // approximation on top of, the shared-pool model this
                    // pallet already lives with.
                    if T::Currency::reserved_balance(&escrow.payer) < max_charge {
                        // Fail-safe path: confirmed shortfall. No protocol
                        // fee is taken; whatever is actually available is
                        // paid to the provider first, exactly as this
                        // fail-safe behaved before ADR-030 existed.
                        let unmoved = T::Currency::repatriate_reserved(
                            &escrow.payer,
                            &escrow.provider,
                            amount,
                            BalanceStatus::Free,
                        )
                        .map_err(|_| Error::<T>::ReserveAccountingInconsistent)?;
                        let paid = amount.saturating_sub(unmoved);
                        let remainder = max_charge.saturating_sub(amount);
                        let mut returned = Zero::zero();
                        if !remainder.is_zero() {
                            let unreleased = T::Currency::unreserve(&escrow.payer, remainder);
                            returned = remainder.saturating_sub(unreleased);
                        }
                        let shortfall = max_charge.saturating_sub(paid.saturating_add(returned));
                        (paid, returned, EscrowState::Completed, shortfall)
                    } else {
                        // Normal path: reserved funds are fully intact, so
                        // apply the identical ADR-030 fee split
                        // `complete_and_payout` uses, and fail closed on
                        // any inconsistency exactly like that path does --
                        // governance affirming delivery is the same "value
                        // was actually delivered" condition as on-chain
                        // verified completion, so the same split applies
                        // to the adjudicated `amount`.
                        let (paid_to_provider, fee_amount, treasury_account) =
                            Self::split_fee(amount)?;
                        if !paid_to_provider.is_zero() {
                            let shortfall = T::Currency::repatriate_reserved(
                                &escrow.payer,
                                &escrow.provider,
                                paid_to_provider,
                                BalanceStatus::Free,
                            )
                            .map_err(|_| Error::<T>::ReserveAccountingInconsistent)?;
                            ensure!(
                                shortfall.is_zero(),
                                Error::<T>::ReserveAccountingInconsistent
                            );
                        }
                        if !fee_amount.is_zero() {
                            let treasury =
                                treasury_account.ok_or(Error::<T>::TreasuryAccountNotConfigured)?;
                            let shortfall = T::Currency::repatriate_reserved(
                                &escrow.payer,
                                &treasury,
                                fee_amount,
                                BalanceStatus::Free,
                            )
                            .map_err(|_| Error::<T>::ReserveAccountingInconsistent)?;
                            ensure!(
                                shortfall.is_zero(),
                                Error::<T>::ReserveAccountingInconsistent
                            );
                            Self::deposit_event(Event::ProtocolFeeCollected {
                                lease_id,
                                fee_amount,
                                treasury_account: treasury,
                            });
                        }
                        let remainder = max_charge.saturating_sub(amount);
                        if !remainder.is_zero() {
                            let unreleased = T::Currency::unreserve(&escrow.payer, remainder);
                            ensure!(
                                unreleased.is_zero(),
                                Error::<T>::ReserveAccountingInconsistent
                            );
                        }
                        // `provider_amount` in `DisputeResolved` below
                        // reports what the provider actually received, net
                        // of the fee -- not the full adjudicated `amount`
                        // -- so the event stays truthful about the real
                        // on-chain transfer (ADR-030's fee is a split of
                        // `amount`, not an add-on, so `paid_to_provider` is
                        // the correct value here, matching `EscrowSettled`
                        // reporting `charged_amount` as the payer's total
                        // charge rather than the provider's net receipt).
                        (
                            paid_to_provider,
                            remainder,
                            EscrowState::Completed,
                            Zero::zero(),
                        )
                    }
                }
                DisputeOutcome::RefundPayer => {
                    let unreleased = T::Currency::unreserve(&escrow.payer, max_charge);
                    let returned = max_charge.saturating_sub(unreleased);
                    // ADR-029 Sec5: the provider was found in the wrong --
                    // apply the bounded reliability penalty. A rejected
                    // dispute (`PayProvider`) applies no penalty to either
                    // side.
                    T::ReputationPenalty::apply(&escrow.provider, T::ReliabilityPenaltyBps::get())?;
                    (Zero::zero(), returned, EscrowState::Refunded, unreleased)
                }
            };

            escrow.state = final_state;
            let now = frame_system::Pallet::<T>::block_number();
            escrow.settled_at = Some(now);
            if funds_still_reserved {
                Self::decrement_payer_open_count(&escrow.payer);
            }
            let payer = escrow.payer.clone();
            let provider = escrow.provider.clone();
            Escrows::<T>::insert(lease_id, escrow);

            Self::deposit_event(Event::DisputeResolved {
                lease_id,
                outcome,
                provider_amount,
                payer_amount,
            });
            if !shortfall.is_zero() {
                Self::deposit_event(Event::EscrowShortfallWrittenOff {
                    lease_id,
                    payer,
                    provider,
                    expected_total: max_charge,
                    provider_amount,
                    payer_amount,
                    shortfall,
                });
            }
            Ok(())
        }

        /// Toggle the emergency pause. `PauseOrigin`-gated. While paused,
        /// no state transition below is possible on any escrow -- reserved
        /// funds stay frozen in place, never auto-refunded and never
        /// seized (ADR-029 Sec10).
        #[pallet::call_index(5)]
        #[pallet::weight(T::WeightInfo::set_paused())]
        pub fn set_paused(origin: OriginFor<T>, paused: bool) -> DispatchResult {
            T::PauseOrigin::ensure_origin(origin)?;
            EscrowPaused::<T>::put(paused);
            Self::deposit_event(Event::EscrowPausedSet { paused });
            Ok(())
        }

        /// Set the governed protocol usage fee rate (ADR-030 Sec4).
        /// `FeeGovernanceOrigin`-gated. Rejects anything above
        /// `MaxFeeBasisPoints`, leaving storage unchanged.
        #[pallet::call_index(6)]
        #[pallet::weight(T::WeightInfo::set_fee_basis_points())]
        pub fn set_fee_basis_points(origin: OriginFor<T>, new_bps: u16) -> DispatchResult {
            T::FeeGovernanceOrigin::ensure_origin(origin)?;
            ensure!(
                new_bps <= T::MaxFeeBasisPoints::get(),
                Error::<T>::FeeExceedsCap
            );
            let old = FeeBasisPoints::<T>::get();
            FeeBasisPoints::<T>::put(new_bps);
            Self::deposit_event(Event::FeeBasisPointsUpdated { old, new: new_bps });
            Ok(())
        }

        /// Set the governed protocol treasury account (ADR-030 Sec3).
        /// `FeeGovernanceOrigin`-gated. This is the sole way a nonzero
        /// `FeeBasisPoints` becomes actionable -- with no configured
        /// treasury, `complete_and_payout` / `resolve_dispute` fail
        /// closed instead (`Error::TreasuryAccountNotConfigured`).
        #[pallet::call_index(7)]
        #[pallet::weight(T::WeightInfo::set_treasury_account())]
        pub fn set_treasury_account(
            origin: OriginFor<T>,
            new_account: T::AccountId,
        ) -> DispatchResult {
            T::FeeGovernanceOrigin::ensure_origin(origin)?;
            let old = TreasuryAccount::<T>::get();
            TreasuryAccount::<T>::put(&new_account);
            Self::deposit_event(Event::TreasuryAccountUpdated {
                old,
                new: new_account,
            });
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        /// The exact byte sequence a [`MeteringSummary`]'s `signature`
        /// field must cover: every field except the signature itself,
        /// SCALE-encoded in declaration order. `pub` so tests (and any
        /// future off-chain signer) construct precisely the bytes this
        /// pallet will verify -- one source of truth, not two encodings
        /// that could silently drift apart.
        pub fn metering_signing_payload(
            evidence: &MeteringSummary<BlockNumberFor<T>>,
        ) -> alloc::vec::Vec<u8> {
            (
                evidence.lease_id,
                evidence.sequence,
                evidence.period_start,
                evidence.period_end,
                evidence.cpu_core_seconds,
                evidence.ram_mb_seconds,
                evidence.storage_gb_seconds,
                evidence.network_egress_mb,
                evidence.network_ingress_mb,
                evidence.gpu_seconds,
                evidence.metering_schema_version,
            )
                .encode()
        }

        /// `cpu_core_seconds * price.cpu_core_second + ram_mb_seconds *
        /// price.ram_mb_second + storage_gb_seconds *
        /// price.storage_gb_second + (network_egress_mb +
        /// network_ingress_mb) * price.network_mb`, entirely `checked_*`
        /// over `u64` (ADR-029 Sec1/Sec4.2) -- `gpu_seconds` is
        /// deliberately never added: reserved, priced at 0 in v1.
        /// Converted to `BalanceOf<T>` only at the very end, via the
        /// `TryFrom<u64>` every `Currency::Balance` already guarantees
        /// through `AtLeast32BitUnsigned`.
        fn compute_charge(
            price: &PriceSchedule,
            evidence: &MeteringSummary<BlockNumberFor<T>>,
        ) -> Result<BalanceOf<T>, DispatchError> {
            let cpu = evidence
                .cpu_core_seconds
                .checked_mul(price.cpu_core_second)
                .ok_or(Error::<T>::ArithmeticOverflow)?;
            let ram = evidence
                .ram_mb_seconds
                .checked_mul(price.ram_mb_second)
                .ok_or(Error::<T>::ArithmeticOverflow)?;
            let storage = evidence
                .storage_gb_seconds
                .checked_mul(price.storage_gb_second)
                .ok_or(Error::<T>::ArithmeticOverflow)?;
            let network_mb = evidence
                .network_egress_mb
                .checked_add(evidence.network_ingress_mb)
                .ok_or(Error::<T>::ArithmeticOverflow)?;
            let network = network_mb
                .checked_mul(price.network_mb)
                .ok_or(Error::<T>::ArithmeticOverflow)?;
            let total: u64 = cpu
                .checked_add(ram)
                .and_then(|value| value.checked_add(storage))
                .and_then(|value| value.checked_add(network))
                .ok_or(Error::<T>::ArithmeticOverflow)?;
            BalanceOf::<T>::try_from(total).map_err(|_| Error::<T>::ArithmeticOverflow.into())
        }

        /// Decrement [`PayerOpenEscrowCount`] for `payer` by one,
        /// saturating at zero. Called exactly once per escrow, at the
        /// point its reserved funds are actually released --
        /// `complete_and_payout`, `refund_escrow`, or `resolve_dispute`
        /// (guarded there by `funds_still_reserved` so a `Completed`/
        /// `Refunded` escrow re-disputed and resolved again within
        /// `DisputeWindow` is not double-decremented).
        fn decrement_payer_open_count(payer: &T::AccountId) {
            PayerOpenEscrowCount::<T>::mutate(payer, |count| *count = count.saturating_sub(1));
        }

        /// Splits a settled amount into `(provider_amount, fee_amount,
        /// treasury_account)` per ADR-030 Sec2/Sec4 -- the one shared
        /// helper both `complete_and_payout` and `resolve_dispute`'s
        /// `PayProvider` outcome call, so they apply identical fee logic
        /// rather than two independent copies that could drift.
        ///
        /// `fee_amount = charged_amount * fee_bps / 10_000`, entirely
        /// `checked_*` over `BalanceOf<T>`; integer division truncates,
        /// so the fee rounds **down** and the provider receives the
        /// remainder -- rounding in the provider's favor, matching this
        /// workspace's only other basis-points-of-a-value precedent
        /// (`pallet-reputation`'s `value * bps / 10_000`, also
        /// truncating).
        ///
        /// When `FeeBasisPoints` is `0`, returns `(charged_amount, 0,
        /// None)` without touching `TreasuryAccount` at all -- a
        /// zero-rate network need not have a treasury configured.
        /// Otherwise, fails closed with `TreasuryAccountNotConfigured`
        /// whenever no treasury account is set, regardless of whether
        /// the computed fee itself would round down to zero for a given
        /// call: a governance-set nonzero rate must always resolve to a
        /// real destination, not depend on a per-call rounding outcome.
        fn split_fee(charged_amount: BalanceOf<T>) -> Result<FeeSplit<T>, DispatchError> {
            let fee_bps = FeeBasisPoints::<T>::get();
            if fee_bps.is_zero() {
                return Ok((charged_amount, Zero::zero(), None));
            }
            let treasury =
                TreasuryAccount::<T>::get().ok_or(Error::<T>::TreasuryAccountNotConfigured)?;
            let fee_amount = charged_amount
                .checked_mul(&BalanceOf::<T>::from(fee_bps))
                .ok_or(Error::<T>::ArithmeticOverflow)?
                .checked_div(&BalanceOf::<T>::from(10_000u32))
                .ok_or(Error::<T>::ArithmeticOverflow)?;
            // `fee_bps <= MaxFeeBasisPoints` is enforced at
            // `set_fee_basis_points` time; as long as that cap is itself
            // configured to <= 10_000 (ADR-030 Sec4's 2,000 default), the
            // division above guarantees `fee_amount <= charged_amount`.
            // `checked_sub` (rather than `saturating_sub`) still fails
            // closed instead of silently clamping if that invariant is
            // ever violated by a misconfigured runtime.
            let provider_amount = charged_amount
                .checked_sub(&fee_amount)
                .ok_or(Error::<T>::ArithmeticOverflow)?;
            Ok((provider_amount, fee_amount, Some(treasury)))
        }
    }
}

#[cfg(test)]
mod tests;
