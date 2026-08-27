#![cfg_attr(not(feature = "std"), no_std)]

//! Provider stake slashing for missed availability commitments (ADR-036).
//!
//! Reads the existing, quorum-gated, disputable `RoundResult` aggregate
//! already committed by `pallet-network-validator::close_round` -- no new
//! evidence type, no new signature scheme, the same accepted source of
//! truth for "a provider's score for round R, attributable to a quorum of
//! independent validators" that ADR-018 already reused for validator-side
//! slashing. A **breach round** is a closed, undisputed (or dispute-
//! rejected) round whose dispute window has already elapsed, scored below
//! [`Config::AvailabilityBreachThresholdBps`], with a materially higher
//! confidence bar than the bare quorum needed merely to close a round
//! ([`Config::SlashConfidenceThresholdBps`]) -- so a round that closes on
//! the bare minimum quorum, fully valid for reputation purposes, never by
//! itself becomes slash-eligible (ADR-036 §2: "degraded quorum reduces
//! confidence rather than producing a slash").
//!
//! [`Pallet::record_breach`] requires [`Config::BreachRounds`] strictly
//! consecutive round numbers, each independently satisfying every
//! condition above, before it will open a [`PendingSlash`]. Two backstops
//! sit between a recorded breach and any fund actually moving:
//! [`Pallet::appeal_slash`] (the provider's own, ADR-036 §6) and the
//! round-level `dispute_round`/`resolve_dispute` this pallet reuses
//! unchanged (ADR-036 §4) -- a round that is `Disputed` or later
//! `DisputeUpheld` can never satisfy a breach round's own conditions, so
//! there is no path from an open or successful round-level dispute into a
//! completed slash, never a race against one.
//!
//! [`Pallet::execute_slash`] mutates `pallet-provider-registry`'s bond
//! through its internal, non-extrinsic `slash_bond` entry point (mirrors
//! `pallet-reputation::set_dimension_score`'s "internal-only" pattern), so
//! that pallet stays the only writer of `ProviderBonds` regardless of
//! which pallet triggers a change. Slashed funds are burned, never
//! redistributed, for the same reasoning ADR-018 §4 already gives for
//! validator slashing.

pub use pallet::*;

use frame_support::{
    pallet_prelude::*,
    sp_runtime::traits::{AtLeast32BitUnsigned, Saturating},
    traits::{EnsureOrigin, Get},
    weights::Weight,
};
use frame_system::pallet_prelude::*;

/// A component of a provider's reputation vector that validators score
/// independently. Redeclared here rather than depending on
/// `pallet-network-validator` directly (no crate dependency between the
/// two -- the runtime bridges [`AvailabilityRoundOracle`] onto its real
/// `Rounds` storage), mirroring `pallet-reputation::VectorDimension`'s own
/// "redeclared per pallet, mapped by the runtime" pattern.
#[derive(
    Clone,
    Copy,
    Encode,
    Decode,
    DecodeWithMemTracking,
    Eq,
    MaxEncodedLen,
    PartialEq,
    Debug,
    TypeInfo,
)]
pub enum ScoreDimension {
    Compute,
    Storage,
    Network,
    Availability,
    Reliability,
}

/// A closed round's lifecycle, mirroring
/// `pallet-network-validator::RoundStatus` exactly -- redeclared for the
/// same no-hard-dependency reason as [`ScoreDimension`].
#[derive(
    Clone,
    Copy,
    Encode,
    Decode,
    DecodeWithMemTracking,
    Eq,
    MaxEncodedLen,
    PartialEq,
    Debug,
    TypeInfo,
)]
pub enum RoundViewStatus {
    Final,
    Disputed,
    DisputeUpheld,
    DisputeRejected,
}

/// The narrow slice of `pallet-network-validator::RoundResult` a breach
/// eligibility check needs (ADR-036 §2's four conditions), read through
/// [`AvailabilityRoundOracle`] rather than the full struct.
#[derive(Clone, Encode, Decode, DecodeWithMemTracking, Eq, PartialEq, Debug, TypeInfo)]
pub struct RoundView<BlockNumber> {
    pub status: RoundViewStatus,
    pub score_bps: u16,
    pub submissions: u32,
    pub committee_target: u32,
    pub closed_at: BlockNumber,
}

/// Narrow, read-only interface into `pallet-network-validator`'s closed
/// rounds -- the oracle can only ever return an already-committed
/// `RoundResult`, never a raw, unaggregated submission (ADR-036 §2:
/// "slashing triggers only on evidence that is attributable,
/// non-repudiable, and already on-chain"). `dispute_window` mirrors
/// `pallet-network-validator::Config::DisputeWindow` so a breach round's
/// own dispute window can be checked without this pallet depending on that
/// pallet's crate.
pub trait AvailabilityRoundOracle<AccountId, BlockNumber> {
    fn round(
        provider: &AccountId,
        round: u64,
        dimension: ScoreDimension,
    ) -> Option<RoundView<BlockNumber>>;
    fn dispute_window() -> BlockNumber;
}

impl<AccountId, BlockNumber: Default> AvailabilityRoundOracle<AccountId, BlockNumber> for () {
    fn round(_: &AccountId, _: u64, _: ScoreDimension) -> Option<RoundView<BlockNumber>> {
        None
    }

    fn dispute_window() -> BlockNumber {
        BlockNumber::default()
    }
}

/// Removes bonded stake from a provider's `pallet-provider-registry` bond.
/// The runtime wires this to that pallet's internal, non-extrinsic
/// `slash_bond` entry point, so `pallet-provider-registry` stays the only
/// writer of `ProviderBonds` regardless of which pallet triggers a change
/// (mirrors `pallet-network-validator`'s `ReputationUpdater`/
/// `ValidatorRewards` pattern). Returns
/// `(amount_actually_slashed, force_suspended)`.
pub trait ProviderStakeSlasher<AccountId, Balance> {
    fn slash(provider: &AccountId, amount: Balance) -> (Balance, bool);
}

impl<AccountId, Balance: Default> ProviderStakeSlasher<AccountId, Balance> for () {
    fn slash(_: &AccountId, _: Balance) -> (Balance, bool) {
        (Balance::default(), false)
    }
}

pub trait WeightInfo {
    fn record_breach() -> Weight;
    fn appeal_slash() -> Weight;
    fn resolve_slash_appeal() -> Weight;
    fn execute_slash() -> Weight;
}

impl WeightInfo for () {
    fn record_breach() -> Weight {
        Weight::from_parts(10_000, 0)
    }

    fn appeal_slash() -> Weight {
        Weight::from_parts(10_000, 0)
    }

    fn resolve_slash_appeal() -> Weight {
        Weight::from_parts(10_000, 0)
    }

    fn execute_slash() -> Weight {
        Weight::from_parts(10_000, 0)
    }
}

#[frame_support::pallet]
pub mod pallet {
    use super::*;

    #[pallet::config]
    pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
        /// Balance-shaped type for [`Config::ProviderSlashAmount`]. This
        /// pallet never reserves or holds currency itself -- only
        /// `pallet-provider-registry` does, through
        /// [`Config::ProviderStakeSlasher`] -- so no `Currency` association
        /// of its own is needed, only a numeric type wide enough to name an
        /// amount.
        type Balance: Parameter + Member + AtLeast32BitUnsigned + Default + Copy + MaxEncodedLen;
        /// Backs every breach-eligibility read (ADR-036 §2); the runtime
        /// wires this to `pallet-network-validator::Rounds`.
        type AvailabilityRoundOracle: AvailabilityRoundOracle<Self::AccountId, BlockNumberFor<Self>>;
        /// Backs [`Pallet::execute_slash`]/[`Pallet::resolve_slash_appeal`];
        /// the runtime wires this to
        /// `pallet-provider-registry::Pallet::slash_bond`.
        type ProviderStakeSlasher: ProviderStakeSlasher<Self::AccountId, Self::Balance>;
        /// Governs [`Pallet::resolve_slash_appeal`]. `EnsureRoot` for the
        /// MVP, the same reused-origin choice every dispute/suspension path
        /// in this codebase already makes (ADR-036 §6).
        type SlashAppealOrigin: EnsureOrigin<Self::RuntimeOrigin>;
        /// A closed round scoring below this basis-points threshold is a
        /// candidate breach round (ADR-036 §3: `AvailabilityBreachThresholdBps`).
        #[pallet::constant]
        type AvailabilityBreachThresholdBps: Get<u16>;
        /// Minimum confidence -- `submissions * 10_000 / committee_target`
        /// -- a closed round must clear to be slash-eligible, strictly
        /// higher than the bare quorum needed merely to close a round
        /// (ADR-036 §3: `SlashConfidenceThresholdBps`).
        #[pallet::constant]
        type SlashConfidenceThresholdBps: Get<u16>;
        /// Strictly consecutive breach rounds required before
        /// [`Pallet::record_breach`] will open a [`PendingSlash`]
        /// (ADR-036 §3: `BreachRounds`).
        #[pallet::constant]
        type BreachRounds: Get<u32>;
        /// Flat amount slashed per executed breach streak (ADR-036 §3:
        /// `ProviderSlashAmount`), not a percentage of current stake --
        /// capped at whatever is actually reserved regardless of this
        /// value (see [`ProviderStakeSlasher`]).
        #[pallet::constant]
        type ProviderSlashAmount: Get<Self::Balance>;
        /// Blocks a provider has to call [`Pallet::appeal_slash`] after
        /// [`Pallet::record_breach`] before [`Pallet::execute_slash`] may
        /// proceed unopposed (ADR-036 §3: `SlashAppealWindow`).
        #[pallet::constant]
        type SlashAppealWindow: Get<BlockNumberFor<Self>>;
        type WeightInfo: WeightInfo;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[derive(
        Clone,
        Copy,
        Encode,
        Decode,
        DecodeWithMemTracking,
        Eq,
        MaxEncodedLen,
        PartialEq,
        Debug,
        TypeInfo,
    )]
    pub enum SlashState {
        Proposed,
        Appealed,
    }

    #[derive(
        Clone, Encode, Decode, DecodeWithMemTracking, Eq, MaxEncodedLen, PartialEq, Debug, TypeInfo,
    )]
    pub struct PendingSlash<BlockNumber> {
        pub first_round: u64,
        pub created_at: BlockNumber,
        pub state: SlashState,
    }

    /// A live, not-yet-executed slash proposal for (provider, dimension).
    /// At most one at a time per (provider, dimension) -- `record_breach`
    /// refuses to open a second while one is already pending.
    #[pallet::storage]
    #[pallet::getter(fn pending_slash)]
    pub type PendingSlashes<T: Config> = StorageNMap<
        _,
        (
            NMapKey<Blake2_128Concat, T::AccountId>,
            NMapKey<Twox64Concat, ScoreDimension>,
        ),
        PendingSlash<BlockNumberFor<T>>,
        OptionQuery,
    >;

    /// High-water mark: the highest round number already consumed by an
    /// *executed or appeal-resolved* breach streak for (provider,
    /// dimension), never decreased. `None` means no streak has ever
    /// completed. Every round in a candidate streak must exceed this,
    /// unconditionally -- the direct mechanism behind ADR-036's
    /// "double-slash for the same round" requirement.
    #[pallet::storage]
    #[pallet::getter(fn last_slashed_round)]
    pub type LastSlashedRound<T: Config> = StorageNMap<
        _,
        (
            NMapKey<Blake2_128Concat, T::AccountId>,
            NMapKey<Twox64Concat, ScoreDimension>,
        ),
        u64,
        OptionQuery,
    >;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        BreachRecorded {
            provider: T::AccountId,
            dimension: ScoreDimension,
            first_round: u64,
        },
        SlashAppealed {
            provider: T::AccountId,
            dimension: ScoreDimension,
        },
        SlashAppealResolved {
            provider: T::AccountId,
            dimension: ScoreDimension,
            upheld: bool,
        },
        /// `amount` is what was actually removed (never more than the
        /// provider's reserved bond, regardless of `ProviderSlashAmount`).
        /// `force_suspended` is true when this slash brought the
        /// provider's bond below `MinStake`.
        ProviderSlashed {
            provider: T::AccountId,
            dimension: ScoreDimension,
            first_round: u64,
            amount: T::Balance,
            force_suspended: bool,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        /// One of the `BreachRounds` consecutive rounds does not satisfy
        /// ADR-036 §2's eligibility conditions (not closed, still within
        /// its own dispute window, disputed/upheld, above the breach
        /// score threshold, or below the confidence threshold).
        RoundNotEligible,
        /// A candidate round has already been consumed by a previously
        /// executed or resolved breach streak.
        RoundAlreadySlashed,
        /// `record_breach` called while a pending slash already exists for
        /// this (provider, dimension).
        SlashAlreadyPending,
        /// No pending slash exists for this (provider, dimension).
        NoPendingSlash,
        /// Only the scored provider itself may appeal a slash against it.
        NotSlashSubject,
        /// The pending slash is not in the state this call requires
        /// (`appeal_slash`/`execute_slash` need `Proposed`;
        /// `resolve_slash_appeal` needs `Appealed`).
        UnexpectedSlashState,
        /// `SlashAppealWindow` after `record_breach` has already elapsed.
        AppealWindowClosed,
        /// `SlashAppealWindow` has not yet elapsed.
        AppealWindowNotElapsed,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Open a slash proposal for `BreachRounds` strictly consecutive
        /// rounds starting at `first_round`, if and only if every one
        /// independently satisfies ADR-036 §2. Permissionless
        /// (`ensure_signed`, any caller): a deterministic function of
        /// already-committed state, mirroring `close_round`'s own
        /// "needs no privileged origin" reasoning.
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::record_breach())]
        pub fn record_breach(
            origin: OriginFor<T>,
            provider: T::AccountId,
            dimension: ScoreDimension,
            first_round: u64,
        ) -> DispatchResult {
            let _ = ensure_signed(origin)?;
            ensure!(
                !PendingSlashes::<T>::contains_key((&provider, dimension)),
                Error::<T>::SlashAlreadyPending
            );

            let last_slashed = LastSlashedRound::<T>::get((&provider, dimension));
            let now = frame_system::Pallet::<T>::block_number();
            let dispute_window = T::AvailabilityRoundOracle::dispute_window();
            let breach_rounds = T::BreachRounds::get();
            ensure!(breach_rounds > 0, Error::<T>::RoundNotEligible);

            for offset in 0..breach_rounds {
                let round = first_round
                    .checked_add(u64::from(offset))
                    .ok_or(Error::<T>::RoundNotEligible)?;
                ensure!(
                    last_slashed.is_none_or(|last| round > last),
                    Error::<T>::RoundAlreadySlashed
                );
                let view = T::AvailabilityRoundOracle::round(&provider, round, dimension)
                    .ok_or(Error::<T>::RoundNotEligible)?;
                ensure!(
                    matches!(
                        view.status,
                        RoundViewStatus::Final | RoundViewStatus::DisputeRejected
                    ),
                    Error::<T>::RoundNotEligible
                );
                ensure!(
                    now >= view.closed_at.saturating_add(dispute_window),
                    Error::<T>::RoundNotEligible
                );
                ensure!(
                    view.score_bps < T::AvailabilityBreachThresholdBps::get(),
                    Error::<T>::RoundNotEligible
                );
                let confidence_bps = u64::from(view.submissions)
                    .saturating_mul(10_000)
                    .checked_div(u64::from(view.committee_target))
                    .unwrap_or(0);
                ensure!(
                    confidence_bps >= u64::from(T::SlashConfidenceThresholdBps::get()),
                    Error::<T>::RoundNotEligible
                );
            }

            PendingSlashes::<T>::insert(
                (&provider, dimension),
                PendingSlash {
                    first_round,
                    created_at: now,
                    state: SlashState::Proposed,
                },
            );
            Self::deposit_event(Event::BreachRecorded {
                provider,
                dimension,
                first_round,
            });
            Ok(())
        }

        /// Only the scored provider itself may appeal, only while the
        /// pending slash is still `Proposed`, only within
        /// `SlashAppealWindow` of `record_breach` (ADR-036 §6).
        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::appeal_slash())]
        pub fn appeal_slash(
            origin: OriginFor<T>,
            provider: T::AccountId,
            dimension: ScoreDimension,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(who == provider, Error::<T>::NotSlashSubject);
            PendingSlashes::<T>::try_mutate((&provider, dimension), |maybe| -> DispatchResult {
                let pending = maybe.as_mut().ok_or(Error::<T>::NoPendingSlash)?;
                ensure!(
                    matches!(pending.state, SlashState::Proposed),
                    Error::<T>::UnexpectedSlashState
                );
                let now = frame_system::Pallet::<T>::block_number();
                let deadline = pending
                    .created_at
                    .saturating_add(T::SlashAppealWindow::get());
                ensure!(now <= deadline, Error::<T>::AppealWindowClosed);
                pending.state = SlashState::Appealed;
                Ok(())
            })?;
            Self::deposit_event(Event::SlashAppealed {
                provider,
                dimension,
            });
            Ok(())
        }

        /// `SlashAppealOrigin`-gated (`EnsureRoot` for the MVP).
        /// `uphold = true` removes the pending slash with no funds ever
        /// moved -- nothing to reverse, because none were ever taken.
        /// `uphold = false` proceeds straight to execution. Either way,
        /// `LastSlashedRound` advances past the streak so it cannot be
        /// re-litigated by a fresh `record_breach`.
        #[pallet::call_index(2)]
        #[pallet::weight(T::WeightInfo::resolve_slash_appeal())]
        pub fn resolve_slash_appeal(
            origin: OriginFor<T>,
            provider: T::AccountId,
            dimension: ScoreDimension,
            uphold: bool,
        ) -> DispatchResult {
            T::SlashAppealOrigin::ensure_origin(origin)?;
            let pending = PendingSlashes::<T>::get((&provider, dimension))
                .ok_or(Error::<T>::NoPendingSlash)?;
            ensure!(
                matches!(pending.state, SlashState::Appealed),
                Error::<T>::UnexpectedSlashState
            );

            Self::advance_watermark(&provider, dimension, pending.first_round);
            if !uphold {
                Self::do_execute_slash(&provider, dimension, pending.first_round);
            }
            PendingSlashes::<T>::remove((&provider, dimension));
            Self::deposit_event(Event::SlashAppealResolved {
                provider,
                dimension,
                upheld: uphold,
            });
            Ok(())
        }

        /// Permissionless, same reasoning as `record_breach`. Requires the
        /// pending slash to still be `Proposed` (never `Appealed` -- an
        /// open appeal blocks execution outright) and
        /// `SlashAppealWindow` to have elapsed unopposed.
        #[pallet::call_index(3)]
        #[pallet::weight(T::WeightInfo::execute_slash())]
        pub fn execute_slash(
            origin: OriginFor<T>,
            provider: T::AccountId,
            dimension: ScoreDimension,
        ) -> DispatchResult {
            let _ = ensure_signed(origin)?;
            let pending = PendingSlashes::<T>::get((&provider, dimension))
                .ok_or(Error::<T>::NoPendingSlash)?;
            ensure!(
                matches!(pending.state, SlashState::Proposed),
                Error::<T>::UnexpectedSlashState
            );
            let now = frame_system::Pallet::<T>::block_number();
            let deadline = pending
                .created_at
                .saturating_add(T::SlashAppealWindow::get());
            ensure!(now >= deadline, Error::<T>::AppealWindowNotElapsed);

            Self::advance_watermark(&provider, dimension, pending.first_round);
            Self::do_execute_slash(&provider, dimension, pending.first_round);
            PendingSlashes::<T>::remove((&provider, dimension));
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        fn advance_watermark(provider: &T::AccountId, dimension: ScoreDimension, first_round: u64) {
            let breach_rounds = T::BreachRounds::get();
            let last_round = first_round.saturating_add(u64::from(breach_rounds.saturating_sub(1)));
            LastSlashedRound::<T>::mutate((provider, dimension), |maybe| {
                *maybe = Some(match maybe {
                    Some(current) => (*current).max(last_round),
                    None => last_round,
                });
            });
        }

        fn do_execute_slash(provider: &T::AccountId, dimension: ScoreDimension, first_round: u64) {
            let (amount, force_suspended) =
                T::ProviderStakeSlasher::slash(provider, T::ProviderSlashAmount::get());
            Self::deposit_event(Event::ProviderSlashed {
                provider: provider.clone(),
                dimension,
                first_round,
                amount,
                force_suspended,
            });
        }
    }
}

#[cfg(test)]
mod tests;
