#![cfg_attr(not(feature = "std"), no_std)]

//! Network Validator identity, stake, lifecycle, and worker scoring
//! (ADR-011).
//!
//! Two responsibilities, deliberately in one pallet because ADR-011 §5
//! places round aggregation here:
//!
//! 1. **Registry**: who is a bonded, active Network Validator
//!    ([`NetworkValidatorInspector`], consumed by `pallet-availability`
//!    and `pallet-reputation` to gate their submission origins).
//! 2. **Scoring**: validators submit per-dimension integer evidence for a
//!    provider/round; once a quorum is reached the round is closed with a
//!    trimmed-mean aggregate that is pushed into `pallet-reputation`
//!    through [`ReputationUpdater`].
//!
//! Committee *assignment* (deterministically selecting which validators
//! are expected to challenge which provider in a round) is still open --
//! today any active validator may submit, bounded by
//! `MaxSubmissionsPerRound` and the self-scoring exclusion below.

extern crate alloc;

use frame_support::{
    pallet_prelude::*,
    traits::{Currency, EnsureOrigin, Get, ReservableCurrency},
    weights::Weight,
    Hashable,
};
use frame_system::pallet_prelude::*;
pub use pallet::*;

/// A component of a provider's reputation vector that validators score
/// independently. Mapped by the runtime onto `pallet-reputation`'s own
/// dimension enum, so neither pallet depends on the other's types.
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

/// Applies an aggregated round result to a provider's reputation.
/// `pallet-reputation` stays the only writer of the reputation vector and
/// keeps enforcing its own bounds (ADR-011 §5).
pub trait ReputationUpdater<AccountId> {
    fn record_dimension_score(
        provider: &AccountId,
        dimension: ScoreDimension,
        score_bps: u16,
    ) -> DispatchResult;
}

impl<AccountId> ReputationUpdater<AccountId> for () {
    fn record_dimension_score(_: &AccountId, _: ScoreDimension, _: u16) -> DispatchResult {
        Ok(())
    }
}

/// Narrow interface for pallets that only need to know whether an account is
/// currently an active, bonded Network Validator (e.g. an origin check on
/// availability/reputation submission calls).
pub trait NetworkValidatorInspector<AccountId> {
    fn is_active(validator: &AccountId) -> bool;
}

impl<AccountId> NetworkValidatorInspector<AccountId> for () {
    fn is_active(_: &AccountId) -> bool {
        false
    }
}

pub trait WeightInfo {
    fn register_validator() -> Weight;
    fn request_exit() -> Weight;
    fn withdraw_unbonded() -> Weight;
    fn suspend() -> Weight;
    fn reinstate() -> Weight;
    fn submit_evidence() -> Weight;
    fn close_round() -> Weight;
}

impl WeightInfo for () {
    fn register_validator() -> Weight {
        Weight::from_parts(10_000, 0)
    }
    fn request_exit() -> Weight {
        Weight::from_parts(10_000, 0)
    }
    fn withdraw_unbonded() -> Weight {
        Weight::from_parts(10_000, 0)
    }
    fn suspend() -> Weight {
        Weight::from_parts(10_000, 0)
    }
    fn reinstate() -> Weight {
        Weight::from_parts(10_000, 0)
    }
    fn submit_evidence() -> Weight {
        Weight::from_parts(10_000, 0)
    }
    fn close_round() -> Weight {
        Weight::from_parts(10_000, 0)
    }
}

#[frame_support::pallet]
pub mod pallet {
    use super::*;

    #[pallet::config]
    pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
        /// Bonds a validator's stake. Reused from the runtime's existing
        /// `pallet_balances` -- a real reservation, not a self-reported
        /// number, so stake is an actual Sybil deterrent (see ADR-011 §1).
        type Currency: ReservableCurrency<Self::AccountId>;
        /// Governs forced suspend/reinstate (e.g. dispute resolution).
        /// `EnsureRoot` for the MVP; a validator committee/governance origin
        /// is future work (ADR-011 §5).
        type SuspensionOrigin: EnsureOrigin<Self::RuntimeOrigin>;
        /// Receives closed-round aggregates; the runtime wires this to
        /// `pallet-reputation`.
        type ReputationUpdater: ReputationUpdater<Self::AccountId>;
        #[pallet::constant]
        type MinStake: Get<BalanceOf<Self>>;
        #[pallet::constant]
        type UnbondingPeriod: Get<BlockNumberFor<Self>>;
        /// Hard bound on stored submissions per (provider, round,
        /// dimension) -- keeps the aggregation loop and storage item
        /// bounded, as consensus state must be.
        #[pallet::constant]
        type MaxSubmissionsPerRound: Get<u32>;
        /// Minimum independent submissions before a round may close. Below
        /// this, the round is explicitly degraded rather than silently
        /// accepted (ADR-011 §5).
        #[pallet::constant]
        type MinQuorum: Get<u32>;
        /// Committee size a fully-attested round is expected to reach.
        /// Doubles as the confidence denominator: a round closed with
        /// fewer submissions than this is visibly under-attested.
        #[pallet::constant]
        type TargetCommitteeSize: Get<u32>;
        /// Hard bound on the enumerable active-validator set. Committee
        /// selection iterates it, so it must stay bounded.
        #[pallet::constant]
        type MaxValidators: Get<u32>;
        type WeightInfo: WeightInfo;
    }

    pub type BalanceOf<T> =
        <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[derive(
        Clone, Encode, Decode, DecodeWithMemTracking, Eq, MaxEncodedLen, PartialEq, Debug, TypeInfo,
    )]
    pub enum ValidatorStatus<BlockNumber> {
        Active,
        Suspended,
        Exiting { available_at: BlockNumber },
    }

    #[derive(
        Clone, Encode, Decode, DecodeWithMemTracking, Eq, MaxEncodedLen, PartialEq, Debug, TypeInfo,
    )]
    pub struct ValidatorRecord<Balance, BlockNumber> {
        pub status: ValidatorStatus<BlockNumber>,
        pub stake: Balance,
        pub registered_at: BlockNumber,
    }

    #[pallet::storage]
    pub type Validators<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        ValidatorRecord<BalanceOf<T>, BlockNumberFor<T>>,
        OptionQuery,
    >;

    /// Enumerable set of currently-`Active` validators, kept in step with
    /// [`Validators`] on every status transition. `Validators` is a
    /// StorageMap and cannot be iterated within a bounded weight, so
    /// committee selection reads this instead.
    #[pallet::storage]
    pub type ActiveValidatorSet<T: Config> =
        StorageValue<_, BoundedVec<T::AccountId, T::MaxValidators>, ValueQuery>;

    /// One validator's attributable, signed-by-extrinsic observation.
    /// `payload_hash` addresses the full evidence off-chain; only this
    /// bounded integer summary is ever kept in consensus state.
    #[derive(
        Clone, Encode, Decode, DecodeWithMemTracking, Eq, MaxEncodedLen, PartialEq, Debug, TypeInfo,
    )]
    pub struct Submission<AccountId> {
        pub validator: AccountId,
        /// 0..=10_000, never a float.
        pub score_bps: u16,
        pub sample_count: u32,
        pub payload_hash: [u8; 32],
    }

    /// The aggregate committed when a round closes.
    #[derive(
        Clone, Encode, Decode, DecodeWithMemTracking, Eq, MaxEncodedLen, PartialEq, Debug, TypeInfo,
    )]
    pub struct RoundResult<BlockNumber> {
        /// Trimmed-mean score in basis points.
        pub score_bps: u16,
        /// How many independent validators contributed.
        pub submissions: u32,
        /// `TargetCommitteeSize` at closing time, so a reader can compute
        /// confidence without assuming today's configuration.
        pub committee_target: u32,
        pub closed_at: BlockNumber,
    }

    /// Open submissions, keyed by (provider, round, dimension).
    #[pallet::storage]
    pub type Evidence<T: Config> = StorageNMap<
        _,
        (
            NMapKey<Blake2_128Concat, T::AccountId>,
            NMapKey<Twox64Concat, u64>,
            NMapKey<Twox64Concat, ScoreDimension>,
        ),
        BoundedVec<Submission<T::AccountId>, T::MaxSubmissionsPerRound>,
        ValueQuery,
    >;

    /// Closed rounds, keyed identically. A present entry means the round
    /// is final: further submissions are rejected and it cannot re-close.
    #[pallet::storage]
    pub type Rounds<T: Config> = StorageNMap<
        _,
        (
            NMapKey<Blake2_128Concat, T::AccountId>,
            NMapKey<Twox64Concat, u64>,
            NMapKey<Twox64Concat, ScoreDimension>,
        ),
        RoundResult<BlockNumberFor<T>>,
        OptionQuery,
    >;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        ValidatorRegistered {
            validator: T::AccountId,
            stake: BalanceOf<T>,
        },
        ValidatorExitRequested {
            validator: T::AccountId,
            available_at: BlockNumberFor<T>,
        },
        ValidatorExited {
            validator: T::AccountId,
            stake: BalanceOf<T>,
        },
        ValidatorSuspended {
            validator: T::AccountId,
        },
        ValidatorReinstated {
            validator: T::AccountId,
        },
        EvidenceSubmitted {
            provider: T::AccountId,
            validator: T::AccountId,
            round: u64,
            dimension: ScoreDimension,
            score_bps: u16,
        },
        RoundClosed {
            provider: T::AccountId,
            round: u64,
            dimension: ScoreDimension,
            score_bps: u16,
            submissions: u32,
            committee_target: u32,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        AlreadyRegistered,
        NotRegistered,
        InsufficientStake,
        InsufficientFreeBalance,
        AlreadyExiting,
        NotExiting,
        UnbondingNotComplete,
        UnbondingPeriodOverflow,
        NotActive,
        NotSuspended,
        /// The submitting account is not an active Network Validator.
        NotAnActiveValidator,
        /// A validator may never score itself (ADR-011 §4).
        SelfScoringForbidden,
        /// This validator already submitted for this provider/round/dimension.
        DuplicateSubmission,
        /// `MaxSubmissionsPerRound` reached for this round.
        TooManySubmissions,
        /// Scores are basis points and must be 0..=10_000.
        ScoreOutOfBounds,
        /// A submission must be backed by at least one sample.
        InvalidSampleCount,
        /// The round is already closed; it can neither accept new evidence
        /// nor be closed twice.
        RoundAlreadyClosed,
        /// Fewer than `MinQuorum` independent submissions -- closing would
        /// report a score the network cannot stand behind.
        QuorumNotReached,
        /// This validator is not in the committee selected for this
        /// provider/round -- slots are assigned, not self-selected.
        NotAssignedToRound,
        /// `MaxValidators` reached; the active set cannot grow.
        TooManyValidators,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Register the caller as a Network Validator, reserving `stake`
        /// from its free balance. Fails below `MinStake` or if already
        /// registered -- re-registration after exit requires
        /// `withdraw_unbonded` to have cleared the previous record first.
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::register_validator())]
        pub fn register_validator(origin: OriginFor<T>, stake: BalanceOf<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(
                !Validators::<T>::contains_key(&who),
                Error::<T>::AlreadyRegistered
            );
            ensure!(stake >= T::MinStake::get(), Error::<T>::InsufficientStake);
            Self::join_active_set(&who)?;
            T::Currency::reserve(&who, stake).map_err(|_| Error::<T>::InsufficientFreeBalance)?;
            let now = frame_system::Pallet::<T>::block_number();
            Validators::<T>::insert(
                &who,
                ValidatorRecord {
                    status: ValidatorStatus::Active,
                    stake,
                    registered_at: now,
                },
            );
            Self::deposit_event(Event::ValidatorRegistered {
                validator: who,
                stake,
            });
            Ok(())
        }

        /// Begin unbonding. The stake stays reserved (and the validator
        /// stays ineligible for new committee assignments -- enforced by
        /// callers checking `is_active`, which is false while `Exiting`)
        /// until `UnbondingPeriod` has elapsed.
        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::request_exit())]
        pub fn request_exit(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let available_at = Validators::<T>::try_mutate(
                &who,
                |maybe_record| -> Result<BlockNumberFor<T>, DispatchError> {
                    let record = maybe_record.as_mut().ok_or(Error::<T>::NotRegistered)?;
                    ensure!(
                        !matches!(record.status, ValidatorStatus::Exiting { .. }),
                        Error::<T>::AlreadyExiting
                    );
                    let now = frame_system::Pallet::<T>::block_number();
                    let available_at = now
                        .checked_add(&T::UnbondingPeriod::get())
                        .ok_or(Error::<T>::UnbondingPeriodOverflow)?;
                    record.status = ValidatorStatus::Exiting { available_at };
                    Ok(available_at)
                },
            )?;
            // An exiting validator takes no new committee assignments.
            Self::leave_active_set(&who);
            Self::deposit_event(Event::ValidatorExitRequested {
                validator: who,
                available_at,
            });
            Ok(())
        }

        /// Release the reserved stake once unbonding has completed and
        /// remove the validator record.
        #[pallet::call_index(2)]
        #[pallet::weight(T::WeightInfo::withdraw_unbonded())]
        pub fn withdraw_unbonded(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let record = Validators::<T>::get(&who).ok_or(Error::<T>::NotRegistered)?;
            match record.status {
                ValidatorStatus::Exiting { available_at } => {
                    let now = frame_system::Pallet::<T>::block_number();
                    ensure!(now >= available_at, Error::<T>::UnbondingNotComplete);
                }
                _ => return Err(Error::<T>::NotExiting.into()),
            }
            T::Currency::unreserve(&who, record.stake);
            Validators::<T>::remove(&who);
            // Defensive: request_exit already removed it, but keep the two
            // stores consistent even if that ever changes.
            Self::leave_active_set(&who);
            Self::deposit_event(Event::ValidatorExited {
                validator: who,
                stake: record.stake,
            });
            Ok(())
        }

        /// Force-suspend a validator (dispute resolution / detected
        /// misbehavior). `SuspensionOrigin`-gated; not self-service.
        #[pallet::call_index(3)]
        #[pallet::weight(T::WeightInfo::suspend())]
        pub fn suspend(origin: OriginFor<T>, validator: T::AccountId) -> DispatchResult {
            T::SuspensionOrigin::ensure_origin(origin)?;
            Validators::<T>::try_mutate(&validator, |maybe_record| -> DispatchResult {
                let record = maybe_record.as_mut().ok_or(Error::<T>::NotRegistered)?;
                ensure!(
                    matches!(record.status, ValidatorStatus::Active),
                    Error::<T>::NotActive
                );
                record.status = ValidatorStatus::Suspended;
                Ok(())
            })?;
            Self::leave_active_set(&validator);
            Self::deposit_event(Event::ValidatorSuspended { validator });
            Ok(())
        }

        /// Reinstate a previously suspended validator.
        /// `SuspensionOrigin`-gated.
        #[pallet::call_index(4)]
        #[pallet::weight(T::WeightInfo::reinstate())]
        pub fn reinstate(origin: OriginFor<T>, validator: T::AccountId) -> DispatchResult {
            T::SuspensionOrigin::ensure_origin(origin)?;
            Validators::<T>::try_mutate(&validator, |maybe_record| -> DispatchResult {
                let record = maybe_record.as_mut().ok_or(Error::<T>::NotRegistered)?;
                ensure!(
                    matches!(record.status, ValidatorStatus::Suspended),
                    Error::<T>::NotSuspended
                );
                record.status = ValidatorStatus::Active;
                Ok(())
            })?;
            Self::join_active_set(&validator)?;
            Self::deposit_event(Event::ValidatorReinstated { validator });
            Ok(())
        }

        /// Submit one validator's integer observation for a provider in a
        /// round. Attributable (the extrinsic signer is recorded), bounded,
        /// replay-resistant, and never self-scoring.
        #[pallet::call_index(5)]
        #[pallet::weight(T::WeightInfo::submit_evidence())]
        pub fn submit_evidence(
            origin: OriginFor<T>,
            provider: T::AccountId,
            round: u64,
            dimension: ScoreDimension,
            score_bps: u16,
            sample_count: u32,
            payload_hash: [u8; 32],
        ) -> DispatchResult {
            let validator = ensure_signed(origin)?;
            ensure!(
                Self::is_active(&validator),
                Error::<T>::NotAnActiveValidator
            );
            // A validator scoring its own provider account is the cheapest
            // possible self-dealing; reject it outright. Checked before
            // assignment so the error stays specific (committee selection
            // already excludes the provider, but this keeps the guarantee
            // explicit rather than emergent).
            ensure!(validator != provider, Error::<T>::SelfScoringForbidden);
            // Slots are assigned, not self-selected: a Sybil cluster cannot
            // fill a round by submitting first (ADR-011 §1).
            ensure!(
                Self::is_assigned(&provider, round, &validator),
                Error::<T>::NotAssignedToRound
            );
            ensure!(score_bps <= 10_000, Error::<T>::ScoreOutOfBounds);
            ensure!(sample_count > 0, Error::<T>::InvalidSampleCount);
            ensure!(
                Rounds::<T>::get((&provider, round, dimension)).is_none(),
                Error::<T>::RoundAlreadyClosed
            );

            Evidence::<T>::try_mutate(
                (&provider, round, dimension),
                |submissions| -> DispatchResult {
                    ensure!(
                        !submissions.iter().any(|entry| entry.validator == validator),
                        Error::<T>::DuplicateSubmission
                    );
                    submissions
                        .try_push(Submission {
                            validator: validator.clone(),
                            score_bps,
                            sample_count,
                            payload_hash,
                        })
                        .map_err(|_| Error::<T>::TooManySubmissions)?;
                    Ok(())
                },
            )?;

            Self::deposit_event(Event::EvidenceSubmitted {
                provider,
                validator,
                round,
                dimension,
                score_bps,
            });
            Ok(())
        }

        /// Close a round once `MinQuorum` independent submissions exist,
        /// aggregate them with a trimmed mean, and push the result into
        /// reputation. Callable by any active validator: closing is a
        /// deterministic function of already-committed state, so it needs
        /// no privileged origin -- only a bounded, quorum-gated trigger.
        #[pallet::call_index(6)]
        #[pallet::weight(T::WeightInfo::close_round())]
        pub fn close_round(
            origin: OriginFor<T>,
            provider: T::AccountId,
            round: u64,
            dimension: ScoreDimension,
        ) -> DispatchResult {
            let caller = ensure_signed(origin)?;
            ensure!(Self::is_active(&caller), Error::<T>::NotAnActiveValidator);
            ensure!(
                Rounds::<T>::get((&provider, round, dimension)).is_none(),
                Error::<T>::RoundAlreadyClosed
            );

            let submissions = Evidence::<T>::get((&provider, round, dimension));
            let count = submissions.len() as u32;
            ensure!(count >= T::MinQuorum::get(), Error::<T>::QuorumNotReached);

            let score_bps = Self::trimmed_mean(&submissions);
            let committee_target = T::TargetCommitteeSize::get();
            let closed_at = frame_system::Pallet::<T>::block_number();

            Rounds::<T>::insert(
                (&provider, round, dimension),
                RoundResult {
                    score_bps,
                    submissions: count,
                    committee_target,
                    closed_at,
                },
            );
            // Raw submissions are no longer needed once the aggregate is
            // committed; the off-chain evidence remains addressable by
            // each submission's payload_hash in the emitted events.
            Evidence::<T>::remove((&provider, round, dimension));

            T::ReputationUpdater::record_dimension_score(&provider, dimension, score_bps)?;

            Self::deposit_event(Event::RoundClosed {
                provider,
                round,
                dimension,
                score_bps,
                submissions: count,
                committee_target,
            });
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        fn join_active_set(who: &T::AccountId) -> DispatchResult {
            ActiveValidatorSet::<T>::try_mutate(|set| -> DispatchResult {
                if !set.contains(who) {
                    set.try_push(who.clone())
                        .map_err(|_| Error::<T>::TooManyValidators)?;
                }
                Ok(())
            })
        }

        fn leave_active_set(who: &T::AccountId) {
            ActiveValidatorSet::<T>::mutate(|set| {
                if let Some(index) = set.iter().position(|entry| entry == who) {
                    // Order-preserving: committee selection indexes into
                    // this set, so a swap_remove would silently reshuffle
                    // assignments for unrelated providers.
                    set.remove(index);
                }
            });
        }

        /// The committee expected to score `provider` in `round`:
        /// `TargetCommitteeSize` distinct active validators, drawn
        /// deterministically from [`ActiveValidatorSet`] and never
        /// including the provider itself.
        ///
        /// Selection is `blake2_256((provider, round, nth))` reduced modulo
        /// the remaining candidates, drawing without replacement. It is a
        /// pure function of committed state, so every node derives the same
        /// committee without extra storage.
        ///
        /// **Known limitation (ADR-011 §1):** the dev chain runs Aura, which
        /// offers no VRF, so this assignment is publicly computable ahead of
        /// time -- a validator can predict which providers it will score.
        /// Security therefore rests on quorum, outlier trimming, and bonded
        /// stake rather than on assignment secrecy. Moving to unpredictable
        /// per-round entropy is tracked as follow-up work.
        pub fn committee(provider: &T::AccountId, round: u64) -> alloc::vec::Vec<T::AccountId> {
            let mut candidates: alloc::vec::Vec<T::AccountId> = ActiveValidatorSet::<T>::get()
                .into_iter()
                .filter(|candidate| candidate != provider)
                .collect();
            let wanted = (T::TargetCommitteeSize::get() as usize).min(candidates.len());
            let mut committee = alloc::vec::Vec::with_capacity(wanted);
            for nth in 0..wanted {
                let seed = (provider.clone(), round, nth as u32).blake2_256();
                // Fold the first 8 bytes into an index over what's left;
                // drawing without replacement keeps members distinct.
                let mut raw = [0u8; 8];
                raw.copy_from_slice(&seed[..8]);
                let index = (u64::from_le_bytes(raw) % candidates.len() as u64) as usize;
                committee.push(candidates.remove(index));
            }
            committee
        }

        /// Whether `validator` holds a slot for `provider` in `round`.
        pub fn is_assigned(provider: &T::AccountId, round: u64, validator: &T::AccountId) -> bool {
            Self::committee(provider, round)
                .iter()
                .any(|member| member == validator)
        }

        /// Integer trimmed mean: with three or more submissions, drop one
        /// lowest and one highest value before averaging, so a single
        /// outlier (a colluding or malfunctioning validator) cannot move
        /// the result. Deterministic and float-free, over a set bounded by
        /// `MaxSubmissionsPerRound`.
        fn trimmed_mean(submissions: &[Submission<T::AccountId>]) -> u16 {
            if submissions.is_empty() {
                return 0;
            }
            let mut scores: alloc::vec::Vec<u32> =
                submissions.iter().map(|s| u32::from(s.score_bps)).collect();
            scores.sort_unstable();
            let considered: &[u32] = if scores.len() >= 3 {
                &scores[1..scores.len() - 1]
            } else {
                &scores[..]
            };
            let total: u32 = considered
                .iter()
                .fold(0u32, |acc, v| acc.saturating_add(*v));
            let mean = total / considered.len() as u32;
            mean.min(10_000) as u16
        }

        /// True only for a registered validator whose status is `Active`
        /// (not `Suspended`, not `Exiting`).
        pub fn is_active(validator: &T::AccountId) -> bool {
            matches!(
                Validators::<T>::get(validator),
                Some(ValidatorRecord {
                    status: ValidatorStatus::Active,
                    ..
                })
            )
        }
    }

    impl<T: Config> super::NetworkValidatorInspector<T::AccountId> for Pallet<T> {
        fn is_active(validator: &T::AccountId) -> bool {
            Pallet::<T>::is_active(validator)
        }
    }
}

#[cfg(test)]
mod tests;
