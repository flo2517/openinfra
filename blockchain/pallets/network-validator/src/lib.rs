#![cfg_attr(not(feature = "std"), no_std)]

//! Network Validator identity, stake, and lifecycle registry (ADR-011).
//!
//! This pallet only answers "is this account a bonded, active Network
//! Validator". It deliberately does not decide *who gets assigned to
//! challenge which provider* (self-assignment exclusion, committee
//! selection) or how evidence is aggregated into reputation -- those are
//! separate, still-to-be-implemented pieces per ADR-011 that consume
//! [`NetworkValidatorInspector`].

use frame_support::{
    pallet_prelude::*,
    traits::{Currency, EnsureOrigin, Get, ReservableCurrency},
    weights::Weight,
};
use frame_system::pallet_prelude::*;
pub use pallet::*;

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
        #[pallet::constant]
        type MinStake: Get<BalanceOf<Self>>;
        #[pallet::constant]
        type UnbondingPeriod: Get<BlockNumberFor<Self>>;
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
            Self::deposit_event(Event::ValidatorReinstated { validator });
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
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
