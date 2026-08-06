#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

use frame_support::weights::Weight;

pub trait WeightInfo {
    fn calculate_reward() -> Weight;
    fn claim_reward() -> Weight;
}

impl WeightInfo for () {
    fn calculate_reward() -> Weight {
        Weight::zero()
    }
    fn claim_reward() -> Weight {
        Weight::zero()
    }
}

#[frame_support::pallet]
pub mod pallet {
    use super::WeightInfo;
    use frame_support::{
        ensure,
        pallet_prelude::*,
        traits::{EnsureOrigin, Get},
    };
    use frame_system::pallet_prelude::*;

    pub type LeaseId = u64;
    pub type RewardPoints = u64;

    #[pallet::config]
    pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
        type RewardOrigin: EnsureOrigin<Self::RuntimeOrigin>;
        #[pallet::constant]
        type MaxResourceUnits: Get<u64>;
        #[pallet::constant]
        type MaxDuration: Get<u64>;
        #[pallet::constant]
        type MaxReputation: Get<u32>;
        type WeightInfo: WeightInfo;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::storage]
    #[pallet::getter(fn reward_balance)]
    pub type RewardBalances<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, RewardPoints, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn processed_reward)]
    pub type ProcessedLeases<T: Config> =
        StorageMap<_, Blake2_128Concat, LeaseId, RewardPoints, OptionQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        RewardCalculated {
            lease_id: LeaseId,
            provider: T::AccountId,
            points: RewardPoints,
        },
        RewardClaimed {
            provider: T::AccountId,
            points: RewardPoints,
        },
        /// Points credited to a Network Validator whose submission
        /// survived a round's outlier trimming (ADR-011 §5).
        ValidatorRewardAccrued {
            validator: T::AccountId,
            points: RewardPoints,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        LeaseAlreadyRewarded,
        InvalidResourceUnits,
        InvalidDuration,
        ReputationOutOfBounds,
        AvailabilityOutOfBounds,
        ArithmeticOverflow,
        ZeroReward,
        InsufficientPoints,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::calculate_reward())]
        pub fn calculate_reward(
            origin: OriginFor<T>,
            lease_id: LeaseId,
            provider: T::AccountId,
            resource_units: u64,
            duration: u64,
            reputation: u32,
            availability_percent: u32,
        ) -> DispatchResult {
            T::RewardOrigin::ensure_origin(origin)?;
            ensure!(
                !ProcessedLeases::<T>::contains_key(lease_id),
                Error::<T>::LeaseAlreadyRewarded
            );
            ensure!(
                resource_units > 0 && resource_units <= T::MaxResourceUnits::get(),
                Error::<T>::InvalidResourceUnits
            );
            ensure!(
                duration > 0 && duration <= T::MaxDuration::get(),
                Error::<T>::InvalidDuration
            );
            ensure!(
                reputation <= T::MaxReputation::get(),
                Error::<T>::ReputationOutOfBounds
            );
            ensure!(
                availability_percent <= 100,
                Error::<T>::AvailabilityOutOfBounds
            );

            let base = resource_units
                .checked_mul(duration)
                .ok_or(Error::<T>::ArithmeticOverflow)?;
            let reputation_multiplier = 1_000_u64
                .checked_add(reputation.into())
                .ok_or(Error::<T>::ArithmeticOverflow)?;
            let scaled = base
                .checked_mul(reputation_multiplier)
                .and_then(|value| value.checked_mul(availability_percent.into()))
                .ok_or(Error::<T>::ArithmeticOverflow)?;
            let points = scaled / 100_000;
            ensure!(points > 0, Error::<T>::ZeroReward);

            let balance = RewardBalances::<T>::get(&provider);
            let new_balance = balance
                .checked_add(points)
                .ok_or(Error::<T>::ArithmeticOverflow)?;
            RewardBalances::<T>::insert(&provider, new_balance);
            ProcessedLeases::<T>::insert(lease_id, points);
            Self::deposit_event(Event::RewardCalculated {
                lease_id,
                provider,
                points,
            });
            Ok(())
        }

        /// Claim the caller's accrued Reward Points. Providers and Network
        /// Validators share this path -- both accrue into
        /// [`RewardBalances`] keyed by their own account.
        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::claim_reward())]
        pub fn claim_reward(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let points = RewardBalances::<T>::get(&who);
            ensure!(points > 0, Error::<T>::InsufficientPoints);
            RewardBalances::<T>::remove(&who);
            Self::deposit_event(Event::RewardClaimed {
                provider: who,
                points,
            });
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        /// Credit Reward Points without an extrinsic.
        ///
        /// Used by the validator scoring pallet to reward submissions that
        /// survived a round's outlier trimming, so this pallet stays the
        /// only writer of [`RewardBalances`] and keeps its own overflow
        /// checking regardless of the caller (ADR-011 §5).
        ///
        /// Crediting is one-way: an upheld dispute does **not** currently
        /// claw back points already accrued for that round. Clawback is
        /// tied to slashing economics, which ADR-011 leaves out of scope.
        pub fn accrue_points(account: &T::AccountId, points: RewardPoints) -> DispatchResult {
            if points == 0 {
                return Ok(());
            }
            let balance = RewardBalances::<T>::get(account);
            let new_balance = balance
                .checked_add(points)
                .ok_or(Error::<T>::ArithmeticOverflow)?;
            RewardBalances::<T>::insert(account, new_balance);
            Self::deposit_event(Event::ValidatorRewardAccrued {
                validator: account.clone(),
                points,
            });
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests;
