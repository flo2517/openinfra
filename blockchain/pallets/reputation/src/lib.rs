#![cfg_attr(not(feature = "std"), no_std)]

use frame_support::{pallet_prelude::*, traits::Get, weights::Weight};
use frame_system::pallet_prelude::*;
pub use pallet::*;

pub trait ProviderInspector<AccountId> {
    fn is_registered(provider: &AccountId) -> bool;
}
impl<AccountId> ProviderInspector<AccountId> for () {
    fn is_registered(_: &AccountId) -> bool {
        true
    }
}

pub trait WeightInfo {
    fn submit_score() -> Weight;
}
impl WeightInfo for () {
    fn submit_score() -> Weight {
        Weight::zero()
    }
}

#[frame_support::pallet]
pub mod pallet {
    use super::*;

    #[pallet::config]
    pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
        type UpdateOrigin: EnsureOrigin<Self::RuntimeOrigin>;
        type ProviderInspector: ProviderInspector<Self::AccountId>;
        #[pallet::constant]
        type DefaultScore: Get<u32>;
        #[pallet::constant]
        type MaxScore: Get<u32>;
        #[pallet::constant]
        type MaxDelta: Get<u32>;
        type WeightInfo: WeightInfo;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::storage]
    pub type ReputationScores<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, u32, OptionQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        ReputationUpdated {
            provider: T::AccountId,
            old_score: u32,
            new_score: u32,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        ProviderNotRegistered,
        InvalidConfiguration,
        DeltaOutOfBounds,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::submit_score())]
        pub fn submit_score(
            origin: OriginFor<T>,
            provider: T::AccountId,
            delta: i32,
        ) -> DispatchResult {
            T::UpdateOrigin::ensure_origin(origin)?;
            ensure!(
                T::ProviderInspector::is_registered(&provider),
                Error::<T>::ProviderNotRegistered
            );
            ensure!(
                T::DefaultScore::get() <= T::MaxScore::get(),
                Error::<T>::InvalidConfiguration
            );
            let magnitude = delta.unsigned_abs();
            ensure!(
                magnitude <= T::MaxDelta::get(),
                Error::<T>::DeltaOutOfBounds
            );
            let old_score =
                ReputationScores::<T>::get(&provider).unwrap_or_else(T::DefaultScore::get);
            let new_score = if delta >= 0 {
                old_score.saturating_add(magnitude).min(T::MaxScore::get())
            } else {
                old_score.saturating_sub(magnitude)
            };
            ReputationScores::<T>::insert(&provider, new_score);
            Self::deposit_event(Event::ReputationUpdated {
                provider,
                old_score,
                new_score,
            });
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests;
