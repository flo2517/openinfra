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
    fn update_vector() -> Weight;
    fn record_availability() -> Weight;
}
impl WeightInfo for () {
    fn submit_score() -> Weight {
        Weight::zero()
    }
    fn update_vector() -> Weight {
        Weight::zero()
    }
    fn record_availability() -> Weight {
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
    pub struct ReputationVector {
        pub compute: u32,
        pub storage: u32,
        pub network: u32,
        pub availability: u32,
        pub reliability: u32,
        pub global: u32,
    }

    #[pallet::storage]
    pub type ReputationScores<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, u32, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn vector)]
    pub type ReputationVectors<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, ReputationVector, OptionQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        ReputationUpdated {
            provider: T::AccountId,
            old_score: u32,
            new_score: u32,
        },
        VectorUpdated {
            provider: T::AccountId,
            vector: ReputationVector,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        ProviderNotRegistered,
        InvalidConfiguration,
        DeltaOutOfBounds,
        VectorValueOutOfBounds,
        AvailabilityOutOfBounds,
        InvalidAvailabilitySamples,
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
            let mut vector =
                ReputationVectors::<T>::get(&provider).unwrap_or_else(|| Self::default_vector());
            vector.availability = new_score;
            vector.global = Self::global(&vector);
            ReputationVectors::<T>::insert(&provider, vector);
            Self::deposit_event(Event::ReputationUpdated {
                provider,
                old_score,
                new_score,
            });
            Ok(())
        }

        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::update_vector())]
        pub fn update_vector(
            origin: OriginFor<T>,
            provider: T::AccountId,
            compute: u32,
            storage: u32,
            network: u32,
            availability: u32,
            reliability: u32,
        ) -> DispatchResult {
            T::UpdateOrigin::ensure_origin(origin)?;
            ensure!(
                T::ProviderInspector::is_registered(&provider),
                Error::<T>::ProviderNotRegistered
            );
            for value in [compute, storage, network, availability, reliability] {
                ensure!(
                    value <= T::MaxScore::get(),
                    Error::<T>::VectorValueOutOfBounds
                );
            }
            let vector = ReputationVector {
                compute,
                storage,
                network,
                availability,
                reliability,
                global: Self::global_values(compute, storage, network, availability, reliability),
            };
            ReputationVectors::<T>::insert(&provider, vector);
            ReputationScores::<T>::insert(&provider, availability);
            Self::deposit_event(Event::VectorUpdated { provider, vector });
            Ok(())
        }

        /// Convert a validator's integer availability observation into the
        /// availability component.  Basis points avoid floats in consensus.
        #[pallet::call_index(2)]
        #[pallet::weight(T::WeightInfo::record_availability())]
        pub fn record_availability(
            origin: OriginFor<T>,
            provider: T::AccountId,
            availability_bps: u32,
            sample_count: u32,
        ) -> DispatchResult {
            T::UpdateOrigin::ensure_origin(origin)?;
            ensure!(
                T::ProviderInspector::is_registered(&provider),
                Error::<T>::ProviderNotRegistered
            );
            ensure!(
                availability_bps <= 10_000,
                Error::<T>::AvailabilityOutOfBounds
            );
            ensure!(sample_count > 0, Error::<T>::InvalidAvailabilitySamples);
            let score = availability_bps
                .checked_mul(T::MaxScore::get())
                .ok_or(Error::<T>::VectorValueOutOfBounds)?
                / 10_000;
            let mut vector =
                ReputationVectors::<T>::get(&provider).unwrap_or_else(|| Self::default_vector());
            vector.availability = score;
            vector.global = Self::global(&vector);
            ReputationVectors::<T>::insert(&provider, vector);
            ReputationScores::<T>::insert(&provider, score);
            Self::deposit_event(Event::VectorUpdated { provider, vector });
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        fn default_vector() -> ReputationVector {
            let score = T::DefaultScore::get();
            ReputationVector {
                compute: score,
                storage: score,
                network: score,
                availability: score,
                reliability: score,
                global: score,
            }
        }
        fn global(vector: &ReputationVector) -> u32 {
            Self::global_values(
                vector.compute,
                vector.storage,
                vector.network,
                vector.availability,
                vector.reliability,
            )
        }
        fn global_values(
            compute: u32,
            storage: u32,
            network: u32,
            availability: u32,
            reliability: u32,
        ) -> u32 {
            compute
                .saturating_add(storage)
                .saturating_add(network)
                .saturating_add(availability)
                .saturating_add(reliability)
                / 5
        }
    }
}

#[cfg(test)]
mod tests;
