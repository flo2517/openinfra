#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

use frame_support::weights::Weight;

/// Narrow interface used by pallets that only need to inspect provider status.
pub trait ProviderInspector<AccountId> {
    fn is_registered(provider: &AccountId) -> bool;
    fn is_active(provider: &AccountId) -> bool;
}

pub trait WeightInfo {
    fn register_provider() -> Weight;
    fn register_provider_for() -> Weight;
    fn set_status() -> Weight;
}

impl WeightInfo for () {
    fn register_provider() -> Weight {
        Weight::from_parts(10_000, 0)
    }

    fn register_provider_for() -> Weight {
        Weight::from_parts(10_000, 0)
    }

    fn set_status() -> Weight {
        Weight::from_parts(10_000, 0)
    }
}

#[frame_support::pallet]
pub mod pallet {
    use super::{ProviderInspector, WeightInfo};
    use frame_support::{pallet_prelude::*, traits::EnsureOrigin};
    use frame_system::pallet_prelude::*;

    #[pallet::config]
    pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
        type RegistrationOrigin: EnsureOrigin<Self::RuntimeOrigin>;
        type StatusOrigin: EnsureOrigin<Self::RuntimeOrigin>;
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
    pub enum ProviderStatus {
        Registered,
        Verified,
        Active,
        Suspended,
        Removed,
    }

    #[derive(
        Clone, Decode, DecodeWithMemTracking, Encode, Eq, MaxEncodedLen, PartialEq, Debug, TypeInfo,
    )]
    #[scale_info(skip_type_params(T))]
    pub struct Provider<T: Config> {
        pub owner: T::AccountId,
        pub public_key: [u8; 32],
        pub status: ProviderStatus,
    }

    #[pallet::storage]
    #[pallet::getter(fn providers)]
    pub type Providers<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, Provider<T>, OptionQuery>;

    #[pallet::storage]
    pub type ProviderByKey<T: Config> =
        StorageMap<_, Blake2_128Concat, [u8; 32], T::AccountId, OptionQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        ProviderRegistered {
            provider: T::AccountId,
        },
        StatusChanged {
            provider: T::AccountId,
            status: ProviderStatus,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        AlreadyRegistered,
        PublicKeyAlreadyRegistered,
        InvalidPublicKey,
        ProviderNotFound,
        InvalidStatusTransition,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::register_provider())]
        pub fn register_provider(origin: OriginFor<T>, public_key: [u8; 32]) -> DispatchResult {
            let owner = ensure_signed(origin)?;
            Self::do_register_provider(owner, public_key)
        }

        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::set_status())]
        pub fn set_status(
            origin: OriginFor<T>,
            provider: T::AccountId,
            status: ProviderStatus,
        ) -> DispatchResult {
            T::StatusOrigin::ensure_origin(origin)?;
            Providers::<T>::try_mutate(&provider, |entry| -> DispatchResult {
                let record = entry.as_mut().ok_or(Error::<T>::ProviderNotFound)?;
                ensure!(
                    Self::valid_transition(record.status, status),
                    Error::<T>::InvalidStatusTransition
                );
                record.status = status;
                Ok(())
            })?;
            Self::deposit_event(Event::StatusChanged { provider, status });
            Ok(())
        }

        /// Register a provider account on behalf of an Agent after the configured
        /// registration authority has verified its off-chain identity proof.
        #[pallet::call_index(2)]
        #[pallet::weight(T::WeightInfo::register_provider_for())]
        pub fn register_provider_for(
            origin: OriginFor<T>,
            provider: T::AccountId,
            public_key: [u8; 32],
        ) -> DispatchResult {
            T::RegistrationOrigin::ensure_origin(origin)?;
            Self::do_register_provider(provider, public_key)
        }
    }

    impl<T: Config> Pallet<T> {
        fn do_register_provider(owner: T::AccountId, public_key: [u8; 32]) -> DispatchResult {
            ensure!(public_key != [0; 32], Error::<T>::InvalidPublicKey);
            ensure!(
                !Providers::<T>::contains_key(&owner),
                Error::<T>::AlreadyRegistered
            );
            ensure!(
                !ProviderByKey::<T>::contains_key(public_key),
                Error::<T>::PublicKeyAlreadyRegistered
            );

            Providers::<T>::insert(
                &owner,
                Provider::<T> {
                    owner: owner.clone(),
                    public_key,
                    status: ProviderStatus::Registered,
                },
            );
            ProviderByKey::<T>::insert(public_key, &owner);
            Self::deposit_event(Event::ProviderRegistered { provider: owner });
            Ok(())
        }

        fn valid_transition(from: ProviderStatus, to: ProviderStatus) -> bool {
            matches!(
                (from, to),
                (ProviderStatus::Registered, ProviderStatus::Verified)
                    | (ProviderStatus::Verified, ProviderStatus::Active)
                    | (ProviderStatus::Active, ProviderStatus::Suspended)
                    | (ProviderStatus::Suspended, ProviderStatus::Active)
                    | (ProviderStatus::Registered, ProviderStatus::Removed)
                    | (ProviderStatus::Verified, ProviderStatus::Removed)
                    | (ProviderStatus::Active, ProviderStatus::Removed)
                    | (ProviderStatus::Suspended, ProviderStatus::Removed)
            )
        }
    }

    impl<T: Config> ProviderInspector<T::AccountId> for Pallet<T> {
        fn is_registered(provider: &T::AccountId) -> bool {
            Providers::<T>::contains_key(provider)
        }

        fn is_active(provider: &T::AccountId) -> bool {
            Providers::<T>::get(provider)
                .is_some_and(|record| record.status == ProviderStatus::Active)
        }
    }
}

#[cfg(test)]
mod tests;
