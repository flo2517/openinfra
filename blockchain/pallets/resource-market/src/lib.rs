#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

use frame_support::weights::Weight;

pub trait WeightInfo {
    fn announce_offer() -> Weight;
    fn remove_offer() -> Weight;
    fn announce_offer_for() -> Weight;
    fn remove_offer_for() -> Weight;
}

impl WeightInfo for () {
    fn announce_offer() -> Weight {
        Weight::from_parts(10_000, 0)
    }
    fn remove_offer() -> Weight {
        Weight::from_parts(10_000, 0)
    }
    fn announce_offer_for() -> Weight {
        Weight::from_parts(10_000, 0)
    }
    fn remove_offer_for() -> Weight {
        Weight::from_parts(10_000, 0)
    }
}

#[frame_support::pallet]
pub mod pallet {
    use super::WeightInfo;
    use frame_support::{pallet_prelude::*, traits::EnsureOrigin};
    use frame_system::pallet_prelude::*;
    use pallet_provider_registry::ProviderInspector;

    #[pallet::config]
    pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
        type ProviderRegistry: ProviderInspector<Self::AccountId>;
        /// Origin for announce_offer_for/remove_offer_for: the Control
        /// Plane bridge publishing on a provider's behalf, since the
        /// Provider Agent never talks to the chain directly (AGENTS.md).
        /// Same delegation shape as pallet-provider-registry's
        /// RegistrationOrigin/register_provider_for (ADR-009) -- self-
        /// service announce_offer/remove_offer stay available for a
        /// future provider that does hold its own chain key.
        type AnnounceOrigin: EnsureOrigin<Self::RuntimeOrigin>;
        #[pallet::constant]
        type MaxCapabilitiesLen: Get<u32>;
        type WeightInfo: WeightInfo;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[derive(
        Clone, Decode, DecodeWithMemTracking, Encode, Eq, MaxEncodedLen, PartialEq, Debug, TypeInfo,
    )]
    #[scale_info(skip_type_params(T))]
    pub struct ResourceOffer<T: Config> {
        pub cpu: u32,
        pub ram: u64,
        pub storage: u64,
        pub capabilities: BoundedVec<u8, T::MaxCapabilitiesLen>,
    }

    #[pallet::storage]
    #[pallet::getter(fn offers)]
    pub type Offers<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, ResourceOffer<T>, OptionQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        ResourceAnnounced { provider: T::AccountId },
        ResourceRemoved { provider: T::AccountId },
    }

    #[pallet::error]
    pub enum Error<T> {
        ProviderNotActive,
        InvalidResources,
        OfferNotFound,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::announce_offer())]
        pub fn announce_offer(
            origin: OriginFor<T>,
            cpu: u32,
            ram: u64,
            storage: u64,
            capabilities: BoundedVec<u8, T::MaxCapabilitiesLen>,
        ) -> DispatchResult {
            let provider = ensure_signed(origin)?;
            Self::do_announce(provider, cpu, ram, storage, capabilities)
        }

        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::remove_offer())]
        pub fn remove_offer(origin: OriginFor<T>) -> DispatchResult {
            let provider = ensure_signed(origin)?;
            Self::do_remove(provider)
        }

        /// Publish or replace `provider`'s offer on its behalf. See
        /// Config::AnnounceOrigin's doc comment for why this exists
        /// alongside the self-service call above.
        #[pallet::call_index(2)]
        #[pallet::weight(T::WeightInfo::announce_offer_for())]
        #[allow(clippy::too_many_arguments)]
        pub fn announce_offer_for(
            origin: OriginFor<T>,
            provider: T::AccountId,
            cpu: u32,
            ram: u64,
            storage: u64,
            capabilities: BoundedVec<u8, T::MaxCapabilitiesLen>,
        ) -> DispatchResult {
            T::AnnounceOrigin::ensure_origin(origin)?;
            Self::do_announce(provider, cpu, ram, storage, capabilities)
        }

        /// Withdraw `provider`'s offer on its behalf (e.g. the provider
        /// went stale/inactive or deregistered).
        #[pallet::call_index(3)]
        #[pallet::weight(T::WeightInfo::remove_offer_for())]
        pub fn remove_offer_for(origin: OriginFor<T>, provider: T::AccountId) -> DispatchResult {
            T::AnnounceOrigin::ensure_origin(origin)?;
            Self::do_remove(provider)
        }
    }

    impl<T: Config> Pallet<T> {
        fn do_announce(
            provider: T::AccountId,
            cpu: u32,
            ram: u64,
            storage: u64,
            capabilities: BoundedVec<u8, T::MaxCapabilitiesLen>,
        ) -> DispatchResult {
            ensure!(
                T::ProviderRegistry::is_active(&provider),
                Error::<T>::ProviderNotActive
            );
            ensure!(
                cpu > 0 && ram > 0 && storage > 0,
                Error::<T>::InvalidResources
            );
            Offers::<T>::insert(
                &provider,
                ResourceOffer::<T> {
                    cpu,
                    ram,
                    storage,
                    capabilities,
                },
            );
            Self::deposit_event(Event::ResourceAnnounced { provider });
            Ok(())
        }

        fn do_remove(provider: T::AccountId) -> DispatchResult {
            ensure!(
                Offers::<T>::contains_key(&provider),
                Error::<T>::OfferNotFound
            );
            Offers::<T>::remove(&provider);
            Self::deposit_event(Event::ResourceRemoved { provider });
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests;
