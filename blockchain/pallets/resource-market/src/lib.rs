#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

use frame_support::weights::Weight;

pub trait WeightInfo {
    fn announce_offer() -> Weight;
    fn remove_offer() -> Weight;
}

impl WeightInfo for () {
    fn announce_offer() -> Weight {
        Weight::from_parts(10_000, 0)
    }
    fn remove_offer() -> Weight {
        Weight::from_parts(10_000, 0)
    }
}

#[frame_support::pallet]
pub mod pallet {
    use super::WeightInfo;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use pallet_provider_registry::ProviderInspector;

    #[pallet::config]
    pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
        type ProviderRegistry: ProviderInspector<Self::AccountId>;
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

        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::remove_offer())]
        pub fn remove_offer(origin: OriginFor<T>) -> DispatchResult {
            let provider = ensure_signed(origin)?;
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
