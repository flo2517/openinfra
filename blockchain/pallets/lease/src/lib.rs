#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

use frame_support::weights::Weight;

pub trait ProviderLookup<AccountId> {
    fn is_lease_eligible(provider: &AccountId) -> bool;
}

pub trait WeightInfo {
    fn create_lease() -> Weight;
    fn update_lease_state() -> Weight;
}

impl WeightInfo for () {
    fn create_lease() -> Weight {
        Weight::zero()
    }
    fn update_lease_state() -> Weight {
        Weight::zero()
    }
}

#[frame_support::pallet]
pub mod pallet {
    use super::{ProviderLookup, WeightInfo};
    use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
    use frame_support::{
        ensure,
        pallet_prelude::*,
        traits::{EnsureOrigin, Get},
    };
    use frame_system::pallet_prelude::*;
    use scale_info::TypeInfo;

    pub type LeaseId = u64;

    #[derive(
        Clone,
        Copy,
        Debug,
        Decode,
        DecodeWithMemTracking,
        Encode,
        Eq,
        MaxEncodedLen,
        PartialEq,
        TypeInfo,
    )]
    pub enum LeaseState {
        Created,
        Active,
        Completed,
        Expired,
        Disputed,
    }

    #[derive(
        Clone, Debug, Decode, DecodeWithMemTracking, Encode, Eq, MaxEncodedLen, PartialEq, TypeInfo,
    )]
    #[scale_info(skip_type_params(T))]
    pub struct Lease<T: Config> {
        pub provider: T::AccountId,
        pub consumer: T::AccountId,
        pub resource_hash: [u8; 32],
        pub start: BlockNumberFor<T>,
        pub end: BlockNumberFor<T>,
        pub state: LeaseState,
    }

    #[pallet::config]
    pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
        type LeaseOrigin: EnsureOrigin<Self::RuntimeOrigin>;
        type ProviderLookup: ProviderLookup<Self::AccountId>;
        #[pallet::constant]
        type MaxDuration: Get<BlockNumberFor<Self>>;
        type WeightInfo: WeightInfo;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::storage]
    #[pallet::getter(fn leases)]
    pub type Leases<T: Config> = StorageMap<_, Blake2_128Concat, LeaseId, Lease<T>, OptionQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        LeaseCreated {
            lease_id: LeaseId,
            provider: T::AccountId,
            consumer: T::AccountId,
            end: BlockNumberFor<T>,
        },
        LeaseStateChanged {
            lease_id: LeaseId,
            old_state: LeaseState,
            new_state: LeaseState,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        LeaseAlreadyExists,
        LeaseNotFound,
        ProviderNotEligible,
        ZeroDuration,
        DurationTooLong,
        EndBlockOverflow,
        InvalidStateTransition,
        LeaseNotYetExpired,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::create_lease())]
        pub fn create_lease(
            origin: OriginFor<T>,
            lease_id: LeaseId,
            provider: T::AccountId,
            resource_hash: [u8; 32],
            duration: BlockNumberFor<T>,
        ) -> DispatchResult {
            let consumer = ensure_signed(origin)?;
            ensure!(
                !Leases::<T>::contains_key(lease_id),
                Error::<T>::LeaseAlreadyExists
            );
            ensure!(
                T::ProviderLookup::is_lease_eligible(&provider),
                Error::<T>::ProviderNotEligible
            );
            ensure!(!duration.is_zero(), Error::<T>::ZeroDuration);
            ensure!(
                duration <= T::MaxDuration::get(),
                Error::<T>::DurationTooLong
            );

            let start = frame_system::Pallet::<T>::block_number();
            let end = start
                .checked_add(&duration)
                .ok_or(Error::<T>::EndBlockOverflow)?;
            let lease = Lease::<T> {
                provider: provider.clone(),
                consumer: consumer.clone(),
                resource_hash,
                start,
                end,
                state: LeaseState::Created,
            };
            Leases::<T>::insert(lease_id, lease);
            Self::deposit_event(Event::LeaseCreated {
                lease_id,
                provider,
                consumer,
                end,
            });
            Ok(())
        }

        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::update_lease_state())]
        pub fn update_lease_state(
            origin: OriginFor<T>,
            lease_id: LeaseId,
            new_state: LeaseState,
        ) -> DispatchResult {
            T::LeaseOrigin::ensure_origin(origin)?;
            Leases::<T>::try_mutate(lease_id, |maybe_lease| -> DispatchResult {
                let lease = maybe_lease.as_mut().ok_or(Error::<T>::LeaseNotFound)?;
                let old_state = lease.state;
                ensure!(
                    matches!(
                        (old_state, new_state),
                        (LeaseState::Created, LeaseState::Active)
                            | (LeaseState::Active, LeaseState::Completed)
                            | (LeaseState::Active, LeaseState::Expired)
                            | (LeaseState::Active, LeaseState::Disputed)
                            | (LeaseState::Disputed, LeaseState::Completed)
                    ),
                    Error::<T>::InvalidStateTransition
                );
                if new_state == LeaseState::Expired {
                    ensure!(
                        frame_system::Pallet::<T>::block_number() >= lease.end,
                        Error::<T>::LeaseNotYetExpired
                    );
                }
                lease.state = new_state;
                Self::deposit_event(Event::LeaseStateChanged {
                    lease_id,
                    old_state,
                    new_state,
                });
                Ok(())
            })
        }
    }
}

#[cfg(test)]
mod tests;
