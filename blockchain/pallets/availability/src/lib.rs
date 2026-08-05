#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

use frame_support::{pallet_prelude::*, traits::Get, weights::Weight};
use frame_system::pallet_prelude::*;

pub trait ProviderInspector<AccountId> {
    fn is_registered(provider: &AccountId) -> bool;
}

impl<AccountId> ProviderInspector<AccountId> for () {
    fn is_registered(_: &AccountId) -> bool {
        true
    }
}

pub trait WeightInfo {
    fn submit_heartbeat() -> Weight;
    fn issue_challenge() -> Weight;
    fn submit_response() -> Weight;
}

impl WeightInfo for () {
    fn submit_heartbeat() -> Weight {
        Weight::zero()
    }
    fn issue_challenge() -> Weight {
        Weight::zero()
    }
    fn submit_response() -> Weight {
        Weight::zero()
    }
}

#[frame_support::pallet]
pub mod pallet {
    use super::*;

    #[derive(
        Clone, Encode, Decode, DecodeWithMemTracking, Eq, MaxEncodedLen, PartialEq, Debug, TypeInfo,
    )]
    pub struct Challenge<BlockNumber> {
        pub expected_response: [u8; 32],
        pub deadline: BlockNumber,
    }

    #[pallet::config]
    pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
        type ChallengeOrigin: EnsureOrigin<Self::RuntimeOrigin>;
        type ProviderInspector: ProviderInspector<Self::AccountId>;
        #[pallet::constant]
        type MaxPendingChallenges: Get<u32>;
        #[pallet::constant]
        type MaxChallengeLifetime: Get<BlockNumberFor<Self>>;
        type WeightInfo: WeightInfo;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::storage]
    pub type LastHeartbeat<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, BlockNumberFor<T>, OptionQuery>;

    #[pallet::storage]
    pub type NextChallengeId<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, u64, ValueQuery>;

    #[pallet::storage]
    pub type Challenges<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        Twox64Concat,
        u64,
        Challenge<BlockNumberFor<T>>,
        OptionQuery,
    >;

    #[pallet::storage]
    pub type PendingChallenges<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        BoundedVec<u64, T::MaxPendingChallenges>,
        ValueQuery,
    >;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        HeartbeatReceived {
            provider: T::AccountId,
            block: BlockNumberFor<T>,
        },
        ChallengeIssued {
            provider: T::AccountId,
            challenge_id: u64,
            deadline: BlockNumberFor<T>,
        },
        ChallengeValidated {
            provider: T::AccountId,
            challenge_id: u64,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        ProviderNotRegistered,
        InvalidChallengeLifetime,
        TooManyPendingChallenges,
        ChallengeIdOverflow,
        ChallengeDeadlineOverflow,
        ChallengeNotFound,
        ChallengeTimeout,
        InvalidResponse,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::submit_heartbeat())]
        pub fn submit_heartbeat(origin: OriginFor<T>) -> DispatchResult {
            let provider = ensure_signed(origin)?;
            ensure!(
                T::ProviderInspector::is_registered(&provider),
                Error::<T>::ProviderNotRegistered
            );
            let block = frame_system::Pallet::<T>::block_number();
            LastHeartbeat::<T>::insert(&provider, block);
            Self::deposit_event(Event::HeartbeatReceived { provider, block });
            Ok(())
        }

        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::issue_challenge())]
        pub fn issue_challenge(
            origin: OriginFor<T>,
            provider: T::AccountId,
            expected_response: [u8; 32],
            lifetime: BlockNumberFor<T>,
        ) -> DispatchResult {
            T::ChallengeOrigin::ensure_origin(origin)?;
            ensure!(
                T::ProviderInspector::is_registered(&provider),
                Error::<T>::ProviderNotRegistered
            );
            ensure!(
                !lifetime.is_zero() && lifetime <= T::MaxChallengeLifetime::get(),
                Error::<T>::InvalidChallengeLifetime
            );
            let now = frame_system::Pallet::<T>::block_number();
            let deadline = now
                .checked_add(&lifetime)
                .ok_or(Error::<T>::ChallengeDeadlineOverflow)?;
            let challenge_id = NextChallengeId::<T>::get(&provider);
            let next_id = challenge_id
                .checked_add(1)
                .ok_or(Error::<T>::ChallengeIdOverflow)?;
            PendingChallenges::<T>::try_mutate(&provider, |pending| {
                pending
                    .try_push(challenge_id)
                    .map_err(|_| Error::<T>::TooManyPendingChallenges)
            })?;
            Challenges::<T>::insert(
                &provider,
                challenge_id,
                Challenge {
                    expected_response,
                    deadline,
                },
            );
            NextChallengeId::<T>::insert(&provider, next_id);
            Self::deposit_event(Event::ChallengeIssued {
                provider,
                challenge_id,
                deadline,
            });
            Ok(())
        }

        #[pallet::call_index(2)]
        #[pallet::weight(T::WeightInfo::submit_response())]
        pub fn submit_response(
            origin: OriginFor<T>,
            challenge_id: u64,
            response: [u8; 32],
        ) -> DispatchResult {
            let provider = ensure_signed(origin)?;
            let challenge = Challenges::<T>::get(&provider, challenge_id)
                .ok_or(Error::<T>::ChallengeNotFound)?;
            ensure!(
                frame_system::Pallet::<T>::block_number() <= challenge.deadline,
                Error::<T>::ChallengeTimeout
            );
            ensure!(
                response == challenge.expected_response,
                Error::<T>::InvalidResponse
            );
            Challenges::<T>::remove(&provider, challenge_id);
            PendingChallenges::<T>::mutate(&provider, |pending| {
                if let Some(index) = pending.iter().position(|id| *id == challenge_id) {
                    pending.swap_remove(index);
                }
            });
            Self::deposit_event(Event::ChallengeValidated {
                provider,
                challenge_id,
            });
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests;
