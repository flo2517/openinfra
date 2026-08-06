#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub use pallet::*;

use frame_support::{
    pallet_prelude::*,
    traits::{EnsureOrigin, Get, OriginTrait},
    weights::Weight,
};
use frame_system::{pallet_prelude::*, RawOrigin};
use sp_runtime::traits::Saturating;

pub trait ProviderInspector<AccountId> {
    fn is_registered(provider: &AccountId) -> bool;
}

impl<AccountId> ProviderInspector<AccountId> for () {
    fn is_registered(_: &AccountId) -> bool {
        true
    }
}

/// Narrow interface for checking whether an account is currently a bonded,
/// active Network Validator (ADR-011). Deliberately redeclared per
/// consuming pallet -- same pattern as [`ProviderInspector`] -- rather than
/// depending on `pallet-network-validator` directly, so this pallet has no
/// hard dependency on it; the runtime glues the two together.
pub trait NetworkValidatorInspector<AccountId> {
    fn is_active(validator: &AccountId) -> bool;
}

impl<AccountId> NetworkValidatorInspector<AccountId> for () {
    fn is_active(_: &AccountId) -> bool {
        false
    }
}

/// An [`EnsureOrigin`] that succeeds only for a signed origin whose account
/// is currently an active Network Validator per `T::ValidatorInspector`.
/// Modeled on `frame_system::EnsureSignedBy`, with a dynamic membership
/// check in place of a static [`SortedMembers`] set.
pub struct EnsureActiveValidator<T>(core::marker::PhantomData<T>);

impl<T, O> EnsureOrigin<O> for EnsureActiveValidator<T>
where
    T: pallet::Config,
    O: OriginTrait<AccountId = T::AccountId> + From<RawOrigin<T::AccountId>>,
{
    type Success = T::AccountId;

    fn try_origin(o: O) -> Result<Self::Success, O> {
        match o.as_system_ref() {
            Some(RawOrigin::Signed(who)) if T::ValidatorInspector::is_active(who) => {
                Ok(who.clone())
            }
            _ => Err(o),
        }
    }

    #[cfg(feature = "runtime-benchmarks")]
    fn try_successful_origin() -> Result<O, ()> {
        // There is no generic way to conjure a *registered, active*
        // validator account without real pallet-network-validator state;
        // benchmarking this origin requires a dedicated setup, not a
        // generic fallback.
        Err(())
    }
}

pub trait WeightInfo {
    fn submit_heartbeat() -> Weight;
    fn issue_challenge() -> Weight;
    fn submit_response() -> Weight;
    fn submit_proof() -> Weight;
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
    fn submit_proof() -> Weight {
        Weight::zero()
    }
}

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use alloc::vec::Vec;

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
        /// Origin used by the validator set/control-plane bridge after it has
        /// verified the provider's signature off-chain.  The runtime stores
        /// only a bounded summary, never the raw metrics payload.
        type ProofOrigin: EnsureOrigin<Self::RuntimeOrigin>;
        type ProviderInspector: ProviderInspector<Self::AccountId>;
        /// Backs [`EnsureActiveValidator`]; the runtime wires this to
        /// `pallet-network-validator`'s registry (ADR-011).
        type ValidatorInspector: NetworkValidatorInspector<Self::AccountId>;
        #[pallet::constant]
        type MaxPendingChallenges: Get<u32>;
        #[pallet::constant]
        type MaxChallengeLifetime: Get<BlockNumberFor<Self>>;
        #[pallet::constant]
        type MaxProofAge: Get<BlockNumberFor<Self>>;
        #[pallet::constant]
        type MaxProofSamples: Get<u32>;
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

    /// Monotonic sequence accepted for each provider.  A sequence can never
    /// be submitted twice, which makes relaying a proof idempotent and
    /// prevents replay of an old availability observation.
    #[pallet::storage]
    pub type LastProofSequence<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, u64, ValueQuery>;

    #[derive(
        Clone, Encode, Decode, DecodeWithMemTracking, Eq, MaxEncodedLen, PartialEq, Debug, TypeInfo,
    )]
    pub struct AvailabilitySummary<BlockNumber> {
        pub sequence: u64,
        pub observed_at: BlockNumber,
        pub successful_samples: u32,
        pub total_samples: u32,
        /// Availability in basis points (0..=10_000), not a float.
        pub availability_bps: u16,
        pub payload_hash: [u8; 32],
        pub signature: BoundedVec<u8, ConstU32<96>>,
    }

    #[pallet::storage]
    pub type LatestProof<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        AvailabilitySummary<BlockNumberFor<T>>,
        OptionQuery,
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
        ProofAccepted {
            provider: T::AccountId,
            sequence: u64,
            availability_bps: u16,
            successful_samples: u32,
            total_samples: u32,
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
        ProofSequenceReplay,
        ProofTooOld,
        InvalidProofSamples,
        InvalidProofSignature,
        ProofSignatureTooLong,
        ProofSequenceOverflow,
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

        /// Commit a validator-verified, provider-signed availability summary.
        /// Signature verification is deliberately performed by the validator
        /// bridge before this authorized call; the runtime enforces bounds,
        /// freshness and monotonic sequencing for deterministic replay safety.
        #[pallet::call_index(3)]
        #[pallet::weight(T::WeightInfo::submit_proof())]
        #[allow(clippy::too_many_arguments)]
        pub fn submit_proof(
            origin: OriginFor<T>,
            provider: T::AccountId,
            sequence: u64,
            observed_at: BlockNumberFor<T>,
            successful_samples: u32,
            total_samples: u32,
            payload_hash: [u8; 32],
            signature: Vec<u8>,
        ) -> DispatchResult {
            T::ProofOrigin::ensure_origin(origin)?;
            ensure!(
                T::ProviderInspector::is_registered(&provider),
                Error::<T>::ProviderNotRegistered
            );
            ensure!(
                sequence > LastProofSequence::<T>::get(&provider),
                Error::<T>::ProofSequenceReplay
            );
            ensure!(
                total_samples > 0 && total_samples <= T::MaxProofSamples::get(),
                Error::<T>::InvalidProofSamples
            );
            ensure!(
                successful_samples <= total_samples,
                Error::<T>::InvalidProofSamples
            );
            let now = frame_system::Pallet::<T>::block_number();
            ensure!(observed_at <= now, Error::<T>::ProofTooOld);
            let age = now.saturating_sub(observed_at);
            ensure!(age <= T::MaxProofAge::get(), Error::<T>::ProofTooOld);
            let availability_bps = ((successful_samples as u64)
                .checked_mul(10_000)
                .ok_or(Error::<T>::InvalidProofSamples)?
                / u64::from(total_samples)) as u16;
            let signature: BoundedVec<u8, ConstU32<96>> = signature
                .try_into()
                .map_err(|_| Error::<T>::ProofSignatureTooLong)?;
            ensure!(!signature.is_empty(), Error::<T>::InvalidProofSignature);
            LastProofSequence::<T>::insert(&provider, sequence);
            LatestProof::<T>::insert(
                &provider,
                AvailabilitySummary {
                    sequence,
                    observed_at,
                    successful_samples,
                    total_samples,
                    availability_bps,
                    payload_hash,
                    signature,
                },
            );
            LastHeartbeat::<T>::insert(&provider, observed_at);
            Self::deposit_event(Event::ProofAccepted {
                provider,
                sequence,
                availability_bps,
                successful_samples,
                total_samples,
            });
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests;
