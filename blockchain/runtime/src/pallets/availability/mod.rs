#[frame_support::pallet]
pub struct Pallet<T>(_);

#[pallet::config]
pub trait Config: frame_system::Config {
    type RuntimeEvent: From<Event<T>>;
}

#[pallet::storage]
pub type LastHeartbeat<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, u64>;

#[pallet::event]
#[pallet::generate_deposits]
pub enum Event<T> {
    HeartbeatReceived(T::AccountId),
    ChallengeValidated(T::AccountId, bool),
}

#[pallet::error]
pub enum Error<T> {
    ChallengeTimeout,
    InvalidResponse,
}

#[pallet::call]
impl<T: Config> Pallet<T> {
    #[pallet::call_index(0)]
    #[pallet::weight(10_000)]
    pub fn submit_heartbeat(origin: OriginFor<T>) -> DispatchResult {
        let who = ensure_signed(origin)?;
        let current_block = <frame_system::Pallet<T>>::block_number();

        LastHeartbeat::<T>::insert(&who, current_block.as_u64());
        Self::deposit_event(Event::HeartbeatReceived(who));
        Ok(())
    }

    #[pallet::call_index(1)]
    #[pallet::weight(10_000)]
    pub fn validate_challenge(
        origin: OriginFor<T>,
        provider: T::AccountId,
        response: [u8; 32],
        expected: [u8; 32],
    ) -> DispatchResult {
        let _ = ensure_signed(origin)?; // Restricted to Validators

        let is_valid = response == expected;
        Self::deposit_event(Event::ChallengeValidated(provider, is_valid));

        if !is_valid {
            return Err(Error::<T>::InvalidResponse.into());
        }
        Ok(())
    }
}
