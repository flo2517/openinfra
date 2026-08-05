#[frame_support::pallet]
pub struct Pallet<T>(_);

#[pallet::config]
pub trait Config: frame_system::Config {
    type RuntimeEvent: From<Event<T>>;
}

#[pallet::storage]
pub type RewardBalances<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, u64>;

#[pallet::event]
#[pallet::generate_deposits]
pub enum Event<T> {
    RewardCalculated(T::AccountId, u64),
    RewardClaimed(T::AccountId, u64),
}

#[pallet::error]
pub enum Error<T> {
    InsufficientPoints,
    InvalidLease,
}

#[pallet::call]
impl<T: Config> Pallet<T> {
    #[pallet::call_index(0)]
    #[pallet::weight(10_000)]
    pub fn calculate_reward(
        origin: OriginFor<T>,
        provider: T::AccountId,
        resource_units: u64,
        duration: u64,
        reputation: u32,
        availability_score: u32, // Percentage 0-100
    ) -> DispatchResult {
        let _ = ensure_signed(origin)?; // Restricted to System/ControlPlane

        // Calculation: (Units * Duration) * (1 + Rep/1000) * (Avail/100)
        let base = resource_units * duration;
        let rep_multiplier = 1000 + reputation;
        let avail_multiplier = availability_score;

        // We use a scaled integer math to avoid floats in runtime
        let points = (base * rep_multiplier as u64 * avail_multiplier as u64) / (1000 * 100);

        let current_bal = RewardBalances::<T>::get(&provider).unwrap_or(0);
        RewardBalances::<T>::insert(&provider, current_bal + points);

        Self::deposit_event(Event::RewardCalculated(provider, points));
        Ok(())
    }

    #[pallet::call_index(1)]
    #[pallet::weight(10_000)]
    pub fn claim_reward(origin: OriginFor<T>) -> DispatchResult {
        let who = ensure_signed(origin)?;
        let balance = RewardBalances::<T>::get(&who).ok_or(Error::<T>::InsufficientPoints)?;

        if balance == 0 {
            return Err(Error::<T>::InsufficientPoints.into());
        }

        // In tokenless MVP, we just emit the event. In tokenized version, this transfers tokens.
        RewardBalances::<T>::insert(&who, 0);
        Self::deposit_event(Event::RewardClaimed(who, balance));
        Ok(())
    }
}
