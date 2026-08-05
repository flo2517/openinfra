#[frame_support::pallet]
pub struct Pallet<T>(_);

#[pallet::config]
pub trait Config: frame_system::Config {
    type RuntimeEvent: From<Event<T>>;
}

#[pallet::storage]
pub type ReputationScores<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, u32>;

#[pallet::event]
#[pallet::generate_deposits]
pub enum Event<T> {
    ReputationUpdated(T::AccountId, u32),
}

#[pallet::error]
pub enum Error<T> {
    ScoreOutOfBounds,
}

#[pallet::call]
impl<T: Config> Pallet<T> {
    #[pallet::call_index(0)]
    #[pallet::weight(10_000)]
    pub fn submit_score(
        origin: OriginFor<T>,
        provider: T::AccountId,
        delta: i32,
    ) -> DispatchResult {
        let _ = ensure_signed(origin)?; // In production, restricted to Reputation Validators

        let current_score = ReputationScores::<T>::get(&provider).unwrap_or(500);
        let new_score = (current_score as i32 + delta).clamp(0, 1000) as u32;

        ReputationScores::<T>::insert(&provider, new_score);
        Self::deposit_event(Event::ReputationUpdated(provider, new_score));
        Ok(())
    }
}
