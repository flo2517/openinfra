#[frame_support::pallet]
pub struct Pallet<T>(_);

#[pallet::config]
pub trait Config: frame_system::Config {
    type RuntimeEvent: From<Event<T>>;
}

#[derive(Clone, PartialEq, Eq, PartlySloped, RuntimeDebug, TypeInfo)]
pub enum ProviderStatus {
    Registered,
    Verified,
    Active,
    Suspended,
    Removed,
}

#[derive(Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub struct Provider<AccountId> {
    pub owner: AccountId,
    pub public_key: [u8; 32],
    pub status: ProviderStatus,
    pub reputation: u32,
}

#[pallet::storage]
pub type Providers<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, Provider<T::AccountId>>;

#[pallet::event]
#[pallet::generate_ deposits]
pub enum Event<T> {
    ProviderRegistered(T::AccountId),
    StatusChanged(T::AccountId, ProviderStatus),
}

#[pallet::error]
pub enum Error<T> {
    AlreadyRegistered,
    UnauthorizedStatusChange,
}

#[pallet::call]
impl<T: Config> Pallet<T> {
    #[pallet::call_index(0)]
    #[pallet::weight(10_000)]
    pub fn register_provider(origin: OriginFor<T>, pubkey: [u8; 32]) -> DispatchResult {
        let who = ensure_signed(origin)?;

        ensure!(!Providers::<T>::contains_key(&who), Error::<T>::AlreadyRegistered);

        let provider = Provider {
            owner: who.clone(),
            public_key: pubkey,
            status: ProviderStatus::Registered,
            reputation: 500, // Default starting reputation
        };

        Providers::<T>::insert(&who, provider);
        Self::deposit_event(Event::ProviderRegistered(who));
        Ok(())
    }
}
