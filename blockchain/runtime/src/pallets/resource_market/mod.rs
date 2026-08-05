#[frame_support::pallet]
pub struct Pallet<T>(_);

#[pallet::config]
pub trait Config: frame_system::Config {
    type RuntimeEvent: From<Event<T>>;
}

#[derive(Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub struct ResourceOffer {
    pub cpu: u32,
    pub ram: u64,
    pub storage: u64,
    pub capabilities: Vec<u8>,
}

#[pallet::storage]
pub type Offers<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, ResourceOffer>;

#[pallet::event]
#[pallet::generate_deposits]
pub enum Event<T> {
    ResourceAnnounced(T::AccountId),
    ResourceRemoved(T::AccountId),
}

#[pallet::error]
pub enum Error<T> {
    ProviderNotRegistered,
}

#[pallet::call]
impl<T: Config> Pallet<T> {
    #[pallet::call_index(0)]
    #[pallet::weight(10_000)]
    pub fn announce_offer(origin: OriginFor<T>, cpu: u32, ram: u64, storage: u64, capabilities: Vec<u8>) -> DispatchResult {
        let who = ensure_signed(origin)?;

        // Logic would check pallet-provider-registry here

        let offer = ResourceOffer { cpu, ram, storage, capabilities };
        Offers::<T>::insert(&who, offer);

        Self::deposit_event(Event::ResourceAnnounced(who));
        Ok(())
    }
}
