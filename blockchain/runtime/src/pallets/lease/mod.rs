#[frame_support::pallet]
pub struct Pallet<T>(_);

#[pallet::config]
pub trait Config: frame_system::Config {
    type RuntimeEvent: From<Event<T>>;
}

#[derive(Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub enum LeaseState {
    Created,
    Active,
    Completed,
    Expired,
    Disputed,
}

#[derive(Clone, PartialEq, Eq, RuntimeDebug, TypeInfo)]
pub struct Lease<AccountId> {
    pub provider: AccountId,
    pub consumer: AccountId,
    pub resource_hash: [u8; 32],
    pub start: u64, // BlockNumber
    pub end: u64,   // BlockNumber
    pub state: LeaseState,
}

#[pallet::storage]
pub type Leases<T: Config> = StorageMap<_, Blake2_128Concat, u64, Lease<T::AccountId>>;

#[pallet::event]
#[pallet::generate_deposits]
pub enum Event<T> {
    LeaseCreated(u64, T::AccountId, T::AccountId),
    LeaseStateChanged(u64, LeaseState),
}

#[pallet::error]
pub enum Error<T> {
    LeaseNotFound,
    InvalidStateTransition,
    InvalidProvider,
}

#[pallet::call]
impl<T: Config> Pallet<T> {
    #[pallet::call_index(0)]
    #[pallet::weight(10_000)]
    pub fn create_lease(
        origin: OriginFor<T>,
        lease_id: u64,
        provider: T::AccountId,
        resource_hash: [u8; 32],
        duration: u64,
    ) -> DispatchResult {
        let consumer = ensure_signed(origin)?;

        let current_block = <frame_system::Pallet<T>>::block_number();

        let lease = Lease {
            provider,
            consumer,
            resource_hash,
            start: current_block.as_u64(),
            end: current_block.as_u64() + duration,
            state: LeaseState::Created,
        };

        Leases::<T>::insert(lease_id, lease);
        Self::deposit_event(Event::LeaseCreated(lease_id, provider, consumer));
        Ok(())
    }

    #[pallet::call_index(1)]
    #[pallet::weight(10_000)]
    pub fn update_lease_state(origin: OriginFor<T>, lease_id: u64, new_state: LeaseState) -> DispatchResult {
        let _ = ensure_signed(origin)?; // In production, would check if origin is Provider or Control Plane

        let mut lease = Leases::<T>::get(lease_id).ok_or(Error::<T>::LeaseNotFound)?;

        lease.state = new_state.clone();
        Leases::<T>::insert(lease_id, lease);

        Self::deposit_event(Event::LeaseStateChanged(lease_id, new_state));
        Ok(())
    }
}
