// Interface abstractions to decouple business logic from pallet implementation
// These traits will be implemented by the future pallets

pub trait LeaseManager<T> {
    type LeaseId;
    type ResourceReq;

    fn create_lease(
        provider: T::AccountId,
        consumer: T::AccountId,
        req: Self::ResourceReq,
        duration: u64
    ) -> Result<Self::LeaseId, T::Error>;

    fn complete_lease(lease_id: Self::LeaseId) -> Result<(), T::Error>;
}

pub trait ReputationManager<T> {
    fn update_score(provider: T::AccountId, delta: i32, proof: Vec<u8>) -> Result<(), T::Error>;
    fn get_score(provider: T::AccountId) -> u32;
}

pub trait RewardManager<T> {
    fn calculate_and_assign_reward(lease_id: u64) -> Result<(), T::Error>;
    fn claim_points(provider: T::AccountId) -> Result<(), T::Error>;
}

pub trait AvailabilityManager<T> {
    fn heartbeat(provider: T::AccountId) -> Result<(), T::Error>;
    fn verify_challenge(provider: T::AccountId, response: Vec<u8>) -> Result<bool, T::Error>;
}
