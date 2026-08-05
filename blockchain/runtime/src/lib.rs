#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

extern crate alloc;
use alloc::{vec, vec::Vec};
use polkadot_sdk::{
    polkadot_sdk_frame::{
        self as frame,
        deps::sp_genesis_builder,
        runtime::{apis, prelude::*},
    },
    *,
};

#[runtime_version]
pub const VERSION: RuntimeVersion = RuntimeVersion {
    spec_name: alloc::borrow::Cow::Borrowed("openinfra-runtime"),
    impl_name: alloc::borrow::Cow::Borrowed("openinfra-runtime"),
    authoring_version: 1,
    spec_version: 3,
    impl_version: 1,
    apis: RUNTIME_API_VERSIONS,
    transaction_version: 1,
    system_version: 1,
};

#[cfg(feature = "std")]
pub fn native_version() -> NativeVersion {
    NativeVersion {
        runtime_version: VERSION,
        can_author_with: Default::default(),
    }
}

type TxExtension = (
    frame_system::AuthorizeCall<Runtime>,
    frame_system::CheckNonZeroSender<Runtime>,
    frame_system::CheckSpecVersion<Runtime>,
    frame_system::CheckTxVersion<Runtime>,
    frame_system::CheckGenesis<Runtime>,
    frame_system::CheckEra<Runtime>,
    frame_system::CheckNonce<Runtime>,
    frame_system::CheckWeight<Runtime>,
    frame_system::WeightReclaim<Runtime>,
);

#[frame_construct_runtime]
mod runtime {
    #[runtime::runtime]
    #[runtime::derive(
        RuntimeCall,
        RuntimeEvent,
        RuntimeError,
        RuntimeOrigin,
        RuntimeFreezeReason,
        RuntimeHoldReason,
        RuntimeSlashReason,
        RuntimeLockId,
        RuntimeTask,
        RuntimeViewFunction
    )]
    pub struct Runtime;

    #[runtime::pallet_index(0)]
    pub type System = frame_system::Pallet<Runtime>;
    #[runtime::pallet_index(1)]
    pub type Timestamp = pallet_timestamp::Pallet<Runtime>;
    #[runtime::pallet_index(2)]
    pub type Sudo = pallet_sudo::Pallet<Runtime>;
    #[runtime::pallet_index(3)]
    pub type Balances = pallet_balances::Pallet<Runtime>;
    #[runtime::pallet_index(4)]
    pub type Aura = pallet_aura::Pallet<Runtime>;
    #[runtime::pallet_index(5)]
    pub type Grandpa = pallet_grandpa::Pallet<Runtime>;
    #[runtime::pallet_index(10)]
    pub type ProviderRegistry = pallet_provider_registry::Pallet<Runtime>;
    #[runtime::pallet_index(11)]
    pub type ResourceMarket = pallet_resource_market::Pallet<Runtime>;
    #[runtime::pallet_index(12)]
    pub type Lease = pallet_openinfra_lease::Pallet<Runtime>;
    #[runtime::pallet_index(13)]
    pub type Reputation = pallet_reputation::Pallet<Runtime>;
    #[runtime::pallet_index(14)]
    pub type Rewards = pallet_openinfra_rewards::Pallet<Runtime>;
    #[runtime::pallet_index(15)]
    pub type Availability = pallet_availability::Pallet<Runtime>;
}

parameter_types! {
    pub const Version: RuntimeVersion = VERSION;
    pub const MaxCapabilitiesLen: u32 = 256;
    pub const MaxLeaseDuration: u32 = 1_000_000;
    pub const DefaultReputation: u32 = 500;
    pub const MaxReputation: u32 = 1_000;
    pub const MaxReputationDelta: u32 = 250;
    pub const MaxPendingChallenges: u32 = 16;
    pub const MaxChallengeLifetime: u32 = 1_000;
    pub const MaxRewardResourceUnits: u64 = 1_000_000_000;
    pub const MaxRewardDuration: u64 = 10_000_000;
}

#[derive_impl(frame_system::config_preludes::SolochainDefaultConfig)]
impl frame_system::Config for Runtime {
    type Block = Block;
    type Version = Version;
    type AccountData = pallet_balances::AccountData<u64>;
}

#[derive_impl(pallet_timestamp::config_preludes::TestDefaultConfig)]
impl pallet_timestamp::Config for Runtime {
    type OnTimestampSet = Aura;
    type MinimumPeriod = frame::traits::ConstU64<1_500>;
}

impl pallet_aura::Config for Runtime {
    type AuthorityId = sp_consensus_aura::sr25519::AuthorityId;
    type DisabledValidators = ();
    type MaxAuthorities = frame::traits::ConstU32<16>;
    type AllowMultipleBlocksPerSlot = frame::traits::ConstBool<false>;
    type SlotDuration = pallet_aura::MinimumPeriodTimesTwo<Runtime>;
}

impl pallet_grandpa::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = ();
    type MaxAuthorities = frame::traits::ConstU32<16>;
    type MaxNominators = frame::traits::ConstU32<0>;
    type MaxSetIdSessionEntries = frame::traits::ConstU64<0>;
    type KeyOwnerProof = sp_core::Void;
    type EquivocationReportSystem = ();
}

#[derive_impl(pallet_sudo::config_preludes::TestDefaultConfig)]
impl pallet_sudo::Config for Runtime {}

#[derive_impl(pallet_balances::config_preludes::TestDefaultConfig)]
impl pallet_balances::Config for Runtime {
    type ExistentialDeposit = frame::traits::ConstU64<1>;
    type AccountStore = System;
}

impl pallet_provider_registry::Config for Runtime {
    type RegistrationOrigin = frame_system::EnsureRoot<Self::AccountId>;
    type StatusOrigin = frame_system::EnsureRoot<Self::AccountId>;
    type WeightInfo = ();
}

impl pallet_resource_market::Config for Runtime {
    type ProviderRegistry = ProviderRegistry;
    type MaxCapabilitiesLen = MaxCapabilitiesLen;
    type WeightInfo = ();
}

pub struct RegisteredProviderInspector;
impl pallet_availability::ProviderInspector<interface::AccountId> for RegisteredProviderInspector {
    fn is_registered(provider: &interface::AccountId) -> bool {
        pallet_provider_registry::Providers::<Runtime>::contains_key(provider)
    }
}
impl pallet_reputation::ProviderInspector<interface::AccountId> for RegisteredProviderInspector {
    fn is_registered(provider: &interface::AccountId) -> bool {
        pallet_provider_registry::Providers::<Runtime>::contains_key(provider)
    }
}

pub struct ActiveProviderLookup;
impl pallet_openinfra_lease::ProviderLookup<interface::AccountId> for ActiveProviderLookup {
    fn is_lease_eligible(provider: &interface::AccountId) -> bool {
        <ProviderRegistry as pallet_provider_registry::ProviderInspector<interface::AccountId>>::is_active(provider)
    }
}

impl pallet_openinfra_lease::Config for Runtime {
    type LeaseOrigin = frame_system::EnsureRoot<Self::AccountId>;
    type ProviderLookup = ActiveProviderLookup;
    type MaxDuration = MaxLeaseDuration;
    type WeightInfo = ();
}

impl pallet_reputation::Config for Runtime {
    type UpdateOrigin = frame_system::EnsureRoot<Self::AccountId>;
    type ProviderInspector = RegisteredProviderInspector;
    type DefaultScore = DefaultReputation;
    type MaxScore = MaxReputation;
    type MaxDelta = MaxReputationDelta;
    type WeightInfo = ();
}

impl pallet_openinfra_rewards::Config for Runtime {
    type RewardOrigin = frame_system::EnsureRoot<Self::AccountId>;
    type MaxResourceUnits = MaxRewardResourceUnits;
    type MaxDuration = MaxRewardDuration;
    type MaxReputation = MaxReputation;
    type WeightInfo = ();
}

impl pallet_availability::Config for Runtime {
    type ChallengeOrigin = frame_system::EnsureRoot<Self::AccountId>;
    type ProviderInspector = RegisteredProviderInspector;
    type MaxPendingChallenges = MaxPendingChallenges;
    type MaxChallengeLifetime = MaxChallengeLifetime;
    type WeightInfo = ();
}

type Block = frame::runtime::types_common::BlockOf<Runtime, TxExtension>;
type RuntimeExecutive =
    Executive<Runtime, Block, frame_system::ChainContext<Runtime>, Runtime, AllPalletsWithSystem>;

impl_runtime_apis! {
    impl apis::Core<Block> for Runtime {
        fn version() -> RuntimeVersion { VERSION }
        fn execute_block(block: <Block as frame::traits::Block>::LazyBlock) { RuntimeExecutive::execute_block(block) }
        fn initialize_block(header: &HeaderFor<Runtime>) -> ExtrinsicInclusionMode { RuntimeExecutive::initialize_block(header) }
    }
    impl apis::Metadata<Block> for Runtime {
        fn metadata() -> OpaqueMetadata { OpaqueMetadata::new(Runtime::metadata().into()) }
        fn metadata_at_version(version: u32) -> Option<OpaqueMetadata> { Runtime::metadata_at_version(version) }
        fn metadata_versions() -> Vec<u32> { Runtime::metadata_versions() }
    }
    impl apis::BlockBuilder<Block> for Runtime {
        fn apply_extrinsic(extrinsic: ExtrinsicFor<Runtime>) -> ApplyExtrinsicResult { RuntimeExecutive::apply_extrinsic(extrinsic) }
        fn finalize_block() -> HeaderFor<Runtime> { RuntimeExecutive::finalize_block() }
        fn inherent_extrinsics(data: InherentData) -> Vec<ExtrinsicFor<Runtime>> { data.create_extrinsics() }
        fn check_inherents(block: <Block as frame::traits::Block>::LazyBlock, data: InherentData) -> CheckInherentsResult { data.check_extrinsics(&block) }
    }
    impl apis::TaggedTransactionQueue<Block> for Runtime {
        fn validate_transaction(source: TransactionSource, tx: ExtrinsicFor<Runtime>, block_hash: <Runtime as frame_system::Config>::Hash) -> TransactionValidity {
            RuntimeExecutive::validate_transaction(source, tx, block_hash)
        }
    }
    impl sp_consensus_aura::AuraApi<Block, sp_consensus_aura::sr25519::AuthorityId> for Runtime {
        fn slot_duration() -> sp_consensus_aura::SlotDuration {
            sp_consensus_aura::SlotDuration::from_millis(Aura::slot_duration())
        }
        fn authorities() -> Vec<sp_consensus_aura::sr25519::AuthorityId> {
            pallet_aura::Authorities::<Runtime>::get().into_inner()
        }
    }
    impl sp_consensus_grandpa::GrandpaApi<Block> for Runtime {
        fn grandpa_authorities() -> sp_consensus_grandpa::AuthorityList {
            Grandpa::grandpa_authorities()
        }
        fn current_set_id() -> sp_consensus_grandpa::SetId {
            Grandpa::current_set_id()
        }
        fn submit_report_equivocation_unsigned_extrinsic(
            _equivocation_proof: sp_consensus_grandpa::EquivocationProof<
                <Block as frame::traits::Block>::Hash,
                frame::deps::sp_runtime::traits::NumberFor<Block>,
            >,
            _key_owner_proof: sp_consensus_grandpa::OpaqueKeyOwnershipProof,
        ) -> Option<()> { None }
        fn generate_key_ownership_proof(
            _set_id: sp_consensus_grandpa::SetId,
            _authority_id: sp_consensus_grandpa::AuthorityId,
        ) -> Option<sp_consensus_grandpa::OpaqueKeyOwnershipProof> { None }
    }
    impl apis::SessionKeys<Block> for Runtime {
        fn generate_session_keys(
            _owner: Vec<u8>,
            _seed: Option<Vec<u8>>,
        ) -> apis::OpaqueGeneratedSessionKeys {
            apis::OpaqueGeneratedSessionKeys {
                keys: Default::default(),
                proof: Default::default(),
            }
        }

        fn decode_session_keys(_encoded: Vec<u8>) -> Option<Vec<(Vec<u8>, apis::KeyTypeId)>> {
            None
        }
    }
    impl apis::AccountNonceApi<Block, interface::AccountId, interface::Nonce> for Runtime {
        fn account_nonce(account: interface::AccountId) -> interface::Nonce { System::account_nonce(account) }
    }
    impl apis::GenesisBuilder<Block> for Runtime {
        fn build_state(config: Vec<u8>) -> sp_genesis_builder::Result { build_state::<RuntimeGenesisConfig>(config) }
        fn get_preset(id: &Option<PresetId>) -> Option<Vec<u8>> { get_preset::<RuntimeGenesisConfig>(id, genesis_config_presets::get_preset) }
        fn preset_names() -> Vec<PresetId> { genesis_config_presets::preset_names() }
    }
}

pub mod genesis_config_presets {
    use super::*;
    use serde_json::Value;

    pub fn development_config_genesis() -> Value {
        frame_support::build_struct_json_patch!(RuntimeGenesisConfig {
            aura: pallet_aura::GenesisConfig {
                authorities: vec![sp_keyring::Sr25519Keyring::Alice.public().into()]
            },
            grandpa: pallet_grandpa::GenesisConfig {
                authorities: vec![(sp_keyring::Ed25519Keyring::Alice.public().into(), 1)]
            },
            sudo: SudoConfig {
                key: Some(sp_keyring::Sr25519Keyring::Alice.to_account_id())
            },
        })
    }
    pub fn get_preset(id: &PresetId) -> Option<Vec<u8>> {
        let patch = match id.as_ref() {
            sp_genesis_builder::DEV_RUNTIME_PRESET => development_config_genesis(),
            _ => return None,
        };
        Some(
            serde_json::to_string(&patch)
                .expect("genesis JSON serialization is infallible")
                .into_bytes(),
        )
    }
    pub fn preset_names() -> Vec<PresetId> {
        vec![PresetId::from(sp_genesis_builder::DEV_RUNTIME_PRESET)]
    }
}

pub mod interface {
    use super::Runtime;
    use polkadot_sdk::{polkadot_sdk_frame as frame, *};

    pub type Block = super::Block;
    pub use frame::runtime::types_common::OpaqueBlock;
    pub type AccountId = <Runtime as frame_system::Config>::AccountId;
    pub type Nonce = <Runtime as frame_system::Config>::Nonce;
}

#[cfg(test)]
mod tests {
    use super::*;
    use codec::Encode;

    #[test]
    fn development_genesis_builds() {
        assert!(genesis_config_presets::development_config_genesis().is_object());
    }

    #[test]
    fn bridge_call_indices_remain_stable_in_spec_version_three() {
        let provider = interface::AccountId::from([7_u8; 32]);
        let registration =
            RuntimeCall::ProviderRegistry(pallet_provider_registry::Call::register_provider_for {
                provider,
                public_key: [7_u8; 32],
            });
        assert_eq!(&registration.encode()[..2], &[10, 2]);

        let sudo = RuntimeCall::Sudo(pallet_sudo::Call::sudo {
            call: alloc::boxed::Box::new(registration),
        });
        assert_eq!(&sudo.encode()[..4], &[2, 0, 10, 2]);
    }
}
