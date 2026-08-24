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
    // ADR-032: bumped 3 -> 4 alongside transaction_version below, for
    // ChargeTip's new TxExtension element -- matching this repo's
    // established practice (#37's spec_version-only bump for the
    // manual-sealing -> Aura/GRANDPA move) of bumping spec_version for a
    // consensus/transaction-validity-affecting change, not for every
    // pallet addition (six pallets landed since #37 without a further
    // bump).
    spec_version: 4,
    impl_version: 1,
    apis: RUNTIME_API_VERSIONS,
    // ADR-032: bumped 1 -> 2. transaction_version signals a change to the
    // SCALE-decoded shape of an extrinsic's `extra` field, independent of
    // whether any pallet call/dispatch logic changed -- exactly what
    // appending ChargeTip as TxExtension's tenth element does. This field
    // has never changed since genesis before this: control-plane's
    // TestSupportedTransactionVersionMatchesRuntime (added alongside this
    // change) is this repo's first drift guard for it, closing the same
    // gap issue #123 found for spec_version alone.
    transaction_version: 2,
    system_version: 1,
};

#[cfg(feature = "std")]
pub fn native_version() -> NativeVersion {
    NativeVersion {
        runtime_version: VERSION,
        can_author_with: Default::default(),
    }
}

/// Carries an optional tip, used only to influence transaction-pool
/// `priority` (ADR-032). Deducts nothing from any account -- this chain has
/// no fee mechanism (`pallet-transaction-payment` is deliberately not a
/// dependency: its `prepare` step unconditionally withdraws
/// `inclusion_fee + tip` from every signed extrinsic, a real behavioral
/// change this MVP chain has no reason to take on for a problem that
/// doesn't require it), and this extension does not introduce one -- see
/// `charge_tip_never_touches_any_balance` below.
///
/// Mechanism: nothing in this runtime's `TxExtension` tuple sets a nonzero
/// `priority` on the `ValidTransaction` it returns today (every extension
/// ahead of `ChargeTip` affects only `requires`/`provides`/weight), so a
/// direct `priority = tip + 1` is the entire signal needed -- no
/// `max_tx_per_block`-scaled formula (the shape
/// `pallet-transaction-payment::get_priority` uses to stay meaningful
/// alongside *other* weight-based-fee priority contributions) is solving a
/// problem this chain has. The `+ 1` tie-breaks two zero-tip transactions
/// ahead of the bare-default priority of 0, matching
/// `pallet-transaction-payment`'s own convention for the same reason. The
/// transaction pool's own displacement rule
/// (`sc-transaction-pool::graph::ready::replace_previous`) rejects an
/// incoming transaction with `old_priority >= tx.priority` and otherwise
/// evicts the old one -- so any resubmission with a strictly higher tip
/// than whatever it collides with wins the slot outright.
///
/// `ChargeTip` is appended as the tenth and last `TxExtension` element,
/// after `WeightReclaim`: every extension ahead of it keeps encoding
/// exactly the bytes it does today, so existing `extra` bytes are a strict
/// prefix of the new `extra` bytes, not reshuffled.
#[derive(Encode, Decode, DecodeWithMemTracking, Clone, Eq, PartialEq, TypeInfo, Debug)]
pub struct ChargeTip(#[codec(compact)] pub u64);

impl TransactionExtension<RuntimeCall> for ChargeTip {
    const IDENTIFIER: &'static str = "ChargeTip";
    type Implicit = ();
    type Val = ();
    type Pre = ();

    fn weight(&self, _call: &RuntimeCall) -> Weight {
        // Pure function of `self`, no storage reads.
        Weight::zero()
    }

    fn validate(
        &self,
        origin: RuntimeOrigin,
        _call: &RuntimeCall,
        _info: &DispatchInfoOf<RuntimeCall>,
        _len: usize,
        _self_implicit: Self::Implicit,
        _inherited_implication: &impl Encode,
        _source: TransactionSource,
    ) -> ValidateResult<Self::Val, RuntimeCall> {
        let priority = self.0.saturating_add(1);
        Ok((
            ValidTransaction {
                priority,
                ..Default::default()
            },
            (),
            origin,
        ))
    }

    fn prepare(
        self,
        _val: Self::Val,
        _origin: &RuntimeOrigin,
        _call: &RuntimeCall,
        _info: &DispatchInfoOf<RuntimeCall>,
        _len: usize,
    ) -> Result<Self::Pre, TransactionValidityError> {
        // Never withdraws, reserves, or otherwise touches any account's
        // balance -- see charge_tip_never_touches_any_balance below.
        Ok(())
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
    ChargeTip,
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
    #[runtime::pallet_index(16)]
    pub type NetworkValidator = pallet_network_validator::Pallet<Runtime>;
    #[runtime::pallet_index(17)]
    pub type Escrow = pallet_escrow::Pallet<Runtime>;
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
    pub const MaxProofAge: u32 = 1_000;
    pub const MaxRewardResourceUnits: u64 = 1_000_000_000;
    pub const MaxRewardDuration: u64 = 10_000_000;
    pub const MinValidatorStake: u64 = 1_000;
    pub const ValidatorUnbondingPeriod: u32 = 14_400; // ~1 day at 6s blocks
    pub const MaxValidatorSubmissionsPerRound: u32 = 32;
    // Three independent submissions is the smallest committee where the
    // trimmed mean can discard an outlier at both ends (ADR-011 §5).
    pub const ValidatorMinQuorum: u32 = 3;
    pub const ValidatorTargetCommitteeSize: u32 = 5;
    pub const MaxNetworkValidators: u32 = 256;
    // ~30 minutes at 6s blocks to contest a closed round.
    pub const ValidatorDisputeWindow: u32 = 300;
    pub const ValidatorPointsPerAcceptedSubmission: u64 = 10;
    // ADR-018 §3: bounded per-incident slash, deliberately a fraction of
    // MinValidatorStake (10%) rather than the whole bond -- repeated
    // upheld disputes compound instead of one governance call being able
    // to destroy a participant's entire stake at once.
    pub const ValidatorSlashAmount: u64 = 100;
    // ADR-029 §4.3: self-service refund window for an uncompleted escrow.
    // ~1 day at 6s blocks, same order of magnitude as
    // ValidatorUnbondingPeriod -- long enough that a slow-but-honest relayer
    // still has time to submit completion evidence before a payer reclaims
    // its funds.
    pub const EscrowRefundWindow: u32 = 14_400;
    // ADR-029 §4.4/§7: mirrors ValidatorDisputeWindow -- ~30 minutes at 6s
    // blocks to contest a settled escrow.
    pub const EscrowDisputeWindow: u32 = 300;
    // ADR-029 §1/§6: safety cap on a single evidence record's claimed
    // period_end - period_start, mirroring MaxProofAge's shape. Not the
    // expected reporting cadence (that is #20's own, much shorter,
    // metering-interval concern) -- this only bounds how large one
    // complete_and_payout call's claimed period may be. ~1 day at 6s
    // blocks.
    pub const EscrowMaxMeteringPeriod: u32 = 14_400;
    // ADR-029 §4.1/§7: dust threshold, just above ExistentialDeposit --
    // rejects escrows too small to be worth the storage.
    pub const MinEscrowAmount: u64 = 100;
    // ADR-029 §5: bounded per-incident reliability penalty on
    // resolve_dispute's RefundPayer outcome, in basis points (0..=10_000).
    // 10%, the same fraction ValidatorSlashAmount uses of MinValidatorStake
    // -- a repeated upheld dispute compounds rather than one governance
    // call zeroing a provider's reliability score at once.
    pub const EscrowReliabilityPenaltyBps: u16 = 1_000;
    // ADR-030 Sec4: compile-time hard cap on the governed FeeBasisPoints
    // rate -- 2,000 bps (20%). Generous room for governance to adjust the
    // rate for years of plausible commission-style pricing without a
    // runtime upgrade, while hard-blocking any single set_fee_basis_points
    // call from reaching anything close to confiscatory without one.
    pub const EscrowMaxFeeBasisPoints: u16 = 2_000;
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
    // Same delegation as pallet_provider_registry::RegistrationOrigin
    // above: the Control Plane bridge publishes on a provider's behalf.
    type AnnounceOrigin = frame_system::EnsureRoot<Self::AccountId>;
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

/// Bridges `pallet-network-validator`'s registry into the narrow
/// `NetworkValidatorInspector` traits `availability`/`reputation` each
/// declare, mirroring `RegisteredProviderInspector` above (ADR-011).
pub struct ActiveValidatorLookup;
impl pallet_availability::NetworkValidatorInspector<interface::AccountId>
    for ActiveValidatorLookup
{
    fn is_active(validator: &interface::AccountId) -> bool {
        NetworkValidator::is_active(validator)
    }
}
impl pallet_reputation::NetworkValidatorInspector<interface::AccountId> for ActiveValidatorLookup {
    fn is_active(validator: &interface::AccountId) -> bool {
        NetworkValidator::is_active(validator)
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
    // Was EnsureRoot (the Control Plane bridge acting alone); ADR-011
    // moves routine scoring to signed, registry-checked Network Validator
    // accounts. EnsureRoot is kept only on pallet-network-validator's own
    // SuspensionOrigin, for emergency admin overrides.
    type UpdateOrigin = pallet_reputation::EnsureActiveValidator<Runtime>;
    type ProviderInspector = RegisteredProviderInspector;
    type ValidatorInspector = ActiveValidatorLookup;
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
    // Unchanged: the Control Plane still issues on-chain challenges.
    type ChallengeOrigin = frame_system::EnsureRoot<Self::AccountId>;
    // Was EnsureRoot; ADR-011 moves proof submission to signed,
    // registry-checked Network Validator accounts.
    type ProofOrigin = pallet_availability::EnsureActiveValidator<Runtime>;
    type ProviderInspector = RegisteredProviderInspector;
    type ValidatorInspector = ActiveValidatorLookup;
    type MaxPendingChallenges = MaxPendingChallenges;
    type MaxChallengeLifetime = MaxChallengeLifetime;
    type MaxProofAge = MaxProofAge;
    type MaxProofSamples = frame::traits::ConstU32<10_000>;
    type WeightInfo = ();
}

/// Applies closed-round aggregates to the reputation vector, mapping the
/// scoring pallet's `ScoreDimension` onto `pallet-reputation`'s own
/// `VectorDimension` so neither pallet depends on the other's types.
pub struct ScoringReputationUpdater;
impl pallet_network_validator::ReputationUpdater<interface::AccountId>
    for ScoringReputationUpdater
{
    fn record_dimension_score(
        provider: &interface::AccountId,
        dimension: pallet_network_validator::ScoreDimension,
        score_bps: u16,
    ) -> frame::deps::sp_runtime::DispatchResult {
        pallet_reputation::Pallet::<Runtime>::set_dimension_score(
            provider,
            Self::map_dimension(dimension),
            score_bps,
        )
    }

    fn dimension_score(
        provider: &interface::AccountId,
        dimension: pallet_network_validator::ScoreDimension,
    ) -> u16 {
        pallet_reputation::Pallet::<Runtime>::dimension_score_bps(
            provider,
            Self::map_dimension(dimension),
        )
    }
}

impl ScoringReputationUpdater {
    fn map_dimension(
        dimension: pallet_network_validator::ScoreDimension,
    ) -> pallet_reputation::pallet::VectorDimension {
        use pallet_network_validator::ScoreDimension;
        use pallet_reputation::pallet::VectorDimension;
        match dimension {
            ScoreDimension::Compute => VectorDimension::Compute,
            ScoreDimension::Storage => VectorDimension::Storage,
            ScoreDimension::Network => VectorDimension::Network,
            ScoreDimension::Availability => VectorDimension::Availability,
            ScoreDimension::Reliability => VectorDimension::Reliability,
        }
    }
}

/// Credits validator Reward Points through `pallet-rewards`, which stays
/// the only writer of reward balances (ADR-011 §5).
pub struct ValidatorRewardsBridge;
impl pallet_network_validator::ValidatorRewards<interface::AccountId> for ValidatorRewardsBridge {
    fn accrue(
        validator: &interface::AccountId,
        points: u64,
    ) -> frame::deps::sp_runtime::DispatchResult {
        pallet_openinfra_rewards::Pallet::<Runtime>::accrue_points(validator, points)
    }
}

/// Bridges `pallet-escrow`'s per-payer open-escrow counter into
/// `pallet-network-validator`'s narrow `EscrowPayerInspector` trait (the
/// reserve-contamination fix's reverse guard, symmetric to
/// `EscrowValidatorInspectorBridge` below): `register_validator` must not
/// succeed for an account that currently has funds locked in an open
/// escrow as `payer`.
pub struct EscrowPayerInspectorBridge;
impl pallet_network_validator::EscrowPayerInspector<interface::AccountId>
    for EscrowPayerInspectorBridge
{
    fn has_open_escrow(payer: &interface::AccountId) -> bool {
        pallet_escrow::PayerOpenEscrowCount::<Runtime>::get(payer) > 0
    }
}

impl pallet_network_validator::Config for Runtime {
    type Currency = Balances;
    type ReputationUpdater = ScoringReputationUpdater;
    type ValidatorRewards = ValidatorRewardsBridge;
    // Suspend/reinstate is root-gated for the MVP; a validator
    // committee/governance origin is ADR-011 §5 follow-up work, not decided
    // by this pallet yet.
    type SuspensionOrigin = frame_system::EnsureRoot<Self::AccountId>;
    // Reserve-contamination fix: register_validator must not bond stake for
    // an account with funds locked in an open escrow as payer.
    type EscrowInspector = EscrowPayerInspectorBridge;
    type MinStake = MinValidatorStake;
    type UnbondingPeriod = ValidatorUnbondingPeriod;
    type MaxSubmissionsPerRound = MaxValidatorSubmissionsPerRound;
    type MinQuorum = ValidatorMinQuorum;
    type TargetCommitteeSize = ValidatorTargetCommitteeSize;
    type MaxValidators = MaxNetworkValidators;
    type DisputeWindow = ValidatorDisputeWindow;
    type PointsPerAcceptedSubmission = ValidatorPointsPerAcceptedSubmission;
    type SlashAmount = ValidatorSlashAmount;
    type WeightInfo = ();
}

/// Bridges `pallet-provider-registry`'s already-on-chain
/// `Provider.public_key` into escrow's narrow `ProviderKeyLookup` trait
/// (ADR-029 §3), so `pallet-escrow` carries no hard compile dependency on
/// `pallet-provider-registry`.
pub struct ProviderKeyLookupBridge;
impl pallet_escrow::ProviderKeyLookup<interface::AccountId> for ProviderKeyLookupBridge {
    fn public_key(provider: &interface::AccountId) -> Option<[u8; 32]> {
        pallet_provider_registry::Providers::<Runtime>::get(provider)
            .map(|record| record.public_key)
    }
}

/// Narrow, read-only sanity check that a lease id exists -- deliberately
/// not a check against `pallet-lease`'s `consumer` field (ADR-029 §3).
pub struct LeaseExistsBridge;
impl pallet_escrow::LeaseExists for LeaseExistsBridge {
    fn exists(lease_id: pallet_escrow::LeaseId) -> bool {
        pallet_openinfra_lease::Leases::<Runtime>::contains_key(lease_id)
    }
}

/// Applies escrow's dispute-loss consequence (ADR-029 §5) to a provider's
/// `Reliability` reputation dimension, through `pallet-reputation`'s
/// existing non-extrinsic `set_dimension_score` entry point -- the same
/// pattern `ScoringReputationUpdater` above already uses, so
/// `pallet-reputation` stays the only writer of the reputation vector
/// regardless of which pallet triggered the update.
pub struct EscrowReputationPenaltyBridge;
impl pallet_escrow::ReputationPenalty<interface::AccountId> for EscrowReputationPenaltyBridge {
    fn apply(
        provider: &interface::AccountId,
        penalty_bps: u16,
    ) -> frame::deps::sp_runtime::DispatchResult {
        let current = pallet_reputation::Pallet::<Runtime>::dimension_score_bps(
            provider,
            pallet_reputation::pallet::VectorDimension::Reliability,
        );
        let penalized = current.saturating_sub(penalty_bps);
        pallet_reputation::Pallet::<Runtime>::set_dimension_score(
            provider,
            pallet_reputation::pallet::VectorDimension::Reliability,
            penalized,
        )
    }
}

/// Bridges `pallet-network-validator`'s registry into `pallet-escrow`'s
/// narrow `ValidatorRegistrationInspector` trait (the reserve-contamination
/// fix): checks presence in `Validators` regardless of status --
/// `Active`, `Suspended`, and `Exiting` all still hold real bonded stake
/// reserved until `withdraw_unbonded` actually releases it, unlike
/// `ActiveValidatorLookup` above, which deliberately narrows to `Active`
/// for a different purpose (gating submission rights).
pub struct EscrowValidatorInspectorBridge;
impl pallet_escrow::ValidatorRegistrationInspector<interface::AccountId>
    for EscrowValidatorInspectorBridge
{
    fn is_registered(account: &interface::AccountId) -> bool {
        pallet_network_validator::Validators::<Runtime>::contains_key(account)
    }
}

impl pallet_escrow::Config for Runtime {
    // Sec2: reuses pallet_balances, the same ReservableCurrency already
    // backing Network Validator stake -- no new asset pallet.
    type Currency = Balances;
    type ProviderKeyLookup = ProviderKeyLookupBridge;
    type LeaseExists = LeaseExistsBridge;
    type ReputationPenalty = EscrowReputationPenaltyBridge;
    // Reserve-contamination fix: fund_escrow must not accept a payer who
    // is currently a registered Network Validator.
    type ValidatorInspector = EscrowValidatorInspectorBridge;
    // Sec4.5/Sec9: the sole remaining sudo-key surface in this pallet.
    type DisputeOrigin = frame_system::EnsureRoot<Self::AccountId>;
    // Sec10: emergency circuit breaker.
    type PauseOrigin = frame_system::EnsureRoot<Self::AccountId>;
    // ADR-030 Sec3: governs set_fee_basis_points/set_treasury_account,
    // the same EnsureRoot surface as DisputeOrigin/PauseOrigin above.
    type FeeGovernanceOrigin = frame_system::EnsureRoot<Self::AccountId>;
    type RefundWindow = EscrowRefundWindow;
    type DisputeWindow = EscrowDisputeWindow;
    type MaxMeteringPeriodSeconds = EscrowMaxMeteringPeriod;
    type MinEscrowAmount = MinEscrowAmount;
    type ReliabilityPenaltyBps = EscrowReliabilityPenaltyBps;
    type MaxFeeBasisPoints = EscrowMaxFeeBasisPoints;
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
    use polkadot_sdk::sp_runtime::traits::TxBaseImplication;

    #[test]
    fn development_genesis_builds() {
        assert!(genesis_config_presets::development_config_genesis().is_object());
    }

    /// End-to-end reproduction of the reserve-balance contamination
    /// finding's exact attack shape, exercised against the real runtime
    /// wiring (not a pallet-level mock): register an account as a Network
    /// Validator, then attempt to fund an escrow as that same account, and
    /// the symmetric order. Both are rejected outright, with the specific
    /// new error and no state change -- the precondition the finding
    /// depends on (one AccountId holding both roles, both drawing on the
    /// same untagged `pallet_balances` reserved pool) can no longer be
    /// created through either pallet's real, wired-together entry point.
    #[test]
    fn escrow_payer_and_network_validator_roles_are_mutually_exclusive() {
        use frame_support::{assert_noop, assert_ok};
        use polkadot_sdk::sp_runtime::BuildStorage;

        let already_validator = interface::AccountId::from([1_u8; 32]);
        let already_payer = interface::AccountId::from([2_u8; 32]);
        let provider = interface::AccountId::from([3_u8; 32]);

        let mut storage = frame_system::GenesisConfig::<Runtime>::default()
            .build_storage()
            .unwrap();
        pallet_balances::GenesisConfig::<Runtime> {
            balances: vec![
                (already_validator.clone(), 1_000_000),
                (already_payer.clone(), 1_000_000),
            ],
            ..Default::default()
        }
        .assimilate_storage(&mut storage)
        .unwrap();
        let mut ext: sp_io::TestExternalities = storage.into();

        ext.execute_with(|| {
            System::set_block_number(1);

            // Satisfy fund_escrow's LeaseExists sanity check directly --
            // this test is about the validator/payer guard, not lease
            // creation's own provider-eligibility flow.
            let lease_id: pallet_escrow::LeaseId = 1;
            pallet_openinfra_lease::Leases::<Runtime>::insert(
                lease_id,
                pallet_openinfra_lease::Lease::<Runtime> {
                    provider: provider.clone(),
                    consumer: already_validator.clone(),
                    resource_hash: [0u8; 32],
                    start: 0,
                    end: 1_000,
                    state: pallet_openinfra_lease::LeaseState::Created,
                },
            );
            let price = pallet_escrow::PriceSchedule {
                cpu_core_second: 1,
                ram_mb_second: 1,
                storage_gb_second: 1,
                network_mb: 1,
            };

            // Direction 1: register as a Network Validator first, then
            // attempt to fund an escrow as the same account as payer.
            assert_ok!(NetworkValidator::register_validator(
                RuntimeOrigin::signed(already_validator.clone()),
                MinValidatorStake::get(),
            ));
            assert_noop!(
                Escrow::fund_escrow(
                    RuntimeOrigin::signed(already_validator.clone()),
                    lease_id,
                    provider.clone(),
                    MinEscrowAmount::get() + 100,
                    price,
                    1,
                ),
                pallet_escrow::Error::<Runtime>::PayerIsRegisteredValidator
            );
            assert!(pallet_escrow::Escrows::<Runtime>::get(lease_id).is_none());

            // Direction 2 (symmetric order): fund an escrow as payer
            // first, then attempt to register the same account as a
            // Network Validator while that escrow is still open.
            let other_lease_id: pallet_escrow::LeaseId = 2;
            pallet_openinfra_lease::Leases::<Runtime>::insert(
                other_lease_id,
                pallet_openinfra_lease::Lease::<Runtime> {
                    provider: provider.clone(),
                    consumer: already_payer.clone(),
                    resource_hash: [0u8; 32],
                    start: 0,
                    end: 1_000,
                    state: pallet_openinfra_lease::LeaseState::Created,
                },
            );
            assert_ok!(Escrow::fund_escrow(
                RuntimeOrigin::signed(already_payer.clone()),
                other_lease_id,
                provider.clone(),
                MinEscrowAmount::get() + 100,
                price,
                1,
            ));
            assert_noop!(
                NetworkValidator::register_validator(
                    RuntimeOrigin::signed(already_payer.clone()),
                    MinValidatorStake::get(),
                ),
                pallet_network_validator::Error::<Runtime>::PayerHasOpenEscrow
            );
            assert!(pallet_network_validator::Validators::<Runtime>::get(&already_payer).is_none());
        });
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

    /// A ChargeTip-shaped `register_provider_for` call, origin, and
    /// `DispatchInfo` -- shared by the ADR-032 tests below since none of
    /// them care which call ChargeTip is wrapping (it never inspects the
    /// call at all).
    fn charge_tip_test_fixture(
        seed: u8,
    ) -> (
        RuntimeCall,
        RuntimeOrigin,
        frame_support::dispatch::DispatchInfo,
    ) {
        let provider = interface::AccountId::from([seed; 32]);
        let call =
            RuntimeCall::ProviderRegistry(pallet_provider_registry::Call::register_provider_for {
                provider: provider.clone(),
                public_key: [seed; 32],
            });
        let origin = RuntimeOrigin::signed(provider);
        let info = frame_support::dispatch::DispatchInfo::default();
        (call, origin, info)
    }

    /// ADR-032 Sec2: `priority = tip + 1` is the entire mechanism, for any
    /// tip value -- including the saturating edge at `u64::MAX`, which must
    /// not panic or wrap.
    #[test]
    fn charge_tip_sets_priority_to_tip_plus_one_for_a_range_of_values() {
        let (call, origin, info) = charge_tip_test_fixture(1);

        for tip in [0_u64, 1, 5, 42, 100, u64::MAX - 1, u64::MAX] {
            let (validity, _, _) = ChargeTip(tip)
                .validate(
                    origin.clone(),
                    &call,
                    &info,
                    0,
                    (),
                    &TxBaseImplication(&call),
                    TransactionSource::External,
                )
                .expect("ChargeTip::validate must never itself reject a transaction");
            let expected_priority = tip.saturating_add(1);
            assert_eq!(
                validity.priority, expected_priority,
                "tip {tip} should produce priority {expected_priority}, got {}",
                validity.priority
            );
        }
    }

    /// No regression for the common case (ADR-032 non-goals): a zero tip
    /// -- what every call site used before this ADR, and every call site
    /// except a bounded 1014 retry uses after it -- must validate exactly
    /// like `ValidTransaction::default()` in every field except `priority`
    /// (1, not 0): unbounded longevity, empty requires/provides, and
    /// `propagate: true` are all untouched by ChargeTip.
    #[test]
    fn charge_tip_zero_matches_the_pre_adr_032_default_case_except_priority() {
        let (call, origin, info) = charge_tip_test_fixture(2);

        let (validity, _, _) = ChargeTip(0)
            .validate(
                origin,
                &call,
                &info,
                0,
                (),
                &TxBaseImplication(&call),
                TransactionSource::External,
            )
            .expect("ChargeTip::validate must never itself reject a transaction");

        let expected = ValidTransaction {
            priority: 1,
            ..Default::default()
        };
        assert_eq!(validity, expected);
    }

    /// ADR-032 Sec1/non-goals' central guarantee, verified end to end
    /// against the real runtime wiring (not a mock): `ChargeTip` never
    /// withdraws, reserves, or otherwise touches any account's balance --
    /// this chain has no fee mechanism, and this extension does not
    /// introduce one. Both `validate` and `prepare` are exercised (the two
    /// pipeline stages that run before/at dispatch), with a nonzero tip
    /// specifically, since a zero tip touching no balance would be the
    /// least interesting case to prove.
    #[test]
    fn charge_tip_never_touches_any_balance() {
        use polkadot_sdk::sp_runtime::BuildStorage;

        let account = interface::AccountId::from([3_u8; 32]);
        let mut storage = frame_system::GenesisConfig::<Runtime>::default()
            .build_storage()
            .unwrap();
        pallet_balances::GenesisConfig::<Runtime> {
            balances: vec![(account.clone(), 1_000_000)],
            ..Default::default()
        }
        .assimilate_storage(&mut storage)
        .unwrap();
        let mut ext: sp_io::TestExternalities = storage.into();

        ext.execute_with(|| {
            System::set_block_number(1);

            let free_before = Balances::free_balance(&account);
            let reserved_before = Balances::reserved_balance(&account);
            assert_eq!(free_before, 1_000_000);
            assert_eq!(reserved_before, 0);

            let (call, origin, info) = charge_tip_test_fixture(3);
            let tip = ChargeTip(50);

            let (_, val, origin) = tip
                .clone()
                .validate(
                    origin,
                    &call,
                    &info,
                    0,
                    (),
                    &TxBaseImplication(&call),
                    TransactionSource::External,
                )
                .expect("ChargeTip::validate must never itself reject a transaction");
            tip.prepare(val, &origin, &call, &info, 0)
                .expect("ChargeTip::prepare must never itself reject a transaction");

            assert_eq!(
                Balances::free_balance(&account),
                free_before,
                "ChargeTip must never change free_balance"
            );
            assert_eq!(
                Balances::reserved_balance(&account),
                reserved_before,
                "ChargeTip must never change reserved_balance"
            );
        });
    }
}
