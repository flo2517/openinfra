use crate as pallet_escrow;
use crate::{DisputeOutcome, EscrowState, LeaseId, MeteringSummary, PriceSchedule};
use frame_support::{
    assert_noop, assert_ok, derive_impl, parameter_types,
    traits::{ConstU64, ReservableCurrency},
};
use sp_core::{ed25519, Pair};
use sp_runtime::{BuildStorage, DispatchError};

type Block = frame_system::mocking::MockBlock<Test>;
frame_support::construct_runtime!(
    pub enum Test {
        System: frame_system,
        Balances: pallet_balances,
        Escrow: pallet_escrow,
    }
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
    type AccountData = pallet_balances::AccountData<u64>;
}

#[derive_impl(pallet_balances::config_preludes::TestDefaultConfig)]
impl pallet_balances::Config for Test {
    type ExistentialDeposit = ConstU64<1>;
    type AccountStore = System;
}

const PAYER: u64 = 1;
const PROVIDER: u64 = 2;
const OTHER: u64 = 3;
const UNFUNDED: u64 = 4;
const LEASE: LeaseId = 42;
const OTHER_LEASE: LeaseId = 43;

/// The provider's real, registered signing key -- deterministic so tests
/// are reproducible.
fn provider_pair() -> ed25519::Pair {
    ed25519::Pair::from_seed(&[7u8; 32])
}

/// A key that is *not* registered as the provider's -- used to build a
/// forged signature.
fn forged_pair() -> ed25519::Pair {
    ed25519::Pair::from_seed(&[9u8; 32])
}

pub struct TestProviderKeyLookup;
impl crate::ProviderKeyLookup<u64> for TestProviderKeyLookup {
    fn public_key(provider: &u64) -> Option<[u8; 32]> {
        if *provider == PROVIDER {
            Some(provider_pair().public().0)
        } else {
            None
        }
    }
}

thread_local! {
    static LEASE_EXISTS: std::cell::RefCell<bool> = const { std::cell::RefCell::new(true) };
    static PENALTIES: std::cell::RefCell<Vec<(u64, u16)>> =
        const { std::cell::RefCell::new(Vec::new()) };
    static REGISTERED_VALIDATORS: std::cell::RefCell<std::collections::BTreeSet<u64>> =
        const { std::cell::RefCell::new(std::collections::BTreeSet::new()) };
}

/// Mock for the reserve-contamination guard's forward direction
/// (`fund_escrow` rejects a payer who is a registered Network Validator).
/// Controlled per-test via [`set_registered_validator`], independent of
/// `pallet-network-validator` -- this pallet carries no dependency on it,
/// same narrow-trait pattern as `TestProviderKeyLookup`/`TestLeaseExists`.
pub struct TestValidatorInspector;
impl crate::ValidatorRegistrationInspector<u64> for TestValidatorInspector {
    fn is_registered(account: &u64) -> bool {
        REGISTERED_VALIDATORS.with(|set| set.borrow().contains(account))
    }
}

fn set_registered_validator(account: u64, registered: bool) {
    REGISTERED_VALIDATORS.with(|set| {
        if registered {
            set.borrow_mut().insert(account);
        } else {
            set.borrow_mut().remove(&account);
        }
    });
}

pub struct TestLeaseExists;
impl crate::LeaseExists for TestLeaseExists {
    fn exists(_: LeaseId) -> bool {
        LEASE_EXISTS.with(|value| *value.borrow())
    }
}

fn set_lease_exists(value: bool) {
    LEASE_EXISTS.with(|cell| *cell.borrow_mut() = value);
}

pub struct RecordingReputationPenalty;
impl crate::ReputationPenalty<u64> for RecordingReputationPenalty {
    fn apply(provider: &u64, penalty_bps: u16) -> sp_runtime::DispatchResult {
        PENALTIES.with(|cell| cell.borrow_mut().push((*provider, penalty_bps)));
        Ok(())
    }
}

fn penalties() -> Vec<(u64, u16)> {
    PENALTIES.with(|cell| cell.borrow().clone())
}

fn reset_fixtures() {
    set_lease_exists(true);
    PENALTIES.with(|cell| cell.borrow_mut().clear());
    REGISTERED_VALIDATORS.with(|set| set.borrow_mut().clear());
}

parameter_types! {
    pub const RefundWindow: u64 = 10;
    pub const DisputeWindow: u64 = 10;
    pub const MaxMeteringPeriodSeconds: u64 = 100;
    pub const MinEscrowAmount: u64 = 10;
    pub const ReliabilityPenaltyBps: u16 = 500;
}

impl crate::Config for Test {
    type Currency = Balances;
    type ProviderKeyLookup = TestProviderKeyLookup;
    type LeaseExists = TestLeaseExists;
    type ReputationPenalty = RecordingReputationPenalty;
    type ValidatorInspector = TestValidatorInspector;
    type DisputeOrigin = frame_system::EnsureRoot<u64>;
    type PauseOrigin = frame_system::EnsureRoot<u64>;
    type RefundWindow = RefundWindow;
    type DisputeWindow = DisputeWindow;
    type MaxMeteringPeriodSeconds = MaxMeteringPeriodSeconds;
    type MinEscrowAmount = MinEscrowAmount;
    type ReliabilityPenaltyBps = ReliabilityPenaltyBps;
    type WeightInfo = ();
}

fn new_test_ext() -> sp_io::TestExternalities {
    reset_fixtures();
    let mut storage = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();
    pallet_balances::GenesisConfig::<Test> {
        balances: vec![
            (PAYER, 1_000_000),
            (PROVIDER, 1_000_000),
            (OTHER, 1_000_000),
            (UNFUNDED, MinEscrowAmount::get() - 1),
        ],
        ..Default::default()
    }
    .assimilate_storage(&mut storage)
    .unwrap();
    let mut ext: sp_io::TestExternalities = storage.into();
    ext.execute_with(|| System::set_block_number(1));
    ext
}

fn price() -> PriceSchedule {
    PriceSchedule {
        cpu_core_second: 2,
        ram_mb_second: 1,
        storage_gb_second: 3,
        network_mb: 5,
    }
}

fn fund(max_charge: u64) -> sp_runtime::DispatchResult {
    Escrow::fund_escrow(
        RuntimeOrigin::signed(PAYER),
        LEASE,
        PROVIDER,
        max_charge,
        price(),
        1,
    )
}

#[allow(clippy::too_many_arguments)]
fn signed_evidence(
    pair: &ed25519::Pair,
    lease_id: LeaseId,
    sequence: u64,
    period_start: u64,
    period_end: u64,
    cpu: u64,
    ram: u64,
    storage: u64,
    egress: u64,
    ingress: u64,
    gpu: u64,
    schema_version: u16,
) -> MeteringSummary<u64> {
    let mut evidence = MeteringSummary {
        lease_id,
        sequence,
        period_start,
        period_end,
        cpu_core_seconds: cpu,
        ram_mb_seconds: ram,
        storage_gb_seconds: storage,
        network_egress_mb: egress,
        network_ingress_mb: ingress,
        gpu_seconds: gpu,
        metering_schema_version: schema_version,
        signature: [0u8; 64],
    };
    let payload = Escrow::metering_signing_payload(&evidence);
    evidence.signature = pair.sign(&payload).0;
    evidence
}

/// The "normal" evidence used by most `complete_and_payout` tests:
/// charged_amount = 10*2 + 20*1 + 5*3 + (3+2)*5 = 20+20+15+25 = 80.
fn normal_evidence() -> MeteringSummary<u64> {
    signed_evidence(&provider_pair(), LEASE, 1, 0, 10, 10, 20, 5, 3, 2, 100, 1)
}

// ---------------------------------------------------------------------
// fund_escrow
// ---------------------------------------------------------------------

#[test]
fn fund_escrow_reserves_funds_and_creates_record() {
    new_test_ext().execute_with(|| {
        assert_ok!(fund(200));
        assert_eq!(Balances::reserved_balance(PAYER), 200);
        assert_eq!(Balances::free_balance(PAYER), 999_800);
        let escrow = Escrow::escrows(LEASE).unwrap();
        assert_eq!(escrow.payer, PAYER);
        assert_eq!(escrow.provider, PROVIDER);
        assert_eq!(escrow.max_charge, 200);
        assert_eq!(escrow.state, EscrowState::Funded);
        assert_eq!(escrow.last_evidence_sequence, 0);
    });
}

#[test]
fn fund_escrow_rejects_duplicate_lease_id() {
    new_test_ext().execute_with(|| {
        assert_ok!(fund(200));
        assert_noop!(fund(200), crate::Error::<Test>::EscrowAlreadyFunded);
    });
}

#[test]
fn fund_escrow_rejects_below_minimum() {
    new_test_ext().execute_with(|| {
        assert_noop!(fund(1), crate::Error::<Test>::EscrowBelowMinimum);
    });
}

#[test]
fn fund_escrow_rejects_insufficient_free_balance() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            Escrow::fund_escrow(
                RuntimeOrigin::signed(UNFUNDED),
                LEASE,
                PROVIDER,
                1_000_000,
                price(),
                1
            ),
            crate::Error::<Test>::InsufficientFreeBalance
        );
    });
}

#[test]
fn fund_escrow_rejects_nonexistent_lease() {
    new_test_ext().execute_with(|| {
        set_lease_exists(false);
        assert_noop!(fund(200), crate::Error::<Test>::LeaseDoesNotExist);
    });
}

#[test]
fn fund_escrow_rejects_unsigned_origin() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            Escrow::fund_escrow(RuntimeOrigin::none(), LEASE, PROVIDER, 200, price(), 1),
            DispatchError::BadOrigin
        );
    });
}

#[test]
fn fund_escrow_rejects_when_paused() {
    new_test_ext().execute_with(|| {
        assert_ok!(Escrow::set_paused(RuntimeOrigin::root(), true));
        assert_noop!(fund(200), crate::Error::<Test>::Paused);
    });
}

// ---------------------------------------------------------------------
// complete_and_payout: happy path
// ---------------------------------------------------------------------

#[test]
fn complete_and_payout_pays_provider_and_refunds_remainder() {
    new_test_ext().execute_with(|| {
        assert_ok!(fund(200));
        assert_ok!(Escrow::complete_and_payout(
            RuntimeOrigin::signed(OTHER), // permissionless: any relayer
            LEASE,
            normal_evidence()
        ));
        // charged_amount = 80, remainder = 120.
        assert_eq!(Balances::free_balance(PROVIDER), 1_000_080);
        assert_eq!(Balances::reserved_balance(PAYER), 0);
        assert_eq!(Balances::free_balance(PAYER), 999_920);
        let escrow = Escrow::escrows(LEASE).unwrap();
        assert_eq!(escrow.state, EscrowState::Completed);
        assert_eq!(escrow.last_evidence_sequence, 1);
    });
}

#[test]
fn complete_and_payout_emits_settled_event_with_evidence_hash() {
    new_test_ext().execute_with(|| {
        assert_ok!(fund(200));
        let evidence = normal_evidence();
        let expected_hash = frame_support::Hashable::blake2_256(&evidence);
        assert_ok!(Escrow::complete_and_payout(
            RuntimeOrigin::signed(OTHER),
            LEASE,
            evidence
        ));
        let found = System::events().into_iter().any(|record| {
            matches!(
                record.event,
                RuntimeEvent::Escrow(crate::Event::EscrowSettled {
                    lease_id: LEASE,
                    provider: PROVIDER,
                    charged_amount: 80,
                    evidence_hash,
                }) if evidence_hash == expected_hash
            )
        });
        assert!(
            found,
            "EscrowSettled with the expected evidence hash was not emitted"
        );
    });
}

#[test]
fn complete_and_payout_zero_usage_refunds_everything() {
    new_test_ext().execute_with(|| {
        assert_ok!(fund(200));
        let evidence = signed_evidence(&provider_pair(), LEASE, 1, 0, 10, 0, 0, 0, 0, 0, 0, 1);
        assert_ok!(Escrow::complete_and_payout(
            RuntimeOrigin::signed(OTHER),
            LEASE,
            evidence
        ));
        assert_eq!(Balances::free_balance(PROVIDER), 1_000_000);
        assert_eq!(Balances::free_balance(PAYER), 1_000_000);
        assert_eq!(Balances::reserved_balance(PAYER), 0);
    });
}

// ---------------------------------------------------------------------
// complete_and_payout: adversarial cases
// ---------------------------------------------------------------------

#[test]
fn complete_and_payout_rejects_double_completion() {
    new_test_ext().execute_with(|| {
        assert_ok!(fund(200));
        assert_ok!(Escrow::complete_and_payout(
            RuntimeOrigin::signed(OTHER),
            LEASE,
            normal_evidence()
        ));
        let replay = signed_evidence(&provider_pair(), LEASE, 2, 10, 20, 1, 1, 1, 1, 1, 0, 1);
        assert_noop!(
            Escrow::complete_and_payout(RuntimeOrigin::signed(OTHER), LEASE, replay),
            crate::Error::<Test>::EscrowNotFunded
        );
    });
}

#[test]
fn complete_and_payout_rejects_forged_signature() {
    new_test_ext().execute_with(|| {
        assert_ok!(fund(200));
        // Signed by a key that is not the registered provider's.
        let forged = signed_evidence(&forged_pair(), LEASE, 1, 0, 10, 10, 20, 5, 3, 2, 100, 1);
        assert_noop!(
            Escrow::complete_and_payout(RuntimeOrigin::signed(OTHER), LEASE, forged),
            crate::Error::<Test>::InvalidSignature
        );
    });
}

#[test]
fn complete_and_payout_rejects_tampered_evidence() {
    new_test_ext().execute_with(|| {
        assert_ok!(fund(200));
        // Validly signed, then a field is mutated after signing -- the
        // signature no longer covers the bytes actually submitted.
        let mut evidence = normal_evidence();
        evidence.cpu_core_seconds += 1;
        assert_noop!(
            Escrow::complete_and_payout(RuntimeOrigin::signed(OTHER), LEASE, evidence),
            crate::Error::<Test>::InvalidSignature
        );
    });
}

#[test]
fn complete_and_payout_rejects_sequence_replay() {
    new_test_ext().execute_with(|| {
        assert_ok!(fund(1_000));
        let first = signed_evidence(&provider_pair(), LEASE, 5, 0, 10, 1, 1, 1, 1, 1, 0, 1);
        assert_ok!(Escrow::complete_and_payout(
            RuntimeOrigin::signed(OTHER),
            LEASE,
            first
        ));
        // A second escrow so the replayed sequence is checked, not
        // rejected merely because the first escrow already completed.
        assert_ok!(Escrow::fund_escrow(
            RuntimeOrigin::signed(PAYER),
            OTHER_LEASE,
            PROVIDER,
            1_000,
            price(),
            1
        ));
        let replay = signed_evidence(&provider_pair(), OTHER_LEASE, 5, 0, 10, 1, 1, 1, 1, 1, 0, 1);
        // sequence 5 was already consumed on LEASE, but each escrow tracks
        // its own last_evidence_sequence starting at 0, so this must
        // succeed for OTHER_LEASE...
        assert_ok!(Escrow::complete_and_payout(
            RuntimeOrigin::signed(OTHER),
            OTHER_LEASE,
            replay
        ));
        // ...while resubmitting the same sequence again against the same
        // escrow is a replay.
        let same_sequence_again =
            signed_evidence(&provider_pair(), LEASE, 5, 10, 20, 1, 1, 1, 1, 1, 0, 1);
        assert_noop!(
            Escrow::complete_and_payout(RuntimeOrigin::signed(OTHER), LEASE, same_sequence_again),
            crate::Error::<Test>::EscrowNotFunded
        );
    });
}

#[test]
fn complete_and_payout_rejects_lease_id_mismatch() {
    new_test_ext().execute_with(|| {
        assert_ok!(fund(200));
        assert_ok!(Escrow::fund_escrow(
            RuntimeOrigin::signed(PAYER),
            OTHER_LEASE,
            PROVIDER,
            200,
            price(),
            1
        ));
        // Evidence genuinely signed for OTHER_LEASE, replayed against LEASE.
        let evidence =
            signed_evidence(&provider_pair(), OTHER_LEASE, 1, 0, 10, 1, 1, 1, 1, 1, 0, 1);
        assert_noop!(
            Escrow::complete_and_payout(RuntimeOrigin::signed(OTHER), LEASE, evidence),
            crate::Error::<Test>::LeaseIdMismatch
        );
    });
}

#[test]
fn complete_and_payout_rejects_charge_exceeding_cap() {
    new_test_ext().execute_with(|| {
        assert_ok!(fund(50)); // charged_amount(80) > max_charge(50)
        assert_noop!(
            Escrow::complete_and_payout(RuntimeOrigin::signed(OTHER), LEASE, normal_evidence()),
            crate::Error::<Test>::ChargedAmountExceedsCap
        );
    });
}

#[test]
fn complete_and_payout_rejects_period_too_long() {
    new_test_ext().execute_with(|| {
        assert_ok!(fund(1_000));
        let evidence = signed_evidence(
            &provider_pair(),
            LEASE,
            1,
            0,
            MaxMeteringPeriodSeconds::get() + 1,
            1,
            1,
            1,
            1,
            1,
            0,
            1,
        );
        assert_noop!(
            Escrow::complete_and_payout(RuntimeOrigin::signed(OTHER), LEASE, evidence),
            crate::Error::<Test>::MeteringPeriodTooLong
        );
    });
}

#[test]
fn complete_and_payout_rejects_invalid_period() {
    new_test_ext().execute_with(|| {
        assert_ok!(fund(1_000));
        let evidence = signed_evidence(&provider_pair(), LEASE, 1, 10, 5, 1, 1, 1, 1, 1, 0, 1);
        assert_noop!(
            Escrow::complete_and_payout(RuntimeOrigin::signed(OTHER), LEASE, evidence),
            crate::Error::<Test>::InvalidMeteringPeriod
        );
    });
}

#[test]
fn complete_and_payout_rejects_schema_version_mismatch() {
    new_test_ext().execute_with(|| {
        assert_ok!(fund(1_000));
        let evidence = signed_evidence(&provider_pair(), LEASE, 1, 0, 10, 1, 1, 1, 1, 1, 0, 2);
        assert_noop!(
            Escrow::complete_and_payout(RuntimeOrigin::signed(OTHER), LEASE, evidence),
            crate::Error::<Test>::MeteringSchemaVersionMismatch
        );
    });
}

#[test]
fn complete_and_payout_rejects_unregistered_provider() {
    new_test_ext().execute_with(|| {
        // Fund an escrow naming a provider ProviderKeyLookup has no key for.
        assert_ok!(Escrow::fund_escrow(
            RuntimeOrigin::signed(PAYER),
            LEASE,
            OTHER,
            200,
            price(),
            1
        ));
        let evidence = signed_evidence(&provider_pair(), LEASE, 1, 0, 10, 1, 1, 1, 1, 1, 0, 1);
        assert_noop!(
            Escrow::complete_and_payout(RuntimeOrigin::signed(OTHER), LEASE, evidence),
            crate::Error::<Test>::ProviderKeyNotFound
        );
    });
}

#[test]
fn complete_and_payout_rejects_multiplication_overflow() {
    new_test_ext().execute_with(|| {
        assert_ok!(fund(1_000));
        let evidence = signed_evidence(
            &provider_pair(),
            LEASE,
            1,
            0,
            10,
            u64::MAX,
            0,
            0,
            0,
            0,
            0,
            1,
        );
        assert_noop!(
            Escrow::complete_and_payout(RuntimeOrigin::signed(OTHER), LEASE, evidence),
            crate::Error::<Test>::ArithmeticOverflow
        );
    });
}

#[test]
fn complete_and_payout_rejects_network_sum_overflow() {
    new_test_ext().execute_with(|| {
        assert_ok!(fund(1_000));
        let evidence = signed_evidence(
            &provider_pair(),
            LEASE,
            1,
            0,
            10,
            0,
            0,
            0,
            u64::MAX,
            u64::MAX,
            0,
            1,
        );
        assert_noop!(
            Escrow::complete_and_payout(RuntimeOrigin::signed(OTHER), LEASE, evidence),
            crate::Error::<Test>::ArithmeticOverflow
        );
    });
}

#[test]
fn complete_and_payout_rejects_when_paused() {
    new_test_ext().execute_with(|| {
        assert_ok!(fund(200));
        assert_ok!(Escrow::set_paused(RuntimeOrigin::root(), true));
        assert_noop!(
            Escrow::complete_and_payout(RuntimeOrigin::signed(OTHER), LEASE, normal_evidence()),
            crate::Error::<Test>::Paused
        );
    });
}

#[test]
fn complete_and_payout_blocked_while_disputed() {
    new_test_ext().execute_with(|| {
        assert_ok!(fund(200));
        assert_ok!(Escrow::dispute_escrow(
            RuntimeOrigin::signed(PAYER),
            LEASE,
            [1u8; 32]
        ));
        assert_noop!(
            Escrow::complete_and_payout(RuntimeOrigin::signed(OTHER), LEASE, normal_evidence()),
            crate::Error::<Test>::EscrowNotFunded
        );
    });
}

// ---------------------------------------------------------------------
// refund_escrow
// ---------------------------------------------------------------------

#[test]
fn refund_escrow_rejects_before_window_elapses() {
    new_test_ext().execute_with(|| {
        assert_ok!(fund(200));
        assert_noop!(
            Escrow::refund_escrow(RuntimeOrigin::signed(PAYER), LEASE),
            crate::Error::<Test>::RefundWindowNotElapsed
        );
    });
}

#[test]
fn refund_escrow_succeeds_after_window_elapses() {
    new_test_ext().execute_with(|| {
        assert_ok!(fund(200));
        System::set_block_number(1 + RefundWindow::get());
        assert_ok!(Escrow::refund_escrow(RuntimeOrigin::signed(PAYER), LEASE));
        assert_eq!(Balances::reserved_balance(PAYER), 0);
        assert_eq!(Balances::free_balance(PAYER), 1_000_000);
        let escrow = Escrow::escrows(LEASE).unwrap();
        assert_eq!(escrow.state, EscrowState::Refunded);
    });
}

#[test]
fn refund_escrow_rejects_non_payer() {
    new_test_ext().execute_with(|| {
        assert_ok!(fund(200));
        System::set_block_number(1 + RefundWindow::get());
        assert_noop!(
            Escrow::refund_escrow(RuntimeOrigin::signed(OTHER), LEASE),
            crate::Error::<Test>::NotPayer
        );
    });
}

#[test]
fn refund_escrow_rejects_when_paused() {
    new_test_ext().execute_with(|| {
        assert_ok!(fund(200));
        System::set_block_number(1 + RefundWindow::get());
        assert_ok!(Escrow::set_paused(RuntimeOrigin::root(), true));
        assert_noop!(
            Escrow::refund_escrow(RuntimeOrigin::signed(PAYER), LEASE),
            crate::Error::<Test>::Paused
        );
    });
}

#[test]
fn refund_escrow_rejects_after_dispute() {
    new_test_ext().execute_with(|| {
        assert_ok!(fund(200));
        assert_ok!(Escrow::dispute_escrow(
            RuntimeOrigin::signed(PAYER),
            LEASE,
            [1u8; 32]
        ));
        System::set_block_number(1 + RefundWindow::get());
        // Self-service refund must not be able to bypass an open dispute --
        // only resolve_dispute can move a Disputed escrow forward.
        assert_noop!(
            Escrow::refund_escrow(RuntimeOrigin::signed(PAYER), LEASE),
            crate::Error::<Test>::EscrowNotFunded
        );
    });
}

// ---------------------------------------------------------------------
// dispute_escrow
// ---------------------------------------------------------------------

#[test]
fn dispute_escrow_allowed_for_payer_and_provider() {
    new_test_ext().execute_with(|| {
        assert_ok!(fund(200));
        assert_ok!(Escrow::dispute_escrow(
            RuntimeOrigin::signed(PAYER),
            LEASE,
            [1u8; 32]
        ));
        assert_eq!(Escrow::escrows(LEASE).unwrap().state, EscrowState::Disputed);

        assert_ok!(fund_other_lease());
        assert_ok!(Escrow::dispute_escrow(
            RuntimeOrigin::signed(PROVIDER),
            OTHER_LEASE,
            [2u8; 32]
        ));
        assert_eq!(
            Escrow::escrows(OTHER_LEASE).unwrap().state,
            EscrowState::Disputed
        );
    });
}

fn fund_other_lease() -> sp_runtime::DispatchResult {
    Escrow::fund_escrow(
        RuntimeOrigin::signed(PAYER),
        OTHER_LEASE,
        PROVIDER,
        200,
        price(),
        1,
    )
}

#[test]
fn dispute_escrow_rejects_unrelated_account() {
    new_test_ext().execute_with(|| {
        assert_ok!(fund(200));
        assert_noop!(
            Escrow::dispute_escrow(RuntimeOrigin::signed(OTHER), LEASE, [1u8; 32]),
            crate::Error::<Test>::NotPartyToEscrow
        );
    });
}

#[test]
fn dispute_escrow_rejects_double_dispute() {
    new_test_ext().execute_with(|| {
        assert_ok!(fund(200));
        assert_ok!(Escrow::dispute_escrow(
            RuntimeOrigin::signed(PAYER),
            LEASE,
            [1u8; 32]
        ));
        assert_noop!(
            Escrow::dispute_escrow(RuntimeOrigin::signed(PAYER), LEASE, [1u8; 32]),
            crate::Error::<Test>::AlreadyDisputed
        );
    });
}

#[test]
fn dispute_escrow_allowed_after_completion_within_window() {
    new_test_ext().execute_with(|| {
        assert_ok!(fund(200));
        assert_ok!(Escrow::complete_and_payout(
            RuntimeOrigin::signed(OTHER),
            LEASE,
            normal_evidence()
        ));
        System::set_block_number(1 + DisputeWindow::get());
        assert_ok!(Escrow::dispute_escrow(
            RuntimeOrigin::signed(PAYER),
            LEASE,
            [1u8; 32]
        ));
        assert_eq!(Escrow::escrows(LEASE).unwrap().state, EscrowState::Disputed);
    });
}

#[test]
fn dispute_escrow_rejects_after_window_elapsed_post_completion() {
    new_test_ext().execute_with(|| {
        assert_ok!(fund(200));
        assert_ok!(Escrow::complete_and_payout(
            RuntimeOrigin::signed(OTHER),
            LEASE,
            normal_evidence()
        ));
        System::set_block_number(2 + DisputeWindow::get());
        assert_noop!(
            Escrow::dispute_escrow(RuntimeOrigin::signed(PAYER), LEASE, [1u8; 32]),
            crate::Error::<Test>::DisputeWindowElapsed
        );
    });
}

#[test]
fn dispute_escrow_rejects_when_paused() {
    new_test_ext().execute_with(|| {
        assert_ok!(fund(200));
        assert_ok!(Escrow::set_paused(RuntimeOrigin::root(), true));
        assert_noop!(
            Escrow::dispute_escrow(RuntimeOrigin::signed(PAYER), LEASE, [1u8; 32]),
            crate::Error::<Test>::Paused
        );
    });
}

// ---------------------------------------------------------------------
// resolve_dispute
// ---------------------------------------------------------------------

#[test]
fn resolve_dispute_pay_provider_outcome() {
    new_test_ext().execute_with(|| {
        assert_ok!(fund(200));
        assert_ok!(Escrow::dispute_escrow(
            RuntimeOrigin::signed(PAYER),
            LEASE,
            [1u8; 32]
        ));
        assert_ok!(Escrow::resolve_dispute(
            RuntimeOrigin::root(),
            LEASE,
            DisputeOutcome::PayProvider(80)
        ));
        assert_eq!(Balances::free_balance(PROVIDER), 1_000_080);
        assert_eq!(Balances::free_balance(PAYER), 999_920);
        assert_eq!(Balances::reserved_balance(PAYER), 0);
        assert_eq!(
            Escrow::escrows(LEASE).unwrap().state,
            EscrowState::Completed
        );
        // A rejected dispute (provider paid as originally billed) applies
        // no reputation penalty to either side.
        assert!(penalties().is_empty());
    });
}

#[test]
fn resolve_dispute_refund_payer_outcome_applies_penalty() {
    new_test_ext().execute_with(|| {
        assert_ok!(fund(200));
        assert_ok!(Escrow::dispute_escrow(
            RuntimeOrigin::signed(PAYER),
            LEASE,
            [1u8; 32]
        ));
        assert_ok!(Escrow::resolve_dispute(
            RuntimeOrigin::root(),
            LEASE,
            DisputeOutcome::RefundPayer
        ));
        assert_eq!(Balances::free_balance(PAYER), 1_000_000);
        assert_eq!(Balances::reserved_balance(PAYER), 0);
        assert_eq!(Escrow::escrows(LEASE).unwrap().state, EscrowState::Refunded);
        assert_eq!(penalties(), vec![(PROVIDER, ReliabilityPenaltyBps::get())]);
    });
}

#[test]
fn resolve_dispute_rejects_non_root_origin() {
    new_test_ext().execute_with(|| {
        assert_ok!(fund(200));
        assert_ok!(Escrow::dispute_escrow(
            RuntimeOrigin::signed(PAYER),
            LEASE,
            [1u8; 32]
        ));
        assert_noop!(
            Escrow::resolve_dispute(
                RuntimeOrigin::signed(PAYER),
                LEASE,
                DisputeOutcome::RefundPayer
            ),
            DispatchError::BadOrigin
        );
    });
}

#[test]
fn resolve_dispute_rejects_when_not_disputed() {
    new_test_ext().execute_with(|| {
        assert_ok!(fund(200));
        assert_noop!(
            Escrow::resolve_dispute(RuntimeOrigin::root(), LEASE, DisputeOutcome::RefundPayer),
            crate::Error::<Test>::NotDisputed
        );
    });
}

#[test]
fn resolve_dispute_rejects_payout_exceeding_cap() {
    new_test_ext().execute_with(|| {
        assert_ok!(fund(200));
        assert_ok!(Escrow::dispute_escrow(
            RuntimeOrigin::signed(PAYER),
            LEASE,
            [1u8; 32]
        ));
        assert_noop!(
            Escrow::resolve_dispute(
                RuntimeOrigin::root(),
                LEASE,
                DisputeOutcome::PayProvider(201)
            ),
            crate::Error::<Test>::PayoutExceedsCap
        );
    });
}

#[test]
fn resolve_dispute_rejects_when_paused() {
    new_test_ext().execute_with(|| {
        assert_ok!(fund(200));
        assert_ok!(Escrow::dispute_escrow(
            RuntimeOrigin::signed(PAYER),
            LEASE,
            [1u8; 32]
        ));
        assert_ok!(Escrow::set_paused(RuntimeOrigin::root(), true));
        assert_noop!(
            Escrow::resolve_dispute(RuntimeOrigin::root(), LEASE, DisputeOutcome::RefundPayer),
            crate::Error::<Test>::Paused
        );
    });
}

// ---------------------------------------------------------------------
// set_paused / emergency pause semantics
// ---------------------------------------------------------------------

#[test]
fn set_paused_requires_root() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            Escrow::set_paused(RuntimeOrigin::signed(PAYER), true),
            DispatchError::BadOrigin
        );
    });
}

#[test]
fn pause_freezes_reserved_funds_without_seizing_or_refunding() {
    new_test_ext().execute_with(|| {
        assert_ok!(fund(200));
        assert_ok!(Escrow::set_paused(RuntimeOrigin::root(), true));
        // Every transition is blocked...
        assert_noop!(fund(200), crate::Error::<Test>::Paused);
        assert_noop!(
            Escrow::complete_and_payout(RuntimeOrigin::signed(OTHER), LEASE, normal_evidence()),
            crate::Error::<Test>::Paused
        );
        // ...but the reservation itself is untouched: not seized, not
        // auto-refunded (ADR-029 Sec10).
        assert_eq!(Balances::reserved_balance(PAYER), 200);
        assert_eq!(Escrow::escrows(LEASE).unwrap().state, EscrowState::Funded);
        // Unpausing restores normal operation.
        assert_ok!(Escrow::set_paused(RuntimeOrigin::root(), false));
        assert_ok!(Escrow::complete_and_payout(
            RuntimeOrigin::signed(OTHER),
            LEASE,
            normal_evidence()
        ));
    });
}

// ---------------------------------------------------------------------
// unauthorized (unsigned) origin on every non-governance privileged call
//
// `fund_escrow_rejects_unsigned_origin` already covers fund_escrow above;
// `resolve_dispute_rejects_non_root_origin` and `set_paused_requires_root`
// already cover the two EnsureRoot-gated calls. The three remaining
// ensure_signed-gated calls are covered here.
// ---------------------------------------------------------------------

#[test]
fn complete_and_payout_rejects_unsigned_origin() {
    new_test_ext().execute_with(|| {
        assert_ok!(fund(200));
        assert_noop!(
            Escrow::complete_and_payout(RuntimeOrigin::none(), LEASE, normal_evidence()),
            DispatchError::BadOrigin
        );
    });
}

#[test]
fn refund_escrow_rejects_unsigned_origin() {
    new_test_ext().execute_with(|| {
        assert_ok!(fund(200));
        System::set_block_number(1 + RefundWindow::get());
        assert_noop!(
            Escrow::refund_escrow(RuntimeOrigin::none(), LEASE),
            DispatchError::BadOrigin
        );
    });
}

#[test]
fn dispute_escrow_rejects_unsigned_origin() {
    new_test_ext().execute_with(|| {
        assert_ok!(fund(200));
        assert_noop!(
            Escrow::dispute_escrow(RuntimeOrigin::none(), LEASE, [1u8; 32]),
            DispatchError::BadOrigin
        );
    });
}

// ---------------------------------------------------------------------
// zero-remainder boundary: charged_amount == max_charge exactly, so the
// `if !remainder.is_zero()` unreserve branch in both complete_and_payout
// and resolve_dispute's PayProvider arm must be skippable without leaving
// any stray reservation behind.
// ---------------------------------------------------------------------

#[test]
fn complete_and_payout_exact_max_charge_leaves_no_remainder() {
    new_test_ext().execute_with(|| {
        // charged_amount = 10*2 + 20*1 + 5*3 + (3+2)*5 = 80; fund exactly 80.
        assert_ok!(fund(80));
        assert_ok!(Escrow::complete_and_payout(
            RuntimeOrigin::signed(OTHER),
            LEASE,
            normal_evidence()
        ));
        assert_eq!(Balances::free_balance(PROVIDER), 1_000_080);
        assert_eq!(Balances::reserved_balance(PAYER), 0);
        assert_eq!(Balances::free_balance(PAYER), 999_920);
    });
}

#[test]
fn resolve_dispute_pay_provider_exact_max_charge_leaves_no_remainder() {
    new_test_ext().execute_with(|| {
        assert_ok!(fund(80));
        assert_ok!(Escrow::dispute_escrow(
            RuntimeOrigin::signed(PAYER),
            LEASE,
            [1u8; 32]
        ));
        assert_ok!(Escrow::resolve_dispute(
            RuntimeOrigin::root(),
            LEASE,
            DisputeOutcome::PayProvider(80)
        ));
        assert_eq!(Balances::free_balance(PROVIDER), 1_000_080);
        assert_eq!(Balances::reserved_balance(PAYER), 0);
        assert_eq!(Balances::free_balance(PAYER), 999_920);
    });
}

// ---------------------------------------------------------------------
// invariant / property-style tests
//
// This workspace has no proptest/quickcheck dependency anywhere (checked
// across every pallet's Cargo.toml); rather than introduce one unilaterally
// for a single pallet, these sweep a deterministic table of cases to assert
// the same invariants a property test would, over a range of inputs.
// ---------------------------------------------------------------------

#[test]
fn invariant_total_balance_conserved_and_charge_plus_remainder_equals_max_charge_across_cases() {
    // (max_charge, cpu, ram, storage, egress, ingress) -- each case funds a
    // fresh lease and completes it, then checks the two invariants that
    // must hold no matter the usage figures: (1) payer + provider free
    // balance combined never changes (funds only ever move between the
    // two parties, never minted or burned), and (2) charged_amount +
    // refunded remainder == max_charge exactly (no dust lost or created).
    let cases: [(u64, u64, u64, u64, u64, u64); 5] = [
        (1_000, 10, 20, 5, 3, 2),      // ordinary partial usage
        (1_000, 0, 0, 0, 0, 0),        // zero usage, full refund
        (80, 10, 20, 5, 3, 2),         // usage exactly exhausts max_charge
        (10, 0, 1, 0, 0, 0),           // tiny usage just above MinEscrowAmount
        (5_000, 100, 200, 50, 30, 20), // large usage, still under cap
    ];

    for (idx, (max_charge, cpu, ram, storage, egress, ingress)) in cases.into_iter().enumerate() {
        new_test_ext().execute_with(|| {
            let lease_id: LeaseId = 1_000 + idx as LeaseId;
            let total_before = Balances::free_balance(PAYER)
                + Balances::reserved_balance(PAYER)
                + Balances::free_balance(PROVIDER);

            assert_ok!(Escrow::fund_escrow(
                RuntimeOrigin::signed(PAYER),
                lease_id,
                PROVIDER,
                max_charge,
                price(),
                1
            ));
            let evidence = signed_evidence(
                &provider_pair(),
                lease_id,
                1,
                0,
                10,
                cpu,
                ram,
                storage,
                egress,
                ingress,
                0,
                1,
            );
            assert_ok!(Escrow::complete_and_payout(
                RuntimeOrigin::signed(OTHER),
                lease_id,
                evidence
            ));

            let total_after = Balances::free_balance(PAYER)
                + Balances::reserved_balance(PAYER)
                + Balances::free_balance(PROVIDER);
            assert_eq!(
                total_before, total_after,
                "case {idx}: total balance across payer+provider must be conserved"
            );
            assert_eq!(
                Balances::reserved_balance(PAYER),
                0,
                "case {idx}: no reservation may survive a completed escrow"
            );

            let provider_price = price();
            let expected_charge = cpu * provider_price.cpu_core_second
                + ram * provider_price.ram_mb_second
                + storage * provider_price.storage_gb_second
                + (egress + ingress) * provider_price.network_mb;
            let provider_gain = Balances::free_balance(PROVIDER) - 1_000_000;
            assert_eq!(
                provider_gain, expected_charge,
                "case {idx}: provider must be paid exactly the computed charge"
            );
            assert_eq!(
                provider_gain + (max_charge - expected_charge),
                max_charge,
                "case {idx}: charged_amount + refunded remainder must equal max_charge"
            );
        });
    }
}

// ---------------------------------------------------------------------
// Reserve-balance contamination guard: fund_escrow rejects a payer who is
// currently a registered Network Validator (the same account is not
// blocked in escrow's own tests from also being tracked by
// `pallet-network-validator` in production -- both reserve against the
// same untagged pallet_balances reserved pool, see this pallet's module
// doc comment).
// ---------------------------------------------------------------------

#[test]
fn fund_escrow_rejects_registered_validator() {
    new_test_ext().execute_with(|| {
        set_registered_validator(PAYER, true);
        assert_noop!(fund(200), crate::Error::<Test>::PayerIsRegisteredValidator);
        // No partial state: nothing reserved, no record created.
        assert_eq!(Balances::reserved_balance(PAYER), 0);
        assert!(Escrow::escrows(LEASE).is_none());
    });
}

#[test]
fn fund_escrow_succeeds_once_validator_status_is_cleared() {
    new_test_ext().execute_with(|| {
        set_registered_validator(PAYER, true);
        assert_noop!(fund(200), crate::Error::<Test>::PayerIsRegisteredValidator);
        set_registered_validator(PAYER, false);
        assert_ok!(fund(200));
    });
}

#[test]
fn fund_escrow_does_not_reject_an_unrelated_validator() {
    new_test_ext().execute_with(|| {
        // Only PAYER's own validator status matters, not the provider's or
        // some other account's.
        set_registered_validator(PROVIDER, true);
        set_registered_validator(OTHER, true);
        assert_ok!(fund(200));
    });
}

// ---------------------------------------------------------------------
// PayerOpenEscrowCount bookkeeping: backs the reverse guard (a Network
// Validator registration must not succeed for an account with an open
// escrow as payer). Exercised directly here since pallet-escrow has no
// dependency on pallet-network-validator to dispatch through.
// ---------------------------------------------------------------------

#[test]
fn fund_escrow_increments_payer_open_escrow_count() {
    new_test_ext().execute_with(|| {
        assert_eq!(crate::PayerOpenEscrowCount::<Test>::get(PAYER), 0);
        assert_ok!(fund(200));
        assert_eq!(crate::PayerOpenEscrowCount::<Test>::get(PAYER), 1);
        assert_ok!(fund_other_lease());
        assert_eq!(crate::PayerOpenEscrowCount::<Test>::get(PAYER), 2);
    });
}

#[test]
fn complete_and_payout_decrements_payer_open_escrow_count() {
    new_test_ext().execute_with(|| {
        assert_ok!(fund(200));
        assert_eq!(crate::PayerOpenEscrowCount::<Test>::get(PAYER), 1);
        assert_ok!(Escrow::complete_and_payout(
            RuntimeOrigin::signed(OTHER),
            LEASE,
            normal_evidence()
        ));
        assert_eq!(crate::PayerOpenEscrowCount::<Test>::get(PAYER), 0);
    });
}

#[test]
fn refund_escrow_decrements_payer_open_escrow_count() {
    new_test_ext().execute_with(|| {
        assert_ok!(fund(200));
        System::set_block_number(1 + RefundWindow::get());
        assert_ok!(Escrow::refund_escrow(RuntimeOrigin::signed(PAYER), LEASE));
        assert_eq!(crate::PayerOpenEscrowCount::<Test>::get(PAYER), 0);
    });
}

#[test]
fn resolve_dispute_from_funded_decrements_payer_open_escrow_count_once() {
    new_test_ext().execute_with(|| {
        assert_ok!(fund(200));
        assert_ok!(Escrow::dispute_escrow(
            RuntimeOrigin::signed(PAYER),
            LEASE,
            [1u8; 32]
        ));
        // Still open (Disputed still holds the reservation) until resolved.
        assert_eq!(crate::PayerOpenEscrowCount::<Test>::get(PAYER), 1);
        assert_ok!(Escrow::resolve_dispute(
            RuntimeOrigin::root(),
            LEASE,
            DisputeOutcome::RefundPayer
        ));
        assert_eq!(crate::PayerOpenEscrowCount::<Test>::get(PAYER), 0);
    });
}

#[test]
fn redispute_after_completion_does_not_double_decrement_payer_open_escrow_count() {
    new_test_ext().execute_with(|| {
        assert_ok!(fund(200));
        assert_ok!(Escrow::complete_and_payout(
            RuntimeOrigin::signed(OTHER),
            LEASE,
            normal_evidence()
        ));
        // Already decremented by complete_and_payout.
        assert_eq!(crate::PayerOpenEscrowCount::<Test>::get(PAYER), 0);
        System::set_block_number(1 + DisputeWindow::get());
        assert_ok!(Escrow::dispute_escrow(
            RuntimeOrigin::signed(PAYER),
            LEASE,
            [1u8; 32]
        ));
        assert_ok!(Escrow::resolve_dispute(
            RuntimeOrigin::root(),
            LEASE,
            DisputeOutcome::RefundPayer
        ));
        // Must not underflow past zero (saturating) or go negative.
        assert_eq!(crate::PayerOpenEscrowCount::<Test>::get(PAYER), 0);
    });
}

// ---------------------------------------------------------------------
// resolve_dispute's shortfall write-off fail-safe.
//
// These reproduce the actual finding's mechanism directly with Balances
// primitives (reserve + slash_reserved), the same shape any other pallet
// sharing this account's reserved balance would trigger -- exactly what
// pallet-network-validator's slash_round_submitters does in production,
// without needing pallet-escrow to depend on pallet-network-validator to
// demonstrate it. `reserve_contamination_strands_escrow_until_writeoff`
// is the direct "would have failed before this fix, passes after" case:
// every existing settlement path (complete_and_payout, refund_escrow)
// still fails closed exactly as before -- that guarantee is not weakened
// -- but resolve_dispute can now recover the escrow instead of leaving it
// permanently stuck.
// ---------------------------------------------------------------------

#[test]
fn reserve_contamination_strands_escrow_until_writeoff() {
    new_test_ext().execute_with(|| {
        assert_ok!(fund(200));
        assert_eq!(Balances::reserved_balance(PAYER), 200);

        // Simulate an unrelated pallet (e.g. pallet-network-validator)
        // also reserving against the *same* AccountId, then slashing a
        // flat amount from the account's total reserved balance --
        // exactly what pallet_balances::ReservableCurrency's untagged
        // reserved pool allows, and exactly the mechanism this PR's fix
        // closes off going forward via the fund_escrow/register_validator
        // guards. Reserve 500 (e.g. validator stake), then slash 600 --
        // more than that 500 -- so the slash eats into the escrow's own
        // 200, leaving only 100 actually reserved for PAYER in total.
        assert_ok!(Balances::reserve(&PAYER, 500));
        assert_eq!(Balances::reserved_balance(PAYER), 700);
        let (imbalance, shortfall) = Balances::slash_reserved(&PAYER, 600);
        drop(imbalance);
        assert_eq!(
            shortfall, 0,
            "600 was available to slash out of 700 reserved"
        );
        assert_eq!(Balances::reserved_balance(PAYER), 100);

        // Every fund-moving path now fails closed -- no partial payment,
        // the escrow stays exactly as it was (Funded, still recording
        // max_charge = 200) because it genuinely cannot deliver on that
        // recorded amount from what's actually left reserved.
        assert_noop!(
            Escrow::complete_and_payout(RuntimeOrigin::signed(OTHER), LEASE, normal_evidence()),
            crate::Error::<Test>::ReserveAccountingInconsistent
        );
        System::set_block_number(1 + RefundWindow::get());
        assert_noop!(
            Escrow::refund_escrow(RuntimeOrigin::signed(PAYER), LEASE),
            crate::Error::<Test>::ReserveAccountingInconsistent
        );
        assert_eq!(Escrow::escrows(LEASE).unwrap().state, EscrowState::Funded);

        // The fail-safe: a root-gated resolve_dispute can now recover it.
        // Dispute evidence indicates the provider should be paid the full
        // 80 owed; pay that first (same priority the normal path always
        // used), return whatever's left to the payer, and write off
        // exactly the portion that's genuinely gone.
        assert_ok!(Escrow::dispute_escrow(
            RuntimeOrigin::signed(PAYER),
            LEASE,
            [1u8; 32]
        ));
        assert_ok!(Escrow::resolve_dispute(
            RuntimeOrigin::root(),
            LEASE,
            DisputeOutcome::PayProvider(80)
        ));

        // Provider made whole for the full disputed amount (it was
        // actually available: 100 reserved >= 80 owed).
        assert_eq!(Balances::free_balance(PROVIDER), 1_000_080);
        // Payer gets back only what was actually left (100 - 80 = 20),
        // not the nominal remainder (200 - 80 = 120) -- the other 100 was
        // already gone before this call ever ran. PAYER's free balance
        // reflects: 1_000_000 - 200 (fund_escrow) - 500 (the simulated
        // other-pallet reserve, never returned -- it was slashed) + 20
        // (the remainder actually recovered here) = 999_320.
        assert_eq!(Balances::free_balance(PAYER), 999_320);
        assert_eq!(Balances::reserved_balance(PAYER), 0);
        assert_eq!(
            Escrow::escrows(LEASE).unwrap().state,
            EscrowState::Completed
        );
        assert_eq!(crate::PayerOpenEscrowCount::<Test>::get(PAYER), 0);

        let found = System::events().into_iter().any(|record| {
            matches!(
                record.event,
                RuntimeEvent::Escrow(crate::Event::EscrowShortfallWrittenOff {
                    lease_id: LEASE,
                    payer: PAYER,
                    provider: PROVIDER,
                    expected_total: 200,
                    provider_amount: 80,
                    payer_amount: 20,
                    shortfall: 100,
                })
            )
        });
        assert!(
            found,
            "EscrowShortfallWrittenOff was not emitted with the expected amounts"
        );
    });
}

#[test]
fn resolve_dispute_refund_payer_writes_off_confirmed_shortfall() {
    new_test_ext().execute_with(|| {
        assert_ok!(fund(200));
        // Drain everything but 50 of PAYER's reserved balance via the same
        // shared-pool mechanism.
        assert_ok!(Balances::reserve(&PAYER, 500));
        let (imbalance, shortfall) = Balances::slash_reserved(&PAYER, 650);
        drop(imbalance);
        assert_eq!(shortfall, 0);
        assert_eq!(Balances::reserved_balance(PAYER), 50);

        assert_ok!(Escrow::dispute_escrow(
            RuntimeOrigin::signed(PROVIDER),
            LEASE,
            [2u8; 32]
        ));
        assert_ok!(Escrow::resolve_dispute(
            RuntimeOrigin::root(),
            LEASE,
            DisputeOutcome::RefundPayer
        ));

        // Payer gets back only the 50 that was actually there, not the
        // nominal 200. PAYER's free balance reflects: 1_000_000 - 200
        // (fund_escrow) - 500 (the simulated other-pallet reserve, never
        // returned -- it was slashed) + 50 (actually recovered here) =
        // 999_350.
        assert_eq!(Balances::free_balance(PAYER), 999_350);
        assert_eq!(Balances::reserved_balance(PAYER), 0);
        assert_eq!(Escrow::escrows(LEASE).unwrap().state, EscrowState::Refunded);
        // The provider-loss reliability penalty still applies -- the
        // write-off changes what could be *paid*, not the dispute's own
        // finding of who was at fault.
        assert_eq!(penalties(), vec![(PROVIDER, ReliabilityPenaltyBps::get())]);

        let found = System::events().into_iter().any(|record| {
            matches!(
                record.event,
                RuntimeEvent::Escrow(crate::Event::EscrowShortfallWrittenOff {
                    lease_id: LEASE,
                    payer: PAYER,
                    provider: PROVIDER,
                    expected_total: 200,
                    provider_amount: 0,
                    payer_amount: 50,
                    shortfall: 150,
                })
            )
        });
        assert!(
            found,
            "EscrowShortfallWrittenOff was not emitted with the expected amounts"
        );
    });
}

#[test]
fn resolve_dispute_without_shortfall_never_emits_writeoff_event() {
    new_test_ext().execute_with(|| {
        // The ordinary, non-contaminated case -- confirms the write-off
        // event is genuinely conditional, not emitted on every resolution.
        assert_ok!(fund(200));
        assert_ok!(Escrow::dispute_escrow(
            RuntimeOrigin::signed(PAYER),
            LEASE,
            [1u8; 32]
        ));
        assert_ok!(Escrow::resolve_dispute(
            RuntimeOrigin::root(),
            LEASE,
            DisputeOutcome::PayProvider(80)
        ));
        let found = System::events().into_iter().any(|record| {
            matches!(
                record.event,
                RuntimeEvent::Escrow(crate::Event::EscrowShortfallWrittenOff { .. })
            )
        });
        assert!(
            !found,
            "EscrowShortfallWrittenOff must not fire when nothing is actually short"
        );
    });
}
