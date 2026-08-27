use crate as pallet_network_validator;
use crate::ScoreDimension;
use frame_support::{assert_noop, assert_ok, derive_impl, parameter_types, traits::ConstU64};
use sp_runtime::{BuildStorage, DispatchError};

type Block = frame_system::mocking::MockBlock<Test>;
frame_support::construct_runtime!(
    pub enum Test {
        System: frame_system,
        Balances: pallet_balances,
        NetworkValidator: pallet_network_validator,
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

parameter_types! {
    pub const MinStake: u64 = 100;
    pub const UnbondingPeriod: u64 = 5;
}

// Records what the scoring rounds pushed into reputation, so tests can
// assert the aggregate actually reached the reputation layer instead of
// only checking this pallet's own storage.
thread_local! {
    static RECORDED: std::cell::RefCell<Vec<(u64, ScoreDimension, u16)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

// Current per-(provider, dimension) score, so the double acts like a
// real reputation store and dispute rollbacks can be asserted.
thread_local! {
    static CURRENT: std::cell::RefCell<std::collections::BTreeMap<(u64, u8), u16>> =
        const { std::cell::RefCell::new(std::collections::BTreeMap::new()) };
}

fn dimension_key(dimension: ScoreDimension) -> u8 {
    match dimension {
        ScoreDimension::Compute => 0,
        ScoreDimension::Storage => 1,
        ScoreDimension::Network => 2,
        ScoreDimension::Availability => 3,
        ScoreDimension::Reliability => 4,
    }
}

pub struct RecordingUpdater;
impl crate::ReputationUpdater<u64> for RecordingUpdater {
    fn record_dimension_score(
        provider: &u64,
        dimension: ScoreDimension,
        score_bps: u16,
    ) -> sp_runtime::DispatchResult {
        RECORDED.with(|recorded| {
            recorded
                .borrow_mut()
                .push((*provider, dimension, score_bps))
        });
        CURRENT.with(|current| {
            current
                .borrow_mut()
                .insert((*provider, dimension_key(dimension)), score_bps)
        });
        Ok(())
    }

    fn dimension_score(provider: &u64, dimension: ScoreDimension) -> u16 {
        CURRENT.with(|current| {
            current
                .borrow()
                .get(&(*provider, dimension_key(dimension)))
                .copied()
                .unwrap_or(0)
        })
    }
}

// Reward Points credited per validator, so tests can assert that only
// non-outlier submitters were paid.
thread_local! {
    static POINTS: std::cell::RefCell<std::collections::BTreeMap<u64, u64>> =
        const { std::cell::RefCell::new(std::collections::BTreeMap::new()) };
}

pub struct RecordingRewards;
impl crate::ValidatorRewards<u64> for RecordingRewards {
    fn accrue(validator: &u64, points: u64) -> sp_runtime::DispatchResult {
        POINTS.with(|store| {
            *store.borrow_mut().entry(*validator).or_default() += points;
        });
        Ok(())
    }
}

fn points_of(validator: u64) -> u64 {
    POINTS.with(|store| store.borrow().get(&validator).copied().unwrap_or(0))
}

// Mock for the reserve-contamination guard's reverse direction
// (`register_validator` rejects an account with funds locked in an open
// escrow as payer). Controlled per-test via `set_has_open_escrow`,
// independent of `pallet-escrow` -- this pallet carries no dependency on
// it, same narrow-trait pattern as `RecordingUpdater`/`RecordingRewards`.
thread_local! {
    static OPEN_ESCROW_PAYERS: std::cell::RefCell<std::collections::BTreeSet<u64>> =
        const { std::cell::RefCell::new(std::collections::BTreeSet::new()) };
}

pub struct TestEscrowInspector;
impl crate::EscrowPayerInspector<u64> for TestEscrowInspector {
    fn has_open_escrow(payer: &u64) -> bool {
        OPEN_ESCROW_PAYERS.with(|set| set.borrow().contains(payer))
    }
}

fn set_has_open_escrow(account: u64, has_open_escrow: bool) {
    OPEN_ESCROW_PAYERS.with(|set| {
        if has_open_escrow {
            set.borrow_mut().insert(account);
        } else {
            set.borrow_mut().remove(&account);
        }
    });
}

// ADR-036 §5: mock for the reserve-contamination guard's third edge
// (`register_validator` rejects an account with an open provider bond).
// Controlled per-test via `set_has_open_bond`, same shape as
// `TestEscrowInspector` above.
thread_local! {
    static BONDED_PROVIDERS: std::cell::RefCell<std::collections::BTreeSet<u64>> =
        const { std::cell::RefCell::new(std::collections::BTreeSet::new()) };
}

pub struct TestProviderBondInspector;
impl pallet_provider_registry::ProviderBondInspector<u64> for TestProviderBondInspector {
    fn has_open_bond(provider: &u64) -> bool {
        BONDED_PROVIDERS.with(|set| set.borrow().contains(provider))
    }
}

fn set_has_open_bond(account: u64, has_open_bond: bool) {
    BONDED_PROVIDERS.with(|set| {
        if has_open_bond {
            set.borrow_mut().insert(account);
        } else {
            set.borrow_mut().remove(&account);
        }
    });
}

fn current_score(provider: u64, dimension: ScoreDimension) -> u16 {
    <RecordingUpdater as crate::ReputationUpdater<u64>>::dimension_score(&provider, dimension)
}

fn recorded() -> Vec<(u64, ScoreDimension, u16)> {
    RECORDED.with(|recorded| recorded.borrow().clone())
}

fn clear_recorded() {
    RECORDED.with(|recorded| recorded.borrow_mut().clear());
    CURRENT.with(|current| current.borrow_mut().clear());
    POINTS.with(|store| store.borrow_mut().clear());
}

parameter_types! {
    pub const MaxSubmissionsPerRound: u32 = 8;
    pub const MinQuorum: u32 = 3;
    pub const TargetCommitteeSize: u32 = 5;
    pub const MaxValidators: u32 = 16;
    pub const DisputeWindow: u64 = 20;
    pub const PointsPerAcceptedSubmission: u64 = 7;
    // Deliberately less than MinStake (100): a single upheld dispute must
    // not be able to wipe a validator's whole bond in one call (ADR-018
    // §3), and tests below rely on being able to observe partial slashes
    // across more than one incident.
    pub const SlashAmount: u64 = 40;
}

impl crate::Config for Test {
    type Currency = Balances;
    type SuspensionOrigin = frame_system::EnsureRoot<u64>;
    type ReputationUpdater = RecordingUpdater;
    type ValidatorRewards = RecordingRewards;
    type EscrowInspector = TestEscrowInspector;
    type ProviderBondInspector = TestProviderBondInspector;
    type MinStake = MinStake;
    type UnbondingPeriod = UnbondingPeriod;
    type MaxSubmissionsPerRound = MaxSubmissionsPerRound;
    type MinQuorum = MinQuorum;
    type TargetCommitteeSize = TargetCommitteeSize;
    type MaxValidators = MaxValidators;
    type DisputeWindow = DisputeWindow;
    type PointsPerAcceptedSubmission = PointsPerAcceptedSubmission;
    type SlashAmount = SlashAmount;
    type WeightInfo = ();
}

fn new_test_ext() -> sp_io::TestExternalities {
    // thread_local fixtures can outlive one #[test] fn if the test harness
    // reuses the same OS thread for a later test -- reset every one of
    // them here (mirroring pallet-escrow's `reset_fixtures`) rather than
    // relying on each test to remember to call `clear_recorded`/clear
    // `OPEN_ESCROW_PAYERS` itself.
    clear_recorded();
    OPEN_ESCROW_PAYERS.with(|set| set.borrow_mut().clear());
    BONDED_PROVIDERS.with(|set| set.borrow_mut().clear());
    let mut storage = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();
    pallet_balances::GenesisConfig::<Test> {
        balances: vec![(1, 1_000), (2, 1_000), (3, 50)],
        ..Default::default()
    }
    .assimilate_storage(&mut storage)
    .unwrap();
    storage.into()
}

#[test]
fn register_reserves_stake_and_marks_active() {
    new_test_ext().execute_with(|| {
        assert_ok!(NetworkValidator::register_validator(
            RuntimeOrigin::signed(1),
            100
        ));
        assert!(NetworkValidator::is_active(&1));
        assert_eq!(Balances::reserved_balance(1), 100);
        assert_eq!(Balances::free_balance(1), 900);
    });
}

#[test]
fn register_rejects_below_min_stake() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            NetworkValidator::register_validator(RuntimeOrigin::signed(1), 99),
            crate::Error::<Test>::InsufficientStake
        );
    });
}

#[test]
fn register_rejects_insufficient_free_balance() {
    new_test_ext().execute_with(|| {
        // Account 3 only has 50 total; registering 100 must fail on the
        // currency reserve, not silently succeed with an unbacked stake.
        assert_noop!(
            NetworkValidator::register_validator(RuntimeOrigin::signed(3), 100),
            crate::Error::<Test>::InsufficientFreeBalance
        );
    });
}

#[test]
fn register_rejects_double_registration() {
    new_test_ext().execute_with(|| {
        assert_ok!(NetworkValidator::register_validator(
            RuntimeOrigin::signed(1),
            100
        ));
        assert_noop!(
            NetworkValidator::register_validator(RuntimeOrigin::signed(1), 100),
            crate::Error::<Test>::AlreadyRegistered
        );
    });
}

// ---------------------------------------------------------------------
// Reserve-balance contamination guard, reverse direction:
// register_validator rejects an account that currently has funds locked
// in an open pallet-escrow escrow as payer -- symmetric to pallet-escrow's
// own fund_escrow guard (see this pallet's module doc comment).
// ---------------------------------------------------------------------

#[test]
fn register_rejects_payer_with_open_escrow() {
    new_test_ext().execute_with(|| {
        set_has_open_escrow(1, true);
        assert_noop!(
            NetworkValidator::register_validator(RuntimeOrigin::signed(1), 100),
            crate::Error::<Test>::PayerHasOpenEscrow
        );
        // No partial state: nothing reserved, no record created.
        assert_eq!(Balances::reserved_balance(1), 0);
        assert!(!NetworkValidator::is_active(&1));
    });
}

#[test]
fn register_succeeds_once_open_escrow_is_cleared() {
    new_test_ext().execute_with(|| {
        set_has_open_escrow(1, true);
        assert_noop!(
            NetworkValidator::register_validator(RuntimeOrigin::signed(1), 100),
            crate::Error::<Test>::PayerHasOpenEscrow
        );
        set_has_open_escrow(1, false);
        assert_ok!(NetworkValidator::register_validator(
            RuntimeOrigin::signed(1),
            100
        ));
        assert!(NetworkValidator::is_active(&1));
    });
}

// ---------------------------------------------------------------------
// ADR-036 §5: reserve-balance contamination guard, third edge --
// register_validator rejects an account with an open bond in
// pallet-provider-registry.
// ---------------------------------------------------------------------

#[test]
fn register_rejects_bonded_provider() {
    new_test_ext().execute_with(|| {
        set_has_open_bond(1, true);
        assert_noop!(
            NetworkValidator::register_validator(RuntimeOrigin::signed(1), 100),
            crate::Error::<Test>::CallerIsBondedProvider
        );
        assert_eq!(Balances::reserved_balance(1), 0);
        assert!(!NetworkValidator::is_active(&1));
    });
}

#[test]
fn register_succeeds_once_bond_is_cleared() {
    new_test_ext().execute_with(|| {
        set_has_open_bond(1, true);
        assert_noop!(
            NetworkValidator::register_validator(RuntimeOrigin::signed(1), 100),
            crate::Error::<Test>::CallerIsBondedProvider
        );
        set_has_open_bond(1, false);
        assert_ok!(NetworkValidator::register_validator(
            RuntimeOrigin::signed(1),
            100
        ));
        assert!(NetworkValidator::is_active(&1));
    });
}

#[test]
fn register_does_not_reject_an_unrelated_account_with_open_escrow() {
    new_test_ext().execute_with(|| {
        // Only account 1's own open-escrow status matters, not some other
        // account's.
        set_has_open_escrow(2, true);
        assert_ok!(NetworkValidator::register_validator(
            RuntimeOrigin::signed(1),
            100
        ));
    });
}

#[test]
fn exit_and_withdraw_flow_respects_unbonding_period() {
    new_test_ext().execute_with(|| {
        System::set_block_number(1);
        assert_ok!(NetworkValidator::register_validator(
            RuntimeOrigin::signed(1),
            100
        ));
        assert_ok!(NetworkValidator::request_exit(RuntimeOrigin::signed(1)));
        // No longer active once exiting, even though the record still exists.
        assert!(!NetworkValidator::is_active(&1));
        assert_noop!(
            NetworkValidator::withdraw_unbonded(RuntimeOrigin::signed(1)),
            crate::Error::<Test>::UnbondingNotComplete
        );
        System::set_block_number(1 + UnbondingPeriod::get());
        assert_ok!(NetworkValidator::withdraw_unbonded(RuntimeOrigin::signed(
            1
        )));
        assert_eq!(Balances::reserved_balance(1), 0);
        assert_eq!(Balances::free_balance(1), 1_000);
        assert_noop!(
            NetworkValidator::withdraw_unbonded(RuntimeOrigin::signed(1)),
            crate::Error::<Test>::NotRegistered
        );
    });
}

#[test]
fn request_exit_is_not_idempotent_while_already_exiting() {
    new_test_ext().execute_with(|| {
        assert_ok!(NetworkValidator::register_validator(
            RuntimeOrigin::signed(1),
            100
        ));
        assert_ok!(NetworkValidator::request_exit(RuntimeOrigin::signed(1)));
        assert_noop!(
            NetworkValidator::request_exit(RuntimeOrigin::signed(1)),
            crate::Error::<Test>::AlreadyExiting
        );
    });
}

#[test]
fn suspend_and_reinstate_require_the_suspension_origin() {
    new_test_ext().execute_with(|| {
        assert_ok!(NetworkValidator::register_validator(
            RuntimeOrigin::signed(1),
            100
        ));
        assert_noop!(
            NetworkValidator::suspend(RuntimeOrigin::signed(2), 1),
            DispatchError::BadOrigin
        );
        assert_ok!(NetworkValidator::suspend(RuntimeOrigin::root(), 1));
        assert!(!NetworkValidator::is_active(&1));
        assert_noop!(
            NetworkValidator::suspend(RuntimeOrigin::root(), 1),
            crate::Error::<Test>::NotActive
        );
        assert_noop!(
            NetworkValidator::reinstate(RuntimeOrigin::signed(2), 1),
            DispatchError::BadOrigin
        );
        assert_ok!(NetworkValidator::reinstate(RuntimeOrigin::root(), 1));
        assert!(NetworkValidator::is_active(&1));
    });
}

#[test]
fn suspended_validator_cannot_exit_or_withdraw_around_suspension() {
    new_test_ext().execute_with(|| {
        assert_ok!(NetworkValidator::register_validator(
            RuntimeOrigin::signed(1),
            100
        ));
        assert_ok!(NetworkValidator::suspend(RuntimeOrigin::root(), 1));
        // Suspended validators can still request exit (to leave the set for
        // good) -- suspension blocks new committee work, not unbonding.
        assert_ok!(NetworkValidator::request_exit(RuntimeOrigin::signed(1)));
        assert!(!NetworkValidator::is_active(&1));
    });
}

#[test]
fn unregistered_account_is_never_active() {
    new_test_ext().execute_with(|| {
        assert!(!NetworkValidator::is_active(&42));
    });
}

// --- Scoring: committee assignment, evidence, aggregation (ADR-011 §1/§3/§5) ---

const PROVIDER: u64 = 1;
const ROUND: u64 = 7;

/// Registers `count` validators (accounts 10..10+count), all funded and
/// active, so scoring tests start from a realistic validator set.
fn register_validators(count: u64) -> Vec<u64> {
    (10..10 + count)
        .inspect(|&account| {
            Balances::force_set_balance(RuntimeOrigin::root(), account, 1_000).expect("fund");
            NetworkValidator::register_validator(RuntimeOrigin::signed(account), 100)
                .expect("register");
        })
        .collect()
}

/// The validators actually assigned to score PROVIDER in ROUND. Tests
/// submit from these rather than from arbitrary accounts, because slots
/// are assigned rather than self-selected.
fn committee() -> Vec<u64> {
    NetworkValidator::committee(&PROVIDER, ROUND)
}

/// Each validator challenges with its own freshly random payload in
/// production (`internal/networkvalidator`), so its `payload_hash` is its
/// own. Deriving the test hash from the validator id keeps that property:
/// a shared constant here would make every multi-validator test submit
/// evidence that is, by the pallet's own definition, copied.
fn payload_hash_for(validator: u64) -> [u8; 32] {
    let mut hash = [0u8; 32];
    hash[..8].copy_from_slice(&validator.to_le_bytes());
    hash
}

fn submit(validator: u64, dimension: ScoreDimension, score: u16) -> sp_runtime::DispatchResult {
    NetworkValidator::submit_evidence(
        RuntimeOrigin::signed(validator),
        PROVIDER,
        ROUND,
        dimension,
        score,
        10,
        payload_hash_for(validator),
    )
}

#[test]
fn committee_is_deterministic_bounded_and_excludes_the_provider() {
    new_test_ext().execute_with(|| {
        // Register the provider itself as a validator too, to prove it is
        // filtered out of its own committee.
        Balances::force_set_balance(RuntimeOrigin::root(), PROVIDER, 1_000).expect("fund");
        assert_ok!(NetworkValidator::register_validator(
            RuntimeOrigin::signed(PROVIDER),
            100
        ));
        register_validators(8);

        let first = committee();
        assert_eq!(
            first.len(),
            TargetCommitteeSize::get() as usize,
            "committee must be exactly the target size when enough validators exist"
        );
        assert!(
            !first.contains(&PROVIDER),
            "a provider must never be assigned to score itself"
        );
        let mut distinct = first.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(distinct.len(), first.len(), "members must be distinct");
        // Pure function of committed state: same inputs, same committee.
        assert_eq!(first, committee());
        // A different round yields a different draw (not a fixed set).
        assert_ne!(first, NetworkValidator::committee(&PROVIDER, ROUND + 1));
    });
}

#[test]
fn committee_shrinks_gracefully_when_few_validators_exist() {
    new_test_ext().execute_with(|| {
        let validators = register_validators(2); // fewer than TargetCommitteeSize
        let assigned = committee();
        assert_eq!(assigned.len(), 2);
        for member in &assigned {
            assert!(validators.contains(member));
        }
    });
}

#[test]
fn suspended_and_exiting_validators_leave_the_committee_pool() {
    new_test_ext().execute_with(|| {
        let validators = register_validators(6);
        assert_eq!(crate::ActiveValidatorSet::<Test>::get().len(), 6);

        assert_ok!(NetworkValidator::suspend(
            RuntimeOrigin::root(),
            validators[0]
        ));
        assert_ok!(NetworkValidator::request_exit(RuntimeOrigin::signed(
            validators[1]
        )));
        let pool = crate::ActiveValidatorSet::<Test>::get();
        assert_eq!(pool.len(), 4);
        assert!(!pool.contains(&validators[0]));
        assert!(!pool.contains(&validators[1]));
        assert!(!committee().contains(&validators[0]));
        assert!(!committee().contains(&validators[1]));

        // Reinstatement puts a validator back in the pool.
        assert_ok!(NetworkValidator::reinstate(
            RuntimeOrigin::root(),
            validators[0]
        ));
        assert!(crate::ActiveValidatorSet::<Test>::get().contains(&validators[0]));
    });
}

#[test]
fn evidence_requires_an_active_validator() {
    new_test_ext().execute_with(|| {
        register_validators(6);
        // Account 2 is funded but never registered as a validator.
        assert_noop!(
            submit(2, ScoreDimension::Compute, 5_000),
            crate::Error::<Test>::NotAnActiveValidator
        );
    });
}

#[test]
fn an_unassigned_validator_cannot_submit() {
    new_test_ext().execute_with(|| {
        let validators = register_validators(8);
        let assigned = committee();
        let outsider = validators
            .iter()
            .find(|candidate| !assigned.contains(candidate))
            .copied()
            .expect("with 8 validators and a committee of 5 some are unassigned");
        assert_noop!(
            submit(outsider, ScoreDimension::Compute, 5_000),
            crate::Error::<Test>::NotAssignedToRound
        );
    });
}

#[test]
fn a_suspended_validator_cannot_submit_evidence() {
    new_test_ext().execute_with(|| {
        register_validators(6);
        let member = committee()[0];
        assert_ok!(NetworkValidator::suspend(RuntimeOrigin::root(), member));
        assert_noop!(
            submit(member, ScoreDimension::Compute, 5_000),
            crate::Error::<Test>::NotAnActiveValidator
        );
    });
}

#[test]
fn a_validator_cannot_score_itself() {
    new_test_ext().execute_with(|| {
        register_validators(6);
        let member = committee()[0];
        assert_noop!(
            NetworkValidator::submit_evidence(
                RuntimeOrigin::signed(member),
                member, // provider == validator
                ROUND,
                ScoreDimension::Compute,
                10_000,
                10,
                [1; 32]
            ),
            crate::Error::<Test>::SelfScoringForbidden
        );
    });
}

#[test]
fn evidence_rejects_duplicate_replayed_and_out_of_range_submissions() {
    new_test_ext().execute_with(|| {
        register_validators(6);
        let member = committee()[0];
        assert_noop!(
            submit(member, ScoreDimension::Compute, 10_001), // > 100.00%
            crate::Error::<Test>::ScoreOutOfBounds
        );
        assert_noop!(
            NetworkValidator::submit_evidence(
                RuntimeOrigin::signed(member),
                PROVIDER,
                ROUND,
                ScoreDimension::Compute,
                5_000,
                0, // no samples backing the claim
                [1; 32]
            ),
            crate::Error::<Test>::InvalidSampleCount
        );
        assert_ok!(submit(member, ScoreDimension::Compute, 5_000));
        // Same validator, same (provider, round, dimension) -> replay.
        assert_noop!(
            submit(member, ScoreDimension::Compute, 9_000),
            crate::Error::<Test>::DuplicateSubmission
        );
        // A different dimension in the same round is a separate slot.
        assert_ok!(submit(member, ScoreDimension::Storage, 9_000));
    });
}

#[test]
fn a_validator_cannot_submit_another_validators_evidence() {
    new_test_ext().execute_with(|| {
        register_validators(6);
        let assigned = committee();
        let (first, second) = (assigned[0], assigned[1]);

        assert_ok!(submit(first, ScoreDimension::Compute, 5_000));

        // A second, distinct, correctly-assigned validator submitting the
        // *same* payload_hash did not measure anything: it reused the
        // first validator's evidence blob. Payloads are 32 random bytes
        // per challenge, so honest validators never collide -- accepting
        // this would let one measurement count twice toward MinQuorum and
        // toward the trimmed mean, which is precisely the independence
        // assumption ADR-011 §2 aggregates under.
        assert_noop!(
            NetworkValidator::submit_evidence(
                RuntimeOrigin::signed(second),
                PROVIDER,
                ROUND,
                ScoreDimension::Compute,
                5_000,
                10,
                payload_hash_for(first),
            ),
            crate::Error::<Test>::CopiedEvidence
        );

        // Its own evidence is still accepted: the rejection is about the
        // copied payload, not about the validator.
        assert_ok!(submit(second, ScoreDimension::Compute, 5_000));

        // The same payload_hash in a *different* dimension is a different
        // round slot and cannot be a copy of anything in this one.
        assert_ok!(NetworkValidator::submit_evidence(
            RuntimeOrigin::signed(second),
            PROVIDER,
            ROUND,
            ScoreDimension::Storage,
            5_000,
            10,
            payload_hash_for(first),
        ));
    });
}

#[test]
fn a_round_cannot_close_below_quorum() {
    new_test_ext().execute_with(|| {
        clear_recorded();
        register_validators(6);
        let assigned = committee();
        // Only two of the five assigned validators report; MinQuorum is 3.
        for member in assigned.iter().take(2) {
            assert_ok!(submit(*member, ScoreDimension::Compute, 5_000));
        }
        assert_noop!(
            NetworkValidator::close_round(
                RuntimeOrigin::signed(assigned[0]),
                PROVIDER,
                ROUND,
                ScoreDimension::Compute
            ),
            crate::Error::<Test>::QuorumNotReached
        );
        // Nothing may reach reputation from a sub-quorum round.
        assert!(recorded().is_empty());
    });
}

#[test]
fn closing_a_round_trims_outliers_and_records_the_aggregate() {
    new_test_ext().execute_with(|| {
        clear_recorded();
        System::set_block_number(11);
        register_validators(6);
        let assigned = committee();
        // One low outlier (0), one high outlier (10_000), three honest
        // observations at 6_000. A plain mean would be 5_200; the trimmed
        // mean drops both extremes and yields exactly 6_000.
        for (member, score) in assigned.iter().zip([0u16, 6_000, 6_000, 6_000, 10_000]) {
            assert_ok!(submit(*member, ScoreDimension::Compute, score));
        }
        assert_ok!(NetworkValidator::close_round(
            RuntimeOrigin::signed(assigned[0]),
            PROVIDER,
            ROUND,
            ScoreDimension::Compute
        ));

        let result = crate::Rounds::<Test>::get((PROVIDER, ROUND, ScoreDimension::Compute))
            .expect("round result is stored");
        assert_eq!(result.score_bps, 6_000, "outliers must be trimmed");
        assert_eq!(result.submissions, 5);
        assert_eq!(result.committee_target, TargetCommitteeSize::get());
        assert_eq!(result.closed_at, 11);
        // The aggregate reached the reputation layer exactly once.
        assert_eq!(recorded(), vec![(PROVIDER, ScoreDimension::Compute, 6_000)]);
        // Raw submissions are cleared once aggregated.
        assert!(
            crate::Evidence::<Test>::get((PROVIDER, ROUND, ScoreDimension::Compute)).is_empty()
        );
    });
}

#[test]
fn a_closed_round_rejects_new_evidence_and_cannot_close_twice() {
    new_test_ext().execute_with(|| {
        clear_recorded();
        register_validators(6);
        let assigned = committee();
        for member in assigned.iter().take(3) {
            assert_ok!(submit(*member, ScoreDimension::Availability, 7_000));
        }
        assert_ok!(NetworkValidator::close_round(
            RuntimeOrigin::signed(assigned[0]),
            PROVIDER,
            ROUND,
            ScoreDimension::Availability
        ));
        assert_noop!(
            NetworkValidator::close_round(
                RuntimeOrigin::signed(assigned[0]),
                PROVIDER,
                ROUND,
                ScoreDimension::Availability
            ),
            crate::Error::<Test>::RoundAlreadyClosed
        );
        // A late but legitimately assigned validator cannot reopen or
        // influence a final round.
        assert_noop!(
            submit(assigned[4], ScoreDimension::Availability, 0),
            crate::Error::<Test>::RoundAlreadyClosed
        );
        // Exactly one reputation update, despite the repeated attempts.
        assert_eq!(recorded().len(), 1);
    });
}

#[test]
fn closing_requires_an_active_validator() {
    new_test_ext().execute_with(|| {
        register_validators(6);
        let assigned = committee();
        for member in assigned.iter().take(3) {
            assert_ok!(submit(*member, ScoreDimension::Network, 5_000));
        }
        assert_noop!(
            NetworkValidator::close_round(
                RuntimeOrigin::signed(2),
                PROVIDER,
                ROUND,
                ScoreDimension::Network
            ),
            crate::Error::<Test>::NotAnActiveValidator
        );
    });
}

#[test]
fn exactly_quorum_sized_committee_trims_to_the_median() {
    new_test_ext().execute_with(|| {
        clear_recorded();
        register_validators(6);
        let assigned = committee();
        // With exactly MinQuorum (3) submissions the trim drops the lowest
        // and highest, leaving the median alone -- a deliberately strong
        // property: at minimum quorum a single dishonest validator cannot
        // shift the result at all.
        for (member, score) in assigned.iter().take(3).zip([0u16, 4_200, 10_000]) {
            assert_ok!(submit(*member, ScoreDimension::Storage, score));
        }
        assert_ok!(NetworkValidator::close_round(
            RuntimeOrigin::signed(assigned[0]),
            PROVIDER,
            ROUND,
            ScoreDimension::Storage
        ));
        assert_eq!(recorded(), vec![(PROVIDER, ScoreDimension::Storage, 4_200)]);
    });
}

#[test]
fn the_active_set_is_bounded() {
    new_test_ext().execute_with(|| {
        // MaxValidators is 16.
        register_validators(16);
        Balances::force_set_balance(RuntimeOrigin::root(), 99, 1_000).expect("fund");
        assert_noop!(
            NetworkValidator::register_validator(RuntimeOrigin::signed(99), 100),
            crate::Error::<Test>::TooManyValidators
        );
    });
}

// --- Disputes (ADR-011 §5) ---

/// Closes a round at `score`, returning the committee, so dispute tests
/// start from a real Final round.
fn close_round_at(dimension: ScoreDimension, score: u16) -> Vec<u64> {
    let assigned = committee();
    for member in assigned.iter().take(3) {
        assert_ok!(submit(*member, dimension, score));
    }
    assert_ok!(NetworkValidator::close_round(
        RuntimeOrigin::signed(assigned[0]),
        PROVIDER,
        ROUND,
        dimension
    ));
    assigned
}

#[test]
fn a_dispute_rolls_reputation_back_to_the_pre_round_value() {
    new_test_ext().execute_with(|| {
        clear_recorded();
        System::set_block_number(1);
        register_validators(6);
        // Establish a prior value via an earlier round -- using that
        // round's own committee -- so the rollback target is a real score
        // rather than the zero default.
        let prior = NetworkValidator::committee(&PROVIDER, ROUND - 1);
        for member in prior.iter().take(3) {
            assert_ok!(NetworkValidator::submit_evidence(
                RuntimeOrigin::signed(*member),
                PROVIDER,
                ROUND - 1,
                ScoreDimension::Compute,
                3_000,
                10,
                payload_hash_for(*member)
            ));
        }
        assert_ok!(NetworkValidator::close_round(
            RuntimeOrigin::signed(prior[0]),
            PROVIDER,
            ROUND - 1,
            ScoreDimension::Compute
        ));
        let before_disputed_round = current_score(PROVIDER, ScoreDimension::Compute);
        assert_eq!(before_disputed_round, 3_000);

        close_round_at(ScoreDimension::Compute, 9_000);
        assert_eq!(current_score(PROVIDER, ScoreDimension::Compute), 9_000);

        // The provider contests its own score.
        assert_ok!(NetworkValidator::dispute_round(
            RuntimeOrigin::signed(PROVIDER),
            PROVIDER,
            ROUND,
            ScoreDimension::Compute
        ));
        assert_eq!(
            current_score(PROVIDER, ScoreDimension::Compute),
            before_disputed_round,
            "a contested score must stop influencing reputation immediately"
        );
        let result =
            crate::Rounds::<Test>::get((PROVIDER, ROUND, ScoreDimension::Compute)).expect("round");
        assert_eq!(result.status, crate::RoundStatus::Disputed);
    });
}

#[test]
fn only_the_provider_or_a_committee_member_may_dispute() {
    new_test_ext().execute_with(|| {
        clear_recorded();
        System::set_block_number(1);
        let validators = register_validators(8);
        let assigned = close_round_at(ScoreDimension::Network, 5_000);
        let outsider = validators
            .iter()
            .find(|candidate| !assigned.contains(candidate))
            .copied()
            .expect("some validators are unassigned");

        assert_noop!(
            NetworkValidator::dispute_round(
                RuntimeOrigin::signed(outsider),
                PROVIDER,
                ROUND,
                ScoreDimension::Network
            ),
            crate::Error::<Test>::NotEntitledToDispute
        );
        // A validator that sat on the committee may dispute.
        assert_ok!(NetworkValidator::dispute_round(
            RuntimeOrigin::signed(assigned[1]),
            PROVIDER,
            ROUND,
            ScoreDimension::Network
        ));
    });
}

#[test]
fn a_dispute_must_land_inside_the_window() {
    new_test_ext().execute_with(|| {
        clear_recorded();
        System::set_block_number(1);
        register_validators(6);
        close_round_at(ScoreDimension::Storage, 5_000);
        System::set_block_number(1 + DisputeWindow::get() + 1);
        assert_noop!(
            NetworkValidator::dispute_round(
                RuntimeOrigin::signed(PROVIDER),
                PROVIDER,
                ROUND,
                ScoreDimension::Storage
            ),
            crate::Error::<Test>::DisputeWindowClosed
        );
    });
}

#[test]
fn a_round_cannot_be_disputed_twice() {
    new_test_ext().execute_with(|| {
        clear_recorded();
        System::set_block_number(1);
        register_validators(6);
        close_round_at(ScoreDimension::Reliability, 5_000);
        assert_ok!(NetworkValidator::dispute_round(
            RuntimeOrigin::signed(PROVIDER),
            PROVIDER,
            ROUND,
            ScoreDimension::Reliability
        ));
        assert_noop!(
            NetworkValidator::dispute_round(
                RuntimeOrigin::signed(PROVIDER),
                PROVIDER,
                ROUND,
                ScoreDimension::Reliability
            ),
            crate::Error::<Test>::AlreadyDisputed
        );
    });
}

#[test]
fn disputing_an_unknown_round_fails() {
    new_test_ext().execute_with(|| {
        register_validators(6);
        assert_noop!(
            NetworkValidator::dispute_round(
                RuntimeOrigin::signed(PROVIDER),
                PROVIDER,
                999,
                ScoreDimension::Compute
            ),
            crate::Error::<Test>::RoundNotFound
        );
    });
}

#[test]
fn upholding_a_dispute_keeps_the_rollback() {
    new_test_ext().execute_with(|| {
        clear_recorded();
        System::set_block_number(1);
        register_validators(6);
        close_round_at(ScoreDimension::Compute, 9_000);
        assert_ok!(NetworkValidator::dispute_round(
            RuntimeOrigin::signed(PROVIDER),
            PROVIDER,
            ROUND,
            ScoreDimension::Compute
        ));
        assert_ok!(NetworkValidator::resolve_dispute(
            RuntimeOrigin::root(),
            PROVIDER,
            ROUND,
            ScoreDimension::Compute,
            true
        ));
        let result =
            crate::Rounds::<Test>::get((PROVIDER, ROUND, ScoreDimension::Compute)).expect("round");
        assert_eq!(result.status, crate::RoundStatus::DisputeUpheld);
        assert_eq!(
            current_score(PROVIDER, ScoreDimension::Compute),
            result.previous_score_bps
        );
    });
}

#[test]
fn rejecting_a_dispute_reapplies_the_aggregate() {
    new_test_ext().execute_with(|| {
        clear_recorded();
        System::set_block_number(1);
        register_validators(6);
        close_round_at(ScoreDimension::Compute, 9_000);
        assert_ok!(NetworkValidator::dispute_round(
            RuntimeOrigin::signed(PROVIDER),
            PROVIDER,
            ROUND,
            ScoreDimension::Compute
        ));
        assert_ne!(current_score(PROVIDER, ScoreDimension::Compute), 9_000);
        assert_ok!(NetworkValidator::resolve_dispute(
            RuntimeOrigin::root(),
            PROVIDER,
            ROUND,
            ScoreDimension::Compute,
            false
        ));
        let result =
            crate::Rounds::<Test>::get((PROVIDER, ROUND, ScoreDimension::Compute)).expect("round");
        assert_eq!(result.status, crate::RoundStatus::DisputeRejected);
        assert_eq!(current_score(PROVIDER, ScoreDimension::Compute), 9_000);
    });
}

// ADR-018: upholding a dispute slashes exactly the validators whose
// submission was counted into the wrong aggregate -- not every committee
// member, and never more than what was actually reserved.
#[test]
fn upholding_a_dispute_slashes_only_the_considered_validators() {
    new_test_ext().execute_with(|| {
        clear_recorded();
        System::set_block_number(1);
        register_validators(6);
        let assigned = close_round_at(ScoreDimension::Compute, 9_000);
        let considered =
            crate::RoundSubmitters::<Test>::get((PROVIDER, ROUND, ScoreDimension::Compute));
        // close_round_at submits identical scores from exactly 3
        // committee members (MinQuorum), so trimmed() -- which discards
        // one lowest and one highest -- keeps exactly the middle one.
        assert_eq!(considered.len(), 1, "exactly one submission survives trimming with 3 identical scores");
        let slashed_validator = considered[0];
        let untouched: Vec<u64> = assigned
            .iter()
            .take(3)
            .copied()
            .filter(|member| *member != slashed_validator)
            .collect();
        assert_eq!(untouched.len(), 2);

        let issuance_before = <Balances as frame_support::traits::Currency<u64>>::total_issuance();
        let reserved_before = Balances::reserved_balance(slashed_validator);

        assert_ok!(NetworkValidator::dispute_round(
            RuntimeOrigin::signed(PROVIDER),
            PROVIDER,
            ROUND,
            ScoreDimension::Compute
        ));
        assert_ok!(NetworkValidator::resolve_dispute(
            RuntimeOrigin::root(),
            PROVIDER,
            ROUND,
            ScoreDimension::Compute,
            true
        ));

        assert_eq!(
            Balances::reserved_balance(slashed_validator),
            reserved_before - SlashAmount::get(),
            "the considered validator's reserved stake must drop by exactly SlashAmount"
        );
        assert_eq!(
            crate::Validators::<Test>::get(slashed_validator).expect("still registered").stake,
            100 - SlashAmount::get(),
            "ValidatorRecord.stake bookkeeping must track the real reserved balance, or withdraw_unbonded would later try to unreserve too much"
        );
        for other in untouched {
            assert_eq!(
                Balances::reserved_balance(other),
                100,
                "a validator trimmed as an outlier (not in RoundSubmitters) must not be slashed"
            );
        }
        assert_eq!(
            <Balances as frame_support::traits::Currency<u64>>::total_issuance(),
            issuance_before - SlashAmount::get(),
            "slashed funds are burned (ADR-018 §3), not paid to the disputer or the provider"
        );
    });
}

#[test]
fn rejecting_a_dispute_slashes_no_one() {
    new_test_ext().execute_with(|| {
        clear_recorded();
        System::set_block_number(1);
        register_validators(6);
        close_round_at(ScoreDimension::Compute, 9_000);
        assert_ok!(NetworkValidator::dispute_round(
            RuntimeOrigin::signed(PROVIDER),
            PROVIDER,
            ROUND,
            ScoreDimension::Compute
        ));
        assert_ok!(NetworkValidator::resolve_dispute(
            RuntimeOrigin::root(),
            PROVIDER,
            ROUND,
            ScoreDimension::Compute,
            false
        ));
        for validator in 10u64..16 {
            assert_eq!(
                Balances::reserved_balance(validator),
                100,
                "rejecting a dispute must leave every validator's stake untouched"
            );
        }
    });
}

// A slash that exhausts a validator's reserved stake must force-suspend
// them -- otherwise a zero-stake validator would keep collecting
// committee assignments until someone notices and calls `suspend`
// manually (ADR-018 §3).
#[test]
fn a_slash_that_exhausts_stake_force_suspends_the_validator() {
    new_test_ext().execute_with(|| {
        clear_recorded();
        System::set_block_number(1);
        let validators = register_validators(6);
        // Two upheld disputes at SlashAmount=40 against a stake of 100
        // leaves 20; a third removes exactly what's left and must zero
        // the stake and force-suspend, not underflow or error.
        for round in [7u64, 8u64, 9u64] {
            let assigned = NetworkValidator::committee(&PROVIDER, round);
            for member in assigned.iter().take(3) {
                assert_ok!(NetworkValidator::submit_evidence(
                    RuntimeOrigin::signed(*member),
                    PROVIDER,
                    round,
                    ScoreDimension::Compute,
                    9_000,
                    10,
                    payload_hash_for(*member)
                ));
            }
            assert_ok!(NetworkValidator::close_round(
                RuntimeOrigin::signed(assigned[0]),
                PROVIDER,
                round,
                ScoreDimension::Compute
            ));
            assert_ok!(NetworkValidator::dispute_round(
                RuntimeOrigin::signed(PROVIDER),
                PROVIDER,
                round,
                ScoreDimension::Compute
            ));
            assert_ok!(NetworkValidator::resolve_dispute(
                RuntimeOrigin::root(),
                PROVIDER,
                round,
                ScoreDimension::Compute,
                true
            ));
        }

        // Every validator that was ever the trimmed-mean's sole survivor
        // across the three rounds must now be suspended if its stake hit
        // zero -- assert on the set, since which single member survives
        // trimming each round is a deterministic function of the
        // committee's account-id ordering, not chosen by this test.
        let mut any_suspended = false;
        for validator in &validators {
            let record = crate::Validators::<Test>::get(validator).expect("still registered");
            if record.stake == 0 {
                assert_eq!(
                    record.status,
                    crate::ValidatorStatus::Suspended,
                    "a validator slashed to zero stake must be force-suspended"
                );
                assert!(
                    !crate::ActiveValidatorSet::<Test>::get().contains(validator),
                    "a force-suspended validator must leave the active set (no further committee assignments)"
                );
                any_suspended = true;
            }
        }
        assert!(
            any_suspended,
            "three upheld disputes against a stake of 100 at SlashAmount=40 must zero out someone's stake"
        );
    });
}

#[test]
fn resolving_requires_governance_and_an_actual_dispute() {
    new_test_ext().execute_with(|| {
        clear_recorded();
        System::set_block_number(1);
        register_validators(6);
        let assigned = close_round_at(ScoreDimension::Compute, 9_000);
        // Not disputed yet.
        assert_noop!(
            NetworkValidator::resolve_dispute(
                RuntimeOrigin::root(),
                PROVIDER,
                ROUND,
                ScoreDimension::Compute,
                true
            ),
            crate::Error::<Test>::NotDisputed
        );
        assert_ok!(NetworkValidator::dispute_round(
            RuntimeOrigin::signed(PROVIDER),
            PROVIDER,
            ROUND,
            ScoreDimension::Compute
        ));
        // A validator cannot settle its own dispute.
        assert_noop!(
            NetworkValidator::resolve_dispute(
                RuntimeOrigin::signed(assigned[0]),
                PROVIDER,
                ROUND,
                ScoreDimension::Compute,
                true
            ),
            DispatchError::BadOrigin
        );
    });
}

// --- Validator reward accrual (ADR-011 §5) ---

#[test]
fn only_submissions_surviving_trimming_are_rewarded() {
    new_test_ext().execute_with(|| {
        clear_recorded();
        System::set_block_number(1);
        register_validators(6);
        let assigned = committee();
        // Sorted by score, the 0 and the 10_000 are trimmed; the three
        // 6_000s survive and are the only ones paid.
        let scores = [0u16, 6_000, 6_000, 6_000, 10_000];
        for (member, score) in assigned.iter().zip(scores) {
            assert_ok!(submit(*member, ScoreDimension::Compute, score));
        }
        assert_ok!(NetworkValidator::close_round(
            RuntimeOrigin::signed(assigned[0]),
            PROVIDER,
            ROUND,
            ScoreDimension::Compute
        ));

        let low_outlier = assigned[0];
        let high_outlier = assigned[4];
        assert_eq!(points_of(low_outlier), 0, "a low outlier earns nothing");
        assert_eq!(points_of(high_outlier), 0, "a high outlier earns nothing");
        for member in assigned.iter().take(4).skip(1) {
            assert_eq!(
                points_of(*member),
                PointsPerAcceptedSubmission::get(),
                "a non-outlier submitter is rewarded exactly once"
            );
        }
    });
}

#[test]
fn round_closed_event_reports_how_many_were_rewarded() {
    new_test_ext().execute_with(|| {
        clear_recorded();
        System::set_block_number(1);
        register_validators(6);
        let assigned = committee();
        for member in assigned.iter().take(3) {
            assert_ok!(submit(*member, ScoreDimension::Network, 5_000));
        }
        assert_ok!(NetworkValidator::close_round(
            RuntimeOrigin::signed(assigned[0]),
            PROVIDER,
            ROUND,
            ScoreDimension::Network
        ));
        // Three submissions -> one trimmed at each end -> one rewarded.
        let rewarded: u64 = assigned
            .iter()
            .take(3)
            .map(|member| points_of(*member))
            .sum();
        assert_eq!(rewarded, PointsPerAcceptedSubmission::get());
    });
}

#[test]
fn tied_scores_are_trimmed_deterministically() {
    new_test_ext().execute_with(|| {
        clear_recorded();
        System::set_block_number(1);
        register_validators(6);
        let assigned = committee();
        // All-equal scores: the mean is unambiguous, and the tie-break on
        // validator id must make the choice of who gets trimmed stable
        // rather than dependent on submission order.
        for member in assigned.iter() {
            assert_ok!(submit(*member, ScoreDimension::Storage, 5_000));
        }
        assert_ok!(NetworkValidator::close_round(
            RuntimeOrigin::signed(assigned[0]),
            PROVIDER,
            ROUND,
            ScoreDimension::Storage
        ));
        assert_eq!(recorded(), vec![(PROVIDER, ScoreDimension::Storage, 5_000)]);
        // Five submitted, two trimmed, three paid.
        let paid = assigned
            .iter()
            .filter(|member| points_of(**member) > 0)
            .count();
        assert_eq!(paid, 3);
        // The trimmed pair is the lowest and highest validator id, since
        // all scores tie.
        let mut sorted = assigned.clone();
        sorted.sort_unstable();
        assert_eq!(points_of(sorted[0]), 0);
        assert_eq!(points_of(sorted[4]), 0);
    });
}
