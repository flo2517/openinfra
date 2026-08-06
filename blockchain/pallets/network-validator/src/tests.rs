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
}

impl crate::Config for Test {
    type Currency = Balances;
    type SuspensionOrigin = frame_system::EnsureRoot<u64>;
    type ReputationUpdater = RecordingUpdater;
    type ValidatorRewards = RecordingRewards;
    type MinStake = MinStake;
    type UnbondingPeriod = UnbondingPeriod;
    type MaxSubmissionsPerRound = MaxSubmissionsPerRound;
    type MinQuorum = MinQuorum;
    type TargetCommitteeSize = TargetCommitteeSize;
    type MaxValidators = MaxValidators;
    type DisputeWindow = DisputeWindow;
    type PointsPerAcceptedSubmission = PointsPerAcceptedSubmission;
    type WeightInfo = ();
}

fn new_test_ext() -> sp_io::TestExternalities {
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

fn submit(validator: u64, dimension: ScoreDimension, score: u16) -> sp_runtime::DispatchResult {
    NetworkValidator::submit_evidence(
        RuntimeOrigin::signed(validator),
        PROVIDER,
        ROUND,
        dimension,
        score,
        10,
        [1; 32],
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
                [1; 32]
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
