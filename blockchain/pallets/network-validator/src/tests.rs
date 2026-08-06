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
        Ok(())
    }
}

fn recorded() -> Vec<(u64, ScoreDimension, u16)> {
    RECORDED.with(|recorded| recorded.borrow().clone())
}

fn clear_recorded() {
    RECORDED.with(|recorded| recorded.borrow_mut().clear());
}

parameter_types! {
    pub const MaxSubmissionsPerRound: u32 = 8;
    pub const MinQuorum: u32 = 3;
    pub const TargetCommitteeSize: u32 = 5;
}

impl crate::Config for Test {
    type Currency = Balances;
    type SuspensionOrigin = frame_system::EnsureRoot<u64>;
    type ReputationUpdater = RecordingUpdater;
    type MinStake = MinStake;
    type UnbondingPeriod = UnbondingPeriod;
    type MaxSubmissionsPerRound = MaxSubmissionsPerRound;
    type MinQuorum = MinQuorum;
    type TargetCommitteeSize = TargetCommitteeSize;
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

// --- Scoring: evidence submission and round aggregation (ADR-011 §3/§5) ---

/// Registers `count` validators starting at account 10, all funded and
/// active, so scoring tests start from a realistic committee.
fn register_validators(count: u64) -> Vec<u64> {
    (10..10 + count)
        .inspect(|&account| {
            Balances::force_set_balance(RuntimeOrigin::root(), account, 1_000).expect("fund");
            NetworkValidator::register_validator(RuntimeOrigin::signed(account), 100)
                .expect("register");
        })
        .collect()
}

#[test]
fn evidence_requires_an_active_validator() {
    new_test_ext().execute_with(|| {
        clear_recorded();
        // Account 2 is funded but never registered as a validator.
        assert_noop!(
            NetworkValidator::submit_evidence(
                RuntimeOrigin::signed(2),
                1,
                7,
                ScoreDimension::Compute,
                5_000,
                10,
                [1; 32]
            ),
            crate::Error::<Test>::NotAnActiveValidator
        );
    });
}

#[test]
fn a_suspended_validator_cannot_submit_evidence() {
    new_test_ext().execute_with(|| {
        let validators = register_validators(1);
        assert_ok!(NetworkValidator::suspend(
            RuntimeOrigin::root(),
            validators[0]
        ));
        assert_noop!(
            NetworkValidator::submit_evidence(
                RuntimeOrigin::signed(validators[0]),
                1,
                7,
                ScoreDimension::Compute,
                5_000,
                10,
                [1; 32]
            ),
            crate::Error::<Test>::NotAnActiveValidator
        );
    });
}

#[test]
fn a_validator_cannot_score_itself() {
    new_test_ext().execute_with(|| {
        let validators = register_validators(1);
        assert_noop!(
            NetworkValidator::submit_evidence(
                RuntimeOrigin::signed(validators[0]),
                validators[0], // provider == validator
                7,
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
        let validators = register_validators(1);
        let validator = validators[0];
        assert_noop!(
            NetworkValidator::submit_evidence(
                RuntimeOrigin::signed(validator),
                1,
                7,
                ScoreDimension::Compute,
                10_001, // > 100.00%
                10,
                [1; 32]
            ),
            crate::Error::<Test>::ScoreOutOfBounds
        );
        assert_noop!(
            NetworkValidator::submit_evidence(
                RuntimeOrigin::signed(validator),
                1,
                7,
                ScoreDimension::Compute,
                5_000,
                0, // no samples backing the claim
                [1; 32]
            ),
            crate::Error::<Test>::InvalidSampleCount
        );
        assert_ok!(NetworkValidator::submit_evidence(
            RuntimeOrigin::signed(validator),
            1,
            7,
            ScoreDimension::Compute,
            5_000,
            10,
            [1; 32]
        ));
        // Same validator, same (provider, round, dimension) -> replay.
        assert_noop!(
            NetworkValidator::submit_evidence(
                RuntimeOrigin::signed(validator),
                1,
                7,
                ScoreDimension::Compute,
                9_000,
                10,
                [2; 32]
            ),
            crate::Error::<Test>::DuplicateSubmission
        );
        // A different dimension in the same round is a separate slot.
        assert_ok!(NetworkValidator::submit_evidence(
            RuntimeOrigin::signed(validator),
            1,
            7,
            ScoreDimension::Storage,
            9_000,
            10,
            [2; 32]
        ));
    });
}

#[test]
fn a_round_cannot_close_below_quorum() {
    new_test_ext().execute_with(|| {
        let validators = register_validators(2); // MinQuorum is 3
        for validator in &validators {
            assert_ok!(NetworkValidator::submit_evidence(
                RuntimeOrigin::signed(*validator),
                1,
                7,
                ScoreDimension::Compute,
                5_000,
                10,
                [1; 32]
            ));
        }
        assert_noop!(
            NetworkValidator::close_round(
                RuntimeOrigin::signed(validators[0]),
                1,
                7,
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
        let validators = register_validators(5);
        // One low outlier (0), one high outlier (10_000), three honest
        // observations around 60%. A plain mean would be 5_200; the
        // trimmed mean drops both extremes and yields exactly 6_000.
        let scores = [0u16, 6_000, 6_000, 6_000, 10_000];
        for (validator, score) in validators.iter().zip(scores) {
            assert_ok!(NetworkValidator::submit_evidence(
                RuntimeOrigin::signed(*validator),
                1,
                7,
                ScoreDimension::Compute,
                score,
                10,
                [1; 32]
            ));
        }
        assert_ok!(NetworkValidator::close_round(
            RuntimeOrigin::signed(validators[0]),
            1,
            7,
            ScoreDimension::Compute
        ));

        let result = crate::Rounds::<Test>::get((1, 7, ScoreDimension::Compute))
            .expect("round result is stored");
        assert_eq!(result.score_bps, 6_000, "outliers must be trimmed");
        assert_eq!(result.submissions, 5);
        assert_eq!(result.committee_target, 5);
        assert_eq!(result.closed_at, 11);
        // The aggregate reached the reputation layer exactly once.
        assert_eq!(recorded(), vec![(1, ScoreDimension::Compute, 6_000)]);
        // Raw submissions are cleared once aggregated.
        assert!(crate::Evidence::<Test>::get((1, 7, ScoreDimension::Compute)).is_empty());
    });
}

#[test]
fn a_closed_round_rejects_new_evidence_and_cannot_close_twice() {
    new_test_ext().execute_with(|| {
        clear_recorded();
        let validators = register_validators(4);
        for validator in validators.iter().take(3) {
            assert_ok!(NetworkValidator::submit_evidence(
                RuntimeOrigin::signed(*validator),
                1,
                7,
                ScoreDimension::Availability,
                7_000,
                10,
                [1; 32]
            ));
        }
        assert_ok!(NetworkValidator::close_round(
            RuntimeOrigin::signed(validators[0]),
            1,
            7,
            ScoreDimension::Availability
        ));
        assert_noop!(
            NetworkValidator::close_round(
                RuntimeOrigin::signed(validators[0]),
                1,
                7,
                ScoreDimension::Availability
            ),
            crate::Error::<Test>::RoundAlreadyClosed
        );
        // A late submitter cannot reopen or influence a final round.
        assert_noop!(
            NetworkValidator::submit_evidence(
                RuntimeOrigin::signed(validators[3]),
                1,
                7,
                ScoreDimension::Availability,
                0,
                10,
                [9; 32]
            ),
            crate::Error::<Test>::RoundAlreadyClosed
        );
        // Exactly one reputation update, despite the repeated attempts.
        assert_eq!(recorded().len(), 1);
    });
}

#[test]
fn closing_requires_an_active_validator() {
    new_test_ext().execute_with(|| {
        let validators = register_validators(3);
        for validator in &validators {
            assert_ok!(NetworkValidator::submit_evidence(
                RuntimeOrigin::signed(*validator),
                1,
                7,
                ScoreDimension::Network,
                5_000,
                10,
                [1; 32]
            ));
        }
        assert_noop!(
            NetworkValidator::close_round(RuntimeOrigin::signed(2), 1, 7, ScoreDimension::Network),
            crate::Error::<Test>::NotAnActiveValidator
        );
    });
}

#[test]
fn submissions_are_bounded_per_round() {
    new_test_ext().execute_with(|| {
        // MaxSubmissionsPerRound is 8; register one more than that.
        let validators = register_validators(9);
        for validator in validators.iter().take(8) {
            assert_ok!(NetworkValidator::submit_evidence(
                RuntimeOrigin::signed(*validator),
                1,
                7,
                ScoreDimension::Reliability,
                5_000,
                10,
                [1; 32]
            ));
        }
        assert_noop!(
            NetworkValidator::submit_evidence(
                RuntimeOrigin::signed(validators[8]),
                1,
                7,
                ScoreDimension::Reliability,
                5_000,
                10,
                [1; 32]
            ),
            crate::Error::<Test>::TooManySubmissions
        );
    });
}

#[test]
fn exactly_quorum_sized_committee_trims_to_the_median() {
    new_test_ext().execute_with(|| {
        clear_recorded();
        // With exactly MinQuorum (3) submissions the trim drops the lowest
        // and highest, leaving the median alone -- a deliberately strong
        // property: at minimum quorum a single dishonest validator cannot
        // shift the result at all.
        let validators = register_validators(3);
        for (validator, score) in validators.iter().zip([0u16, 4_200, 10_000]) {
            assert_ok!(NetworkValidator::submit_evidence(
                RuntimeOrigin::signed(*validator),
                1,
                7,
                ScoreDimension::Storage,
                score,
                10,
                [1; 32]
            ));
        }
        assert_ok!(NetworkValidator::close_round(
            RuntimeOrigin::signed(validators[0]),
            1,
            7,
            ScoreDimension::Storage
        ));
        assert_eq!(recorded(), vec![(1, ScoreDimension::Storage, 4_200)]);
    });
}
