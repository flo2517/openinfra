use crate::{self as pallet_openinfra_rewards, *};
use frame_support::{
    assert_noop, assert_ok, construct_runtime, derive_impl,
    traits::{ConstU32, ConstU64, Everything},
    weights::Weight,
};
use frame_system::EnsureSignedBy;
use sp_runtime::{BuildStorage, DispatchError};

type AccountId = u64;

construct_runtime!(
    pub enum Test {
        System: frame_system,
        Rewards: pallet_openinfra_rewards,
    }
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = frame_system::mocking::MockBlock<Test>;
    type AccountId = AccountId;
    type BaseCallFilter = Everything;
}

frame_support::ord_parameter_types! {
    pub const RewardAuthority: AccountId = 99;
}

pub struct TestWeightInfo;
impl WeightInfo for TestWeightInfo {
    fn calculate_reward() -> Weight {
        Weight::from_parts(10_000, 0)
    }
    fn claim_reward() -> Weight {
        Weight::from_parts(10_000, 0)
    }
}

impl Config for Test {
    type RewardOrigin = EnsureSignedBy<RewardAuthority, AccountId>;
    type MaxResourceUnits = ConstU64<1_000_000>;
    type MaxDuration = ConstU64<1_000_000>;
    type MaxReputation = ConstU32<1_000>;
    type WeightInfo = TestWeightInfo;
}

fn new_test_ext() -> sp_io::TestExternalities {
    frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap()
        .into()
}

#[test]
fn controlled_origin_calculates_expected_points_once() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            Rewards::calculate_reward(RuntimeOrigin::signed(1), 7, 2, 10, 100, 500, 100),
            DispatchError::BadOrigin
        );
        assert_ok!(Rewards::calculate_reward(
            RuntimeOrigin::signed(99),
            7,
            2,
            10,
            100,
            500,
            100
        ));
        assert_eq!(Rewards::reward_balance(2), 1_500);
        assert_eq!(Rewards::processed_reward(7), Some(1_500));
        assert_noop!(
            Rewards::calculate_reward(RuntimeOrigin::signed(99), 7, 2, 10, 100, 500, 100),
            Error::<Test>::LeaseAlreadyRewarded
        );
    });
}

#[test]
fn validates_all_reward_inputs() {
    new_test_ext().execute_with(|| {
        let origin = || RuntimeOrigin::signed(99);
        assert_noop!(
            Rewards::calculate_reward(origin(), 1, 2, 0, 1, 0, 100),
            Error::<Test>::InvalidResourceUnits
        );
        assert_noop!(
            Rewards::calculate_reward(origin(), 1, 2, 1, 0, 0, 100),
            Error::<Test>::InvalidDuration
        );
        assert_noop!(
            Rewards::calculate_reward(origin(), 1, 2, 1, 1, 1_001, 100),
            Error::<Test>::ReputationOutOfBounds
        );
        assert_noop!(
            Rewards::calculate_reward(origin(), 1, 2, 1, 1, 0, 101),
            Error::<Test>::AvailabilityOutOfBounds
        );
        assert_noop!(
            Rewards::calculate_reward(origin(), 1, 2, 1, 1, 0, 0),
            Error::<Test>::ZeroReward
        );
    });
}

#[test]
fn claim_clears_points_and_empty_claim_fails() {
    new_test_ext().execute_with(|| {
        assert_ok!(Rewards::calculate_reward(
            RuntimeOrigin::signed(99),
            7,
            2,
            10,
            100,
            500,
            100
        ));
        assert_ok!(Rewards::claim_reward(RuntimeOrigin::signed(2)));
        assert_eq!(Rewards::reward_balance(2), 0);
        assert_noop!(
            Rewards::claim_reward(RuntimeOrigin::signed(2)),
            Error::<Test>::InsufficientPoints
        );
    });
}

#[test]
fn checked_math_rejects_overflow_without_marking_lease() {
    new_test_ext().execute_with(|| {
        // The configured input bounds keep ordinary values safe. This directly
        // seeds a full balance to exercise the final checked addition.
        RewardBalances::<Test>::insert(2, u64::MAX);
        assert_noop!(
            Rewards::calculate_reward(RuntimeOrigin::signed(99), 7, 2, 10, 100, 500, 100),
            Error::<Test>::ArithmeticOverflow
        );
        assert_eq!(Rewards::processed_reward(7), None);
    });
}
