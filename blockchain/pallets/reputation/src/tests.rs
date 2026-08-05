use crate as pallet_reputation;
use frame_support::{assert_noop, assert_ok, derive_impl, parameter_types};
use sp_runtime::{BuildStorage, DispatchError};

type Block = frame_system::mocking::MockBlock<Test>;
frame_support::construct_runtime!(pub enum Test { System: frame_system, Reputation: pallet_reputation });

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
}

parameter_types! {
    pub const DefaultScore: u32 = 500;
    pub const MaxScore: u32 = 1_000;
    pub const MaxDelta: u32 = 500;
}
impl crate::Config for Test {
    type UpdateOrigin = frame_system::EnsureRoot<u64>;
    type ProviderInspector = ();
    type DefaultScore = DefaultScore;
    type MaxScore = MaxScore;
    type MaxDelta = MaxDelta;
    type WeightInfo = ();
}

fn new_test_ext() -> sp_io::TestExternalities {
    frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap()
        .into()
}

#[test]
fn origin_and_delta_are_bounded() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            Reputation::submit_score(RuntimeOrigin::signed(1), 2, 1),
            DispatchError::BadOrigin
        );
        assert_noop!(
            Reputation::submit_score(RuntimeOrigin::root(), 2, 501),
            crate::Error::<Test>::DeltaOutOfBounds
        );
    });
}

#[test]
fn score_clamps_without_overflow_or_underflow() {
    new_test_ext().execute_with(|| {
        assert_ok!(Reputation::submit_score(RuntimeOrigin::root(), 2, 500));
        assert_eq!(crate::ReputationScores::<Test>::get(2), Some(1_000));
        assert_ok!(Reputation::submit_score(RuntimeOrigin::root(), 2, 500));
        assert_eq!(crate::ReputationScores::<Test>::get(2), Some(1_000));
        assert_ok!(Reputation::submit_score(RuntimeOrigin::root(), 2, -500));
        assert_ok!(Reputation::submit_score(RuntimeOrigin::root(), 2, -500));
        assert_ok!(Reputation::submit_score(RuntimeOrigin::root(), 2, -500));
        assert_eq!(crate::ReputationScores::<Test>::get(2), Some(0));
    });
}

#[test]
fn i32_min_is_rejected_without_panicking() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            Reputation::submit_score(RuntimeOrigin::root(), 2, i32::MIN),
            crate::Error::<Test>::DeltaOutOfBounds
        );
    });
}
