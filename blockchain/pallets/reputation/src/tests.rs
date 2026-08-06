use crate as pallet_reputation;
use crate::{EnsureActiveValidator, NetworkValidatorInspector};
use frame_support::{assert_noop, assert_ok, derive_impl, parameter_types, traits::EnsureOrigin};
use sp_runtime::{BuildStorage, DispatchError};

type Block = frame_system::mocking::MockBlock<Test>;
frame_support::construct_runtime!(pub enum Test { System: frame_system, Reputation: pallet_reputation });

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
}

/// Account 7 only -- just enough to distinguish an active validator from
/// every other signed account in EnsureActiveValidator tests below.
pub struct OnlyAccountSeven;
impl NetworkValidatorInspector<u64> for OnlyAccountSeven {
    fn is_active(validator: &u64) -> bool {
        *validator == 7
    }
}

parameter_types! {
    pub const DefaultScore: u32 = 500;
    pub const MaxScore: u32 = 1_000;
    pub const MaxDelta: u32 = 500;
}
impl crate::Config for Test {
    type UpdateOrigin = frame_system::EnsureRoot<u64>;
    type ProviderInspector = ();
    type ValidatorInspector = OnlyAccountSeven;
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

#[test]
fn availability_updates_integer_vector_and_global_score() {
    new_test_ext().execute_with(|| {
        assert_ok!(Reputation::record_availability(
            RuntimeOrigin::root(),
            2,
            9_000,
            10
        ));
        let vector = Reputation::vector(2).expect("vector");
        assert_eq!(vector.availability, 900);
        assert_eq!(vector.global, 580);
        assert_eq!(crate::ReputationScores::<Test>::get(2), Some(900));
    });
}

#[test]
fn vector_rejects_unauthorized_and_out_of_range_values() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            Reputation::update_vector(RuntimeOrigin::signed(1), 2, 1, 1, 1, 1, 1),
            DispatchError::BadOrigin
        );
        assert_noop!(
            Reputation::update_vector(RuntimeOrigin::root(), 2, 1_001, 1, 1, 1, 1),
            crate::Error::<Test>::VectorValueOutOfBounds
        );
        assert_noop!(
            Reputation::record_availability(RuntimeOrigin::root(), 2, 10_001, 1),
            crate::Error::<Test>::AvailabilityOutOfBounds
        );
    });
}

#[test]
fn ensure_active_validator_accepts_only_a_signed_active_validator() {
    let result = EnsureActiveValidator::<Test>::ensure_origin(RuntimeOrigin::signed(7));
    assert_eq!(
        result.expect("account 7 is configured as the active validator"),
        7
    );
}

#[test]
fn ensure_active_validator_rejects_a_signed_inactive_account() {
    assert!(EnsureActiveValidator::<Test>::ensure_origin(RuntimeOrigin::signed(1)).is_err());
}

#[test]
fn ensure_active_validator_rejects_root_even_though_it_outranks_everything_else() {
    assert!(EnsureActiveValidator::<Test>::ensure_origin(RuntimeOrigin::root()).is_err());
}

#[test]
fn ensure_active_validator_rejects_none_origin() {
    assert!(EnsureActiveValidator::<Test>::ensure_origin(RuntimeOrigin::none()).is_err());
}
