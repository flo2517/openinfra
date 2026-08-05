use crate as pallet_availability;
use frame_support::{assert_noop, assert_ok, derive_impl, parameter_types, traits::ConstU32};
use sp_runtime::{BuildStorage, DispatchError};

type Block = frame_system::mocking::MockBlock<Test>;
frame_support::construct_runtime!(pub enum Test { System: frame_system, Availability: pallet_availability });

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
}

parameter_types! { pub const MaxLifetime: u64 = 10; }
impl crate::Config for Test {
    type ChallengeOrigin = frame_system::EnsureRoot<u64>;
    type ProviderInspector = ();
    type MaxPendingChallenges = ConstU32<1>;
    type MaxChallengeLifetime = MaxLifetime;
    type WeightInfo = ();
}

fn new_test_ext() -> sp_io::TestExternalities {
    let storage = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();
    storage.into()
}

#[test]
fn heartbeat_records_block() {
    new_test_ext().execute_with(|| {
        System::set_block_number(3);
        assert_ok!(Availability::submit_heartbeat(RuntimeOrigin::signed(1)));
        assert_eq!(crate::LastHeartbeat::<Test>::get(1), Some(3));
    });
}

#[test]
fn challenge_origin_and_pending_bound_are_enforced() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            Availability::issue_challenge(RuntimeOrigin::signed(9), 1, [1; 32], 2),
            DispatchError::BadOrigin
        );
        assert_ok!(Availability::issue_challenge(
            RuntimeOrigin::root(),
            1,
            [1; 32],
            2
        ));
        assert_noop!(
            Availability::issue_challenge(RuntimeOrigin::root(), 1, [2; 32], 2),
            crate::Error::<Test>::TooManyPendingChallenges
        );
    });
}

#[test]
fn response_is_checked_for_owner_expiry_and_replay() {
    new_test_ext().execute_with(|| {
        System::set_block_number(1);
        assert_ok!(Availability::issue_challenge(
            RuntimeOrigin::root(),
            1,
            [7; 32],
            2
        ));
        assert_noop!(
            Availability::submit_response(RuntimeOrigin::signed(2), 0, [7; 32]),
            crate::Error::<Test>::ChallengeNotFound
        );
        assert_noop!(
            Availability::submit_response(RuntimeOrigin::signed(1), 0, [8; 32]),
            crate::Error::<Test>::InvalidResponse
        );
        assert_ok!(Availability::submit_response(
            RuntimeOrigin::signed(1),
            0,
            [7; 32]
        ));
        assert_noop!(
            Availability::submit_response(RuntimeOrigin::signed(1), 0, [7; 32]),
            crate::Error::<Test>::ChallengeNotFound
        );
        assert_ok!(Availability::issue_challenge(
            RuntimeOrigin::root(),
            1,
            [9; 32],
            1
        ));
        System::set_block_number(3);
        assert_noop!(
            Availability::submit_response(RuntimeOrigin::signed(1), 1, [9; 32]),
            crate::Error::<Test>::ChallengeTimeout
        );
    });
}
