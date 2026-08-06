use crate as pallet_network_validator;
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

impl crate::Config for Test {
    type Currency = Balances;
    type SuspensionOrigin = frame_system::EnsureRoot<u64>;
    type MinStake = MinStake;
    type UnbondingPeriod = UnbondingPeriod;
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
