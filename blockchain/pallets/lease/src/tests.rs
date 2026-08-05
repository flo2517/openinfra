use crate::{self as pallet_openinfra_lease, *};
use frame_support::{
    assert_noop, assert_ok, construct_runtime, derive_impl,
    traits::{ConstU64, Everything},
    weights::Weight,
};
use frame_system::EnsureSignedBy;
use sp_runtime::{BuildStorage, DispatchError};

type AccountId = u64;

construct_runtime!(
    pub enum Test {
        System: frame_system,
        Lease: pallet_openinfra_lease,
    }
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = frame_system::mocking::MockBlock<Test>;
    type AccountId = AccountId;
    type BaseCallFilter = Everything;
}

pub struct EligibleProviders;
impl ProviderLookup<AccountId> for EligibleProviders {
    fn is_lease_eligible(provider: &AccountId) -> bool {
        *provider == 2
    }
}

frame_support::ord_parameter_types! {
    pub const LeaseAuthority: AccountId = 99;
}

pub struct TestWeightInfo;
impl WeightInfo for TestWeightInfo {
    fn create_lease() -> Weight {
        Weight::from_parts(10_000, 0)
    }
    fn update_lease_state() -> Weight {
        Weight::from_parts(10_000, 0)
    }
}

impl Config for Test {
    type LeaseOrigin = EnsureSignedBy<LeaseAuthority, AccountId>;
    type ProviderLookup = EligibleProviders;
    type MaxDuration = ConstU64<100>;
    type WeightInfo = TestWeightInfo;
}

fn new_test_ext() -> sp_io::TestExternalities {
    let mut ext: sp_io::TestExternalities = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap()
        .into();
    ext.execute_with(|| System::set_block_number(10));
    ext
}

fn create() {
    assert_ok!(Lease::create_lease(
        RuntimeOrigin::signed(1),
        7,
        2,
        [3; 32],
        20
    ));
}

#[test]
fn creates_a_bounded_unique_lease() {
    new_test_ext().execute_with(|| {
        create();
        let lease = Lease::leases(7).unwrap();
        assert_eq!(lease.start, 10);
        assert_eq!(lease.end, 30);
        assert_eq!(lease.state, LeaseState::Created);
        assert_noop!(
            Lease::create_lease(RuntimeOrigin::signed(1), 7, 2, [3; 32], 20),
            Error::<Test>::LeaseAlreadyExists
        );
    });
}

#[test]
fn rejects_invalid_provider_and_duration() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            Lease::create_lease(RuntimeOrigin::signed(1), 1, 3, [0; 32], 1),
            Error::<Test>::ProviderNotEligible
        );
        assert_noop!(
            Lease::create_lease(RuntimeOrigin::signed(1), 1, 2, [0; 32], 0),
            Error::<Test>::ZeroDuration
        );
        assert_noop!(
            Lease::create_lease(RuntimeOrigin::signed(1), 1, 2, [0; 32], 101),
            Error::<Test>::DurationTooLong
        );
    });
}

#[test]
fn state_changes_are_authorized_and_follow_the_state_machine() {
    new_test_ext().execute_with(|| {
        create();
        assert_noop!(
            Lease::update_lease_state(RuntimeOrigin::signed(1), 7, LeaseState::Active),
            DispatchError::BadOrigin
        );
        assert_noop!(
            Lease::update_lease_state(RuntimeOrigin::signed(99), 7, LeaseState::Completed),
            Error::<Test>::InvalidStateTransition
        );
        assert_ok!(Lease::update_lease_state(
            RuntimeOrigin::signed(99),
            7,
            LeaseState::Active
        ));
        assert_noop!(
            Lease::update_lease_state(RuntimeOrigin::signed(99), 7, LeaseState::Expired),
            Error::<Test>::LeaseNotYetExpired
        );
        System::set_block_number(30);
        assert_ok!(Lease::update_lease_state(
            RuntimeOrigin::signed(99),
            7,
            LeaseState::Expired
        ));
        assert_noop!(
            Lease::update_lease_state(RuntimeOrigin::signed(99), 7, LeaseState::Active),
            Error::<Test>::InvalidStateTransition
        );
    });
}

#[test]
fn checked_end_rejects_overflow() {
    new_test_ext().execute_with(|| {
        System::set_block_number(u64::MAX - 5);
        assert_noop!(
            Lease::create_lease(RuntimeOrigin::signed(1), 1, 2, [0; 32], 10),
            Error::<Test>::EndBlockOverflow
        );
    });
}
