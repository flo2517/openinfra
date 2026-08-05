use crate::{self as pallet_provider_registry, Error, ProviderInspector, ProviderStatus};
use frame_support::{assert_noop, assert_ok, derive_impl};
use sp_runtime::BuildStorage;

type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
    pub enum Test {
        System: frame_system,
        ProviderRegistry: pallet_provider_registry,
    }
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
}

impl crate::Config for Test {
    type RegistrationOrigin = frame_system::EnsureRoot<u64>;
    type StatusOrigin = frame_system::EnsureRoot<u64>;
    type WeightInfo = ();
}

#[test]
fn delegated_registration_requires_authorized_origin_and_emits_event() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            ProviderRegistry::register_provider_for(RuntimeOrigin::signed(9), 1, [1; 32]),
            sp_runtime::DispatchError::BadOrigin
        );
        assert_ok!(ProviderRegistry::register_provider_for(
            RuntimeOrigin::root(),
            1,
            [1; 32]
        ));

        let provider = ProviderRegistry::providers(1).expect("provider is stored");
        assert_eq!(provider.owner, 1);
        assert_eq!(provider.public_key, [1; 32]);
        assert_eq!(provider.status, ProviderStatus::Registered);
        System::assert_last_event(RuntimeEvent::ProviderRegistry(
            crate::Event::ProviderRegistered { provider: 1 },
        ));
    });
}

#[test]
fn delegated_registration_rejects_duplicate_account_and_public_key() {
    new_test_ext().execute_with(|| {
        assert_ok!(ProviderRegistry::register_provider_for(
            RuntimeOrigin::root(),
            1,
            [1; 32]
        ));
        assert_noop!(
            ProviderRegistry::register_provider_for(RuntimeOrigin::root(), 1, [2; 32]),
            Error::<Test>::AlreadyRegistered
        );
        assert_noop!(
            ProviderRegistry::register_provider_for(RuntimeOrigin::root(), 2, [1; 32]),
            Error::<Test>::PublicKeyAlreadyRegistered
        );
    });
}

fn new_test_ext() -> sp_io::TestExternalities {
    let mut ext: sp_io::TestExternalities = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap()
        .into();
    ext.execute_with(|| System::set_block_number(1));
    ext
}

#[test]
fn registration_enforces_owner_and_key_uniqueness() {
    new_test_ext().execute_with(|| {
        assert_ok!(ProviderRegistry::register_provider(
            RuntimeOrigin::signed(1),
            [1; 32]
        ));
        assert_noop!(
            ProviderRegistry::register_provider(RuntimeOrigin::signed(1), [2; 32]),
            Error::<Test>::AlreadyRegistered
        );
        assert_noop!(
            ProviderRegistry::register_provider(RuntimeOrigin::signed(2), [1; 32]),
            Error::<Test>::PublicKeyAlreadyRegistered
        );
        assert_noop!(
            ProviderRegistry::register_provider(RuntimeOrigin::signed(2), [0; 32]),
            Error::<Test>::InvalidPublicKey
        );
    });
}

#[test]
fn status_changes_require_root_and_follow_transition_graph() {
    new_test_ext().execute_with(|| {
        assert_ok!(ProviderRegistry::register_provider(
            RuntimeOrigin::signed(1),
            [1; 32]
        ));
        assert_noop!(
            ProviderRegistry::set_status(RuntimeOrigin::signed(1), 1, ProviderStatus::Verified),
            sp_runtime::DispatchError::BadOrigin
        );
        assert_noop!(
            ProviderRegistry::set_status(RuntimeOrigin::root(), 1, ProviderStatus::Active),
            Error::<Test>::InvalidStatusTransition
        );
        assert_ok!(ProviderRegistry::set_status(
            RuntimeOrigin::root(),
            1,
            ProviderStatus::Verified
        ));
        assert_ok!(ProviderRegistry::set_status(
            RuntimeOrigin::root(),
            1,
            ProviderStatus::Active
        ));
        assert!(<ProviderRegistry as ProviderInspector<u64>>::is_active(&1));
    });
}
