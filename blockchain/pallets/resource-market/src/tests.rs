use crate::{self as pallet_resource_market, Error};
use frame_support::{assert_noop, assert_ok, derive_impl, BoundedVec};
use pallet_provider_registry::ProviderStatus;
use sp_runtime::BuildStorage;

type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
    pub enum Test {
        System: frame_system,
        ProviderRegistry: pallet_provider_registry,
        ResourceMarket: pallet_resource_market,
    }
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
}

impl pallet_provider_registry::Config for Test {
    type RegistrationOrigin = frame_system::EnsureRoot<u64>;
    type StatusOrigin = frame_system::EnsureRoot<u64>;
    type WeightInfo = ();
}

frame_support::parameter_types! { pub const MaxCapabilitiesLen: u32 = 4; }

impl crate::Config for Test {
    type ProviderRegistry = ProviderRegistry;
    type AnnounceOrigin = frame_system::EnsureRoot<u64>;
    type MaxCapabilitiesLen = MaxCapabilitiesLen;
    type WeightInfo = ();
}

fn new_test_ext() -> sp_io::TestExternalities {
    frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap()
        .into()
}

fn activate(provider: u64) {
    assert_ok!(ProviderRegistry::register_provider(
        RuntimeOrigin::signed(provider),
        [provider as u8; 32]
    ));
    assert_ok!(ProviderRegistry::set_status(
        RuntimeOrigin::root(),
        provider,
        ProviderStatus::Verified
    ));
    assert_ok!(ProviderRegistry::set_status(
        RuntimeOrigin::root(),
        provider,
        ProviderStatus::Active
    ));
}

#[test]
fn only_active_provider_can_announce_valid_offer() {
    new_test_ext().execute_with(|| {
        let capabilities = BoundedVec::try_from(vec![1, 2]).unwrap();
        assert_noop!(
            ResourceMarket::announce_offer(
                RuntimeOrigin::signed(1),
                2,
                1024,
                4096,
                capabilities.clone()
            ),
            Error::<Test>::ProviderNotActive
        );
        activate(1);
        assert_noop!(
            ResourceMarket::announce_offer(
                RuntimeOrigin::signed(1),
                0,
                1024,
                4096,
                capabilities.clone()
            ),
            Error::<Test>::InvalidResources
        );
        assert_ok!(ResourceMarket::announce_offer(
            RuntimeOrigin::signed(1),
            2,
            1024,
            4096,
            capabilities
        ));
        assert_eq!(ResourceMarket::offers(1).unwrap().cpu, 2);
    });
}

#[test]
fn capabilities_are_bounded_and_owner_can_remove_offer() {
    new_test_ext().execute_with(|| {
        assert!(BoundedVec::<u8, MaxCapabilitiesLen>::try_from(vec![0; 5]).is_err());
        activate(1);
        assert_ok!(ResourceMarket::announce_offer(
            RuntimeOrigin::signed(1),
            1,
            1,
            1,
            BoundedVec::try_from(vec![1]).unwrap()
        ));
        assert_noop!(
            ResourceMarket::remove_offer(RuntimeOrigin::signed(2)),
            Error::<Test>::OfferNotFound
        );
        assert_ok!(ResourceMarket::remove_offer(RuntimeOrigin::signed(1)));
    });
}

#[test]
fn announce_offer_for_requires_the_announce_origin() {
    new_test_ext().execute_with(|| {
        activate(1);
        let capabilities = BoundedVec::try_from(vec![1]).unwrap();
        assert_noop!(
            ResourceMarket::announce_offer_for(
                RuntimeOrigin::signed(2),
                1,
                2,
                1024,
                4096,
                capabilities.clone()
            ),
            sp_runtime::DispatchError::BadOrigin
        );
        assert_ok!(ResourceMarket::announce_offer_for(
            RuntimeOrigin::root(),
            1,
            2,
            1024,
            4096,
            capabilities
        ));
        assert_eq!(ResourceMarket::offers(1).unwrap().cpu, 2);
    });
}

#[test]
fn announce_offer_for_still_requires_an_active_provider_and_valid_resources() {
    new_test_ext().execute_with(|| {
        let capabilities = BoundedVec::try_from(vec![1]).unwrap();
        // Never registered, let alone active.
        assert_noop!(
            ResourceMarket::announce_offer_for(
                RuntimeOrigin::root(),
                1,
                2,
                1024,
                4096,
                capabilities.clone()
            ),
            Error::<Test>::ProviderNotActive
        );
        activate(1);
        assert_noop!(
            ResourceMarket::announce_offer_for(
                RuntimeOrigin::root(),
                1,
                0,
                1024,
                4096,
                capabilities
            ),
            Error::<Test>::InvalidResources
        );
    });
}

#[test]
fn remove_offer_for_requires_the_announce_origin_and_an_existing_offer() {
    new_test_ext().execute_with(|| {
        activate(1);
        assert_ok!(ResourceMarket::announce_offer_for(
            RuntimeOrigin::root(),
            1,
            2,
            1024,
            4096,
            BoundedVec::try_from(vec![1]).unwrap()
        ));
        assert_noop!(
            ResourceMarket::remove_offer_for(RuntimeOrigin::signed(2), 1),
            sp_runtime::DispatchError::BadOrigin
        );
        assert_noop!(
            ResourceMarket::remove_offer_for(RuntimeOrigin::root(), 99),
            Error::<Test>::OfferNotFound
        );
        assert_ok!(ResourceMarket::remove_offer_for(RuntimeOrigin::root(), 1));
        assert!(ResourceMarket::offers(1).is_none());
    });
}

#[test]
fn self_service_and_delegated_calls_share_the_same_offer_slot() {
    new_test_ext().execute_with(|| {
        activate(1);
        assert_ok!(ResourceMarket::announce_offer(
            RuntimeOrigin::signed(1),
            1,
            1,
            1,
            BoundedVec::try_from(vec![1]).unwrap()
        ));
        // The delegated path replaces the same offer, not a separate one.
        assert_ok!(ResourceMarket::announce_offer_for(
            RuntimeOrigin::root(),
            1,
            9,
            9,
            9,
            BoundedVec::try_from(vec![2]).unwrap()
        ));
        assert_eq!(ResourceMarket::offers(1).unwrap().cpu, 9);
    });
}
