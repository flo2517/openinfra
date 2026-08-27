use crate::{
    self as pallet_provider_registry, BondStatus, Error, ProviderInspector, ProviderStatus,
};
use frame_support::{assert_noop, assert_ok, derive_impl, parameter_types, traits::ConstU64};
use sp_runtime::BuildStorage;

type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
    pub enum Test {
        System: frame_system,
        Balances: pallet_balances,
        ProviderRegistry: pallet_provider_registry,
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

// Mocks for the reserve-contamination guard's forward direction
// (`bond_stake` rejects an account that already has an open escrow as
// payer, or is a registered Network Validator). Controlled per-test,
// independent of `pallet-escrow`/`pallet-network-validator` -- this pallet
// carries no dependency on either, same narrow-trait pattern those two
// pallets already use for each other.
thread_local! {
    static OPEN_ESCROW_PAYERS: std::cell::RefCell<std::collections::BTreeSet<u64>> =
        const { std::cell::RefCell::new(std::collections::BTreeSet::new()) };
    static REGISTERED_VALIDATORS: std::cell::RefCell<std::collections::BTreeSet<u64>> =
        const { std::cell::RefCell::new(std::collections::BTreeSet::new()) };
    static PENDING_SLASHES: std::cell::RefCell<std::collections::BTreeSet<u64>> =
        const { std::cell::RefCell::new(std::collections::BTreeSet::new()) };
}

pub struct TestEscrowInspector;
impl crate::EscrowPayerInspector<u64> for TestEscrowInspector {
    fn has_open_escrow(payer: &u64) -> bool {
        OPEN_ESCROW_PAYERS.with(|set| set.borrow().contains(payer))
    }
}

pub struct TestValidatorInspector;
impl crate::ValidatorRegistrationInspector<u64> for TestValidatorInspector {
    fn is_registered(account: &u64) -> bool {
        REGISTERED_VALIDATORS.with(|set| set.borrow().contains(account))
    }
}

pub struct TestSlashInspector;
impl crate::ProviderSlashInspector<u64> for TestSlashInspector {
    fn has_pending_slash(provider: &u64) -> bool {
        PENDING_SLASHES.with(|set| set.borrow().contains(provider))
    }
}

fn set_has_open_escrow(account: u64, value: bool) {
    OPEN_ESCROW_PAYERS.with(|set| {
        if value {
            set.borrow_mut().insert(account);
        } else {
            set.borrow_mut().remove(&account);
        }
    });
}

fn set_is_registered_validator(account: u64, value: bool) {
    REGISTERED_VALIDATORS.with(|set| {
        if value {
            set.borrow_mut().insert(account);
        } else {
            set.borrow_mut().remove(&account);
        }
    });
}

fn set_has_pending_slash(account: u64, value: bool) {
    PENDING_SLASHES.with(|set| {
        if value {
            set.borrow_mut().insert(account);
        } else {
            set.borrow_mut().remove(&account);
        }
    });
}

impl crate::Config for Test {
    type RegistrationOrigin = frame_system::EnsureRoot<u64>;
    type StatusOrigin = frame_system::EnsureRoot<u64>;
    type Currency = Balances;
    type EscrowInspector = TestEscrowInspector;
    type ValidatorInspector = TestValidatorInspector;
    type SlashInspector = TestSlashInspector;
    type MinStake = MinStake;
    type UnbondingPeriod = UnbondingPeriod;
    type WeightInfo = ();
}

const PROVIDER: u64 = 1;
const OTHER_PROVIDER: u64 = 2;

fn new_test_ext() -> sp_io::TestExternalities {
    OPEN_ESCROW_PAYERS.with(|set| set.borrow_mut().clear());
    REGISTERED_VALIDATORS.with(|set| set.borrow_mut().clear());
    PENDING_SLASHES.with(|set| set.borrow_mut().clear());

    let mut storage = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();
    pallet_balances::GenesisConfig::<Test> {
        balances: vec![(PROVIDER, 1_000_000), (OTHER_PROVIDER, 1_000_000)],
        ..Default::default()
    }
    .assimilate_storage(&mut storage)
    .unwrap();
    let mut ext: sp_io::TestExternalities = storage.into();
    ext.execute_with(|| System::set_block_number(1));
    ext
}

fn register(provider: u64, key_byte: u8) {
    assert_ok!(ProviderRegistry::register_provider(
        RuntimeOrigin::signed(provider),
        [key_byte; 32]
    ));
}

fn register_and_verify(provider: u64, key_byte: u8) {
    register(provider, key_byte);
    assert_ok!(ProviderRegistry::set_status(
        RuntimeOrigin::root(),
        provider,
        ProviderStatus::Verified
    ));
}

// ---------------------------------------------------------------------
// Pre-existing registration/status tests
// ---------------------------------------------------------------------

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
        // ADR-036: Verified -> Active now additionally requires a bond of
        // at least MinStake.
        assert_ok!(ProviderRegistry::bond_stake(
            RuntimeOrigin::signed(1),
            MinStake::get()
        ));
        assert_ok!(ProviderRegistry::set_status(
            RuntimeOrigin::root(),
            1,
            ProviderStatus::Active
        ));
        assert!(<ProviderRegistry as ProviderInspector<u64>>::is_active(&1));
    });
}

// ---------------------------------------------------------------------
// ADR-036: bonding
// ---------------------------------------------------------------------

#[test]
fn bond_stake_requires_registered_provider() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            ProviderRegistry::bond_stake(RuntimeOrigin::signed(PROVIDER), MinStake::get()),
            Error::<Test>::ProviderNotFound
        );
    });
}

#[test]
fn bond_stake_first_call_requires_min_stake() {
    new_test_ext().execute_with(|| {
        register(PROVIDER, 1);
        assert_noop!(
            ProviderRegistry::bond_stake(RuntimeOrigin::signed(PROVIDER), MinStake::get() - 1),
            Error::<Test>::InsufficientStake
        );
        assert!(ProviderRegistry::provider_bonds(PROVIDER).is_none());
    });
}

#[test]
fn bond_stake_top_up_allows_any_amount_once_bonded() {
    new_test_ext().execute_with(|| {
        register(PROVIDER, 1);
        assert_ok!(ProviderRegistry::bond_stake(
            RuntimeOrigin::signed(PROVIDER),
            MinStake::get()
        ));
        // A top-up below MinStake is fine once the floor is already met.
        assert_ok!(ProviderRegistry::bond_stake(
            RuntimeOrigin::signed(PROVIDER),
            1
        ));
        let bond = ProviderRegistry::provider_bonds(PROVIDER).expect("bond exists");
        assert_eq!(bond.stake, MinStake::get() + 1);
        assert_eq!(bond.status, BondStatus::Active);
    });
}

#[test]
fn bond_stake_reserves_from_free_balance_and_emits_event() {
    new_test_ext().execute_with(|| {
        register(PROVIDER, 1);
        let free_before = Balances::free_balance(PROVIDER);
        assert_ok!(ProviderRegistry::bond_stake(
            RuntimeOrigin::signed(PROVIDER),
            MinStake::get()
        ));
        assert_eq!(
            Balances::free_balance(PROVIDER),
            free_before - MinStake::get()
        );
        assert_eq!(Balances::reserved_balance(PROVIDER), MinStake::get());
        System::assert_last_event(RuntimeEvent::ProviderRegistry(
            crate::Event::BondIncreased {
                provider: PROVIDER,
                added: MinStake::get(),
                total: MinStake::get(),
            },
        ));
    });
}

#[test]
fn bond_stake_rejects_insufficient_free_balance() {
    new_test_ext().execute_with(|| {
        register(PROVIDER, 1);
        assert_noop!(
            ProviderRegistry::bond_stake(RuntimeOrigin::signed(PROVIDER), 10_000_000),
            Error::<Test>::InsufficientFreeBalance
        );
    });
}

#[test]
fn bond_stake_rejects_open_escrow_payer() {
    new_test_ext().execute_with(|| {
        register(PROVIDER, 1);
        set_has_open_escrow(PROVIDER, true);
        assert_noop!(
            ProviderRegistry::bond_stake(RuntimeOrigin::signed(PROVIDER), MinStake::get()),
            Error::<Test>::PayerHasOpenEscrow
        );
        assert!(ProviderRegistry::provider_bonds(PROVIDER).is_none());
    });
}

#[test]
fn bond_stake_rejects_registered_validator() {
    new_test_ext().execute_with(|| {
        register(PROVIDER, 1);
        set_is_registered_validator(PROVIDER, true);
        assert_noop!(
            ProviderRegistry::bond_stake(RuntimeOrigin::signed(PROVIDER), MinStake::get()),
            Error::<Test>::CallerIsRegisteredValidator
        );
        assert!(ProviderRegistry::provider_bonds(PROVIDER).is_none());
    });
}

#[test]
fn verified_to_active_requires_min_bond() {
    new_test_ext().execute_with(|| {
        register_and_verify(PROVIDER, 1);
        assert_noop!(
            ProviderRegistry::set_status(RuntimeOrigin::root(), PROVIDER, ProviderStatus::Active),
            Error::<Test>::InsufficientBondForActive
        );
    });
}

/// A bond that has fallen below `MinStake` (via a slash) also blocks
/// `Verified -> Active` -- the check reads the live bond, not merely
/// "has bonded at least once".
#[test]
fn verified_to_active_rejects_bond_reduced_below_min_by_a_slash() {
    new_test_ext().execute_with(|| {
        register_and_verify(PROVIDER, 1);
        assert_ok!(ProviderRegistry::bond_stake(
            RuntimeOrigin::signed(PROVIDER),
            MinStake::get()
        ));
        let (slashed, _) = ProviderRegistry::slash_bond(&PROVIDER, 1);
        assert_eq!(slashed, 1);
        assert_noop!(
            ProviderRegistry::set_status(RuntimeOrigin::root(), PROVIDER, ProviderStatus::Active),
            Error::<Test>::InsufficientBondForActive
        );
    });
}

#[test]
fn active_transition_succeeds_once_bonded() {
    new_test_ext().execute_with(|| {
        register_and_verify(PROVIDER, 1);
        assert_ok!(ProviderRegistry::bond_stake(
            RuntimeOrigin::signed(PROVIDER),
            MinStake::get()
        ));
        assert_ok!(ProviderRegistry::set_status(
            RuntimeOrigin::root(),
            PROVIDER,
            ProviderStatus::Active
        ));
    });
}

// ---------------------------------------------------------------------
// ADR-036: unbonding
// ---------------------------------------------------------------------

#[test]
fn request_unbond_requires_existing_bond() {
    new_test_ext().execute_with(|| {
        register(PROVIDER, 1);
        assert_noop!(
            ProviderRegistry::request_unbond(RuntimeOrigin::signed(PROVIDER)),
            Error::<Test>::NotBonded
        );
    });
}

#[test]
fn request_unbond_sets_exiting_status_and_emits_event() {
    new_test_ext().execute_with(|| {
        register(PROVIDER, 1);
        assert_ok!(ProviderRegistry::bond_stake(
            RuntimeOrigin::signed(PROVIDER),
            MinStake::get()
        ));
        assert_ok!(ProviderRegistry::request_unbond(RuntimeOrigin::signed(
            PROVIDER
        )));
        let bond = ProviderRegistry::provider_bonds(PROVIDER).expect("bond still exists");
        assert_eq!(
            bond.status,
            BondStatus::Exiting {
                available_at: 1 + UnbondingPeriod::get()
            }
        );
        System::assert_last_event(RuntimeEvent::ProviderRegistry(
            crate::Event::UnbondRequested {
                provider: PROVIDER,
                available_at: 1 + UnbondingPeriod::get(),
            },
        ));
    });
}

#[test]
fn request_unbond_rejects_double_exit() {
    new_test_ext().execute_with(|| {
        register(PROVIDER, 1);
        assert_ok!(ProviderRegistry::bond_stake(
            RuntimeOrigin::signed(PROVIDER),
            MinStake::get()
        ));
        assert_ok!(ProviderRegistry::request_unbond(RuntimeOrigin::signed(
            PROVIDER
        )));
        assert_noop!(
            ProviderRegistry::request_unbond(RuntimeOrigin::signed(PROVIDER)),
            Error::<Test>::AlreadyExiting
        );
    });
}

#[test]
fn request_unbond_rejects_pending_slash() {
    new_test_ext().execute_with(|| {
        register(PROVIDER, 1);
        assert_ok!(ProviderRegistry::bond_stake(
            RuntimeOrigin::signed(PROVIDER),
            MinStake::get()
        ));
        set_has_pending_slash(PROVIDER, true);
        assert_noop!(
            ProviderRegistry::request_unbond(RuntimeOrigin::signed(PROVIDER)),
            Error::<Test>::SlashPending
        );
    });
}

#[test]
fn withdraw_unbonded_requires_exiting_status() {
    new_test_ext().execute_with(|| {
        register(PROVIDER, 1);
        assert_ok!(ProviderRegistry::bond_stake(
            RuntimeOrigin::signed(PROVIDER),
            MinStake::get()
        ));
        assert_noop!(
            ProviderRegistry::withdraw_unbonded(RuntimeOrigin::signed(PROVIDER)),
            Error::<Test>::NotExiting
        );
    });
}

#[test]
fn withdraw_unbonded_before_period_fails() {
    new_test_ext().execute_with(|| {
        register(PROVIDER, 1);
        assert_ok!(ProviderRegistry::bond_stake(
            RuntimeOrigin::signed(PROVIDER),
            MinStake::get()
        ));
        assert_ok!(ProviderRegistry::request_unbond(RuntimeOrigin::signed(
            PROVIDER
        )));
        System::set_block_number(1 + UnbondingPeriod::get() - 1);
        assert_noop!(
            ProviderRegistry::withdraw_unbonded(RuntimeOrigin::signed(PROVIDER)),
            Error::<Test>::UnbondingNotComplete
        );
    });
}

#[test]
fn withdraw_unbonded_releases_funds_and_removes_record() {
    new_test_ext().execute_with(|| {
        register(PROVIDER, 1);
        let free_before = Balances::free_balance(PROVIDER);
        assert_ok!(ProviderRegistry::bond_stake(
            RuntimeOrigin::signed(PROVIDER),
            MinStake::get()
        ));
        assert_ok!(ProviderRegistry::request_unbond(RuntimeOrigin::signed(
            PROVIDER
        )));
        System::set_block_number(1 + UnbondingPeriod::get());
        assert_ok!(ProviderRegistry::withdraw_unbonded(RuntimeOrigin::signed(
            PROVIDER
        )));
        assert!(ProviderRegistry::provider_bonds(PROVIDER).is_none());
        assert_eq!(Balances::free_balance(PROVIDER), free_before);
        assert_eq!(Balances::reserved_balance(PROVIDER), 0);
        System::assert_last_event(RuntimeEvent::ProviderRegistry(
            crate::Event::BondWithdrawn {
                provider: PROVIDER,
                amount: MinStake::get(),
            },
        ));
    });
}

/// ADR-036 §6: a breach can be detected *after* unbonding has already
/// begun -- the check must be repeated at `withdraw_unbonded`, not only at
/// `request_unbond`.
#[test]
fn withdraw_unbonded_rechecks_pending_slash_detected_after_request() {
    new_test_ext().execute_with(|| {
        register(PROVIDER, 1);
        assert_ok!(ProviderRegistry::bond_stake(
            RuntimeOrigin::signed(PROVIDER),
            MinStake::get()
        ));
        assert_ok!(ProviderRegistry::request_unbond(RuntimeOrigin::signed(
            PROVIDER
        )));
        System::set_block_number(1 + UnbondingPeriod::get());
        // Detected only now, after the exit request was already accepted.
        set_has_pending_slash(PROVIDER, true);
        assert_noop!(
            ProviderRegistry::withdraw_unbonded(RuntimeOrigin::signed(PROVIDER)),
            Error::<Test>::SlashPending
        );
        assert!(ProviderRegistry::provider_bonds(PROVIDER).is_some());
    });
}

// ---------------------------------------------------------------------
// ADR-036: slash_bond (internal entry point)
// ---------------------------------------------------------------------

#[test]
fn slash_bond_reduces_stake_and_burns_the_imbalance() {
    new_test_ext().execute_with(|| {
        register(PROVIDER, 1);
        assert_ok!(ProviderRegistry::bond_stake(
            RuntimeOrigin::signed(PROVIDER),
            1_000
        ));
        let total_issuance_before = Balances::total_issuance();
        let (slashed, force_suspended) = ProviderRegistry::slash_bond(&PROVIDER, 150);
        assert_eq!(slashed, 150);
        assert!(!force_suspended);
        let bond = ProviderRegistry::provider_bonds(PROVIDER).expect("bond remains");
        assert_eq!(bond.stake, 850);
        assert_eq!(Balances::reserved_balance(PROVIDER), 850);
        assert_eq!(Balances::total_issuance(), total_issuance_before - 150);
    });
}

#[test]
fn slash_bond_caps_at_reserved_balance() {
    new_test_ext().execute_with(|| {
        register(PROVIDER, 1);
        assert_ok!(ProviderRegistry::bond_stake(
            RuntimeOrigin::signed(PROVIDER),
            100
        ));
        let (slashed, _) = ProviderRegistry::slash_bond(&PROVIDER, 10_000);
        assert_eq!(slashed, 100);
        let bond = ProviderRegistry::provider_bonds(PROVIDER).expect("bond remains, zeroed");
        assert_eq!(bond.stake, 0);
    });
}

#[test]
fn slash_bond_force_suspends_active_provider_when_below_min_stake() {
    new_test_ext().execute_with(|| {
        register_and_verify(PROVIDER, 1);
        assert_ok!(ProviderRegistry::bond_stake(
            RuntimeOrigin::signed(PROVIDER),
            MinStake::get()
        ));
        assert_ok!(ProviderRegistry::set_status(
            RuntimeOrigin::root(),
            PROVIDER,
            ProviderStatus::Active
        ));
        let (_, force_suspended) = ProviderRegistry::slash_bond(&PROVIDER, 1);
        assert!(force_suspended);
        let provider = ProviderRegistry::providers(PROVIDER).expect("provider exists");
        assert_eq!(provider.status, ProviderStatus::Suspended);
        System::assert_last_event(RuntimeEvent::ProviderRegistry(
            crate::Event::StatusChanged {
                provider: PROVIDER,
                status: ProviderStatus::Suspended,
            },
        ));
    });
}

#[test]
fn slash_bond_does_not_suspend_when_stake_stays_at_or_above_min() {
    new_test_ext().execute_with(|| {
        register_and_verify(PROVIDER, 1);
        assert_ok!(ProviderRegistry::bond_stake(
            RuntimeOrigin::signed(PROVIDER),
            MinStake::get() + 50
        ));
        assert_ok!(ProviderRegistry::set_status(
            RuntimeOrigin::root(),
            PROVIDER,
            ProviderStatus::Active
        ));
        let (_, force_suspended) = ProviderRegistry::slash_bond(&PROVIDER, 40);
        assert!(!force_suspended);
        let provider = ProviderRegistry::providers(PROVIDER).expect("provider exists");
        assert_eq!(provider.status, ProviderStatus::Active);
    });
}

#[test]
fn slash_bond_does_not_suspend_a_provider_that_is_not_active() {
    new_test_ext().execute_with(|| {
        // Registered but never verified/activated: still bonded, still
        // slashable, but there is no `Active` status to force out of.
        register(PROVIDER, 1);
        assert_ok!(ProviderRegistry::bond_stake(
            RuntimeOrigin::signed(PROVIDER),
            MinStake::get()
        ));
        let (slashed, force_suspended) = ProviderRegistry::slash_bond(&PROVIDER, 1);
        assert_eq!(slashed, 1);
        assert!(!force_suspended);
        let provider = ProviderRegistry::providers(PROVIDER).expect("provider exists");
        assert_eq!(provider.status, ProviderStatus::Registered);
    });
}

#[test]
fn slash_bond_on_unbonded_provider_is_a_noop() {
    new_test_ext().execute_with(|| {
        register(PROVIDER, 1);
        let (slashed, force_suspended) = ProviderRegistry::slash_bond(&PROVIDER, 100);
        assert_eq!(slashed, 0);
        assert!(!force_suspended);
    });
}
