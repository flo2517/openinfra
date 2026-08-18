use crate as pallet_availability;
use crate::{EnsureActiveValidator, NetworkValidatorInspector};
use frame_support::{
    assert_noop, assert_ok, derive_impl, parameter_types,
    traits::{ConstU32, EnsureOrigin},
};
use sp_runtime::{BuildStorage, DispatchError};

type Block = frame_system::mocking::MockBlock<Test>;
frame_support::construct_runtime!(pub enum Test { System: frame_system, Availability: pallet_availability });

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
}

/// Account 7 only, mirroring how other tests in this crate pick an
/// arbitrary fixed id -- just enough to distinguish an active validator
/// from every other signed account in EnsureActiveValidator tests below.
pub struct OnlyAccountSeven;
impl NetworkValidatorInspector<u64> for OnlyAccountSeven {
    fn is_active(validator: &u64) -> bool {
        *validator == 7
    }
}

parameter_types! { pub const MaxLifetime: u64 = 10; }
impl crate::Config for Test {
    type ChallengeOrigin = frame_system::EnsureRoot<u64>;
    type ProofOrigin = frame_system::EnsureRoot<u64>;
    type ProviderInspector = ();
    type ValidatorInspector = OnlyAccountSeven;
    type MaxPendingChallenges = ConstU32<1>;
    type MaxChallengeLifetime = MaxLifetime;
    type MaxProofAge = MaxLifetime;
    type MaxProofSamples = ConstU32<100>;
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

#[test]
fn proof_is_bounded_fresh_monotonic_and_idempotent() {
    new_test_ext().execute_with(|| {
        System::set_block_number(5);
        assert_ok!(Availability::submit_proof(
            RuntimeOrigin::root(),
            1,
            1,
            4,
            9,
            10,
            [3; 32],
            vec![7; 64]
        ));
        let summary = crate::LatestProof::<Test>::get(1).expect("summary");
        assert_eq!(summary.availability_bps, 9_000);
        assert_noop!(
            Availability::submit_proof(RuntimeOrigin::root(), 1, 1, 5, 1, 1, [4; 32], vec![7]),
            crate::Error::<Test>::ProofSequenceReplay
        );
        assert_noop!(
            Availability::submit_proof(RuntimeOrigin::root(), 1, 2, 5, 2, 1, [4; 32], vec![7]),
            crate::Error::<Test>::InvalidProofSamples
        );
        System::set_block_number(20);
        assert_noop!(
            Availability::submit_proof(RuntimeOrigin::root(), 1, 2, 1, 1, 1, [4; 32], vec![7]),
            crate::Error::<Test>::ProofTooOld
        );
    });
}

#[test]
fn proof_origin_and_signature_bounds_are_enforced() {
    new_test_ext().execute_with(|| {
        System::set_block_number(1);
        assert_noop!(
            Availability::submit_proof(RuntimeOrigin::signed(2), 1, 1, 1, 1, 1, [1; 32], vec![1]),
            DispatchError::BadOrigin
        );
        assert_noop!(
            Availability::submit_proof(RuntimeOrigin::root(), 1, 1, 1, 1, 1, [1; 32], vec![]),
            crate::Error::<Test>::InvalidProofSignature
        );
        assert_noop!(
            Availability::submit_proof(RuntimeOrigin::root(), 1, 1, 1, 1, 1, [1; 32], vec![1; 97]),
            crate::Error::<Test>::ProofSignatureTooLong
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
    // Root is deliberately not a shortcut here: only a real, signed,
    // registered validator account may submit availability proofs.
    assert!(EnsureActiveValidator::<Test>::ensure_origin(RuntimeOrigin::root()).is_err());
}

#[test]
fn ensure_active_validator_rejects_none_origin() {
    assert!(EnsureActiveValidator::<Test>::ensure_origin(RuntimeOrigin::none()).is_err());
}

/// Pins `AvailabilitySummary`'s SCALE encoding, byte for byte.
///
/// The Control Plane decodes this struct straight off chain storage in
/// `control-plane/internal/blockchainbridge/availability.go`, by hand --
/// there is no shared schema between the two, so nothing but a test
/// stops the Rust side from reordering a field, widening a type, or
/// adding one, and leaving the Go decoder silently reading garbage that
/// still parses.
///
/// `TestDecodeAvailabilitySummaryMatchesThePalletEncoding` asserts the
/// same bytes decode to the same values on the Go side. Changing this
/// struct should break both; if you find yourself updating only one,
/// that is the bug this pair exists to catch.
///
/// Instantiated with `u32` rather than `BlockNumberFor<Test>` on purpose:
/// the encoding that matters is the one the *runtime* produces, and the
/// runtime's BlockNumber is u32 (the mock's is not necessarily).
#[test]
fn availability_summary_encoding_is_stable_for_the_control_plane_decoder() {
    use codec::Encode;

    let summary = crate::AvailabilitySummary::<u32> {
        sequence: 7,
        observed_at: 42,
        successful_samples: 95,
        total_samples: 100,
        availability_bps: 9_500,
        payload_hash: [0xAB; 32],
        signature: sp_runtime::BoundedVec::truncate_from(vec![0xCD; 64]),
    };

    let mut expected = Vec::new();
    expected.extend_from_slice(&7u64.to_le_bytes());
    expected.extend_from_slice(&42u32.to_le_bytes());
    expected.extend_from_slice(&95u32.to_le_bytes());
    expected.extend_from_slice(&100u32.to_le_bytes());
    expected.extend_from_slice(&9_500u16.to_le_bytes());
    expected.extend_from_slice(&[0xAB; 32]);
    // BoundedVec carries a SCALE compact length prefix: 64 << 2 | 0b01
    // == 0x0101, two-byte mode, little-endian. This is the one
    // variable-length part of the struct and the only place the Go
    // decoder has to parse rather than slice at a fixed offset.
    expected.extend_from_slice(&[0x01, 0x01]);
    expected.extend_from_slice(&[0xCD; 64]);

    assert_eq!(summary.encode(), expected);
    assert_eq!(summary.encode().len(), 120);
}
