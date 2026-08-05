#[cfg(test)]
mod tests {
    use super::*;
    use frame_support::{assert_ok, assert_noop};

    #[test]
    fn test_create_lease_success() {
        let origin = RuntimeOrigin::signed(1); // Consumer
        let provider = AccountId::from(2);
        let res_hash = [0u8; 32];
        assert_ok!(Pallet::<TestRuntime>::create_lease(origin, 101, provider, res_hash, 100));
    }

    #[test]
    fn test_update_lease_state_success() {
        let origin = RuntimeOrigin::signed(1);
        let provider = AccountId::from(2);
        let res_hash = [0u8; 32];
        assert_ok!(Pallet::<TestRuntime>::create_lease(origin, 101, provider, res_hash, 100));

        assert_ok!(Pallet::<TestRuntime>::update_lease_state(origin, 101, LeaseState::Active));
    }

    #[test]
    fn test_update_non_existent_lease_fails() {
        let origin = RuntimeOrigin::signed(1);
        assert_noop!(Pallet::<TestRuntime>::update_lease_state(origin, 999, LeaseState::Active), Error::<TestRuntime>::LeaseNotFound);
    }
}
