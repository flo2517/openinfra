#[cfg(test)]
mod tests {
    use super::*;
    use frame_support::{assert_ok, assert_noop};

    #[test]
    fn test_heartbeat_success() {
        let origin = RuntimeOrigin::signed(1);
        assert_ok!(Pallet::<TestRuntime>::submit_heartbeat(origin));
    }

    #[test]
    fn test_validate_challenge_success() {
        let origin = RuntimeOrigin::signed(0); // Validator
        let provider = AccountId::from(1);
        let response = [1u8; 32];
        let expected = [1u8; 32];
        assert_ok!(Pallet::<TestRuntime>::validate_challenge(origin, provider, response, expected));
    }

    #[test]
    fn test_validate_challenge_fail() {
        let origin = RuntimeOrigin::signed(0);
        let provider = AccountId::from(1);
        let response = [1u8; 32];
        let expected = [0u8; 32];
        assert_noop!(Pallet::<TestRuntime>::validate_challenge(origin, provider, response, expected), Error::<TestRuntime>::InvalidResponse);
    }
}
