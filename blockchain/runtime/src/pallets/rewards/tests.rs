#[cfg(test)]
mod tests {
    use super::*;
    use frame_support::{assert_ok, assert_noop};

    #[test]
    fn test_calculate_reward_math() {
        let origin = RuntimeOrigin::signed(0); // System
        let provider = AccountId::from(1);

        // 10 units * 100 blocks * (1 + 500/1000) * (100/100) = 1500
        assert_ok!(Pallet::<TestRuntime>::calculate_reward(origin, provider, 10, 100, 500, 100));
    }

    #[test]
    fn test_claim_reward_success() {
        let origin = RuntimeOrigin::signed(1);
        let provider = AccountId::from(1);
        assert_ok!(Pallet::<TestRuntime>::calculate_reward(origin, provider, 10, 100, 500, 100));
        assert_ok!(Pallet::<TestRuntime>::claim_reward(origin));
    }

    #[test]
    fn test_claim_empty_balance_fails() {
        let origin = RuntimeOrigin::signed(2);
        assert_noop!(Pallet::<TestRuntime>::claim_reward(origin), Error::<TestRuntime>::InsufficientPoints);
    }
}
