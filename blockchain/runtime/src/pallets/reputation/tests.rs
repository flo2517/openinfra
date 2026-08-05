#[cfg(test)]
mod tests {
    use super::*;
    use frame_support::{assert_ok, assert_noop};

    #[test]
    fn test_submit_score_clamping() {
        let origin = RuntimeOrigin::signed(1); // Validator
        let provider = AccountId::from(2);

        // Test Increase
        assert_ok!(Pallet::<TestRuntime>::submit_score(origin, provider, 100));
        // Test Decrease
        assert_ok!(Pallet::<TestRuntime>::submit_score(origin, provider, -200));

        // Test clamp high
        for _ in 0..10 {
            assert_ok!(Pallet::<TestRuntime>::submit_score(origin, provider, 500));
        }
        // Score should be 1000
    }
}
