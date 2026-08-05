#[cfg(test)]
mod tests {
    use super::*;
    use frame_support::{assert_ok, assert_noop};

    #[test]
    fn test_announce_offer_success() {
        let origin = RuntimeOrigin::signed(1);
        assert_ok!(Pallet::<TestRuntime>::announce_offer(origin, 8, 16, 500, vec![1, 2, 3]));
    }

    #[test]
    fn test_remove_offer_success() {
        let origin = RuntimeOrigin::signed(1);
        assert_ok!(Pallet::<TestRuntime>::announce_offer(origin, 8, 16, 500, vec![1, 2, 3]));
        assert_ok!(Pallet::<TestRuntime>::remove_offer(origin));
    }
}
