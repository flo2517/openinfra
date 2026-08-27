use crate::{
    self as pallet_provider_slashing, RoundView, RoundViewStatus, ScoreDimension, SlashState,
};
use frame_support::{assert_noop, assert_ok, derive_impl, parameter_types};
use sp_runtime::BuildStorage;
use std::{cell::RefCell, collections::BTreeMap};

type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
    pub enum Test {
        System: frame_system,
        ProviderSlashing: pallet_provider_slashing,
    }
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
}

const PROVIDER: u64 = 1;
const OTHER_PROVIDER: u64 = 2;
const DIM: ScoreDimension = ScoreDimension::Availability;

/// Fixed dispute window the mock oracle reports -- mirrors
/// `pallet-network-validator::Config::DisputeWindow` in shape only, no
/// crate dependency.
const DISPUTE_WINDOW: u64 = 20;

fn dim_key(dimension: ScoreDimension) -> u8 {
    match dimension {
        ScoreDimension::Compute => 0,
        ScoreDimension::Storage => 1,
        ScoreDimension::Network => 2,
        ScoreDimension::Availability => 3,
        ScoreDimension::Reliability => 4,
    }
}

thread_local! {
    static ROUNDS: RefCell<BTreeMap<(u64, u64, u8), RoundView<u64>>> =
        const { RefCell::new(BTreeMap::new()) };
    static SLASH_CALLS: RefCell<Vec<(u64, u64)>> = const { RefCell::new(Vec::new()) };
    static FORCE_SUSPENDED: RefCell<bool> = const { RefCell::new(false) };
}

pub struct TestOracle;
impl crate::AvailabilityRoundOracle<u64, u64> for TestOracle {
    fn round(provider: &u64, round: u64, dimension: ScoreDimension) -> Option<RoundView<u64>> {
        ROUNDS.with(|rounds| {
            rounds
                .borrow()
                .get(&(*provider, round, dim_key(dimension)))
                .cloned()
        })
    }

    fn dispute_window() -> u64 {
        DISPUTE_WINDOW
    }
}

pub struct TestSlasher;
impl crate::ProviderStakeSlasher<u64, u64> for TestSlasher {
    fn slash(provider: &u64, amount: u64) -> (u64, bool) {
        SLASH_CALLS.with(|calls| calls.borrow_mut().push((*provider, amount)));
        let force_suspended = FORCE_SUSPENDED.with(|f| *f.borrow());
        (amount, force_suspended)
    }
}

fn set_round(provider: u64, round: u64, dimension: ScoreDimension, view: RoundView<u64>) {
    ROUNDS.with(|rounds| {
        rounds
            .borrow_mut()
            .insert((provider, round, dim_key(dimension)), view);
    });
}

/// A round that satisfies every ADR-036 §2 condition on its own:
/// `Final`, closed long enough ago that `DISPUTE_WINDOW` has elapsed by
/// block `closed_at + DISPUTE_WINDOW`, scored well under the breach
/// threshold, and at exactly the confidence threshold (4 of a
/// 5-target committee, 80%).
fn eligible_round(closed_at: u64) -> RoundView<u64> {
    RoundView {
        status: RoundViewStatus::Final,
        score_bps: 1_000,
        submissions: 4,
        committee_target: 5,
        closed_at,
    }
}

fn set_eligible_streak(provider: u64, first_round: u64, closed_at: u64) {
    for offset in 0..3u64 {
        set_round(
            provider,
            first_round + offset,
            DIM,
            eligible_round(closed_at),
        );
    }
}

fn slash_calls() -> Vec<(u64, u64)> {
    SLASH_CALLS.with(|calls| calls.borrow().clone())
}

parameter_types! {
    pub const AvailabilityBreachThresholdBps: u16 = 5_000;
    pub const SlashConfidenceThresholdBps: u16 = 8_000;
    pub const BreachRounds: u32 = 3;
    pub const ProviderSlashAmount: u64 = 150;
    pub const SlashAppealWindow: u64 = 100;
}

impl crate::Config for Test {
    type Balance = u64;
    type AvailabilityRoundOracle = TestOracle;
    type ProviderStakeSlasher = TestSlasher;
    type SlashAppealOrigin = frame_system::EnsureRoot<u64>;
    type AvailabilityBreachThresholdBps = AvailabilityBreachThresholdBps;
    type SlashConfidenceThresholdBps = SlashConfidenceThresholdBps;
    type BreachRounds = BreachRounds;
    type ProviderSlashAmount = ProviderSlashAmount;
    type SlashAppealWindow = SlashAppealWindow;
    type WeightInfo = ();
}

fn new_test_ext() -> sp_io::TestExternalities {
    ROUNDS.with(|rounds| rounds.borrow_mut().clear());
    SLASH_CALLS.with(|calls| calls.borrow_mut().clear());
    FORCE_SUSPENDED.with(|f| *f.borrow_mut() = false);

    let storage = frame_system::GenesisConfig::<Test>::default()
        .build_storage()
        .unwrap();
    let mut ext: sp_io::TestExternalities = storage.into();
    ext.execute_with(|| System::set_block_number(1));
    ext
}

fn record_breach_ok(provider: u64, first_round: u64) {
    assert_ok!(ProviderSlashing::record_breach(
        RuntimeOrigin::signed(9),
        provider,
        DIM,
        first_round,
    ));
}

// ---------------------------------------------------------------------
// record_breach
// ---------------------------------------------------------------------

#[test]
fn record_breach_succeeds_for_three_consecutive_eligible_rounds() {
    new_test_ext().execute_with(|| {
        set_eligible_streak(PROVIDER, 1, 5);
        System::set_block_number(5 + DISPUTE_WINDOW);
        record_breach_ok(PROVIDER, 1);

        let pending = ProviderSlashing::pending_slash((PROVIDER, DIM)).expect("pending exists");
        assert_eq!(pending.first_round, 1);
        assert_eq!(pending.state, SlashState::Proposed);
        System::assert_last_event(RuntimeEvent::ProviderSlashing(
            crate::Event::BreachRecorded {
                provider: PROVIDER,
                dimension: DIM,
                first_round: 1,
            },
        ));
    });
}

#[test]
fn record_breach_fails_if_a_round_in_the_streak_is_missing() {
    new_test_ext().execute_with(|| {
        set_round(PROVIDER, 1, DIM, eligible_round(5));
        set_round(PROVIDER, 3, DIM, eligible_round(5));
        // Round 2 never closed.
        System::set_block_number(5 + DISPUTE_WINDOW);
        assert_noop!(
            ProviderSlashing::record_breach(RuntimeOrigin::signed(9), PROVIDER, DIM, 1),
            crate::Error::<Test>::RoundNotEligible
        );
    });
}

/// "Slash attempted during an open dispute window": a round is `Final` but
/// its own `DisputeWindow` has not yet elapsed.
#[test]
fn record_breach_fails_while_a_round_is_still_within_its_own_dispute_window() {
    new_test_ext().execute_with(|| {
        set_eligible_streak(PROVIDER, 1, 5);
        System::set_block_number(5 + DISPUTE_WINDOW - 1);
        assert_noop!(
            ProviderSlashing::record_breach(RuntimeOrigin::signed(9), PROVIDER, DIM, 1),
            crate::Error::<Test>::RoundNotEligible
        );
    });
}

#[test]
fn record_breach_succeeds_exactly_when_dispute_window_elapses() {
    new_test_ext().execute_with(|| {
        set_eligible_streak(PROVIDER, 1, 5);
        System::set_block_number(5 + DISPUTE_WINDOW);
        record_breach_ok(PROVIDER, 1);
    });
}

/// A round still under an open dispute can never count -- there is no
/// path from `Disputed` into a completed slash, never a race against one
/// (ADR-036 §4).
#[test]
fn record_breach_fails_for_a_disputed_round() {
    new_test_ext().execute_with(|| {
        set_round(PROVIDER, 1, DIM, eligible_round(5));
        set_round(PROVIDER, 2, DIM, eligible_round(5));
        set_round(
            PROVIDER,
            3,
            DIM,
            RoundView {
                status: RoundViewStatus::Disputed,
                ..eligible_round(5)
            },
        );
        System::set_block_number(5 + DISPUTE_WINDOW);
        assert_noop!(
            ProviderSlashing::record_breach(RuntimeOrigin::signed(9), PROVIDER, DIM, 1),
            crate::Error::<Test>::RoundNotEligible
        );
    });
}

/// "Slash reversed by an upheld dispute": once a round flips to
/// `DisputeUpheld`, the streak it was part of can never complete.
#[test]
fn record_breach_fails_for_a_round_whose_dispute_was_upheld() {
    new_test_ext().execute_with(|| {
        set_round(PROVIDER, 1, DIM, eligible_round(5));
        set_round(
            PROVIDER,
            2,
            DIM,
            RoundView {
                status: RoundViewStatus::DisputeUpheld,
                ..eligible_round(5)
            },
        );
        set_round(PROVIDER, 3, DIM, eligible_round(5));
        System::set_block_number(5 + DISPUTE_WINDOW);
        assert_noop!(
            ProviderSlashing::record_breach(RuntimeOrigin::signed(9), PROVIDER, DIM, 1),
            crate::Error::<Test>::RoundNotEligible
        );
    });
}

/// A round whose dispute was rejected (the aggregate stands) still counts.
#[test]
fn record_breach_succeeds_for_a_round_whose_dispute_was_rejected() {
    new_test_ext().execute_with(|| {
        set_round(PROVIDER, 1, DIM, eligible_round(5));
        set_round(
            PROVIDER,
            2,
            DIM,
            RoundView {
                status: RoundViewStatus::DisputeRejected,
                ..eligible_round(5)
            },
        );
        set_round(PROVIDER, 3, DIM, eligible_round(5));
        System::set_block_number(5 + DISPUTE_WINDOW);
        record_breach_ok(PROVIDER, 1);
    });
}

#[test]
fn record_breach_fails_if_score_is_not_below_the_breach_threshold() {
    new_test_ext().execute_with(|| {
        set_round(
            PROVIDER,
            1,
            DIM,
            RoundView {
                score_bps: AvailabilityBreachThresholdBps::get(),
                ..eligible_round(5)
            },
        );
        set_round(PROVIDER, 2, DIM, eligible_round(5));
        set_round(PROVIDER, 3, DIM, eligible_round(5));
        System::set_block_number(5 + DISPUTE_WINDOW);
        assert_noop!(
            ProviderSlashing::record_breach(RuntimeOrigin::signed(9), PROVIDER, DIM, 1),
            crate::Error::<Test>::RoundNotEligible
        );
    });
}

/// "Colluding minority failing to trigger a slash": a round can close on
/// the bare quorum (below the slash confidence bar) and still be fully
/// valid for reputation purposes, but it must never itself become
/// slash-eligible.
#[test]
fn record_breach_fails_if_confidence_is_below_the_slash_threshold() {
    new_test_ext().execute_with(|| {
        // 3 of 5 = 60%, above whatever MinQuorum needs but below this
        // pallet's own 80% SlashConfidenceThresholdBps.
        let low_confidence = RoundView {
            submissions: 3,
            ..eligible_round(5)
        };
        set_round(PROVIDER, 1, DIM, low_confidence.clone());
        set_round(PROVIDER, 2, DIM, low_confidence.clone());
        set_round(PROVIDER, 3, DIM, low_confidence);
        System::set_block_number(5 + DISPUTE_WINDOW);
        assert_noop!(
            ProviderSlashing::record_breach(RuntimeOrigin::signed(9), PROVIDER, DIM, 1),
            crate::Error::<Test>::RoundNotEligible
        );
    });
}

#[test]
fn record_breach_fails_if_already_pending() {
    new_test_ext().execute_with(|| {
        set_eligible_streak(PROVIDER, 1, 5);
        System::set_block_number(5 + DISPUTE_WINDOW);
        record_breach_ok(PROVIDER, 1);
        assert_noop!(
            ProviderSlashing::record_breach(RuntimeOrigin::signed(9), PROVIDER, DIM, 1),
            crate::Error::<Test>::SlashAlreadyPending
        );
    });
}

/// "Double-slash for the same round": once a streak is fully consumed
/// (watermark advanced), no later `record_breach` may re-use any of its
/// rounds, even for a differently-anchored, overlapping streak.
#[test]
fn record_breach_rejects_a_round_already_consumed_by_a_slashed_streak() {
    new_test_ext().execute_with(|| {
        set_eligible_streak(PROVIDER, 1, 5);
        System::set_block_number(5 + DISPUTE_WINDOW);
        record_breach_ok(PROVIDER, 1);
        System::set_block_number(5 + DISPUTE_WINDOW + SlashAppealWindow::get());
        assert_ok!(ProviderSlashing::execute_slash(
            RuntimeOrigin::signed(9),
            PROVIDER,
            DIM
        ));
        assert_eq!(
            ProviderSlashing::last_slashed_round((PROVIDER, DIM)),
            Some(3)
        );

        // Rounds 2-4 overlap with the already-consumed 1-3 streak.
        set_round(PROVIDER, 4, DIM, eligible_round(5));
        assert_noop!(
            ProviderSlashing::record_breach(RuntimeOrigin::signed(9), PROVIDER, DIM, 2),
            crate::Error::<Test>::RoundAlreadySlashed
        );
        // A streak strictly after the watermark is fine.
        set_round(PROVIDER, 5, DIM, eligible_round(5));
        set_round(PROVIDER, 6, DIM, eligible_round(5));
        record_breach_ok(PROVIDER, 4);
    });
}

#[test]
fn record_breach_is_scoped_per_provider() {
    new_test_ext().execute_with(|| {
        set_eligible_streak(PROVIDER, 1, 5);
        System::set_block_number(5 + DISPUTE_WINDOW);
        assert_noop!(
            ProviderSlashing::record_breach(RuntimeOrigin::signed(9), OTHER_PROVIDER, DIM, 1),
            crate::Error::<Test>::RoundNotEligible
        );
    });
}

// ---------------------------------------------------------------------
// appeal_slash
// ---------------------------------------------------------------------

#[test]
fn appeal_slash_requires_pending_slash() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            ProviderSlashing::appeal_slash(RuntimeOrigin::signed(PROVIDER), PROVIDER, DIM),
            crate::Error::<Test>::NoPendingSlash
        );
    });
}

#[test]
fn appeal_slash_rejects_a_caller_other_than_the_provider() {
    new_test_ext().execute_with(|| {
        set_eligible_streak(PROVIDER, 1, 5);
        System::set_block_number(5 + DISPUTE_WINDOW);
        record_breach_ok(PROVIDER, 1);
        assert_noop!(
            ProviderSlashing::appeal_slash(RuntimeOrigin::signed(OTHER_PROVIDER), PROVIDER, DIM),
            crate::Error::<Test>::NotSlashSubject
        );
    });
}

#[test]
fn appeal_slash_succeeds_within_window_and_blocks_execution() {
    new_test_ext().execute_with(|| {
        set_eligible_streak(PROVIDER, 1, 5);
        System::set_block_number(5 + DISPUTE_WINDOW);
        record_breach_ok(PROVIDER, 1);
        assert_ok!(ProviderSlashing::appeal_slash(
            RuntimeOrigin::signed(PROVIDER),
            PROVIDER,
            DIM
        ));
        let pending = ProviderSlashing::pending_slash((PROVIDER, DIM)).expect("still pending");
        assert_eq!(pending.state, SlashState::Appealed);
        System::assert_last_event(RuntimeEvent::ProviderSlashing(
            crate::Event::SlashAppealed {
                provider: PROVIDER,
                dimension: DIM,
            },
        ));

        System::set_block_number(System::block_number() + SlashAppealWindow::get() + 1);
        assert_noop!(
            ProviderSlashing::execute_slash(RuntimeOrigin::signed(9), PROVIDER, DIM),
            crate::Error::<Test>::UnexpectedSlashState
        );
        assert!(slash_calls().is_empty());
    });
}

#[test]
fn appeal_slash_exactly_at_the_deadline_still_succeeds() {
    new_test_ext().execute_with(|| {
        set_eligible_streak(PROVIDER, 1, 5);
        let created_at = 5 + DISPUTE_WINDOW;
        System::set_block_number(created_at);
        record_breach_ok(PROVIDER, 1);
        System::set_block_number(created_at + SlashAppealWindow::get());
        assert_ok!(ProviderSlashing::appeal_slash(
            RuntimeOrigin::signed(PROVIDER),
            PROVIDER,
            DIM
        ));
    });
}

#[test]
fn appeal_slash_one_block_past_the_deadline_fails() {
    new_test_ext().execute_with(|| {
        set_eligible_streak(PROVIDER, 1, 5);
        let created_at = 5 + DISPUTE_WINDOW;
        System::set_block_number(created_at);
        record_breach_ok(PROVIDER, 1);
        System::set_block_number(created_at + SlashAppealWindow::get() + 1);
        assert_noop!(
            ProviderSlashing::appeal_slash(RuntimeOrigin::signed(PROVIDER), PROVIDER, DIM),
            crate::Error::<Test>::AppealWindowClosed
        );
    });
}

#[test]
fn appeal_slash_twice_fails() {
    new_test_ext().execute_with(|| {
        set_eligible_streak(PROVIDER, 1, 5);
        System::set_block_number(5 + DISPUTE_WINDOW);
        record_breach_ok(PROVIDER, 1);
        assert_ok!(ProviderSlashing::appeal_slash(
            RuntimeOrigin::signed(PROVIDER),
            PROVIDER,
            DIM
        ));
        assert_noop!(
            ProviderSlashing::appeal_slash(RuntimeOrigin::signed(PROVIDER), PROVIDER, DIM),
            crate::Error::<Test>::UnexpectedSlashState
        );
    });
}

// ---------------------------------------------------------------------
// resolve_slash_appeal
// ---------------------------------------------------------------------

#[test]
fn resolve_slash_appeal_requires_root() {
    new_test_ext().execute_with(|| {
        set_eligible_streak(PROVIDER, 1, 5);
        System::set_block_number(5 + DISPUTE_WINDOW);
        record_breach_ok(PROVIDER, 1);
        assert_ok!(ProviderSlashing::appeal_slash(
            RuntimeOrigin::signed(PROVIDER),
            PROVIDER,
            DIM
        ));
        assert_noop!(
            ProviderSlashing::resolve_slash_appeal(
                RuntimeOrigin::signed(PROVIDER),
                PROVIDER,
                DIM,
                true
            ),
            sp_runtime::DispatchError::BadOrigin
        );
    });
}

#[test]
fn resolve_slash_appeal_requires_appealed_state() {
    new_test_ext().execute_with(|| {
        set_eligible_streak(PROVIDER, 1, 5);
        System::set_block_number(5 + DISPUTE_WINDOW);
        record_breach_ok(PROVIDER, 1);
        assert_noop!(
            ProviderSlashing::resolve_slash_appeal(RuntimeOrigin::root(), PROVIDER, DIM, true),
            crate::Error::<Test>::UnexpectedSlashState
        );
    });
}

/// The second of ADR-036's two "reversed" scenarios: an upheld appeal
/// moves no funds at all -- nothing was ever taken, so there is nothing to
/// reverse.
#[test]
fn resolve_slash_appeal_uphold_true_removes_pending_and_slashes_nothing() {
    new_test_ext().execute_with(|| {
        set_eligible_streak(PROVIDER, 1, 5);
        System::set_block_number(5 + DISPUTE_WINDOW);
        record_breach_ok(PROVIDER, 1);
        assert_ok!(ProviderSlashing::appeal_slash(
            RuntimeOrigin::signed(PROVIDER),
            PROVIDER,
            DIM
        ));
        assert_ok!(ProviderSlashing::resolve_slash_appeal(
            RuntimeOrigin::root(),
            PROVIDER,
            DIM,
            true
        ));
        assert!(ProviderSlashing::pending_slash((PROVIDER, DIM)).is_none());
        assert!(slash_calls().is_empty());
        assert_eq!(
            ProviderSlashing::last_slashed_round((PROVIDER, DIM)),
            Some(3)
        );
        System::assert_last_event(RuntimeEvent::ProviderSlashing(
            crate::Event::SlashAppealResolved {
                provider: PROVIDER,
                dimension: DIM,
                upheld: true,
            },
        ));
    });
}

#[test]
fn resolve_slash_appeal_uphold_false_executes_the_slash() {
    new_test_ext().execute_with(|| {
        set_eligible_streak(PROVIDER, 1, 5);
        System::set_block_number(5 + DISPUTE_WINDOW);
        record_breach_ok(PROVIDER, 1);
        assert_ok!(ProviderSlashing::appeal_slash(
            RuntimeOrigin::signed(PROVIDER),
            PROVIDER,
            DIM
        ));
        assert_ok!(ProviderSlashing::resolve_slash_appeal(
            RuntimeOrigin::root(),
            PROVIDER,
            DIM,
            false
        ));
        assert!(ProviderSlashing::pending_slash((PROVIDER, DIM)).is_none());
        assert_eq!(slash_calls(), vec![(PROVIDER, ProviderSlashAmount::get())]);
    });
}

// ---------------------------------------------------------------------
// execute_slash
// ---------------------------------------------------------------------

#[test]
fn execute_slash_requires_pending_slash() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            ProviderSlashing::execute_slash(RuntimeOrigin::signed(9), PROVIDER, DIM),
            crate::Error::<Test>::NoPendingSlash
        );
    });
}

#[test]
fn execute_slash_fails_before_the_appeal_window_elapses() {
    new_test_ext().execute_with(|| {
        set_eligible_streak(PROVIDER, 1, 5);
        let created_at = 5 + DISPUTE_WINDOW;
        System::set_block_number(created_at);
        record_breach_ok(PROVIDER, 1);
        System::set_block_number(created_at + SlashAppealWindow::get() - 1);
        assert_noop!(
            ProviderSlashing::execute_slash(RuntimeOrigin::signed(9), PROVIDER, DIM),
            crate::Error::<Test>::AppealWindowNotElapsed
        );
        assert!(slash_calls().is_empty());
    });
}

#[test]
fn execute_slash_succeeds_exactly_at_the_deadline() {
    new_test_ext().execute_with(|| {
        set_eligible_streak(PROVIDER, 1, 5);
        let created_at = 5 + DISPUTE_WINDOW;
        System::set_block_number(created_at);
        record_breach_ok(PROVIDER, 1);
        System::set_block_number(created_at + SlashAppealWindow::get());
        assert_ok!(ProviderSlashing::execute_slash(
            RuntimeOrigin::signed(9),
            PROVIDER,
            DIM
        ));
    });
}

/// "Justified slash": the full happy-path flow end to end.
#[test]
fn execute_slash_removes_pending_advances_watermark_and_slashes_the_full_amount() {
    new_test_ext().execute_with(|| {
        set_eligible_streak(PROVIDER, 10, 5);
        let created_at = 5 + DISPUTE_WINDOW;
        System::set_block_number(created_at);
        record_breach_ok(PROVIDER, 10);
        System::set_block_number(created_at + SlashAppealWindow::get());
        assert_ok!(ProviderSlashing::execute_slash(
            RuntimeOrigin::signed(9),
            PROVIDER,
            DIM
        ));

        assert!(ProviderSlashing::pending_slash((PROVIDER, DIM)).is_none());
        assert_eq!(
            ProviderSlashing::last_slashed_round((PROVIDER, DIM)),
            Some(12)
        );
        assert_eq!(slash_calls(), vec![(PROVIDER, ProviderSlashAmount::get())]);
        System::assert_last_event(RuntimeEvent::ProviderSlashing(
            crate::Event::ProviderSlashed {
                provider: PROVIDER,
                dimension: DIM,
                first_round: 10,
                amount: ProviderSlashAmount::get(),
                force_suspended: false,
            },
        ));
    });
}

#[test]
fn execute_slash_fails_while_appealed() {
    new_test_ext().execute_with(|| {
        set_eligible_streak(PROVIDER, 1, 5);
        let created_at = 5 + DISPUTE_WINDOW;
        System::set_block_number(created_at);
        record_breach_ok(PROVIDER, 1);
        assert_ok!(ProviderSlashing::appeal_slash(
            RuntimeOrigin::signed(PROVIDER),
            PROVIDER,
            DIM
        ));
        System::set_block_number(created_at + SlashAppealWindow::get());
        assert_noop!(
            ProviderSlashing::execute_slash(RuntimeOrigin::signed(9), PROVIDER, DIM),
            crate::Error::<Test>::UnexpectedSlashState
        );
        assert!(slash_calls().is_empty());
    });
}

#[test]
fn execute_slash_propagates_force_suspended_from_the_slasher() {
    new_test_ext().execute_with(|| {
        FORCE_SUSPENDED.with(|f| *f.borrow_mut() = true);
        set_eligible_streak(PROVIDER, 1, 5);
        let created_at = 5 + DISPUTE_WINDOW;
        System::set_block_number(created_at);
        record_breach_ok(PROVIDER, 1);
        System::set_block_number(created_at + SlashAppealWindow::get());
        assert_ok!(ProviderSlashing::execute_slash(
            RuntimeOrigin::signed(9),
            PROVIDER,
            DIM
        ));
        System::assert_last_event(RuntimeEvent::ProviderSlashing(
            crate::Event::ProviderSlashed {
                provider: PROVIDER,
                dimension: DIM,
                first_round: 1,
                amount: ProviderSlashAmount::get(),
                force_suspended: true,
            },
        ));
    });
}
