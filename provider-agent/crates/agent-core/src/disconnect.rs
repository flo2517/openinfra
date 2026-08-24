//! ADR-028 §1: shared disconnected-mode state between the Agent's
//! background heartbeat task and its gRPC request handlers.
//!
//! `agent-cli::handle_start` already spawns the heartbeat loop and builds
//! the `ProviderAgentServiceServer` in the same process, both holding
//! `Arc<LocalState>` -- this needs no cross-process coordination for the
//! same reason: a `Clone`-able, atomically-updated handle shared between
//! the loop that observes heartbeat outcomes (writer) and the `Deploy`
//! handler that must refuse new work once disconnected (reader).

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// ADR-028 §1: 3 consecutive failed heartbeat attempts (~45s at the
/// existing 15s cadence) before the Agent declares itself disconnected --
/// chosen to match the Control Plane's own existing heartbeat staleness
/// window (`providerjoin.defaultHeartbeatTTL` = 45s =
/// 3 * `defaultHeartbeatInterval`), so both sides agree on the same
/// boundary rather than each independently guessing when the other has
/// given up. A single transient failure does not trip disconnected mode.
pub const DISCONNECT_THRESHOLD: u32 = 3;

#[derive(Debug, Default)]
struct Inner {
    consecutive_failures: AtomicU32,
    /// 0 means "not currently disconnected". Otherwise the unix-seconds
    /// timestamp of the failure that tripped disconnected mode -- carried
    /// for observability only; no policy in this codebase currently reads
    /// it (the lease-expiry policy in agent-executor's
    /// `enforce_lease_expiry` is deliberately unconditional, connected or
    /// not, per ADR-028 §3).
    disconnected_since_unix: AtomicU64,
}

/// A cheap, `Clone`-able, `Send + Sync` handle onto one Agent process's
/// disconnected/connected status. Every clone shares the same underlying
/// counters (`Arc` internally) -- there is exactly one true state per
/// process, matching the ADR's "one in-process marker" design.
#[derive(Debug, Clone, Default)]
pub struct DisconnectState {
    inner: Arc<Inner>,
}

impl DisconnectState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a successful heartbeat round trip: resets the failure streak
    /// and immediately clears disconnected status. ADR-028 §1 has no
    /// separate "recovering" state -- a single success reconnects.
    pub fn record_success(&self) {
        self.inner.consecutive_failures.store(0, Ordering::SeqCst);
        self.inner
            .disconnected_since_unix
            .store(0, Ordering::SeqCst);
    }

    /// Records one failed heartbeat attempt (network error, unreachable
    /// Control Plane, an expired mTLS certificate, or a non-2xx gRPC
    /// status -- ADR-028 §1 treats all of these identically). Returns
    /// `true` exactly once, on the call that reaches
    /// [`DISCONNECT_THRESHOLD`], so a caller can log the transition
    /// exactly once instead of on every subsequent failure too.
    pub fn record_failure(&self) -> bool {
        let failures = self
            .inner
            .consecutive_failures
            .fetch_add(1, Ordering::SeqCst)
            + 1;
        if failures == DISCONNECT_THRESHOLD {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_secs())
                .unwrap_or(0);
            self.inner
                .disconnected_since_unix
                .store(now, Ordering::SeqCst);
            return true;
        }
        false
    }

    /// `true` once [`record_failure`](Self::record_failure) has been
    /// called [`DISCONNECT_THRESHOLD`] or more consecutive times with no
    /// intervening [`record_success`](Self::record_success).
    pub fn is_disconnected(&self) -> bool {
        self.inner.consecutive_failures.load(Ordering::SeqCst) >= DISCONNECT_THRESHOLD
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stays_connected_below_the_threshold() {
        let state = DisconnectState::new();
        assert!(!state.record_failure());
        assert!(!state.is_disconnected());
        assert!(!state.record_failure());
        assert!(
            !state.is_disconnected(),
            "two consecutive failures must not trip disconnected mode"
        );
    }

    #[test]
    fn trips_disconnected_mode_on_exactly_the_third_consecutive_failure() {
        let state = DisconnectState::new();
        assert!(!state.record_failure());
        assert!(!state.record_failure());
        assert!(
            state.record_failure(),
            "the third consecutive failure must trip disconnected mode"
        );
        assert!(state.is_disconnected());
    }

    #[test]
    fn a_single_success_immediately_reconnects() {
        let state = DisconnectState::new();
        for _ in 0..DISCONNECT_THRESHOLD {
            state.record_failure();
        }
        assert!(state.is_disconnected());
        state.record_success();
        assert!(!state.is_disconnected());
    }

    #[test]
    fn an_intervening_success_resets_the_streak() {
        let state = DisconnectState::new();
        assert!(!state.record_failure());
        assert!(!state.record_failure());
        state.record_success();
        // The streak restarted: two more failures must not trip
        // disconnected mode, since only two have happened *consecutively*
        // since the last success.
        assert!(!state.record_failure());
        assert!(!state.record_failure());
        assert!(!state.is_disconnected());
    }

    #[test]
    fn clones_share_the_same_underlying_state() {
        let state = DisconnectState::new();
        let clone = state.clone();
        for _ in 0..DISCONNECT_THRESHOLD {
            state.record_failure();
        }
        assert!(
            clone.is_disconnected(),
            "a cloned handle must observe the same disconnected status"
        );
    }
}
