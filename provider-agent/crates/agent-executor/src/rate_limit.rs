//! ADR-025 §3: host-side egress rate-limit enforcement, a fourth quota
//! alongside the memory/CPU/PID quotas `DockerExecutor::deployment`
//! already builds into `ContainerSpec`. Docker's `HostConfig` has no
//! bandwidth field (confirmed against `bollard::models::HostConfig`, see
//! the ADR's Verification section), so this applies a Linux `tc`
//! token-bucket-filter (`tbf`) qdisc directly against the *host* side of
//! the workload's veth pair -- the same interface `bandwidth.rs` already
//! resolves via `resolve_veth_name` to read usage counters, reused here
//! rather than re-derived.
//!
//! Egress only, matching the ADR: `tbf` on the host-side veth caps what
//! the *container* transmits, i.e. what the host side *receives* (see
//! `bandwidth.rs`'s doc comment on the veth-pair mirroring). Symmetric
//! ingress shaping would need an `ifb` redirect and is a deliberately
//! deferred asymmetry, not solved here.
//!
//! Teardown: no separate cleanup call. A `tc qdisc` is kernel state
//! scoped to the interface it is attached to, not to the Agent process --
//! when Docker tears down a container's network sandbox (which already
//! happens on `docker stop`, not only on removal, for the default bridge
//! network driver this Agent uses), the veth pair is destroyed, and
//! destroying either end of a veth pair -- along with every qdisc
//! attached to it -- is atomic kernel behavior, not something a
//! coordinating process can observe a window to leak. This is the same
//! conclusion `DockerExecutor::stop`'s existing veth-free teardown already
//! assumes for `bandwidth.rs`'s counters (which likewise go away with the
//! interface); nothing about attaching a qdisc changes that.
//!
//! Testability: running real `tc` needs `CAP_NET_ADMIN` and a real veth,
//! neither available in an ordinary test run. `CommandRunner` is the same
//! seam `control-plane/internal/wireguard.CommandBackend` uses on the Go
//! side for the same reason (an injectable "run this privileged command"
//! function tests can fake) -- `RateLimiter::apply`'s tests exercise the
//! exact `tc` invocation (program, args, target interface, rate) against
//! a `FakeCommandRunner`, never a real interface.

use crate::bandwidth::resolve_veth_name;
use crate::ExecutorError;
use std::path::Path;
use std::process::Output;
use std::sync::Arc;

/// Runs an external command and returns its captured output. The real
/// implementation (`SystemCommandRunner`) shells out via
/// `std::process::Command`; tests substitute a fake that records
/// invocations and returns canned output, without needing `CAP_NET_ADMIN`
/// or a real interface.
pub trait CommandRunner: Send + Sync {
    fn run(&self, program: &str, args: &[String]) -> std::io::Result<Output>;
}

/// The real, privileged `CommandRunner` -- shells out via
/// `std::process::Command`, exactly like `wireguard.go`'s
/// `NewCommandBackend` default `Runner`.
pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&self, program: &str, args: &[String]) -> std::io::Result<Output> {
        std::process::Command::new(program).args(args).output()
    }
}

/// Token-bucket-filter burst size, bytes. A fixed, bounded constant
/// (matching the ADR's "burst <bounded>" wording) rather than a per-
/// workload setting -- there is no product requirement yet for
/// operator/workload control over burst tolerance, and a fixed value
/// avoids a second unbounded input into a privileged `tc` invocation.
/// 32 KiB is `tc`'s own commonly documented default for `tbf` at
/// moderate rates -- large enough that a single MTU-sized packet always
/// fits in one token-bucket refill, small enough to bound queueing delay.
const TBF_BURST_BYTES: u32 = 32 * 1024;

/// Token-bucket-filter maximum queueing latency before a packet is
/// dropped rather than delayed. Fixed and bounded for the same reason as
/// `TBF_BURST_BYTES` above.
const TBF_LATENCY_MS: u32 = 50;

/// Applies (or reports a failure applying) an egress rate ceiling to a
/// workload's veth pair.
pub struct RateLimiter {
    runner: Arc<dyn CommandRunner>,
}

impl RateLimiter {
    pub fn new(runner: Arc<dyn CommandRunner>) -> Self {
        Self { runner }
    }

    /// Resolves `container_pid`'s host-side veth (via
    /// `bandwidth::resolve_veth_name`) and runs `tc qdisc add ... tbf
    /// rate <egress_mbps>mbit burst <TBF_BURST_BYTES> latency
    /// <TBF_LATENCY_MS>ms` against it. Callers must not invoke this with
    /// `egress_mbps <= 0` -- that means "no reservation declared," which
    /// is "apply no rule," not "apply a zero-rate rule" (checked by the
    /// caller, `DockerExecutor::deploy`, not re-validated here, matching
    /// how `deployment()` is the single validation point for the other
    /// three quotas).
    pub fn apply(
        &self,
        sys_root: &Path,
        container_pid: i64,
        egress_mbps: i32,
    ) -> Result<(), ExecutorError> {
        let veth = resolve_veth_name(sys_root, container_pid)?;
        self.apply_to_interface(&veth, egress_mbps)
    }

    /// The same `tc qdisc replace ... tbf` enforcement `apply` performs,
    /// against an interface name the caller already knows directly rather
    /// than one that needs PID-based veth resolution first. ADR-033 §5's
    /// tap-device networking path (`vm::tap`) calls this directly: a VM's
    /// tap device name is chosen by this Agent itself at creation time
    /// (`vm::tap::tap_device_name`), not discovered after the fact the
    /// way a container's veth peer is via `resolve_veth_name`.
    pub fn apply_to_interface(&self, iface: &str, egress_mbps: i32) -> Result<(), ExecutorError> {
        let args = tbf_args(iface, egress_mbps);
        let output = self
            .runner
            .run("tc", &args)
            .map_err(|error| ExecutorError::Engine(format!("run tc: {error}")))?;
        if !output.status.success() {
            return Err(ExecutorError::Engine(format!(
                "tc qdisc add on {iface} failed (status {}): {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        Ok(())
    }
}

fn tbf_args(veth: &str, egress_mbps: i32) -> Vec<String> {
    vec![
        "qdisc".to_string(),
        // `replace`, not `add`: an `add` fails with "Exclusivity flag on,
        // cannot modify" if a root qdisc is already attached to this
        // veth -- which a retried `deploy()` (e.g. Agent restart between
        // a successful `tc` call and the phase being persisted `Running`)
        // would hit re-invoking this against the same still-live
        // interface. `replace` is the standard idempotent form: applies
        // the rule if absent, atomically updates it if present, matching
        // the same "safe to call again" property `create`/`start`
        // already have for the other three quotas via Docker's own
        // idempotent container API.
        "replace".to_string(),
        "dev".to_string(),
        veth.to_string(),
        "root".to_string(),
        "tbf".to_string(),
        "rate".to_string(),
        format!("{egress_mbps}mbit"),
        "burst".to_string(),
        TBF_BURST_BYTES.to_string(),
        "latency".to_string(),
        format!("{TBF_LATENCY_MS}ms"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;
    use std::sync::Mutex as StdMutex;

    #[derive(Default)]
    struct FakeCommandRunner {
        invocations: StdMutex<Vec<(String, Vec<String>)>>,
        outcome: StdMutex<Option<Result<i32, String>>>,
    }

    impl FakeCommandRunner {
        fn succeeding() -> Self {
            Self {
                invocations: StdMutex::new(Vec::new()),
                outcome: StdMutex::new(Some(Ok(0))),
            }
        }

        fn failing(exit_code: i32, stderr: &str) -> Self {
            Self {
                invocations: StdMutex::new(Vec::new()),
                outcome: StdMutex::new(Some(Err(format!("{exit_code}\x00{stderr}")))),
            }
        }
    }

    impl CommandRunner for FakeCommandRunner {
        fn run(&self, program: &str, args: &[String]) -> std::io::Result<Output> {
            self.invocations
                .lock()
                .expect("invocations lock")
                .push((program.to_string(), args.to_vec()));
            match self
                .outcome
                .lock()
                .expect("outcome lock")
                .as_ref()
                .expect("configured outcome")
            {
                Ok(code) => Ok(Output {
                    status: ExitStatus::from_raw(*code << 8),
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                }),
                Err(encoded) => {
                    let (code, stderr) = encoded.split_once('\x00').expect("encoded failure");
                    Ok(Output {
                        status: ExitStatus::from_raw(code.parse::<i32>().expect("exit code") << 8),
                        stdout: Vec::new(),
                        stderr: stderr.as_bytes().to_vec(),
                    })
                }
            }
        }
    }

    fn write(path: &Path, contents: &str) {
        std::fs::create_dir_all(path.parent().expect("parent")).expect("create dir");
        std::fs::write(path, contents).expect("write fixture file");
    }

    fn fixture_root_with_veth(directory: &std::path::Path, veth: &str) {
        write(
            &directory.join("proc/4242/root/sys/class/net/eth0/iflink"),
            "17\n",
        );
        write(
            &directory.join("sys/class/net").join(veth).join("ifindex"),
            "17\n",
        );
    }

    #[test]
    fn apply_issues_the_correct_tc_command_for_the_resolved_interface_and_rate() {
        let directory = tempfile::tempdir().expect("temp dir");
        fixture_root_with_veth(directory.path(), "veth-abc123");
        let runner = Arc::new(FakeCommandRunner::succeeding());
        let limiter = RateLimiter::new(runner.clone());

        limiter
            .apply(directory.path(), 4242, 100)
            .expect("apply rate limit");

        let invocations = runner.invocations.lock().expect("invocations lock");
        assert_eq!(invocations.len(), 1, "exactly one tc invocation");
        let (program, args) = &invocations[0];
        assert_eq!(program, "tc");
        assert_eq!(
            args,
            &[
                "qdisc",
                "replace",
                "dev",
                "veth-abc123",
                "root",
                "tbf",
                "rate",
                "100mbit",
                "burst",
                "32768",
                "latency",
                "50ms",
            ]
        );
    }

    #[test]
    fn apply_uses_the_exact_requested_rate_not_a_rounded_or_default_one() {
        let directory = tempfile::tempdir().expect("temp dir");
        fixture_root_with_veth(directory.path(), "veth-xyz");
        let runner = Arc::new(FakeCommandRunner::succeeding());
        let limiter = RateLimiter::new(runner.clone());

        limiter
            .apply(directory.path(), 4242, 7)
            .expect("apply rate limit");

        let invocations = runner.invocations.lock().expect("invocations lock");
        assert!(invocations[0].1.contains(&"7mbit".to_string()));
    }

    #[test]
    fn apply_fails_when_veth_cannot_be_resolved_and_never_shells_out() {
        let directory = tempfile::tempdir().expect("temp dir");
        let runner = Arc::new(FakeCommandRunner::succeeding());
        let limiter = RateLimiter::new(runner.clone());

        let result = limiter.apply(directory.path(), 9999, 100);

        assert!(result.is_err());
        assert!(
            runner
                .invocations
                .lock()
                .expect("invocations lock")
                .is_empty(),
            "tc must not be invoked when veth resolution fails"
        );
    }

    #[test]
    fn apply_surfaces_a_nonzero_tc_exit_as_an_error() {
        let directory = tempfile::tempdir().expect("temp dir");
        fixture_root_with_veth(directory.path(), "veth-abc123");
        let runner = Arc::new(FakeCommandRunner::failing(
            2,
            "RTNETLINK answers: Permission denied",
        ));
        let limiter = RateLimiter::new(runner);

        let result = limiter.apply(directory.path(), 4242, 100);

        let error = result.expect_err("nonzero tc exit must surface as an error");
        assert!(error.to_string().contains("Permission denied"));
    }

    // Congestion-test-adjacent coverage (ADR-025 §5): two workloads
    // sharing one provider's link only holds one workload's reservation
    // if each workload's *own* veth gets its *own* independent rate --
    // this asserts `apply` never reuses another workload's target
    // interface or rate across calls with the same RateLimiter.
    #[test]
    fn apply_targets_each_workloads_own_veth_and_rate_independently() {
        let directory = tempfile::tempdir().expect("temp dir");
        write(
            &directory
                .path()
                .join("proc/100/root/sys/class/net/eth0/iflink"),
            "1\n",
        );
        write(
            &directory.path().join("sys/class/net/veth-a/ifindex"),
            "1\n",
        );
        write(
            &directory
                .path()
                .join("proc/200/root/sys/class/net/eth0/iflink"),
            "2\n",
        );
        write(
            &directory.path().join("sys/class/net/veth-b/ifindex"),
            "2\n",
        );
        let runner = Arc::new(FakeCommandRunner::succeeding());
        let limiter = RateLimiter::new(runner.clone());

        limiter
            .apply(directory.path(), 100, 50)
            .expect("apply workload a");
        limiter
            .apply(directory.path(), 200, 200)
            .expect("apply workload b");

        let invocations = runner.invocations.lock().expect("invocations lock");
        assert_eq!(invocations.len(), 2);
        assert!(invocations[0].1.contains(&"veth-a".to_string()));
        assert!(invocations[0].1.contains(&"50mbit".to_string()));
        assert!(invocations[1].1.contains(&"veth-b".to_string()));
        assert!(invocations[1].1.contains(&"200mbit".to_string()));
    }

    // --- apply_to_interface (ADR-033 §5): the same tc invocation, against
    // an interface name the caller already knows -- no sys_root/PID
    // resolution fixture needed, unlike `apply`'s tests above.

    #[test]
    fn apply_to_interface_issues_the_same_tc_command_shape_apply_does() {
        let runner = Arc::new(FakeCommandRunner::succeeding());
        let limiter = RateLimiter::new(runner.clone());

        limiter
            .apply_to_interface("oivmabcd1234", 100)
            .expect("apply_to_interface");

        let invocations = runner.invocations.lock().expect("invocations lock");
        assert_eq!(invocations.len(), 1);
        let (program, args) = &invocations[0];
        assert_eq!(program, "tc");
        assert_eq!(
            args,
            &[
                "qdisc",
                "replace",
                "dev",
                "oivmabcd1234",
                "root",
                "tbf",
                "rate",
                "100mbit",
                "burst",
                "32768",
                "latency",
                "50ms",
            ]
        );
    }

    #[test]
    fn apply_to_interface_never_attempts_any_pid_based_resolution() {
        // No sys_root fixture exists anywhere for this call -- if
        // apply_to_interface tried to resolve a veth via a PID the way
        // `apply` does, this would fail before tc is ever invoked.
        let runner = Arc::new(FakeCommandRunner::succeeding());
        let limiter = RateLimiter::new(runner.clone());

        limiter
            .apply_to_interface("oivmdeadbeef", 7)
            .expect("apply_to_interface must not need any veth/PID resolution");

        let invocations = runner.invocations.lock().expect("invocations lock");
        assert_eq!(invocations.len(), 1);
        assert!(invocations[0].1.contains(&"oivmdeadbeef".to_string()));
    }

    #[test]
    fn apply_to_interface_surfaces_a_nonzero_tc_exit_as_an_error() {
        let runner = Arc::new(FakeCommandRunner::failing(
            2,
            "RTNETLINK answers: Permission denied",
        ));
        let limiter = RateLimiter::new(runner);

        let result = limiter.apply_to_interface("oivmabcd1234", 100);

        let error = result.expect_err("nonzero tc exit must surface as an error");
        assert!(error.to_string().contains("Permission denied"));
    }
}
