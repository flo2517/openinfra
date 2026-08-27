//! ADR-033 §5: tap-device networking for VM workloads -- the tap-device
//! equivalent of `ContainerEngine`'s veth-pair-based attachment point for
//! WireGuard's lease-gated overlay. A Cloud Hypervisor VM's `net` device
//! (see `cloud_hypervisor.rs`'s `create()`) takes a pre-existing host tap
//! device by name (Cloud Hypervisor's own `NetConfig.tap` field, verified
//! against its published OpenAPI spec while writing this module -- Cloud
//! Hypervisor opens a tap given by name, it does not create one itself),
//! so this module owns tap-device lifecycle end to end: create it before
//! the VM boots, tear it down after the VM is removed.
//!
//! **Networking model this is one piece of** (ADR-033 §5, ADR-010): the
//! Control-Plane-side WireGuard `Backend` lifecycle (validate a
//! non-expired Lease, allocate a short-lived UDP port, Attach only after
//! finalized on-chain confirmation *and* Agent RUNNING confirmation,
//! Revoke on stop) is unchanged and still lives entirely in
//! `internal/wireguard` -- ADR-010 already abstracted the privileged
//! mechanism behind a `Backend` interface specifically so that lifecycle
//! logic never needs to know what it attaches to. This module is the
//! provider-host mechanism a VM-specific Go-side `Backend` implementation
//! would eventually attach a WireGuard peer's traffic to. Wiring an actual
//! VM-specific Go `Backend` through to this tap device is Control-Plane-
//! side follow-up work this change does not do (see the PR description);
//! this crate's job -- named explicitly by issue #176 point 1 -- is the
//! host-mechanism half: create the tap, rate-limit it, read its counters,
//! tear it down, all wired into `VmEngine`/`CloudHypervisorEngine`.
//!
//! **Kernel-interaction style deliberately matches `rate_limit.rs`/
//! `bandwidth.rs` exactly, rather than introducing a second, netlink-crate
//! dependency for the same job**: `ip tuntap add`/`ip link set .. up`/
//! `ip tuntap del`, shelled out through the exact same `CommandRunner`
//! seam `rate_limit.rs` already uses for `tc`. This module's own
//! bandwidth/rate-limit reads reuse `bandwidth.rs`/`rate_limit.rs`'s own
//! interface-name-based helpers directly (`read_bandwidth_for_interface`,
//! `RateLimiter::apply_to_interface`) rather than a second implementation
//! of either counter-reading or `tc` command construction.
//!
//! **Testability / honesty discipline, matching this crate's established
//! pattern exactly** (see `rate_limit.rs`'s and `cloud_hypervisor.rs`'s own
//! top doc comments): creating a real tap device needs `CAP_NET_ADMIN` and
//! a real kernel netlink socket, neither available in an ordinary test run
//! in this sandbox. What **is** tested for real: `SystemTapBackend`'s exact
//! `ip` command construction (program, args, in order) against a
//! `FakeCommandRunner`, and `tap_device_name`'s determinism/length
//! properties. What this module's tests do **not** and cannot prove: that
//! a real `ip tuntap add`/`ip link set up` invocation, run with
//! `CAP_NET_ADMIN` on a real Linux host, actually causes a tap device to
//! appear in `/sys/class/net` and become attachable to a real Cloud
//! Hypervisor VM end to end -- that needs a real host and is the same kind
//! of gap `cloud_hypervisor.rs`'s own top doc comment already names for
//! spawning a real `cloud-hypervisor` process.

use crate::rate_limit::CommandRunner;
use crate::ExecutorError;
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// Linux's `IFNAMSIZ` is 16 bytes including the trailing NUL, so a kernel
/// interface name must be 15 bytes or fewer. A workload_id is a 36-
/// character UUID -- far too long to use directly -- so the tap device
/// name is derived from a short hash of it rather than the workload_id
/// itself, the same "the natural identifier doesn't fit in the kernel's
/// namespace" problem Docker's own random-short-hex veth naming solves
/// for container workloads. `"oivm"` (4 bytes) + 8 lowercase hex chars =
/// 12 bytes, safely under the 15-byte limit, and namespaced so a tap
/// device this Agent created is recognizable as its own (e.g. during
/// manual `ip link` debugging) rather than an anonymous-looking name.
///
/// Deterministic in `name` (the same workload always gets the same tap
/// name), which is what makes `CloudHypervisorEngine::create`'s
/// create-then-lookup idempotency possible without a separate persisted
/// mapping the way `taps` tracks the process handle -- the tap name is
/// always recomputable from the VM's own `VmSpec.name`.
pub fn tap_device_name(name: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(name.as_bytes());
    let digest = hasher.finalize();
    format!("oivm{}", hex::encode(&digest[..4]))
}

/// Creates and tears down the host tap device a VM's virtio-net interface
/// attaches to. Abstracted the same way `CommandRunner`/`VmmTransport`/
/// `VmmProcessSpawner` already are, so `CloudHypervisorEngine`'s lifecycle
/// logic stays testable without `CAP_NET_ADMIN` or a real kernel netlink
/// socket.
pub trait TapBackend: Send + Sync {
    /// Creates `name` as a tap device and brings it up (`ip tuntap add ...
    /// mode tap`, then `ip link set ... up`). Must tolerate `name` already
    /// existing in the state this backend would itself have left it in --
    /// `CloudHypervisorEngine::create`'s own crash-recovery/retry path can
    /// reach this a second time for the same workload's deterministic tap
    /// name, the same idempotency requirement `RateLimiter::apply`'s own
    /// `tc ... replace` already has for the rate-limit side.
    fn attach(&self, name: &str) -> Result<(), ExecutorError>;

    /// Removes `name` (`ip tuntap del ... mode tap`). Must tolerate the
    /// device already being gone -- mirrors `CloudHypervisorEngine::remove`'s
    /// own "a 404 vm.delete means already-removed" idempotency for the
    /// identical reason: a retried `stop()`/`remove()` after a prior
    /// teardown partially succeeded must not itself become a hard error.
    fn detach(&self, name: &str) -> Result<(), ExecutorError>;
}

/// The real backend -- shells out to `ip` (iproute2, present on every
/// mainstream Linux distribution this Agent targets, the same "reuse a
/// narrowly-scoped, widely available mechanism" precedent `tc`/`setpriv`
/// already set for `rate_limit.rs`/`cloud_hypervisor.rs`), through the
/// same `CommandRunner` seam `RateLimiter` uses for `tc`.
pub struct SystemTapBackend {
    runner: Arc<dyn CommandRunner>,
}

impl SystemTapBackend {
    pub fn new(runner: Arc<dyn CommandRunner>) -> Self {
        Self { runner }
    }

    fn run(&self, args: &[&str]) -> Result<std::process::Output, ExecutorError> {
        let owned_args: Vec<String> = args.iter().map(|arg| arg.to_string()).collect();
        self.runner
            .run("ip", &owned_args)
            .map_err(|error| ExecutorError::Engine(format!("run ip {args:?}: {error}")))
    }
}

impl TapBackend for SystemTapBackend {
    fn attach(&self, name: &str) -> Result<(), ExecutorError> {
        let add = self.run(&["tuntap", "add", "dev", name, "mode", "tap"])?;
        if !add.status.success() {
            let stderr = String::from_utf8_lossy(&add.stderr);
            // "File exists": a prior attempt already created this device
            // (the retried-deploy/crash-recovery case this trait's own
            // doc comment names) -- tolerated for that idempotency
            // reason; every other failure is real.
            if !stderr.contains("File exists") {
                return Err(ExecutorError::Engine(format!(
                    "ip tuntap add dev {name} mode tap failed (status {}): {stderr}",
                    add.status
                )));
            }
        }
        let up = self.run(&["link", "set", "dev", name, "up"])?;
        if !up.status.success() {
            return Err(ExecutorError::Engine(format!(
                "ip link set dev {name} up failed (status {}): {}",
                up.status,
                String::from_utf8_lossy(&up.stderr)
            )));
        }
        Ok(())
    }

    fn detach(&self, name: &str) -> Result<(), ExecutorError> {
        let del = self.run(&["tuntap", "del", "dev", name, "mode", "tap"])?;
        if !del.status.success() {
            let stderr = String::from_utf8_lossy(&del.stderr);
            // Already gone -- tolerated the same way
            // `CloudHypervisorEngine::remove` tolerates a 404 from
            // `vm.delete`. iproute2 has phrased this both ways across
            // versions, so both are checked.
            if !stderr.contains("Cannot find device") && !stderr.contains("No such device") {
                return Err(ExecutorError::Engine(format!(
                    "ip tuntap del dev {name} mode tap failed (status {}): {stderr}",
                    del.status
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::process::{ExitStatus, Output};
    use std::sync::Mutex as StdMutex;

    #[derive(Default)]
    struct FakeCommandRunner {
        invocations: StdMutex<Vec<(String, Vec<String>)>>,
        // Keyed by the joined args (e.g. "tuntap add dev oivm... mode
        // tap") so a test can configure different outcomes for the two
        // different `ip` subcommands attach()/detach() issue.
        outcomes: StdMutex<std::collections::HashMap<String, (i32, String)>>,
    }

    impl FakeCommandRunner {
        fn succeeding() -> Self {
            Self::default()
        }

        fn failing_for(args_prefix: &str, exit_code: i32, stderr: &str) -> Self {
            let runner = Self::default();
            runner
                .outcomes
                .lock()
                .expect("outcomes lock")
                .insert(args_prefix.to_string(), (exit_code, stderr.to_string()));
            runner
        }
    }

    impl CommandRunner for FakeCommandRunner {
        fn run(&self, program: &str, args: &[String]) -> std::io::Result<Output> {
            self.invocations
                .lock()
                .expect("invocations lock")
                .push((program.to_string(), args.to_vec()));
            let joined = args.join(" ");
            let outcomes = self.outcomes.lock().expect("outcomes lock");
            for (prefix, (code, stderr)) in outcomes.iter() {
                if joined.starts_with(prefix.as_str()) {
                    return Ok(Output {
                        status: ExitStatus::from_raw(*code << 8),
                        stdout: Vec::new(),
                        stderr: stderr.as_bytes().to_vec(),
                    });
                }
            }
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        }
    }

    // --- tap_device_name ---

    #[test]
    fn tap_device_name_is_within_ifnamsiz_and_namespaced() {
        let name = tap_device_name("openinfra-11111111-1111-1111-1111-111111111111");
        assert!(
            name.len() < 16,
            "tap device name {name:?} must fit IFNAMSIZ (16 incl. NUL)"
        );
        assert!(name.starts_with("oivm"));
    }

    #[test]
    fn tap_device_name_is_deterministic_for_the_same_input() {
        let a = tap_device_name("openinfra-workload-a");
        let b = tap_device_name("openinfra-workload-a");
        assert_eq!(a, b);
    }

    #[test]
    fn tap_device_name_differs_across_workloads() {
        let a = tap_device_name("openinfra-workload-a");
        let b = tap_device_name("openinfra-workload-b");
        assert_ne!(a, b);
    }

    // --- SystemTapBackend::attach ---

    #[test]
    fn attach_runs_tuntap_add_then_link_set_up_in_order() {
        let runner = Arc::new(FakeCommandRunner::succeeding());
        let backend = SystemTapBackend::new(runner.clone());

        backend.attach("oivmabcd1234").expect("attach");

        let invocations = runner.invocations.lock().expect("invocations lock");
        assert_eq!(invocations.len(), 2);
        assert_eq!(invocations[0].0, "ip");
        assert_eq!(
            invocations[0].1,
            vec!["tuntap", "add", "dev", "oivmabcd1234", "mode", "tap"]
        );
        assert_eq!(invocations[1].0, "ip");
        assert_eq!(
            invocations[1].1,
            vec!["link", "set", "dev", "oivmabcd1234", "up"]
        );
    }

    #[test]
    fn attach_tolerates_a_tap_that_already_exists_from_a_prior_attempt() {
        let runner = Arc::new(FakeCommandRunner::failing_for(
            "tuntap add",
            2,
            "RTNETLINK answers: File exists",
        ));
        let backend = SystemTapBackend::new(runner.clone());

        backend
            .attach("oivmabcd1234")
            .expect("a pre-existing tap must not be a hard error");

        // link set up must still run even though add "failed" with the
        // tolerated error -- the device may exist but not yet be up.
        let invocations = runner.invocations.lock().expect("invocations lock");
        assert_eq!(invocations.len(), 2);
    }

    #[test]
    fn attach_fails_on_a_real_tuntap_add_error() {
        let runner = Arc::new(FakeCommandRunner::failing_for(
            "tuntap add",
            1,
            "RTNETLINK answers: Permission denied",
        ));
        let backend = SystemTapBackend::new(runner.clone());

        let result = backend.attach("oivmabcd1234");

        let error = result.expect_err("a real tuntap add failure must surface");
        assert!(error.to_string().contains("Permission denied"));
        // link set up must never run after a real (non-tolerated) add
        // failure.
        assert_eq!(runner.invocations.lock().expect("lock").len(), 1);
    }

    #[test]
    fn attach_fails_when_link_set_up_fails() {
        let runner = Arc::new(FakeCommandRunner::failing_for(
            "link set",
            1,
            "Cannot find device",
        ));
        let backend = SystemTapBackend::new(runner.clone());

        let result = backend.attach("oivmabcd1234");

        assert!(result.is_err());
    }

    // --- SystemTapBackend::detach ---

    #[test]
    fn detach_runs_tuntap_del() {
        let runner = Arc::new(FakeCommandRunner::succeeding());
        let backend = SystemTapBackend::new(runner.clone());

        backend.detach("oivmabcd1234").expect("detach");

        let invocations = runner.invocations.lock().expect("invocations lock");
        assert_eq!(invocations.len(), 1);
        assert_eq!(
            invocations[0].1,
            vec!["tuntap", "del", "dev", "oivmabcd1234", "mode", "tap"]
        );
    }

    #[test]
    fn detach_tolerates_a_device_that_is_already_gone() {
        for stderr in ["Cannot find device \"oivmabcd1234\"", "No such device"] {
            let runner = Arc::new(FakeCommandRunner::failing_for("tuntap del", 1, stderr));
            let backend = SystemTapBackend::new(runner);

            backend
                .detach("oivmabcd1234")
                .expect("an already-gone tap must not be a hard error");
        }
    }

    #[test]
    fn detach_fails_on_a_real_error() {
        let runner = Arc::new(FakeCommandRunner::failing_for(
            "tuntap del",
            1,
            "RTNETLINK answers: Permission denied",
        ));
        let backend = SystemTapBackend::new(runner);

        let result = backend.detach("oivmabcd1234");

        let error = result.expect_err("a real tuntap del failure must surface");
        assert!(error.to_string().contains("Permission denied"));
    }
}
