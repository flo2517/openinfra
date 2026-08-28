//! ADR-035 §3, the security-critical half of that ADR: host-side nftables
//! enforcement of a workload's Neutron security-group rules, applied
//! against the *host* side of the workload's veth pair -- the exact same
//! interface `rate_limit.rs` already attaches a `tc` qdisc to (resolved
//! the same way, via `bandwidth::resolve_veth_name`), using the same
//! `CAP_NET_ADMIN` privilege ADR-025 §3 already granted this process.
//! "No *new* standing privilege is requested... the scope of what that
//! capability is used for grows" (ADR-035 Consequences).
//!
//! **Fail-safe default, stated as the load-bearing rule first** (ADR-035
//! §3): every call to [`SecurityGroupEnforcer::apply`]/`apply_to_interface`
//! installs a default-drop base chain *before* adding any accept rule, for
//! *both* directions, unconditionally -- there is no code path in this
//! module that ever installs an accept-everything chain, and an empty
//! `rules` slice is not a special case this module branches on: it simply
//! means the loop that adds accept rules runs zero times, leaving the
//! default-drop policy as the only thing enforced. This is the same
//! "absence of an allow rule is the only way traffic is ever denied"
//! property `internal/openstackapi/neutron`'s Go-side schema establishes
//! on the Control-Plane side (see that package's securitygroup.go doc
//! comment) -- there is no allow-by-default sentinel value anywhere on
//! either side of this wire.
//!
//! **Enforcement point and mechanism** (ADR-035 §3): a dedicated `netdev`
//! family nftables table (`openinfra_sg`), with two chains per managed
//! interface -- `sg_in_<iface>` hooked on `ingress` (packets *arriving at
//! the host* from the container, i.e. the workload's own **egress**
//! traffic -- the same host/container mirror-image relationship
//! `bandwidth.rs`'s own doc comment already establishes for byte
//! counters, applied here to which nftables hook enforces which
//! `SecurityGroupDirection`) and `sg_out_<iface>` hooked on `egress`
//! (packets the host is about to *send to* the container, the workload's
//! own **ingress** traffic). A `SecurityGroupRule` with
//! `direction == Egress` is therefore enforced on the `ingress` hook, and
//! `direction == Ingress` on the `egress` hook -- deliberately the
//! reverse of what the names alone suggest, exactly mirroring
//! `bandwidth.rs`/`rate_limit.rs`'s own established "host side is the
//! opposite of the container side" convention, not a new one invented
//! here.
//!
//! On each hook, `remote_ip_prefix` matches whichever side of the packet
//! is the "remote peer" for that rule's direction: `ip daddr` for an
//! `Egress` rule (the workload is the source; the remote is the
//! destination it's allowed to reach), `ip saddr` for an `Ingress` rule
//! (the remote is the source; the workload is the destination). The
//! packet's own destination port (`tcp`/`udp dport`) is always the
//! correct port to match in both cases -- for an `Ingress` rule that is
//! the workload's own listening port; for an `Egress` rule it is the
//! remote service's port -- with no direction-dependent swap needed for
//! ports the way there is for addresses.
//!
//! **Teardown is implicit, matching `rate_limit.rs`'s established
//! precedent exactly**: this module exposes no `revoke`/`detach`
//! function, and `DockerExecutor::stop` calls none. ADR-035 §3 point 3
//! states plainly that "destroying a veth pair destroys every qdisc *and*
//! every nftables rule scoped to it," the same "no window to leak"
//! reasoning `rate_limit.rs`'s own doc comment already relies on for
//! `tc`. **This module cannot independently verify that claim in this
//! sandbox** (no real `CAP_NET_ADMIN`, no real kernel, no real veth --
//! see this crate's established honesty discipline for exactly this class
//! of code, e.g. the VM tap-networking work from issue #176/PR #182): if
//! the kernel does *not* fully garbage-collect a `netdev`-family hook
//! chain once its bound device is destroyed (as opposed to merely
//! deactivating the hook), reapplying this module's fixed table/chain-
//! naming scheme against a *recycled* interface name would still behave
//! correctly (the idempotent flush-then-readd sequence below handles
//! that), but a long-running Agent could accumulate inert, orphaned
//! chains for interface names that are never reused. Any such leak is
//! fail-safe, not fail-open (an orphaned chain can only ever *drop*
//! traffic for an interface name that no longer exists, never grant
//! access to anything) -- flagged explicitly here, and in this
//! implementing PR's own description, as a real, named gap for the
//! dedicated security review this ADR calls for, not silently assumed
//! away.
//!
//! **Testability follows `rate_limit.rs`'s exact seam**: this module
//! reuses `crate::rate_limit::CommandRunner` (an injectable "run this
//! privileged command" trait, already implemented by
//! `SystemCommandRunner` and faked by `FakeCommandRunner` in tests) --
//! not a second, parallel command-execution abstraction. Every test in
//! this module exercises the exact sequence of `nft` invocations
//! (program, args) this module issues against a fake, asserting the
//! fail-closed default, idempotent reapplication (flush before re-add,
//! never duplicate accept rules), and the direction/hook/address-field
//! mapping above -- never a real interface or real `CAP_NET_ADMIN`.

use crate::bandwidth::resolve_veth_name;
use crate::ExecutorError;
use agent_core::local_state::{SecurityGroupDirection, SecurityGroupProtocol, SecurityGroupRule};
use std::path::Path;
use std::sync::Arc;

use crate::rate_limit::CommandRunner;

/// The single, fixed `netdev`-family table every managed interface's
/// chains live under -- one table for the whole Agent process, not one
/// per interface, matching how `WORKLOAD_NETWORK_NAME` in `lib.rs` is
/// also one fixed, shared Docker network rather than one per workload.
const TABLE_NAME: &str = "openinfra_sg";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Hook {
    Ingress,
    Egress,
}

impl Hook {
    fn nft_name(self) -> &'static str {
        match self {
            Hook::Ingress => "ingress",
            Hook::Egress => "egress",
        }
    }

    /// See this module's own doc comment for why this mapping is the
    /// reverse of what the names alone suggest.
    fn enforces(self, direction: SecurityGroupDirection) -> bool {
        match self {
            Hook::Ingress => direction == SecurityGroupDirection::Egress,
            Hook::Egress => direction == SecurityGroupDirection::Ingress,
        }
    }

    /// The address field a rule enforced on this hook matches
    /// `remote_ip_prefix` against -- see this module's own doc comment.
    fn remote_address_field(self) -> &'static str {
        match self {
            Hook::Ingress => "daddr",
            Hook::Egress => "saddr",
        }
    }
}

fn chain_name(hook: Hook, iface: &str) -> String {
    match hook {
        Hook::Ingress => format!("sg_in_{iface}"),
        Hook::Egress => format!("sg_out_{iface}"),
    }
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

fn add_table_args() -> Vec<String> {
    strings(&["add", "table", "netdev", TABLE_NAME])
}

/// Builds `nft add chain netdev openinfra_sg <chain> { type filter hook
/// <ingress|egress> device <iface> priority 0 ; policy drop ; }`, tokenized
/// one nft-grammar token per argv element (no shell is involved in
/// `CommandRunner::run` -- each element here is exactly one token nft's
/// own parser expects, the same way a shell would have split an
/// equivalent typed command line before exec'ing it).
fn add_chain_args(hook: Hook, iface: &str) -> Vec<String> {
    let mut args = strings(&["add", "chain", "netdev", TABLE_NAME]);
    args.push(chain_name(hook, iface));
    args.extend(strings(&[
        "{",
        "type",
        "filter",
        "hook",
        hook.nft_name(),
        "device",
    ]));
    args.push(iface.to_string());
    args.extend(strings(&["priority", "0", ";", "policy", "drop", ";", "}"]));
    args
}

fn flush_chain_args(hook: Hook, iface: &str) -> Vec<String> {
    let mut args = strings(&["flush", "chain", "netdev", TABLE_NAME]);
    args.push(chain_name(hook, iface));
    args
}

/// Builds one `nft add rule netdev openinfra_sg <chain> [<protocol match>]
/// ip <daddr|saddr> <remote_ip_prefix> accept` invocation for `rule` on
/// `hook`. Only called for a `rule` this `hook` actually
/// [`Hook::enforces`] -- callers filter first, this function does not
/// re-check direction.
fn add_rule_args(hook: Hook, iface: &str, rule: &SecurityGroupRule) -> Vec<String> {
    let mut args = strings(&["add", "rule", "netdev", TABLE_NAME]);
    args.push(chain_name(hook, iface));
    match rule.protocol {
        SecurityGroupProtocol::Tcp | SecurityGroupProtocol::Udp => {
            let proto = match rule.protocol {
                SecurityGroupProtocol::Tcp => "tcp",
                SecurityGroupProtocol::Udp => "udp",
                _ => unreachable!(),
            };
            let (min, max) = (
                rule.port_range_min.unwrap_or(0),
                rule.port_range_max.unwrap_or(0),
            );
            args.extend(strings(&[proto, "dport"]));
            args.push(format!("{min}-{max}"));
        }
        SecurityGroupProtocol::Icmp => {
            args.extend(strings(&["ip", "protocol", "icmp"]));
        }
        SecurityGroupProtocol::Any => {}
    }
    args.push("ip".to_string());
    args.push(hook.remote_address_field().to_string());
    args.push(rule.remote_ip_prefix.clone());
    args.push("accept".to_string());
    args
}

/// Applies (or reports a failure applying) ADR-035 §3's fail-closed
/// security-group enforcement to a workload's veth pair.
pub struct SecurityGroupEnforcer {
    runner: Arc<dyn CommandRunner>,
}

impl SecurityGroupEnforcer {
    pub fn new(runner: Arc<dyn CommandRunner>) -> Self {
        Self { runner }
    }

    /// Resolves `container_pid`'s host-side veth (via
    /// `bandwidth::resolve_veth_name`, the exact lookup `rate_limit.rs`
    /// already shares) and applies `rules` to it.
    pub fn apply(
        &self,
        sys_root: &Path,
        container_pid: i64,
        rules: &[SecurityGroupRule],
    ) -> Result<(), ExecutorError> {
        let veth = resolve_veth_name(sys_root, container_pid)?;
        self.apply_to_interface(&veth, rules)
    }

    /// The same enforcement `apply` performs, against an interface name
    /// the caller already knows directly -- mirrors
    /// `RateLimiter::apply_to_interface`'s identical split for the same
    /// reason (a caller with a directly-known interface name, e.g. a
    /// retry/`recover()` path, skips PID-based veth resolution).
    ///
    /// Idempotent: `add table`/`add chain` are themselves idempotent
    /// no-ops against an already-existing table/identically-specified
    /// chain, and this method `flush`es each chain before re-adding
    /// accept rules, so calling this twice for the same `iface` and
    /// `rules` never duplicates or conflicts with a prior application --
    /// the exact property `rate_limit.rs`'s `qdisc replace` gives `tc`
    /// enforcement, reproduced here with nftables' own idempotent
    /// primitives instead.
    pub fn apply_to_interface(
        &self,
        iface: &str,
        rules: &[SecurityGroupRule],
    ) -> Result<(), ExecutorError> {
        self.run(add_table_args())?;
        for hook in [Hook::Ingress, Hook::Egress] {
            self.run(add_chain_args(hook, iface))?;
            self.run(flush_chain_args(hook, iface))?;
            for rule in rules.iter().filter(|rule| hook.enforces(rule.direction)) {
                self.run(add_rule_args(hook, iface, rule))?;
            }
        }
        Ok(())
    }

    fn run(&self, args: Vec<String>) -> Result<(), ExecutorError> {
        let output = self
            .runner
            .run("nft", &args)
            .map_err(|error| ExecutorError::Engine(format!("run nft: {error}")))?;
        if !output.status.success() {
            return Err(ExecutorError::Engine(format!(
                "nft {} failed (status {}): {}",
                args.join(" "),
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )));
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
    }

    impl CommandRunner for FakeCommandRunner {
        fn run(&self, program: &str, args: &[String]) -> std::io::Result<Output> {
            self.invocations
                .lock()
                .expect("invocations lock")
                .push((program.to_string(), args.to_vec()));
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        }
    }

    fn tcp_rule(
        direction: SecurityGroupDirection,
        min: u16,
        max: u16,
        cidr: &str,
    ) -> SecurityGroupRule {
        SecurityGroupRule {
            direction,
            protocol: SecurityGroupProtocol::Tcp,
            port_range_min: Some(min),
            port_range_max: Some(max),
            remote_ip_prefix: cidr.to_string(),
        }
    }

    #[test]
    fn empty_rules_installs_default_drop_chains_and_adds_no_accept_rule() {
        // ADR-035 §3's fail-closed default, verified structurally: with
        // zero rules, both chains are created (drop policy) and flushed,
        // and no "add rule" invocation is ever issued.
        let runner = Arc::new(FakeCommandRunner::default());
        let enforcer = SecurityGroupEnforcer::new(runner.clone());

        enforcer
            .apply_to_interface("veth-abc123", &[])
            .expect("apply empty rule set");

        let invocations = runner.invocations.lock().expect("lock");
        assert_eq!(invocations.len(), 5, "table + 2x(chain + flush), no rules");
        assert_eq!(invocations[0].1, add_table_args());
        assert_eq!(
            invocations[1].1,
            add_chain_args(Hook::Ingress, "veth-abc123")
        );
        assert_eq!(
            invocations[2].1,
            flush_chain_args(Hook::Ingress, "veth-abc123")
        );
        assert_eq!(
            invocations[3].1,
            add_chain_args(Hook::Egress, "veth-abc123")
        );
        assert_eq!(
            invocations[4].1,
            flush_chain_args(Hook::Egress, "veth-abc123")
        );
        for (program, _) in invocations.iter() {
            assert_eq!(program, "nft");
        }
        assert!(
            invocations[1].1.contains(&"drop".to_string()),
            "ingress chain must be created with a drop policy"
        );
        assert!(
            invocations[3].1.contains(&"drop".to_string()),
            "egress chain must be created with a drop policy"
        );
    }

    #[test]
    fn egress_rule_is_enforced_on_the_ingress_hook_matching_daddr() {
        // A workload EGRESS rule (traffic leaving the workload) is
        // enforced on the host's INGRESS hook (packets arriving at the
        // host from the container) -- the mirror-image mapping this
        // module's doc comment establishes. remote_ip_prefix is the
        // destination the rule permits reaching, so it matches `ip
        // daddr`.
        let runner = Arc::new(FakeCommandRunner::default());
        let enforcer = SecurityGroupEnforcer::new(runner.clone());
        let rule = tcp_rule(SecurityGroupDirection::Egress, 443, 443, "203.0.113.0/24");

        enforcer
            .apply_to_interface("veth-x", std::slice::from_ref(&rule))
            .expect("apply");

        let invocations = runner.invocations.lock().expect("lock");
        // table, ingress-chain, ingress-flush, ingress-rule, egress-chain, egress-flush (no egress rule)
        assert_eq!(invocations.len(), 6);
        let rule_invocation = &invocations[3].1;
        assert_eq!(
            rule_invocation,
            &add_rule_args(Hook::Ingress, "veth-x", &rule)
        );
        assert!(rule_invocation.contains(&"daddr".to_string()));
        assert!(rule_invocation.contains(&"203.0.113.0/24".to_string()));
        assert!(rule_invocation.contains(&"443-443".to_string()));
        assert!(rule_invocation.contains(&"accept".to_string()));
    }

    #[test]
    fn ingress_rule_is_enforced_on_the_egress_hook_matching_saddr() {
        let runner = Arc::new(FakeCommandRunner::default());
        let enforcer = SecurityGroupEnforcer::new(runner.clone());
        let rule = tcp_rule(SecurityGroupDirection::Ingress, 22, 22, "198.51.100.0/24");

        enforcer
            .apply_to_interface("veth-y", std::slice::from_ref(&rule))
            .expect("apply");

        let invocations = runner.invocations.lock().expect("lock");
        assert_eq!(invocations.len(), 6);
        let rule_invocation = &invocations[5].1;
        assert_eq!(
            rule_invocation,
            &add_rule_args(Hook::Egress, "veth-y", &rule)
        );
        assert!(rule_invocation.contains(&"saddr".to_string()));
        assert!(rule_invocation.contains(&"198.51.100.0/24".to_string()));
    }

    #[test]
    fn icmp_rule_matches_protocol_with_no_port() {
        let runner = Arc::new(FakeCommandRunner::default());
        let enforcer = SecurityGroupEnforcer::new(runner.clone());
        let rule = SecurityGroupRule {
            direction: SecurityGroupDirection::Ingress,
            protocol: SecurityGroupProtocol::Icmp,
            port_range_min: None,
            port_range_max: None,
            remote_ip_prefix: "0.0.0.0/0".to_string(),
        };

        enforcer
            .apply_to_interface("veth-icmp", std::slice::from_ref(&rule))
            .expect("apply");

        let invocations = runner.invocations.lock().expect("lock");
        let rule_invocation = &invocations[5].1;
        assert!(rule_invocation.contains(&"icmp".to_string()));
        assert!(!rule_invocation.iter().any(|token| token.contains("dport")));
    }

    #[test]
    fn any_protocol_rule_has_no_protocol_or_port_match() {
        let runner = Arc::new(FakeCommandRunner::default());
        let enforcer = SecurityGroupEnforcer::new(runner.clone());
        let rule = SecurityGroupRule {
            direction: SecurityGroupDirection::Egress,
            protocol: SecurityGroupProtocol::Any,
            port_range_min: None,
            port_range_max: None,
            remote_ip_prefix: "10.0.0.0/8".to_string(),
        };

        enforcer
            .apply_to_interface("veth-any", std::slice::from_ref(&rule))
            .expect("apply");

        let invocations = runner.invocations.lock().expect("lock");
        let rule_invocation = &invocations[3].1;
        assert_eq!(
            rule_invocation,
            &strings(&[
                "add",
                "rule",
                "netdev",
                "openinfra_sg",
                "sg_in_veth-any",
                "ip",
                "daddr",
                "10.0.0.0/8",
                "accept",
            ])
        );
    }

    #[test]
    fn multiple_security_groups_on_one_port_are_unioned_not_intersected() {
        // ADR-035 §3 point 2: every matching rule from every attached
        // group gets its own accept rule -- there is no intersection
        // logic anywhere in this module, verified here by two
        // independent egress rules both surfacing as two independent
        // "add rule" invocations.
        let runner = Arc::new(FakeCommandRunner::default());
        let enforcer = SecurityGroupEnforcer::new(runner.clone());
        let rules = vec![
            tcp_rule(SecurityGroupDirection::Egress, 80, 80, "10.0.0.0/8"),
            tcp_rule(SecurityGroupDirection::Egress, 443, 443, "10.0.0.0/8"),
        ];

        enforcer
            .apply_to_interface("veth-union", &rules)
            .expect("apply");

        let invocations = runner.invocations.lock().expect("lock");
        let rule_invocations: Vec<_> = invocations
            .iter()
            .filter(|(_, args)| {
                args.first().map(String::as_str) == Some("add")
                    && args.get(1).map(String::as_str) == Some("rule")
            })
            .collect();
        assert_eq!(
            rule_invocations.len(),
            2,
            "both rules must be applied, not intersected"
        );
    }

    #[test]
    fn reapplying_the_same_rules_flushes_before_readding_never_duplicating() {
        // Idempotency: applying twice must not accumulate a second copy
        // of the same accept rule -- the flush before each hook's rule
        // loop is what guarantees this; verified here by counting "add
        // rule" invocations across two calls.
        let runner = Arc::new(FakeCommandRunner::default());
        let enforcer = SecurityGroupEnforcer::new(runner.clone());
        let rule = tcp_rule(SecurityGroupDirection::Egress, 443, 443, "203.0.113.0/24");

        enforcer
            .apply_to_interface("veth-retry", std::slice::from_ref(&rule))
            .expect("first apply");
        enforcer
            .apply_to_interface("veth-retry", std::slice::from_ref(&rule))
            .expect("second apply (retry/recover path)");

        let invocations = runner.invocations.lock().expect("lock");
        let flush_count = invocations
            .iter()
            .filter(|(_, args)| args.first().map(String::as_str) == Some("flush"))
            .count();
        let rule_count = invocations
            .iter()
            .filter(|(_, args)| {
                args.first().map(String::as_str) == Some("add")
                    && args.get(1).map(String::as_str) == Some("rule")
            })
            .count();
        assert_eq!(
            flush_count, 4,
            "each of the 2 hooks is flushed on each of the 2 applies"
        );
        assert_eq!(
            rule_count, 2,
            "the rule is (re)added once per apply -- a flush between the two prevents duplication server-side"
        );
    }

    #[test]
    fn nft_failure_surfaces_as_an_error() {
        struct FailingRunner;
        impl CommandRunner for FailingRunner {
            fn run(&self, _program: &str, _args: &[String]) -> std::io::Result<Output> {
                Ok(Output {
                    status: ExitStatus::from_raw(1 << 8),
                    stdout: Vec::new(),
                    stderr: b"Operation not permitted".to_vec(),
                })
            }
        }
        let enforcer = SecurityGroupEnforcer::new(Arc::new(FailingRunner));

        let result = enforcer.apply_to_interface("veth-fail", &[]);

        let error = result.expect_err("a nonzero nft exit must surface as an error");
        assert!(error.to_string().contains("Operation not permitted"));
    }

    #[test]
    fn apply_resolves_veth_via_pid_the_same_way_rate_limit_does() {
        let directory = tempfile::tempdir().expect("temp dir");
        let root = directory.path();
        std::fs::create_dir_all(root.join("proc/4242/root/sys/class/net/eth0")).expect("mkdir");
        std::fs::write(
            root.join("proc/4242/root/sys/class/net/eth0/iflink"),
            "17\n",
        )
        .expect("write iflink");
        std::fs::create_dir_all(root.join("sys/class/net/veth-resolved")).expect("mkdir");
        std::fs::write(root.join("sys/class/net/veth-resolved/ifindex"), "17\n")
            .expect("write ifindex");
        let runner = Arc::new(FakeCommandRunner::default());
        let enforcer = SecurityGroupEnforcer::new(runner.clone());

        enforcer.apply(root, 4242, &[]).expect("apply via pid");

        let invocations = runner.invocations.lock().expect("lock");
        assert!(invocations[1]
            .1
            .contains(&"sg_in_veth-resolved".to_string()));
    }

    #[test]
    fn apply_fails_when_veth_cannot_be_resolved_and_never_shells_out() {
        let directory = tempfile::tempdir().expect("temp dir");
        let runner = Arc::new(FakeCommandRunner::default());
        let enforcer = SecurityGroupEnforcer::new(runner.clone());

        let result = enforcer.apply(directory.path(), 9999, &[]);

        assert!(result.is_err());
        assert!(
            runner.invocations.lock().expect("lock").is_empty(),
            "nft must not be invoked when veth resolution fails"
        );
    }
}
