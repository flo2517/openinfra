//! ADR-025 §2: per-workload cumulative bandwidth counters, read from the
//! Linux interface byte counters of each workload's own network
//! namespace -- `/sys/class/net/<veth>/statistics/{rx,tx}_bytes`.
//!
//! `resolve_veth_name` is also used by ADR-025 §3's `tc` rate-limit
//! enforcement (`rate_limit.rs`), exactly as this module's original doc
//! comment anticipated ("the same lookup serves both") -- `rate_limit.rs`
//! calls it directly rather than re-deriving veth resolution.

use crate::ExecutorError;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// One workload's cumulative ingress/egress byte counters and the moment
/// its container (and therefore its counters) started. Cumulative since
/// container start, never a delta -- matching WorkloadBandwidthUsage's
/// proto doc comment: the Control Plane computes deltas across
/// successive heartbeats itself, so a dropped heartbeat cannot be used
/// to hide a window's usage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadBandwidth {
    pub ingress_bytes_total: u64,
    pub egress_bytes_total: u64,
    pub window_started_at: SystemTime,
}

/// Reads `container_pid`'s veth pair's cumulative byte counters from
/// under `sys_root` (`/` in production; overridable so tests can point
/// at a fake sysfs/procfs tree without root or a real container/Docker).
///
/// Directions are named from the *workload's* point of view to match the
/// proto: `ingress` is traffic arriving at the container's `eth0`,
/// `egress` is traffic leaving it. Read from the *host* side of the veth
/// pair (reachable without entering the container's own namespace a
/// second time), where the counters are the *opposite* of what their
/// names suggest relative to the container: a veth pair is a
/// point-to-point link, so whatever the container's `eth0` transmits is
/// what the host-side peer *receives*, and vice versa. The host side's
/// `rx_bytes` is therefore the container's egress, and the host side's
/// `tx_bytes` is the container's ingress -- not "identical counters",
/// each is the other end's mirror image.
pub fn read_bandwidth(
    sys_root: &Path,
    container_pid: i64,
    window_started_at: SystemTime,
) -> Result<WorkloadBandwidth, ExecutorError> {
    let veth = resolve_veth_name(sys_root, container_pid)?;
    read_bandwidth_for_interface(sys_root, &veth, window_started_at)
}

/// The same host-side-counter read `read_bandwidth` performs, against an
/// interface name the caller already knows directly rather than one that
/// needs PID-based veth resolution first. ADR-033 §5's tap-device path
/// (`vm::tap`) calls this directly: a VM's tap device name is chosen by
/// this Agent itself at creation time, not discovered after the fact the
/// way a container's veth peer is.
///
/// Direction convention is the identical mirror-image relationship this
/// module's other doc comments explain for veth: the *host* owns the tap
/// device directly (there is no separate peer-namespace end to traverse
/// the way a veth pair has one), and what the guest's virtio-net transmits
/// arrives at the host as the tap's `rx_bytes` -- so, exactly like a
/// veth's host side, `rx_bytes` is still the workload's egress and
/// `tx_bytes` is still its ingress.
pub(crate) fn read_bandwidth_for_interface(
    sys_root: &Path,
    iface: &str,
    window_started_at: SystemTime,
) -> Result<WorkloadBandwidth, ExecutorError> {
    let ingress_bytes_total = read_counter(sys_root, iface, "tx_bytes")?;
    let egress_bytes_total = read_counter(sys_root, iface, "rx_bytes")?;
    Ok(WorkloadBandwidth {
        ingress_bytes_total,
        egress_bytes_total,
        window_started_at,
    })
}

/// Names the host-side veth paired with `container_pid`'s `eth0`, by
/// matching `eth0`'s `iflink` (the ifindex of its veth peer) against the
/// host's own `/sys/class/net/*/ifindex`.
///
/// `eth0`'s `iflink` is read through the container's own network-
/// namespace view of sysfs via `/proc/<pid>/root/sys/class/net/eth0/
/// iflink` -- no `CAP_SYS_ADMIN` `setns` call needed, because a sysfs
/// mount is bound to whichever network namespace was active when it was
/// mounted (at container start, inside the container's own namespace),
/// and traversing to it via `/proc/<pid>/root` reads that same mount,
/// not the host's. This is the same technique `nsenter -t <pid> -n cat
/// /sys/class/net/eth0/iflink` and `ip link` use internally.
pub(crate) fn resolve_veth_name(
    sys_root: &Path,
    container_pid: i64,
) -> Result<String, ExecutorError> {
    let iflink_path = sys_root
        .join("proc")
        .join(container_pid.to_string())
        .join("root/sys/class/net/eth0/iflink");
    let iflink = read_u64(&iflink_path)?;

    let net_class_dir = sys_root.join("sys/class/net");
    let entries = fs::read_dir(&net_class_dir).map_err(|error| {
        ExecutorError::Engine(format!("read {}: {error}", net_class_dir.display()))
    })?;
    for entry in entries {
        let entry = entry.map_err(|error| ExecutorError::Engine(error.to_string()))?;
        let ifindex_path = entry.path().join("ifindex");
        let Ok(ifindex) = read_u64(&ifindex_path) else {
            // Not every /sys/class/net entry is guaranteed readable at the
            // instant this scans (interfaces can appear/disappear), and a
            // decoy/irrelevant interface is expected, not an error --
            // only "no interface matched at all" (below the loop) is.
            continue;
        };
        if ifindex == iflink {
            return entry.file_name().into_string().map_err(|_| {
                ExecutorError::Engine("veth interface name is not valid UTF-8".to_string())
            });
        }
    }
    Err(ExecutorError::Engine(format!(
        "no host interface matches iflink {iflink} for container pid {container_pid}"
    )))
}

fn read_counter(sys_root: &Path, iface: &str, stat: &str) -> Result<u64, ExecutorError> {
    let path: PathBuf = sys_root
        .join("sys/class/net")
        .join(iface)
        .join("statistics")
        .join(stat);
    read_u64(&path)
}

fn read_u64(path: &Path) -> Result<u64, ExecutorError> {
    fs::read_to_string(path)
        .map_err(|error| ExecutorError::Engine(format!("read {}: {error}", path.display())))?
        .trim()
        .parse::<u64>()
        .map_err(|error| ExecutorError::Engine(format!("parse {}: {error}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    fn write(path: &Path, contents: &str) {
        fs::create_dir_all(path.parent().expect("parent")).expect("create dir");
        fs::write(path, contents).expect("write fixture file");
    }

    #[test]
    fn resolves_veth_and_reads_counters_by_matching_iflink() {
        let directory = tempfile::tempdir().expect("temp dir");
        let root = directory.path();
        write(
            &root.join("proc/4242/root/sys/class/net/eth0/iflink"),
            "17\n",
        );
        write(&root.join("sys/class/net/veth-abc123/ifindex"), "17\n");
        // Host-side rx_bytes is the container's *egress* and host-side
        // tx_bytes is the container's *ingress* -- a veth pair mirrors,
        // it does not duplicate (see read_bandwidth's doc comment). These
        // two values are deliberately different so a direction swap in
        // the implementation fails this assertion instead of passing by
        // coincidence.
        write(
            &root.join("sys/class/net/veth-abc123/statistics/rx_bytes"),
            "1024\n",
        );
        write(
            &root.join("sys/class/net/veth-abc123/statistics/tx_bytes"),
            "2048\n",
        );
        // A decoy host interface with a different ifindex must not match.
        write(&root.join("sys/class/net/eth0/ifindex"), "1\n");

        let reading = read_bandwidth(root, 4242, UNIX_EPOCH).expect("read bandwidth");
        assert_eq!(
            reading.ingress_bytes_total, 2048,
            "container ingress must come from the host side's tx_bytes"
        );
        assert_eq!(
            reading.egress_bytes_total, 1024,
            "container egress must come from the host side's rx_bytes"
        );
        assert_eq!(reading.window_started_at, UNIX_EPOCH);
    }

    #[test]
    fn missing_iflink_file_is_a_clear_error_not_a_panic() {
        let directory = tempfile::tempdir().expect("temp dir");
        assert!(read_bandwidth(directory.path(), 9999, UNIX_EPOCH).is_err());
    }

    #[test]
    fn no_matching_host_interface_is_a_clear_error() {
        let directory = tempfile::tempdir().expect("temp dir");
        let root = directory.path();
        write(
            &root.join("proc/4242/root/sys/class/net/eth0/iflink"),
            "17\n",
        );
        // No /sys/class/net/*/ifindex entries at all exist under root, so
        // the scan must fail closed rather than default to some interface.
        assert!(read_bandwidth(root, 4242, UNIX_EPOCH).is_err());
    }

    #[test]
    fn unreadable_ifindex_entries_are_skipped_not_fatal() {
        let directory = tempfile::tempdir().expect("temp dir");
        let root = directory.path();
        write(
            &root.join("proc/4242/root/sys/class/net/eth0/iflink"),
            "17\n",
        );
        // veth-broken has no ifindex file at all (simulating a transient
        // read failure/race) -- it must be skipped, not abort the whole
        // scan before the real match is reached.
        fs::create_dir_all(root.join("sys/class/net/veth-broken")).expect("create dir");
        write(&root.join("sys/class/net/veth-good/ifindex"), "17\n");
        write(
            &root.join("sys/class/net/veth-good/statistics/rx_bytes"),
            "5\n",
        );
        write(
            &root.join("sys/class/net/veth-good/statistics/tx_bytes"),
            "6\n",
        );

        let reading = read_bandwidth(root, 4242, UNIX_EPOCH).expect("read bandwidth");
        assert_eq!(
            reading.ingress_bytes_total, 6,
            "container ingress must come from the host side's tx_bytes"
        );
        assert_eq!(
            reading.egress_bytes_total, 5,
            "container egress must come from the host side's rx_bytes"
        );
    }

    // --- read_bandwidth_for_interface (ADR-033 §5): the same counter read,
    // against an interface name the caller already knows -- no PID/iflink
    // resolution fixture needed, unlike read_bandwidth's tests above.

    #[test]
    fn read_bandwidth_for_interface_reads_counters_directly_by_name() {
        let directory = tempfile::tempdir().expect("temp dir");
        let root = directory.path();
        // Deliberately no proc/<pid>/... fixture at all -- if this
        // function tried PID-based resolution the way read_bandwidth
        // does, this would fail before ever reaching the counters.
        write(
            &root.join("sys/class/net/oivmabcd1234/statistics/rx_bytes"),
            "111\n",
        );
        write(
            &root.join("sys/class/net/oivmabcd1234/statistics/tx_bytes"),
            "222\n",
        );

        let reading = read_bandwidth_for_interface(root, "oivmabcd1234", UNIX_EPOCH).expect("read");
        assert_eq!(
            reading.ingress_bytes_total, 222,
            "workload ingress must come from the tap's tx_bytes, mirroring veth's host side"
        );
        assert_eq!(
            reading.egress_bytes_total, 111,
            "workload egress must come from the tap's rx_bytes, mirroring veth's host side"
        );
        assert_eq!(reading.window_started_at, UNIX_EPOCH);
    }

    #[test]
    fn read_bandwidth_for_interface_is_a_clear_error_when_the_interface_is_missing() {
        let directory = tempfile::tempdir().expect("temp dir");
        assert!(
            read_bandwidth_for_interface(directory.path(), "oivmmissing1", UNIX_EPOCH).is_err()
        );
    }
}
