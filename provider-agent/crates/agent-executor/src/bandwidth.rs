//! ADR-025 §2: per-workload cumulative bandwidth counters, read from the
//! Linux interface byte counters of each workload's own network
//! namespace -- `/sys/class/net/<veth>/statistics/{rx,tx}_bytes`.
//!
//! `resolve_veth_name` is also the intended home for ADR-025 §3's `tc`
//! rate-limit enforcement (not implemented here -- sequenced after this
//! slice by the ADR itself, which needs `CAP_NET_ADMIN` and its own
//! explicit sign-off): the ADR calls this "the same lookup serves both",
//! so §3 can call this function directly instead of re-deriving it.

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
/// proto: `ingress` is `rx_bytes` (traffic arriving at the container's
/// `eth0`), `egress` is `tx_bytes` (traffic leaving it) -- read from the
/// *host* side of the veth pair, where the byte counts are identical to
/// the container-side counters (a veth pair mirrors traffic, it does not
/// duplicate or drop it) but reachable without entering the container's
/// own namespace a second time.
pub fn read_bandwidth(
    sys_root: &Path,
    container_pid: i64,
    window_started_at: SystemTime,
) -> Result<WorkloadBandwidth, ExecutorError> {
    let veth = resolve_veth_name(sys_root, container_pid)?;
    let ingress_bytes_total = read_counter(sys_root, &veth, "rx_bytes")?;
    let egress_bytes_total = read_counter(sys_root, &veth, "tx_bytes")?;
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
fn resolve_veth_name(sys_root: &Path, container_pid: i64) -> Result<String, ExecutorError> {
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
        assert_eq!(reading.ingress_bytes_total, 1024);
        assert_eq!(reading.egress_bytes_total, 2048);
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
        assert_eq!(reading.ingress_bytes_total, 5);
        assert_eq!(reading.egress_bytes_total, 6);
    }
}
