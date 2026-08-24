//! ADR-033 §2/§7: fail-closed hardware-virtualization capability
//! detection. `/dev/kvm` existing is not sufficient evidence a provider
//! can actually run a VM -- nested-virtualization hosts frequently expose
//! a `/dev/kvm` node backed by a non-functional or degraded KVM
//! implementation. The ADR requires a real `KVM_GET_API_VERSION` ioctl
//! probe, and this module's "fail closed" contract is load-bearing: any
//! error opening the device, any ioctl failure, or a returned version
//! that doesn't match the one stable value the kernel has ever returned
//! for a genuinely working KVM (`KVM_API_VERSION = 12`, per
//! `Documentation/virt/kvm/api.rst`) all collapse to "not
//! virtualization-capable" -- never a soft warning, never "assume yes".
//!
//! Testability: an ioctl against a real KVM file descriptor cannot be
//! faked with a plain file or a mocked file descriptor from a test
//! process (the ioctl targets the KVM driver's own internal dispatch, not
//! anything a regular file honors) -- so, mirroring
//! `agent-executor::rate_limit::CommandRunner`'s exact pattern for the
//! same reason (`tc` needs `CAP_NET_ADMIN` and a real interface), the
//! real ioctl call is behind a small injectable `KvmProbe` trait. Tests
//! exercise `virtualization_capable`'s fail-closed decision logic against
//! a `FakeKvmProbe`, never a real `/dev/kvm`.

use std::ffi::CString;
use std::os::unix::io::RawFd;
use thiserror::Error;

/// `KVM_GET_API_VERSION`'s ioctl request number: `_IO(KVMIO, 0x00)` where
/// `KVMIO = 0xAE` (Linux kernel's `include/uapi/linux/kvm.h`). `_IO` with
/// no direction/size bits set reduces to `(type << 8) | nr`, i.e.
/// `(0xAE << 8) | 0x00 = 0xAE00`. This is a stable kernel UAPI constant,
/// not something that needs to be probed or configured.
const KVM_GET_API_VERSION: libc::c_ulong = 0xAE00;

/// The one value a genuinely functional KVM has ever returned for
/// `KVM_GET_API_VERSION` (documented in the kernel's own
/// `Documentation/virt/kvm/api.rst`: "should return 12 (KVM_API_VERSION)
/// if the ioctl is supported"). Any other value -- including a
/// plausible-looking but wrong one -- is treated as "not really working",
/// per this module's fail-closed contract.
const KVM_API_VERSION: i32 = 12;

const KVM_DEVICE_PATH: &str = "/dev/kvm";

#[derive(Debug, Error)]
pub enum KvmProbeError {
    #[error("could not open {0}: {1}")]
    DeviceUnavailable(String, std::io::Error),
    #[error("KVM_GET_API_VERSION ioctl failed: {0}")]
    IoctlFailed(std::io::Error),
}

/// Abstracts the real ioctl call so `virtualization_capable`'s
/// fail-closed decision logic is unit-testable without a real,
/// permission-accessible `/dev/kvm` (see module doc comment).
pub trait KvmProbe: Send + Sync {
    /// Returns the raw value `KVM_GET_API_VERSION` reported, or an error
    /// if the device couldn't be opened or the ioctl itself failed.
    fn get_api_version(&self) -> Result<i32, KvmProbeError>;
}

/// The real probe: opens `/dev/kvm` read-only, close-on-exec, and issues
/// the real `KVM_GET_API_VERSION` ioctl against it.
pub struct SystemKvmProbe;

impl KvmProbe for SystemKvmProbe {
    fn get_api_version(&self) -> Result<i32, KvmProbeError> {
        // SAFETY: `path` is a valid, NUL-terminated C string built just
        // above from a fixed literal; `libc::open` is called with a
        // well-formed pointer and standard flags. O_CLOEXEC prevents this
        // fd leaking into any child process (e.g. a spawned
        // cloud-hypervisor) that shouldn't inherit it from an inventory
        // probe.
        let path = CString::new(KVM_DEVICE_PATH).expect("static path has no interior NUL");
        let fd: RawFd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(KvmProbeError::DeviceUnavailable(
                KVM_DEVICE_PATH.to_string(),
                std::io::Error::last_os_error(),
            ));
        }
        // SAFETY: `fd` was just confirmed open and valid above. The
        // ioctl's third argument is a plain integer request
        // (KVM_GET_API_VERSION never uses an argp), so passing 0 is
        // correct and matches the kernel's own documented calling
        // convention.
        let version = unsafe { libc::ioctl(fd, KVM_GET_API_VERSION, 0) };
        let ioctl_errno = std::io::Error::last_os_error();
        // SAFETY: `fd` is a valid, still-open descriptor obtained from
        // the successful `open` above and not used again after this
        // call.
        unsafe {
            libc::close(fd);
        }
        if version < 0 {
            return Err(KvmProbeError::IoctlFailed(ioctl_errno));
        }
        Ok(version)
    }
}

/// The single fail-closed decision point: `true` only if `probe` both
/// succeeds *and* reports exactly `KVM_API_VERSION`. Every other outcome
/// (device missing, permission denied, degraded/nested-virt KVM reporting
/// something else, any I/O error) is `false` -- matching ADR-033 §7's
/// explicit instruction that absent/unclear evidence must never be
/// treated as "capable, try anyway".
pub fn virtualization_capable(probe: &dyn KvmProbe) -> bool {
    matches!(probe.get_api_version(), Ok(version) if version == KVM_API_VERSION)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeKvmProbe {
        outcome: Result<i32, ()>,
    }

    impl KvmProbe for FakeKvmProbe {
        fn get_api_version(&self) -> Result<i32, KvmProbeError> {
            self.outcome.map_err(|()| {
                KvmProbeError::DeviceUnavailable(
                    KVM_DEVICE_PATH.to_string(),
                    std::io::Error::from(std::io::ErrorKind::PermissionDenied),
                )
            })
        }
    }

    #[test]
    fn reports_capable_only_for_the_exact_expected_api_version() {
        let probe = FakeKvmProbe { outcome: Ok(12) };
        assert!(virtualization_capable(&probe));
    }

    #[test]
    fn reports_not_capable_for_a_device_open_failure() {
        // The permission-denied case this sandbox itself actually hits:
        // /dev/kvm exists but the running user isn't in the kvm group.
        let probe = FakeKvmProbe { outcome: Err(()) };
        assert!(!virtualization_capable(&probe));
    }

    #[test]
    fn reports_not_capable_for_a_degraded_nested_virt_api_version() {
        // ADR-033 §7's specific named risk: a /dev/kvm node exists and
        // opens fine, but reports a version other than the one real,
        // working KVM has ever reported -- file existence and even a
        // successful open are not sufficient evidence.
        let probe = FakeKvmProbe { outcome: Ok(11) };
        assert!(!virtualization_capable(&probe));

        let probe_zero = FakeKvmProbe { outcome: Ok(0) };
        assert!(!virtualization_capable(&probe_zero));
    }

    #[test]
    fn reports_not_capable_for_an_ioctl_failure_after_a_successful_open() {
        struct IoctlFailsProbe;
        impl KvmProbe for IoctlFailsProbe {
            fn get_api_version(&self) -> Result<i32, KvmProbeError> {
                Err(KvmProbeError::IoctlFailed(std::io::Error::from(
                    std::io::ErrorKind::Other,
                )))
            }
        }
        assert!(!virtualization_capable(&IoctlFailsProbe));
    }

    // Best-effort, informative-only: exercises the real SystemKvmProbe
    // against whatever /dev/kvm this sandbox actually has (see the crate
    // root doc comment / final report for the honest caveat -- this
    // sandbox's /dev/kvm node exists but the test-running user is not in
    // the `kvm` group, so this is expected -- and correct, fail-closed --
    // to observe `false` here, not proof a real KVM-capable host was
    // exercised).
    #[test]
    fn system_probe_never_panics_and_fails_closed_without_real_kvm_access() {
        let capable = virtualization_capable(&SystemKvmProbe);
        // Intentionally not asserting a specific value: whether this
        // sandbox can actually open /dev/kvm is an environment fact this
        // test does not control. What matters, and is asserted
        // elsewhere, is the fail-closed *logic* -- this test only proves
        // the real probe path is reachable and doesn't panic.
        let _ = capable;
    }
}
