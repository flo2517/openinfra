use anyhow::Result;
use std::path::Path;
use sysinfo::{Disks, System};

pub struct InventoryManager;

impl Default for InventoryManager {
    fn default() -> Self {
        Self::new()
    }
}

impl InventoryManager {
    pub fn new() -> Self {
        Self
    }

    /// storage_path identifies which filesystem's capacity to report as
    /// this provider's storage total/available -- the disk that path
    /// resolves onto (the mount point with the longest matching prefix,
    /// the same resolution `df <path>` uses), not a sum across every
    /// disk sysinfo can see (which would double-count tmpfs/boot/other
    /// unrelated mounts and wildly overstate real capacity).
    ///
    /// Known limitation: this assumes Docker's storage driver writes onto
    /// whichever filesystem storage_path lives on. A provider with a
    /// separate data volume for /var/lib/docker that differs from
    /// storage_path will get an inaccurate figure -- tracked as a known
    /// gap (issue #30 discussion), not solved here.
    pub fn get_inventory(&self, storage_path: &Path) -> Result<SystemResources> {
        let mut sys = System::new_all();
        sys.refresh_all();

        let cpu_cores = sys.cpus().len() as f32;
        let total_memory = sys.total_memory() / 1024 / 1024; // MB
        let available_memory = sys.available_memory() / 1024 / 1024; // MB

        let disks = Disks::new_with_refreshed_list();
        let (total_storage_gb, available_storage_gb) = disk_for_path(&disks, storage_path)
            .map(|disk| {
                (
                    (disk.total_space() / 1_000_000_000) as i64,
                    (disk.available_space() / 1_000_000_000) as i64,
                )
            })
            .unwrap_or((0, 0));

        Ok(SystemResources {
            cpu_cores,
            total_memory_mb: total_memory as i64,
            available_memory_mb: available_memory as i64,
            total_storage_gb,
            available_storage_gb,
        })
    }
}

/// Finds the disk whose mount point is the longest prefix of path --
/// sysinfo lists disks in no particular order and nested mounts are
/// common (e.g. "/" and "/var/lib/docker" both present), so the longest
/// match is the most specific, correct answer.
fn disk_for_path<'a>(disks: &'a Disks, path: &Path) -> Option<&'a sysinfo::Disk> {
    disks
        .list()
        .iter()
        .filter(|disk| path.starts_with(disk.mount_point()))
        .max_by_key(|disk| disk.mount_point().as_os_str().len())
}

pub struct SystemResources {
    pub cpu_cores: f32,
    pub total_memory_mb: i64,
    pub available_memory_mb: i64,
    pub total_storage_gb: i64,
    pub available_storage_gb: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn inventory_reports_consistent_memory() {
        let resources = InventoryManager::new()
            .get_inventory(Path::new("/"))
            .expect("inventory");

        assert!(resources.cpu_cores >= 0.0);
        assert!(resources.available_memory_mb <= resources.total_memory_mb);
    }

    #[test]
    fn inventory_reports_nonnegative_storage_for_the_root_filesystem() {
        let resources = InventoryManager::new()
            .get_inventory(Path::new("/"))
            .expect("inventory");

        // Every CI/dev sandbox has a root filesystem sysinfo can see; a
        // total of 0 here would mean disk_for_path silently failed to
        // match anything, which previously happened for the whole
        // capability (it was never reported at all -- see #30).
        assert!(
            resources.total_storage_gb > 0,
            "expected a nonzero root filesystem size"
        );
        assert!(resources.available_storage_gb <= resources.total_storage_gb);
    }

    #[test]
    fn inventory_reports_zero_storage_for_an_unmatched_path() {
        // A relative path can never start_with any real (absolute) mount
        // point's root component, so disk_for_path is guaranteed not to
        // match -- unlike an absolute path, which "/" itself would always
        // match on every real system.
        let resources = InventoryManager::new()
            .get_inventory(Path::new("relative/path/matches/no/mount"))
            .expect("inventory");

        assert_eq!(resources.total_storage_gb, 0);
        assert_eq!(resources.available_storage_gb, 0);
    }
}
