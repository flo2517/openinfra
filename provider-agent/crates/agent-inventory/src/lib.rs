use anyhow::Result;
use sysinfo::System;

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

    pub fn get_inventory(&self) -> Result<SystemResources> {
        let mut sys = System::new_all();
        sys.refresh_all();

        let cpu_cores = sys.cpus().len() as f32;
        let total_memory = sys.total_memory() / 1024 / 1024; // MB
        let available_memory = sys.available_memory() / 1024 / 1024; // MB

        Ok(SystemResources {
            cpu_cores,
            total_memory_mb: total_memory as i64,
            available_memory_mb: available_memory as i64,
        })
    }
}

pub struct SystemResources {
    pub cpu_cores: f32,
    pub total_memory_mb: i64,
    pub available_memory_mb: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inventory_reports_consistent_memory() {
        let resources = InventoryManager::new().get_inventory().expect("inventory");

        assert!(resources.cpu_cores >= 0.0);
        assert!(resources.available_memory_mb <= resources.total_memory_mb);
    }
}
