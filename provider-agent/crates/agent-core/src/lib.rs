pub mod errors;
pub mod identity;
pub mod local_state;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AgentConfig {
    pub agent: AgentSettings,
    pub security: SecuritySettings,
    pub control_plane: ControlPlaneSettings,
    #[serde(default)]
    pub executor: ExecutorSettings,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AgentSettings {
    pub id: Option<String>,
    pub protocol_version: String,
    pub agent_version: String,
    #[serde(default = "default_listen_address")]
    pub listen_address: String,
    #[serde(default)]
    pub advertised_endpoint: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SecuritySettings {
    pub key_path: PathBuf,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ControlPlaneSettings {
    pub endpoint: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExecutorSettings {
    pub state_path: PathBuf,
    pub max_workloads: usize,
    pub max_cpu_cores: f32,
    pub max_memory_mb: i64,
    pub pids_limit: i64,
}

impl Default for ExecutorSettings {
    fn default() -> Self {
        Self {
            state_path: PathBuf::from(".openinfra-state"),
            max_workloads: 8,
            max_cpu_cores: 8.0,
            max_memory_mb: 16_384,
            pids_limit: 128,
        }
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            agent: AgentSettings {
                id: None,
                protocol_version: "1".to_string(),
                agent_version: "0.1.0".to_string(),
                listen_address: default_listen_address(),
                advertised_endpoint: String::new(),
            },
            security: SecuritySettings {
                key_path: PathBuf::from("identity.key"),
            },
            control_plane: ControlPlaneSettings {
                endpoint: "https://127.0.0.1:50051".to_string(),
            },
            executor: ExecutorSettings::default(),
        }
    }
}

fn default_listen_address() -> String {
    "127.0.0.1:50052".to_string()
}
