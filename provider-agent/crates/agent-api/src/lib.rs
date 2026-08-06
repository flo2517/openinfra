pub mod openinfra {
    pub mod shared {
        pub mod v1 {
            tonic::include_proto!("openinfra.shared.v1");
        }
    }
    pub mod agent {
        pub mod v1 {
            tonic::include_proto!("openinfra.agent.v1");
        }
    }
    pub mod controlplane {
        pub mod v1 {
            tonic::include_proto!("openinfra.controlplane.v1");
        }
    }
}

pub use openinfra::agent::v1 as proto;

use crate::proto::*;
use agent_core::{identity::IdentityManager, local_state::LocalStateError, AgentConfig};
use agent_inventory::InventoryManager;
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::{error, info};

fn executor_status_error(error: anyhow::Error) -> Status {
    if matches!(
        error.downcast_ref::<LocalStateError>(),
        Some(LocalStateError::WorkloadNotFound(_))
    ) {
        return Status::not_found(error.to_string());
    }
    Status::internal(format!("Executor error: {error:?}"))
}

const CHALLENGE_DOMAIN: &[u8] = b"openinfra-availability-proof-v1\0";
const MAX_CHALLENGE_ID: usize = 128;
const MAX_CHALLENGE_PAYLOAD: usize = 4096;

#[derive(Debug)]
pub enum AgentEvent {
    CmdDeploy {
        request: DeployRequest,
        responder: oneshot::Sender<Result<String, String>>,
    },
    CmdStop {
        workload_id: String,
        responder: oneshot::Sender<Result<(), String>>,
    },
    CmdChallenge(SolveChallengeRequest),
    StateChanged {
        workload_id: String,
        state: String,
    },
}

pub struct WorkloadStatus {
    pub state: i32,
    pub details: String,
}

#[async_trait]
pub trait Executor: Send + Sync {
    async fn deploy(&self, req: DeployRequest) -> anyhow::Result<String>;
    async fn stop(&self, workload_id: &str) -> anyhow::Result<()>;
    async fn get_status(&self, workload_id: &str) -> anyhow::Result<WorkloadStatus>;
}

pub struct AgentGrpcServer {
    pub config: AgentConfig,
    pub event_bus: mpsc::Sender<AgentEvent>,
    pub identity_manager: Arc<dyn IdentityManager>,
    pub inventory_manager: Arc<InventoryManager>,
    pub executor: Arc<dyn Executor>,
}

#[tonic::async_trait]
impl provider_agent_service_server::ProviderAgentService for AgentGrpcServer {
    async fn get_agent_info(
        &self,
        _: Request<GetAgentInfoRequest>,
    ) -> Result<Response<GetAgentInfoResponse>, Status> {
        info!("gRPC: GetAgentInfo requested");

        let public_key = self
            .identity_manager
            .get_public_key()
            .await
            .map_err(|e| Status::internal(format!("Identity error: {:?}", e)))?;

        Ok(Response::new(GetAgentInfoResponse {
            version: self.config.agent.agent_version.clone(),
            node_id: self.config.agent.id.clone().unwrap_or_default(),
            public_key,
            protocol_version: self.config.agent.protocol_version.clone(),
            capabilities: vec!["docker".to_string()],
            uptime_seconds: 0, // Uptime calculation could be added here
        }))
    }

    async fn health_check(
        &self,
        _: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        Ok(Response::new(HealthCheckResponse {
            healthy: true,
            status: "OK".to_string(),
        }))
    }

    async fn deploy(
        &self,
        request: Request<DeployRequest>,
    ) -> Result<Response<DeployResponse>, Status> {
        let req = request.into_inner();
        info!(
            "gRPC: DeployRequest received for workload {}",
            req.workload_id
        );

        let (tx, rx) = oneshot::channel();

        let event = AgentEvent::CmdDeploy {
            request: req.clone(),
            responder: tx,
        };

        if let Err(e) = self.event_bus.send(event).await {
            error!("Failed to send deploy event to bus: {}", e);
            return Err(Status::internal("Internal event bus error"));
        }

        match tokio::time::timeout(Duration::from_secs(60), rx).await {
            Ok(Ok(Ok(container_id))) => Ok(Response::new(DeployResponse {
                success: true,
                container_id,
                error: "".to_string(),
            })),
            Ok(Ok(Err(e))) => Ok(Response::new(DeployResponse {
                success: false,
                container_id: "".to_string(),
                error: e,
            })),
            Ok(Err(_)) => Err(Status::internal(
                "Responder dropped without sending response",
            )),
            Err(_) => Err(Status::deadline_exceeded(
                "Deployment timed out after 60 seconds",
            )),
        }
    }

    async fn get_inventory(
        &self,
        _: Request<GetInventoryRequest>,
    ) -> Result<Response<GetInventoryResponse>, Status> {
        info!("gRPC: GetInventory requested");

        let resources = self
            .inventory_manager
            .get_inventory(&self.config.executor.state_path)
            .map_err(|e| Status::internal(format!("Inventory error: {:?}", e)))?;

        Ok(Response::new(GetInventoryResponse {
            cpu_cores: resources.cpu_cores,
            total_memory_mb: resources.total_memory_mb,
            available_memory_mb: resources.available_memory_mb,
        }))
    }

    async fn solve_challenge(
        &self,
        request: Request<SolveChallengeRequest>,
    ) -> Result<Response<SolveChallengeResponse>, Status> {
        let request = request.into_inner();
        if request.challenge_id.is_empty() || request.challenge_id.len() > MAX_CHALLENGE_ID {
            return Err(Status::invalid_argument(
                "challenge_id is empty or too long",
            ));
        }
        if request.payload.len() > MAX_CHALLENGE_PAYLOAD {
            return Err(Status::resource_exhausted("challenge payload is too large"));
        }
        let challenge_type = solve_challenge_request::Type::try_from(request.r#type)
            .map_err(|_| Status::invalid_argument("unknown challenge type"))?;
        if challenge_type == solve_challenge_request::Type::Unspecified {
            return Err(Status::invalid_argument("challenge type is required"));
        }
        let started = Instant::now();
        // The validator supplies a bounded nonce/payload. Hashing it gives a
        // deterministic proof of work without executing provider-controlled
        // code in the Agent process.
        let mut hasher = Sha256::new();
        hasher.update(&request.payload);
        let result = hasher.finalize().to_vec();
        let mut signed = Vec::with_capacity(
            CHALLENGE_DOMAIN.len() + request.challenge_id.len() + result.len() + 8,
        );
        signed.extend_from_slice(CHALLENGE_DOMAIN);
        signed.extend_from_slice(&(request.challenge_id.len() as u32).to_be_bytes());
        signed.extend_from_slice(request.challenge_id.as_bytes());
        signed.extend_from_slice(&request.r#type.to_be_bytes());
        signed.extend_from_slice(&result);
        let signature = self
            .identity_manager
            .sign(&signed)
            .await
            .map_err(|error| Status::internal(format!("identity signing failed: {error}")))?;
        let resource_type = match challenge_type {
            solve_challenge_request::Type::Compute => "compute",
            solve_challenge_request::Type::Storage => "storage",
            solve_challenge_request::Type::Availability => "availability",
            solve_challenge_request::Type::Unspecified => unreachable!(),
        };
        Ok(Response::new(SolveChallengeResponse {
            challenge_id: request.challenge_id,
            resource_type: resource_type.to_string(),
            result,
            duration_ms: started.elapsed().as_millis().min(u128::from(u32::MAX)) as u32,
            signature,
        }))
    }

    async fn stop(&self, request: Request<StopRequest>) -> Result<Response<StopResponse>, Status> {
        let req = request.into_inner();
        info!(
            "gRPC: StopRequest received for workload {}",
            req.workload_id
        );

        let (tx, rx) = oneshot::channel();

        let event = AgentEvent::CmdStop {
            workload_id: req.workload_id,
            responder: tx,
        };

        if let Err(e) = self.event_bus.send(event).await {
            error!("Failed to send stop event to bus: {}", e);
            return Err(Status::internal("Internal event bus error"));
        }

        match tokio::time::timeout(Duration::from_secs(30), rx).await {
            Ok(Ok(Ok(_))) => Ok(Response::new(StopResponse {
                success: true,
                error: "".to_string(),
            })),
            Ok(Ok(Err(e))) => Ok(Response::new(StopResponse {
                success: false,
                error: e,
            })),
            Ok(Err(_)) => Err(Status::internal(
                "Responder dropped without sending response",
            )),
            Err(_) => Err(Status::deadline_exceeded("Stop operation timed out")),
        }
    }

    async fn get_workload_status(
        &self,
        request: Request<GetWorkloadStatusRequest>,
    ) -> Result<Response<GetWorkloadStatusResponse>, Status> {
        let req = request.into_inner();
        info!("gRPC: GetWorkloadStatus requested for {}", req.workload_id);

        let status = self
            .executor
            .get_status(&req.workload_id)
            .await
            .map_err(executor_status_error)?;

        Ok(Response::new(GetWorkloadStatusResponse {
            workload_id: req.workload_id,
            state: status.state,
            details: status.details,
        }))
    }

    type StreamMetricsStream = ReceiverStream<Result<StreamMetricsResponse, Status>>;
    async fn stream_metrics(
        &self,
        _: Request<StreamMetricsRequest>,
    ) -> Result<Response<Self::StreamMetricsStream>, Status> {
        Err(Status::unimplemented("StreamMetrics not yet implemented"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_workload_maps_to_grpc_not_found() {
        let status = executor_status_error(
            LocalStateError::WorkloadNotFound("missing-workload".to_string()).into(),
        );

        assert_eq!(status.code(), tonic::Code::NotFound);
        assert!(status.message().contains("missing-workload"));
    }

    #[test]
    fn other_executor_errors_remain_internal() {
        let status = executor_status_error(anyhow::anyhow!("Docker unavailable"));

        assert_eq!(status.code(), tonic::Code::Internal);
    }
}
