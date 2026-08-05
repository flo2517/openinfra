use agent_api::{
    openinfra::{controlplane::v1 as controlplanev1, shared::v1 as sharedv1},
    proto::provider_agent_service_server::ProviderAgentServiceServer,
    AgentEvent, AgentGrpcServer, Executor,
};
use agent_core::{
    identity::{Ed25519IdentityManager, IdentityManager},
    local_state::LocalState,
    AgentConfig,
};
use agent_executor::DockerExecutor;
use agent_inventory::InventoryManager;
use anyhow::Result;
use clap::{Parser, Subcommand};
use prost::Message;
use std::{env, fs, net::SocketAddr, sync::Arc, time::Duration};
use tonic::transport::{
    Certificate, Channel, ClientTlsConfig, Endpoint, Identity, ServerTlsConfig,
};
use tracing::{error, info};
use uuid::Uuid;

const JOIN_DOMAIN: &[u8] = b"openinfra-join-v1\0";
const HEARTBEAT_DOMAIN: &[u8] = b"openinfra-heartbeat-v1\0";

#[derive(Parser)]
#[command(name = "openinfra-agent")]
#[command(about = "OpenInfra Network Provider Agent", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(long, default_value_t = false)]
    dev: bool,
}

#[derive(Subcommand)]
enum Commands {
    Init,
    Join,
    Heartbeat,
    Start,
    Doctor,
    Status,
}

async fn handle_init() -> Result<()> {
    let config = AgentConfig::default();
    let key_path = config.security.key_path.clone();
    info!(?key_path, "generating agent identity");
    let _identity = Ed25519IdentityManager::generate(key_path)?;
    fs::write("config.yaml", serde_yaml::to_string(&config)?)?;
    info!("agent initialized");
    Ok(())
}

async fn handle_doctor() -> Result<()> {
    let identity_ok = std::path::Path::new("identity.key").exists();
    let config_ok = std::path::Path::new("config.yaml").exists();
    let docker_ok = std::process::Command::new("docker")
        .arg("info")
        .output()
        .is_ok_and(|output| output.status.success());

    println!("Identity: {}", if identity_ok { "OK" } else { "MISSING" });
    println!("Config: {}", if config_ok { "OK" } else { "MISSING" });
    println!("Docker: {}", if docker_ok { "OK" } else { "UNAVAILABLE" });
    Ok(())
}

async fn handle_start(dev: bool) -> Result<()> {
    let config = load_config()?;
    let identity_manager = Arc::new(Ed25519IdentityManager::new(
        config.security.key_path.clone(),
    )?);
    let inventory_manager = Arc::new(InventoryManager::new());
    let local_state = Arc::new(LocalState::open(&config.executor.state_path)?);
    let heartbeat_config = config.clone();
    let heartbeat_state = Arc::clone(&local_state);
    tokio::spawn(async move {
        loop {
            if let Err(error) =
                report_heartbeat_with_state(&heartbeat_config, dev, &heartbeat_state).await
            {
                error!(%error, "background heartbeat failed");
            }
            tokio::time::sleep(Duration::from_secs(15)).await;
        }
    });
    let executor =
        Arc::new(DockerExecutor::connect(Arc::clone(&local_state), config.executor.clone()).await?);
    let (event_bus, mut events) = tokio::sync::mpsc::channel(100);
    let event_executor = Arc::clone(&executor);

    tokio::spawn(async move {
        while let Some(event) = events.recv().await {
            match event {
                AgentEvent::CmdDeploy { request, responder } => {
                    let result = event_executor
                        .deploy(request)
                        .await
                        .map_err(|e| e.to_string());
                    let _ = responder.send(result);
                }
                AgentEvent::CmdStop {
                    workload_id,
                    responder,
                } => {
                    let result = event_executor
                        .stop(&workload_id)
                        .await
                        .map_err(|e| e.to_string());
                    let _ = responder.send(result);
                }
                _ => {}
            }
        }
    });

    let addr: SocketAddr = config.agent.listen_address.parse()?;
    let server = AgentGrpcServer {
        config,
        event_bus,
        identity_manager,
        inventory_manager,
        executor,
    };

    let mut builder = tonic::transport::Server::builder();
    if dev {
        if !addr.ip().is_loopback() {
            anyhow::bail!("plaintext development Agent requires a loopback listen address")
        }
        info!(%addr, "gRPC server listening in loopback plaintext development mode");
    } else {
        let certificate = fs::read(env::var("AGENT_TLS_CERT_FILE")?)?;
        let private_key = fs::read(env::var("AGENT_TLS_KEY_FILE")?)?;
        let client_ca = fs::read(env::var("AGENT_TLS_CLIENT_CA_FILE")?)?;
        builder = builder.tls_config(
            ServerTlsConfig::new()
                .identity(Identity::from_pem(certificate, private_key))
                .client_ca_root(Certificate::from_pem(client_ca)),
        )?;
        info!(%addr, "gRPC server listening with mandatory mTLS");
    }
    builder
        .add_service(ProviderAgentServiceServer::new(server))
        .serve(addr)
        .await?;
    Ok(())
}

async fn handle_join(dev: bool) -> Result<()> {
    let mut config = load_config()?;
    let identity = Ed25519IdentityManager::new(config.security.key_path.clone())?;
    let public_key = hex::decode(identity.get_public_key().await?)?;
    let inventory = InventoryManager::new().get_inventory()?;
    let channel = connect_control_plane(&config.control_plane.endpoint, dev).await?;
    let mut client =
        controlplanev1::control_plane_service_client::ControlPlaneServiceClient::new(channel);

    let mut begin_request = tonic::Request::new(controlplanev1::BeginJoinRequest {
        request_id: Uuid::new_v4().to_string(),
        public_key,
        protocol_version: config.agent.protocol_version.clone(),
        agent_version: config.agent.agent_version.clone(),
        agent_endpoint: config.agent.advertised_endpoint.clone(),
    });
    begin_request.set_timeout(Duration::from_secs(10));
    let challenge = client.begin_join(begin_request).await?.into_inner();

    let mut signed = Vec::with_capacity(JOIN_DOMAIN.len() + challenge.challenge_nonce.len());
    signed.extend_from_slice(JOIN_DOMAIN);
    signed.extend_from_slice(&challenge.challenge_nonce);
    let signature = identity.sign(&signed).await?;

    let mut complete_request = tonic::Request::new(controlplanev1::CompleteJoinRequest {
        request_id: Uuid::new_v4().to_string(),
        challenge_id: challenge.challenge_id,
        challenge_signature: signature,
        capabilities: Some(sharedv1::ResourceCapability {
            cpu_total: inventory.cpu_cores,
            cpu_available: inventory.cpu_cores,
            ram_total_mb: inventory.total_memory_mb,
            ram_available_mb: inventory.available_memory_mb,
            ..Default::default()
        }),
    });
    // Registration may span multiple manually sealed blocks before finality.
    complete_request.set_timeout(Duration::from_secs(30));
    let joined = client.complete_join(complete_request).await?.into_inner();
    if joined.status != sharedv1::NodeStatus::Active as i32 {
        anyhow::bail!("Control Plane returned non-active provider status")
    }
    config.agent.id = Some(joined.provider_id.clone());
    persist_config(&config)?;
    info!(provider_id = %joined.provider_id, "provider joined Control Plane");
    println!("Provider ACTIVE: {}", joined.provider_id);
    Ok(())
}

async fn handle_heartbeat(dev: bool) -> Result<()> {
    let config = load_config()?;
    let state = LocalState::open(&config.executor.state_path)?;
    report_heartbeat_with_state(&config, dev, &state).await
}

async fn report_heartbeat_with_state(
    config: &AgentConfig,
    dev: bool,
    state: &LocalState,
) -> Result<()> {
    let provider_id = config
        .agent
        .id
        .clone()
        .ok_or_else(|| anyhow::anyhow!("provider is not joined; run join first"))?;
    let identity = Ed25519IdentityManager::new(config.security.key_path.clone())?;
    let inventory = InventoryManager::new().get_inventory()?;
    let sequence = state.next_heartbeat_sequence()?;
    let observed_at = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
    let payload = controlplanev1::HeartbeatSigningPayload {
        request_id: Uuid::new_v4().to_string(),
        provider_id: provider_id.clone(),
        sequence,
        observed_at: Some(prost_types::Timestamp {
            seconds: observed_at.as_secs().try_into()?,
            nanos: observed_at.subsec_nanos().try_into()?,
        }),
        capabilities: Some(sharedv1::ResourceCapability {
            cpu_total: inventory.cpu_cores,
            cpu_available: inventory.cpu_cores,
            ram_total_mb: inventory.total_memory_mb,
            ram_available_mb: inventory.available_memory_mb,
            ..Default::default()
        }),
    };
    let mut signed = Vec::with_capacity(HEARTBEAT_DOMAIN.len() + payload.encoded_len());
    signed.extend_from_slice(HEARTBEAT_DOMAIN);
    payload.encode(&mut signed)?;
    let signature = identity.sign(&signed).await?;
    let channel = connect_control_plane(&config.control_plane.endpoint, dev).await?;
    let mut client =
        controlplanev1::control_plane_service_client::ControlPlaneServiceClient::new(channel);
    let mut request = tonic::Request::new(controlplanev1::ReportHeartbeatRequest {
        payload: Some(payload),
        signature,
    });
    request.set_timeout(Duration::from_secs(10));
    let response = client.report_heartbeat(request).await?.into_inner();
    if response.status != sharedv1::NodeStatus::Active as i32 {
        anyhow::bail!("Control Plane returned non-active heartbeat status")
    }
    info!(%provider_id, sequence, "heartbeat accepted");
    println!("Provider ACTIVE: {provider_id} (heartbeat {sequence})");
    Ok(())
}

fn load_config() -> Result<AgentConfig> {
    let contents = fs::read_to_string("config.yaml")?;
    Ok(serde_yaml::from_str(&contents)?)
}

fn persist_config(config: &AgentConfig) -> Result<()> {
    let temporary = "config.yaml.tmp";
    fs::write(temporary, serde_yaml::to_string(config)?)?;
    fs::rename(temporary, "config.yaml")?;
    Ok(())
}

async fn connect_control_plane(endpoint: &str, dev: bool) -> Result<Channel> {
    let mut connection = Endpoint::from_shared(endpoint.to_string())?
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10));

    if endpoint.starts_with("https://") {
        let certificate = fs::read(env::var("TLS_CERT_FILE")?)?;
        let private_key = fs::read(env::var("TLS_KEY_FILE")?)?;
        let ca = fs::read(env::var("TLS_CA_FILE")?)?;
        let domain = env::var("TLS_SERVER_NAME")?;
        connection = connection.tls_config(
            ClientTlsConfig::new()
                .identity(Identity::from_pem(certificate, private_key))
                .ca_certificate(Certificate::from_pem(ca))
                .domain_name(domain),
        )?;
    } else if !dev
        || !(endpoint.starts_with("http://127.0.0.1") || endpoint.starts_with("http://localhost"))
    {
        anyhow::bail!("plaintext Control Plane connections require --dev and a loopback endpoint")
    }

    Ok(connection.connect().await?)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => handle_init().await?,
        Commands::Doctor => handle_doctor().await?,
        Commands::Start => handle_start(cli.dev).await?,
        Commands::Join => handle_join(cli.dev).await?,
        Commands::Heartbeat => handle_heartbeat(cli.dev).await?,
        Commands::Status => error!("status is not implemented"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn plaintext_endpoint_requires_dev_mode() {
        let error = connect_control_plane("http://127.0.0.1:50051", false)
            .await
            .expect_err("plaintext must be rejected");
        assert!(error.to_string().contains("require --dev"));
    }

    #[tokio::test]
    async fn plaintext_endpoint_rejects_non_loopback() {
        let error = connect_control_plane("http://192.0.2.1:50051", true)
            .await
            .expect_err("non-loopback plaintext must be rejected");
        assert!(error.to_string().contains("loopback"));
    }
}
