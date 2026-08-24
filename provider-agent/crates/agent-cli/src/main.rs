mod mtls;
mod pki;

use agent_api::{
    openinfra::{controlplane::v1 as controlplanev1, shared::v1 as sharedv1},
    proto::provider_agent_service_server::ProviderAgentServiceServer,
    AgentEvent, AgentGrpcServer, Executor,
};
use agent_core::{
    identity::{Ed25519IdentityManager, IdentityManager},
    local_state::{LeafCertificate, LocalState},
    AgentConfig,
};
use agent_executor::DockerExecutor;
use agent_inventory::InventoryManager;
use anyhow::Result;
use clap::{Parser, Subcommand};
use mtls::ValidatorAllowlist;
use prost::Message;
use std::{env, fs, net::SocketAddr, sync::Arc, time::Duration};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
use tracing::{error, info, warn};
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
    // ADR-013 §3: the most recently ReportHeartbeat-pushed set of active
    // Network Validator keys, read live by the mTLS verifier built below
    // (non-dev branch) and updated after every successful heartbeat
    // round-trip by the background task spawned here. Built unconditionally
    // (even in --dev, where it's never read) so report_heartbeat_with_state
    // has one signature regardless of mode.
    let validator_allowlist = ValidatorAllowlist::new();
    let heartbeat_config = config.clone();
    let heartbeat_state = Arc::clone(&local_state);
    let heartbeat_allowlist = validator_allowlist.clone();
    tokio::spawn(async move {
        loop {
            if let Err(error) = report_heartbeat_with_state(
                &heartbeat_config,
                dev,
                &heartbeat_state,
                &heartbeat_allowlist,
            )
            .await
            {
                error!(%error, "background heartbeat failed");
            }
            tokio::time::sleep(Duration::from_secs(15)).await;
        }
    });
    // ADR-027 §3: renews the persisted mTLS leaf certificate once 50% of
    // its lifetime has elapsed, with bounded backoff on failure -- the
    // same long-running-process shape the heartbeat loop above already
    // uses. A no-op poll loop (not spawned conditionally) when this Agent
    // hasn't enrolled yet or the Control Plane isn't running in ADR-027
    // mTLS PKI mode: run_renewal_loop's first check is always "is there a
    // persisted leaf certificate at all."
    let renewal_config = config.clone();
    let renewal_state = Arc::clone(&local_state);
    let renewal_identity = Arc::clone(&identity_manager);
    tokio::spawn(async move {
        run_renewal_loop(renewal_config, dev, renewal_state, renewal_identity).await;
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
        bandwidth_rate_limiter: agent_api::BandwidthRateLimiter::new(),
    };

    // tonic's default per-message limit (4 MiB, both directions) predates
    // MeasureBandwidth (ADR-015) and would reject its whole premise --
    // agent_api::MAX_BANDWIDTH_PROBE_BYTES (8 MiB) plus a fixed margin for
    // protobuf/gRPC framing overhead beyond the raw payload bytes.
    const BANDWIDTH_MESSAGE_SIZE_LIMIT: usize = agent_api::MAX_BANDWIDTH_PROBE_BYTES + 64 * 1024;
    let router = tonic::transport::Server::builder().add_service(
        ProviderAgentServiceServer::new(server)
            .max_decoding_message_size(BANDWIDTH_MESSAGE_SIZE_LIMIT)
            .max_encoding_message_size(BANDWIDTH_MESSAGE_SIZE_LIMIT),
    );
    if dev {
        if !addr.ip().is_loopback() {
            anyhow::bail!("plaintext development Agent requires a loopback listen address")
        }
        info!(%addr, "gRPC server listening in loopback plaintext development mode");
        router.serve(addr).await?;
    } else {
        let certificate = fs::read(env::var("AGENT_TLS_CERT_FILE")?)?;
        let private_key = fs::read(env::var("AGENT_TLS_KEY_FILE")?)?;
        let client_ca = fs::read(env::var("AGENT_TLS_CLIENT_CA_FILE")?)?;
        // ADR-013 §3: tonic's ServerTlsConfig has no hook for a custom
        // rustls ClientCertVerifier, so this builds the rustls::ServerConfig
        // by hand (mtls::build_server_config) and drives the listener
        // through tonic's serve_with_incoming escape hatch instead of
        // Server::tls_config/serve. See mtls.rs's module doc for the full
        // reasoning.
        let incoming = mtls::serve_incoming(
            addr,
            &certificate,
            &private_key,
            &client_ca,
            validator_allowlist,
        )
        .await?;
        info!(%addr, "gRPC server listening with mandatory mTLS (Control Plane CA or allowlisted Network Validator key)");
        router.serve_with_incoming(incoming).await?;
    }
    Ok(())
}

async fn handle_join(dev: bool) -> Result<()> {
    let mut config = load_config()?;
    let identity = Ed25519IdentityManager::new(config.security.key_path.clone())?;
    let public_key = hex::decode(identity.get_public_key().await?)?;
    let inventory = InventoryManager::new().get_inventory(&config.executor.state_path)?;

    // ADR-027 §2/§6 migration: TLS_CERT_FILE configured means this Agent
    // is deliberately still on the pre-ADR-027 static-cert deployment
    // shape (retired as the *default* by this change, but kept working
    // per the ADR §6 migration sequencing note, not removed) -- keep
    // using that identity for BeginJoin/CompleteJoin exactly as before
    // this PR, and never request mTLS enrollment.
    //
    // A fresh deployment that leaves TLS_CERT_FILE unset (the new
    // default: deployments/docker-compose.yml no longer sets it for
    // provider-agent) uses the real ADR-027 flow instead: a freshly
    // generated mTLS leaf keypair, distinct from the long-term identity
    // key above -- its self-signed certificate is the bootstrap identity
    // this connection presents (the Control Plane's dual-trust-basis
    // verifier accepts it for exactly BeginJoin/CompleteJoin, granting no
    // authorization by itself; challenge_signature below is what actually
    // authorizes anything). In --dev plaintext mode there is no TLS
    // handshake at all, so neither the keypair nor tls_public_key serve
    // any purpose; enrollment is skipped entirely rather than asking a
    // plaintext-only Control Plane for a certificate it has nowhere to
    // bind.
    let use_bootstrap_enrollment = !dev && env::var("TLS_CERT_FILE").is_err();
    let bootstrap = if use_bootstrap_enrollment {
        Some(pki::generate_leaf_keypair()?)
    } else {
        None
    };
    let bootstrap_certificate_pem = match &bootstrap {
        Some(keypair) => Some(pki::bootstrap_certificate_pem(keypair)?),
        None => None,
    };
    let channel = connect_control_plane_with_identity(
        &config.control_plane.endpoint,
        dev,
        bootstrap
            .as_ref()
            .zip(bootstrap_certificate_pem.as_ref())
            .map(|(keypair, cert_pem)| (cert_pem.clone(), keypair.private_key_pem.clone())),
    )
    .await?;
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
        capabilities: Some(resource_capability(&config, &inventory)),
        tls_public_key: bootstrap
            .as_ref()
            .map(|keypair| keypair.public_key_raw.to_vec())
            .unwrap_or_default(),
    });
    // Registration may span multiple manually sealed blocks before finality.
    complete_request.set_timeout(Duration::from_secs(30));
    let joined = client.complete_join(complete_request).await?.into_inner();
    if joined.status != sharedv1::NodeStatus::Active as i32 {
        anyhow::bail!("Control Plane returned non-active provider status")
    }
    config.agent.id = Some(joined.provider_id.clone());
    persist_config(&config)?;

    // ADR-027 §2/§5: persist the issued leaf identity so heartbeat/start
    // use it instead of any static TLS_CERT_FILE from here on, and so the
    // renewal loop (handle_start) knows there is something to renew. Only
    // happens when the Control Plane actually issued one (non-empty
    // certificate_pem) -- a Control Plane not running in ADR-027 mTLS PKI
    // mode (CA_KEY_FILE unset) leaves this empty, and the Agent keeps
    // using its static TLS_CERT_FILE identity exactly as before, per the
    // ADR §6 migration sequencing note.
    if let (Some(keypair), false) = (&bootstrap, joined.certificate_pem.is_empty()) {
        let expires_at_unix = joined
            .certificate_expires_at
            .as_ref()
            .map(|timestamp| timestamp.seconds)
            .ok_or_else(|| anyhow::anyhow!("Control Plane issued a certificate with no expiry"))?;
        let serial = pki::leaf_certificate_serial(&joined.certificate_pem)?;
        let state = LocalState::open(&config.executor.state_path)?;
        state.store_leaf_certificate(&LeafCertificate {
            private_key_pem: keypair.private_key_pem.clone(),
            certificate_pem: joined.certificate_pem.clone(),
            serial,
            expires_at_unix,
        })?;
        info!("mTLS leaf certificate issued and persisted (ADR-027 enrollment)");
    }

    info!(provider_id = %joined.provider_id, "provider joined Control Plane");
    println!("Provider ACTIVE: {}", joined.provider_id);
    Ok(())
}

async fn handle_heartbeat(dev: bool) -> Result<()> {
    let config = load_config()?;
    let state = LocalState::open(&config.executor.state_path)?;
    // A one-shot `heartbeat` CLI invocation has no running mTLS server to
    // update, so this allowlist handle is discarded after the call; it
    // only matters to the long-running loop `handle_start` spawns.
    report_heartbeat_with_state(&config, dev, &state, &ValidatorAllowlist::new()).await
}

async fn report_heartbeat_with_state(
    config: &AgentConfig,
    dev: bool,
    state: &LocalState,
    validator_allowlist: &ValidatorAllowlist,
) -> Result<()> {
    let provider_id = config
        .agent
        .id
        .clone()
        .ok_or_else(|| anyhow::anyhow!("provider is not joined; run join first"))?;
    let identity = Ed25519IdentityManager::new(config.security.key_path.clone())?;
    let inventory = InventoryManager::new().get_inventory(&config.executor.state_path)?;
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
        capabilities: Some(resource_capability(config, &inventory)),
        workload_bandwidth: workload_bandwidth_usage(state).await,
    };
    let mut signed = Vec::with_capacity(HEARTBEAT_DOMAIN.len() + payload.encoded_len());
    signed.extend_from_slice(HEARTBEAT_DOMAIN);
    payload.encode(&mut signed)?;
    let signature = identity.sign(&signed).await?;
    // ADR-027 §3: present the persisted Control-Plane-issued leaf
    // certificate once enrolled, instead of the static TLS_CERT_FILE
    // identity every earlier Agent still falls back to.
    let channel = connect_control_plane_with_identity(
        &config.control_plane.endpoint,
        dev,
        control_plane_client_identity(state)?,
    )
    .await?;
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
    // ADR-013 §3: replace -- never merge into -- the mTLS allowlist with
    // exactly what this heartbeat carried, so a validator the Control
    // Plane no longer reports as active stops being trusted starting with
    // the very next inbound handshake. A malformed (non-32-byte) entry is
    // dropped with a warning, not treated as fatal: one bad entry must not
    // take every other legitimate validator off the allowlist.
    let active_validators = response
        .active_validators
        .iter()
        .filter_map(|key| match <[u8; 32]>::try_from(key.as_slice()) {
            Ok(key) => Some(key),
            Err(_) => {
                warn!(
                    length = key.len(),
                    "dropping malformed active_validators entry"
                );
                None
            }
        })
        .collect::<Vec<_>>();
    validator_allowlist.set(active_validators);
    info!(%provider_id, sequence, "heartbeat accepted");
    println!("Provider ACTIVE: {provider_id} (heartbeat {sequence})");
    Ok(())
}

/// ADR-027 §3's renewal timer, run as its own long-running background
/// task for the lifetime of `handle_start` (mirroring the heartbeat
/// loop's shape, but on its own independent cadence -- renewal happens
/// roughly once a day, heartbeats every ~15s, and the two must not block
/// each other). Polls every `poll_interval` for whether the persisted
/// leaf certificate (if any) has crossed its renewal threshold
/// (`pki::RENEWAL_OVERLAP` before `expires_at_unix`, i.e. 50% of a 24h
/// certificate's lifetime elapsed); on a failed attempt, backs off
/// (`pki::RENEWAL_BACKOFF_BASE` doubling to `pki::RENEWAL_BACKOFF_CAP`)
/// before checking again, resetting to `poll_interval` after any success.
/// Never returns -- runs for the life of the process, the same contract
/// the heartbeat loop above already has.
async fn run_renewal_loop(
    config: AgentConfig,
    dev: bool,
    state: Arc<LocalState>,
    identity_manager: Arc<Ed25519IdentityManager>,
) {
    const POLL_INTERVAL: Duration = Duration::from_secs(60);
    let mut backoff = pki::RENEWAL_BACKOFF_BASE;
    loop {
        let leaf = match state.leaf_certificate() {
            Ok(Some(leaf)) => leaf,
            Ok(None) => {
                // Not yet enrolled (or talking to a Control Plane not
                // running in ADR-027 mTLS PKI mode) -- nothing to renew.
                tokio::time::sleep(POLL_INTERVAL).await;
                continue;
            }
            Err(error) => {
                error!(%error, "failed to read the persisted mTLS leaf certificate");
                tokio::time::sleep(POLL_INTERVAL).await;
                continue;
            }
        };
        let now = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(duration) => duration.as_secs() as i64,
            Err(_) => {
                tokio::time::sleep(POLL_INTERVAL).await;
                continue;
            }
        };
        let renew_at = leaf.expires_at_unix - pki::RENEWAL_OVERLAP.as_secs() as i64;
        if now < renew_at {
            tokio::time::sleep(POLL_INTERVAL).await;
            continue;
        }
        if now >= leaf.expires_at_unix {
            // ADR-027 §3: "no soft grace period past NotAfter" -- once
            // expired, this Agent can no longer open a new mTLS
            // connection to the Control Plane at all (a hard boundary,
            // deliberately, per the ADR). Kept logging on every poll
            // rather than giving up the task entirely: an operator fixing
            // connectivity (or the Agent's clock) should see renewal
            // resume without needing a process restart.
            error!("mTLS leaf certificate has expired without a successful renewal; the Agent cannot open new connections to the Control Plane until the operator intervenes (see ADR-027 §3 / ADR-028 disconnected mode)");
            tokio::time::sleep(POLL_INTERVAL).await;
            continue;
        }
        match attempt_renewal(&config, dev, &state, &identity_manager, &leaf).await {
            Ok(expires_at_unix) => {
                info!(expires_at_unix, "mTLS leaf certificate renewed");
                backoff = pki::RENEWAL_BACKOFF_BASE;
                tokio::time::sleep(POLL_INTERVAL).await;
            }
            Err(error) => {
                warn!(%error, backoff_secs = backoff.as_secs(), "certificate renewal attempt failed; retrying with backoff");
                tokio::time::sleep(backoff).await;
                backoff = pki::next_backoff(backoff);
            }
        }
    }
}

/// A single ADR-027 §3 renewal attempt: signs a fresh
/// `RenewCertificateRequest` with the long-term identity key (never the
/// TLS key itself), calls it over a connection authenticated with
/// `current` (the still-valid, previously issued leaf certificate --
/// never the bootstrap path, which is reserved for `handle_join`'s first
/// enrollment), and on success persists the new leaf identity, replacing
/// `current`. Returns the new certificate's expiry on success.
async fn attempt_renewal(
    config: &AgentConfig,
    dev: bool,
    state: &LocalState,
    identity_manager: &Ed25519IdentityManager,
    current: &LeafCertificate,
) -> Result<i64> {
    let provider_id = config
        .agent
        .id
        .clone()
        .ok_or_else(|| anyhow::anyhow!("provider is not joined; run join first"))?;
    let new_keypair = pki::generate_leaf_keypair()?;
    let nonce = state.next_renewal_nonce()?;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
    let timestamp_seconds: i64 = now.as_secs().try_into()?;
    let timestamp_nanos: i32 = now.subsec_nanos().try_into()?;
    let signed = pki::renewal_signing_payload(
        &new_keypair.public_key_raw,
        &current.serial,
        timestamp_seconds,
        timestamp_nanos,
        nonce,
    );
    let signature = identity_manager.sign(&signed).await?;

    let channel = connect_control_plane_with_identity(
        &config.control_plane.endpoint,
        dev,
        Some((
            current.certificate_pem.clone(),
            current.private_key_pem.clone(),
        )),
    )
    .await?;
    let mut client =
        controlplanev1::control_plane_service_client::ControlPlaneServiceClient::new(channel);
    let mut request = tonic::Request::new(controlplanev1::RenewCertificateRequest {
        request_id: Uuid::new_v4().to_string(),
        provider_id: provider_id.clone(),
        new_tls_public_key: new_keypair.public_key_raw.to_vec(),
        current_certificate_serial: current.serial.clone(),
        timestamp: Some(prost_types::Timestamp {
            seconds: timestamp_seconds,
            nanos: timestamp_nanos,
        }),
        nonce,
        signature,
    });
    request.set_timeout(Duration::from_secs(15));
    let response = client.renew_certificate(request).await?.into_inner();
    let expires_at_unix = response
        .certificate_expires_at
        .as_ref()
        .map(|timestamp| timestamp.seconds)
        .ok_or_else(|| anyhow::anyhow!("renewed certificate response has no expiry"))?;
    state.store_leaf_certificate(&LeafCertificate {
        private_key_pem: new_keypair.private_key_pem,
        certificate_pem: response.certificate_pem,
        serial: response.certificate_serial,
        expires_at_unix,
    })?;
    Ok(expires_at_unix)
}

/// ADR-025 §2: this heartbeat's `workload_bandwidth` entries.
///
/// No per-entry signature exists on `WorkloadBandwidthUsage` (see that
/// message's proto doc comment): it lives inside `HeartbeatSigningPayload`,
/// so the one Ed25519 signature `report_heartbeat_with_state` already
/// computes over the whole payload (`HEARTBEAT_DOMAIN` ++
/// `payload.encode()`) covers these entries too. A second signature here
/// would be the same key signing the same data on the same transport --
/// deliberately not built, per the WIP commit that added this field.
///
/// Connecting to Docker is attempted fresh on every call rather than
/// reusing a long-lived engine, so this works uniformly from both
/// `handle_start`'s background loop and the one-shot `handle_heartbeat`
/// CLI command (which never otherwise touches Docker). A connection
/// failure degrades to an empty list with a warning rather than failing
/// the heartbeat -- liveness (this RPC's core job) must not depend on
/// Docker being reachable, the same reasoning the Control Plane's
/// `activeValidators` already applies to its own optional heartbeat data.
async fn workload_bandwidth_usage(
    state: &LocalState,
) -> Vec<controlplanev1::WorkloadBandwidthUsage> {
    let engine = match agent_executor::BollardEngine::connect() {
        Ok(engine) => engine,
        Err(error) => {
            warn!(%error, "Docker unavailable; reporting this heartbeat without workload bandwidth usage");
            return Vec::new();
        }
    };
    agent_executor::collect_workload_bandwidth(state, &engine)
        .await
        .into_iter()
        .filter_map(|(workload_id, reading)| {
            let window_started_at = match reading
                .window_started_at
                .duration_since(std::time::UNIX_EPOCH)
            {
                Ok(duration) => duration,
                Err(error) => {
                    warn!(%workload_id, %error, "workload window_started_at predates the UNIX epoch; omitting from this heartbeat");
                    return None;
                }
            };
            let (seconds, nanos) = match (
                i64::try_from(window_started_at.as_secs()),
                i32::try_from(window_started_at.subsec_nanos()),
            ) {
                (Ok(seconds), Ok(nanos)) => (seconds, nanos),
                _ => {
                    warn!(%workload_id, "workload window_started_at overflows a protobuf Timestamp; omitting from this heartbeat");
                    return None;
                }
            };
            Some(controlplanev1::WorkloadBandwidthUsage {
                workload_id,
                ingress_bytes_total: reading.ingress_bytes_total,
                egress_bytes_total: reading.egress_bytes_total,
                window_started_at: Some(prost_types::Timestamp { seconds, nanos }),
            })
        })
        .collect()
}

/// Builds the ResourceCapability reported on both CompleteJoin and every
/// ReportHeartbeat, so the two call sites can't drift out of sync with
/// each other. cpu/ram/storage come from InventoryManager's live OS
/// reads; bandwidth is the operator-declared config value (see
/// AgentSettings::bandwidth_ingress_mbps's doc comment for why bandwidth
/// isn't auto-detected the same way).
fn resource_capability(
    config: &AgentConfig,
    inventory: &agent_inventory::SystemResources,
) -> sharedv1::ResourceCapability {
    let bandwidth =
        if config.agent.bandwidth_ingress_mbps > 0 || config.agent.bandwidth_egress_mbps > 0 {
            Some(sharedv1::Bandwidth {
                ingress_mbps: config.agent.bandwidth_ingress_mbps,
                egress_mbps: config.agent.bandwidth_egress_mbps,
                ..Default::default()
            })
        } else {
            None
        };
    sharedv1::ResourceCapability {
        cpu_total: inventory.cpu_cores,
        cpu_available: inventory.cpu_cores,
        ram_total_mb: inventory.total_memory_mb,
        ram_available_mb: inventory.available_memory_mb,
        storage_total_gb: inventory.total_storage_gb,
        storage_available_gb: inventory.available_storage_gb,
        bandwidth,
        zone: config.agent.zone.clone(),
        ..Default::default()
    }
}

fn load_config() -> Result<AgentConfig> {
    let contents = fs::read_to_string("config.yaml")?;
    let mut config: AgentConfig = serde_yaml::from_str(&contents)?;
    apply_executor_env_overrides(&mut config)?;
    Ok(config)
}

// Overrides the five ExecutorSettings fields from environment variables when
// set, matching the docker-compose.yml OPENINFRA_AGENT_* vars an operator
// expects to take effect. An unset var leaves config.yaml's value untouched;
// a set-but-unparseable var is a hard error rather than a silently ignored
// or defaulted value.
fn apply_executor_env_overrides(config: &mut AgentConfig) -> Result<()> {
    if let Some(value) = parse_env("OPENINFRA_AGENT_MAX_WORKLOADS")? {
        config.executor.max_workloads = value;
    }
    if let Some(value) = parse_env("OPENINFRA_AGENT_MAX_CPU_CORES")? {
        config.executor.max_cpu_cores = value;
    }
    if let Some(value) = parse_env("OPENINFRA_AGENT_MAX_MEMORY_MB")? {
        config.executor.max_memory_mb = value;
    }
    if let Some(value) = parse_env("OPENINFRA_AGENT_PIDS_LIMIT")? {
        config.executor.pids_limit = value;
    }
    if let Some(value) = parse_env("OPENINFRA_AGENT_MAX_EGRESS_MBPS")? {
        config.executor.max_egress_mbps = value;
    }
    Ok(())
}

fn parse_env<T: std::str::FromStr>(name: &str) -> Result<Option<T>>
where
    T::Err: std::fmt::Display,
{
    match env::var(name) {
        Ok(raw) => raw
            .parse()
            .map(Some)
            .map_err(|error| anyhow::anyhow!("{name}={raw:?} is not valid: {error}")),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(anyhow::anyhow!("{name} is set but unreadable: {error}")),
    }
}

fn persist_config(config: &AgentConfig) -> Result<()> {
    let temporary = "config.yaml.tmp";
    fs::write(temporary, serde_yaml::to_string(config)?)?;
    fs::rename(temporary, "config.yaml")?;
    Ok(())
}

/// Connects to the Control Plane. `identity_override`, when set to
/// `(certificate_pem, private_key_pem)`, is presented as the client's
/// mTLS identity instead of reading `TLS_CERT_FILE`/`TLS_KEY_FILE` from
/// disk. Used for two ADR-027 cases: `handle_join`'s bootstrap self-signed
/// certificate (§2), and the persisted Control-Plane-issued leaf
/// certificate once one has been enrolled/renewed (§3) -- see
/// `control_plane_client_identity`. `TLS_CA_FILE`/`TLS_SERVER_NAME` are
/// unaffected either way: both cases still need to verify the Control
/// Plane's own long-lived server identity against the same CA.
async fn connect_control_plane_with_identity(
    endpoint: &str,
    dev: bool,
    identity_override: Option<(String, String)>,
) -> Result<Channel> {
    let mut connection = Endpoint::from_shared(endpoint.to_string())?
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10));

    if endpoint.starts_with("https://") {
        let (certificate, private_key) = match identity_override {
            Some((certificate_pem, private_key_pem)) => {
                (certificate_pem.into_bytes(), private_key_pem.into_bytes())
            }
            None => (
                fs::read(env::var("TLS_CERT_FILE")?)?,
                fs::read(env::var("TLS_KEY_FILE")?)?,
            ),
        };
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

/// Resolves the mTLS client identity `report_heartbeat_with_state` and the
/// renewal loop should present: the persisted ADR-027 leaf certificate
/// when one exists (regardless of how close to expiry it is -- an
/// almost-expired certificate is still valid until the Control Plane says
/// otherwise, and the renewal loop's own job, not this function's, is to
/// replace it before that happens), or `None` to fall back to
/// `TLS_CERT_FILE`/`TLS_KEY_FILE`, matching every Agent that hasn't
/// enrolled (or is talking to a Control Plane not running in ADR-027 mTLS
/// PKI mode) unaffected.
fn control_plane_client_identity(state: &LocalState) -> Result<Option<(String, String)>> {
    Ok(state
        .leaf_certificate()?
        .map(|leaf| (leaf.certificate_pem, leaf.private_key_pem)))
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
    use std::sync::Mutex;

    #[tokio::test]
    async fn plaintext_endpoint_requires_dev_mode() {
        let error = connect_control_plane_with_identity("http://127.0.0.1:50051", false, None)
            .await
            .expect_err("plaintext must be rejected");
        assert!(error.to_string().contains("require --dev"));
    }

    #[tokio::test]
    async fn plaintext_endpoint_rejects_non_loopback() {
        let error = connect_control_plane_with_identity("http://192.0.2.1:50051", true, None)
            .await
            .expect_err("non-loopback plaintext must be rejected");
        assert!(error.to_string().contains("loopback"));
    }

    // The four OPENINFRA_AGENT_* tests below mutate process-global env vars,
    // so they're serialized against each other via this lock to avoid
    // cross-test races under cargo test's default parallelism.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvVarGuard {
        name: &'static str,
    }

    impl EnvVarGuard {
        fn set(name: &'static str, value: &str) -> Self {
            env::set_var(name, value);
            Self { name }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            env::remove_var(self.name);
        }
    }

    #[test]
    fn max_workloads_env_override_applies() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _guard = EnvVarGuard::set("OPENINFRA_AGENT_MAX_WORKLOADS", "16");
        let mut config = AgentConfig::default();
        apply_executor_env_overrides(&mut config).expect("override should apply");
        assert_eq!(config.executor.max_workloads, 16);
    }

    #[test]
    fn max_cpu_cores_env_override_applies() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _guard = EnvVarGuard::set("OPENINFRA_AGENT_MAX_CPU_CORES", "4.5");
        let mut config = AgentConfig::default();
        apply_executor_env_overrides(&mut config).expect("override should apply");
        assert_eq!(config.executor.max_cpu_cores, 4.5);
    }

    #[test]
    fn max_memory_mb_env_override_applies() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _guard = EnvVarGuard::set("OPENINFRA_AGENT_MAX_MEMORY_MB", "32768");
        let mut config = AgentConfig::default();
        apply_executor_env_overrides(&mut config).expect("override should apply");
        assert_eq!(config.executor.max_memory_mb, 32768);
    }

    #[test]
    fn pids_limit_env_override_applies() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _guard = EnvVarGuard::set("OPENINFRA_AGENT_PIDS_LIMIT", "256");
        let mut config = AgentConfig::default();
        apply_executor_env_overrides(&mut config).expect("override should apply");
        assert_eq!(config.executor.pids_limit, 256);
    }

    #[test]
    fn max_egress_mbps_env_override_applies() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _guard = EnvVarGuard::set("OPENINFRA_AGENT_MAX_EGRESS_MBPS", "500");
        let mut config = AgentConfig::default();
        apply_executor_env_overrides(&mut config).expect("override should apply");
        assert_eq!(config.executor.max_egress_mbps, 500);
    }

    #[test]
    fn unset_env_leaves_config_value_untouched() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        env::remove_var("OPENINFRA_AGENT_MAX_WORKLOADS");
        env::remove_var("OPENINFRA_AGENT_MAX_CPU_CORES");
        env::remove_var("OPENINFRA_AGENT_MAX_MEMORY_MB");
        env::remove_var("OPENINFRA_AGENT_PIDS_LIMIT");
        env::remove_var("OPENINFRA_AGENT_MAX_EGRESS_MBPS");

        let mut config = AgentConfig::default();
        config.executor.max_workloads = 3;
        config.executor.max_cpu_cores = 1.5;
        config.executor.max_memory_mb = 2048;
        config.executor.pids_limit = 64;
        config.executor.max_egress_mbps = 100;

        apply_executor_env_overrides(&mut config).expect("no env vars set, nothing to apply");

        assert_eq!(config.executor.max_workloads, 3);
        assert_eq!(config.executor.max_cpu_cores, 1.5);
        assert_eq!(config.executor.max_memory_mb, 2048);
        assert_eq!(config.executor.pids_limit, 64);
        assert_eq!(config.executor.max_egress_mbps, 100);
    }

    #[test]
    fn unparseable_env_value_produces_clear_error() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _guard = EnvVarGuard::set("OPENINFRA_AGENT_MAX_WORKLOADS", "not-a-number");
        let mut config = AgentConfig::default();
        let error = apply_executor_env_overrides(&mut config)
            .expect_err("unparseable value must be rejected, not silently ignored");
        assert!(error.to_string().contains("OPENINFRA_AGENT_MAX_WORKLOADS"));
        assert!(error.to_string().contains("not-a-number"));
    }

    // ADR-025 §2's exact signed byte layout: this fixture is the
    // cross-language pin. `WorkloadBandwidthUsage` has no signature field
    // of its own (see its proto doc comment) -- it rides inside
    // `HeartbeatSigningPayload`, so the ONE existing heartbeat signature
    // (HEARTBEAT_DOMAIN ++ payload.encode(), exactly what
    // report_heartbeat_with_state computes above) already covers it. The
    // actual cross-language risk is therefore not a hand-rolled byte
    // layout (there isn't one) but whether prost's `encode` here and
    // protobuf-go's `proto.MarshalOptions{Deterministic: true}.Marshal`
    // agree byte-for-byte on the same field values, including the new
    // repeated `workload_bandwidth` field.
    //
    // This test builds a fixed payload (literal, not random, field
    // values -- so it's reproducible) and pins its encoded hex and the
    // Ed25519 signature over it with a fixed 32-byte seed key. Both
    // constants are asserted byte-for-byte identical in
    // control-plane/internal/providerjoin/bandwidth_test.go's
    // TestHeartbeatSigningPayloadWireBytesMatchRustFixture -- a mismatch
    // there means Go's deterministic marshal has drifted from prost's
    // encode, which would silently break every heartbeat signature
    // verification once an Agent starts sending workload_bandwidth.
    #[tokio::test]
    async fn heartbeat_signing_payload_wire_bytes_are_a_pinned_cross_language_fixture() {
        let payload = controlplanev1::HeartbeatSigningPayload {
            request_id: "11111111-1111-1111-1111-111111111111".to_string(),
            provider_id: "a".repeat(64),
            sequence: 7,
            observed_at: Some(prost_types::Timestamp {
                seconds: 1_700_000_000,
                nanos: 0,
            }),
            capabilities: Some(sharedv1::ResourceCapability {
                cpu_total: 8.0,
                cpu_available: 6.0,
                ram_total_mb: 16_384,
                ram_available_mb: 12_000,
                ..Default::default()
            }),
            workload_bandwidth: vec![controlplanev1::WorkloadBandwidthUsage {
                workload_id: "22222222-2222-2222-2222-222222222222".to_string(),
                ingress_bytes_total: 123_456,
                egress_bytes_total: 654_321,
                window_started_at: Some(prost_types::Timestamp {
                    seconds: 1_699_999_000,
                    nanos: 0,
                }),
            }],
        };
        let mut signed = Vec::with_capacity(HEARTBEAT_DOMAIN.len() + payload.encoded_len());
        signed.extend_from_slice(HEARTBEAT_DOMAIN);
        payload.encode(&mut signed).expect("encode payload");

        const EXPECTED_WIRE_BYTES_HEX: &str = "6f70656e696e6672612d6865617274626561742d7631000a2431313131313131312d313131312d313131312d313131312d313131313131313131313131124061616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161180722060880e2cfaa062a110d00000041150000c0401880800120e05d32360a2432323232323232322d323232322d323232322d323232322d32323232323232323232323210c0c40718f1f72722060898dacfaa06";
        assert_eq!(
            hex::encode(&signed),
            EXPECTED_WIRE_BYTES_HEX,
            "encoded wire bytes changed -- update this fixture and the \
             mirrored one in bandwidth_test.go together"
        );

        let directory = tempfile::tempdir().expect("temp dir");
        let key_path = directory.path().join("identity.key");
        std::fs::write(&key_path, [0x01u8; 32]).expect("write fixed key");
        let identity = Ed25519IdentityManager::new(key_path).expect("load fixed-seed identity");
        let public_key = identity.get_public_key().await.expect("public key");
        let signature = identity.sign(&signed).await.expect("sign fixture payload");

        assert!(identity
            .verify(&signed, &signature, &hex::decode(&public_key).expect("hex"))
            .await
            .expect("verify"));

        println!("wire_bytes_hex = {}", hex::encode(&signed));
        println!("public_key_hex = {public_key}");
        println!("signature_hex = {}", hex::encode(&signature));
    }
}
