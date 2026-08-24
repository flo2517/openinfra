// clippy::result_large_err fires against tonic::include_proto!'s generated
// trait method signatures below (every RPC handler returns
// Result<Response<T>, tonic::Status>) -- tonic::Status is a dependency
// type this crate has no control over, not something in this codebase to
// shrink or box; the lint newly started firing here on a clippy 1.98
// toolchain bump (CI floats `stable`, see .github/workflows/ci.yml) with
// no code change on our side. Crate-level, not per-function, since every
// RPC handler trips it identically for the same external-type reason.
#![allow(clippy::result_large_err)]

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

use crate::openinfra::shared::v1::MeteringSummary;
use crate::proto::*;
use agent_core::{identity::IdentityManager, local_state::LocalStateError, AgentConfig};
use agent_inventory::InventoryManager;
use async_trait::async_trait;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
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

// ADR-015 §1/§3: MeasureBandwidth's domain-separated signing constant and
// its payload-size bound. Reuses MAX_CHALLENGE_ID's convention for
// probe_id (same shape of field, same reasoning) but gets its own, much
// larger, payload bound -- MAX_CHALLENGE_PAYLOAD (4096 bytes) exists to
// bound a liveness/correctness proof-of-work input, not to produce a
// meaningful throughput timing signal. 8 MiB is large enough to time
// meaningfully even on a fast link (~7ms at 10 Gbps) and long enough to
// resolve realistic slower tiers (~640ms at 100 Mbps) without either
// flooding a slow link for an unreasonable duration or bounding the
// Agent's per-request memory/CPU cost any more loosely than every other
// Agent RPC already is bounded.
const BANDWIDTH_PROBE_DOMAIN: &[u8] = b"openinfra-bandwidth-probe-v1\0";
// pub: agent-cli's server setup needs this value too, to raise tonic's
// default 4 MiB gRPC message-size limit (which would otherwise reject
// this RPC's whole premise) -- see main.rs's ProviderAgentServiceServer
// construction. Keeping one definition, referenced from both places,
// instead of a second hard-coded number that could silently drift from
// this one.
pub const MAX_BANDWIDTH_PROBE_BYTES: usize = 8 * 1024 * 1024;

// ADR-015 §3: a per-caller rate limit scoped to just this RPC, so a
// validator (malicious or buggy) cannot use repeated MAX_BANDWIDTH_
// PROBE_BYTES-sized probes as a bandwidth-exhaustion vector against a
// provider it does not like. A plain fixed-window counter (see
// BandwidthRateLimiter below), not a token bucket -- this is an MVP abuse
// bound, not a QoS system, and the codebase's other MVP-shortcut rate
// limiters (e.g. control-plane/internal/ratelimit) are similarly simple.
// 10 calls/minute per caller is generous enough that the Network
// Validator's tick-driven retry loop (control-plane/internal/
// networkvalidator/run.go, ~3s poll interval, retries a failed submit_
// evidence on the next tick) is not throttled under ordinary transient
// chain-RPC failures, while still tightly bounding one caller's
// worst-case sustained traffic to a provider.
const BANDWIDTH_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const BANDWIDTH_RATE_LIMIT_MAX_CALLS: u32 = 10;

// ADR-029 §6 / issue #20: GetUsageSummary's signing domain, and the
// explicit metering-evidence schema version this Agent build produces
// (ADR-029 §1/§7 -- a future dimension/unit change bumps this rather
// than silently reinterpreting old evidence). Mirrored verbatim on the
// Control Plane side (control-plane/internal/metering) for both the
// domain string and the canonical byte layout below -- deliberately a
// hand-rolled encoding, not a proto marshal, for the same reason
// SolveChallenge/MeasureBandwidth already use one (agreement no longer
// depends on prost and protobuf-go producing byte-identical output).
const METERING_DOMAIN: &[u8] = b"openinfra-metering-v1\0";
const METERING_SCHEMA_VERSION: u32 = 1;
// Bounds one GetUsageSummary call's claimed period_end - period_start
// (ADR-029 §6/§7's MaxMeteringPeriodSeconds, mirrored here on the
// producing side; the Control Plane enforces its own bound
// independently and is the authoritative check). One hour: short enough
// that a lost/delayed relay does not accumulate an unbounded backlog of
// unbilled usage in a single summary, long enough not to require a
// GetUsageSummary call more than once an hour under normal operation.
const MAX_METERING_PERIOD_SECONDS: u64 = 3600;

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

/// One workload's bounded usage sample for a single metering period,
/// returned by `Executor::usage_summary` (ADR-029 §6 / issue #20).
///
/// `lease_id`/`sequence`/`period_start`/`period_end` are real, sourced
/// from the Agent's own durable local state
/// (`agent_core::local_state::LocalState::next_metering_period`) -- not
/// stubs. **The five usage counters are honest zero stubs in this PR**:
/// no per-container CPU/RAM/storage/network metric collection exists
/// yet anywhere in this codebase (bollard's container stats API is
/// unused; `agent-inventory` only reads host-level, not per-container,
/// resources). Wiring real collection is explicitly out of scope here
/// and tracked as its own follow-up issue (see the implementing PR's
/// description) -- returning fabricated non-zero numbers instead would
/// violate this repository's "never fake numbers as real" instruction
/// far more than an honest, documented zero does. Every value here still
/// flows through the same signed, bounded, replay-resistant evidence
/// pipeline a later PR's real collector will populate without any wire
/// or schema change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageSample {
    pub lease_id: String,
    pub sequence: u64,
    pub period_start: u64,
    pub period_end: u64,
    pub cpu_core_seconds: u64,
    pub ram_mb_seconds: u64,
    pub storage_gb_seconds: u64,
    pub network_egress_mb: u64,
    pub network_ingress_mb: u64,
    pub gpu_seconds: u64,
}

#[async_trait]
pub trait Executor: Send + Sync {
    async fn deploy(&self, req: DeployRequest) -> anyhow::Result<String>;
    async fn stop(&self, workload_id: &str) -> anyhow::Result<()>;
    async fn get_status(&self, workload_id: &str) -> anyhow::Result<WorkloadStatus>;
    /// `now`/`max_period_seconds` are passed down rather than read
    /// internally so the caller (agent-api's `get_usage_summary` RPC
    /// handler) owns the wall-clock read and the governed bound,
    /// keeping this trait's implementors (real or test doubles)
    /// deterministic given their inputs.
    async fn usage_summary(
        &self,
        workload_id: &str,
        now: u64,
        max_period_seconds: u64,
    ) -> anyhow::Result<UsageSample>;
}

pub struct AgentGrpcServer {
    pub config: AgentConfig,
    pub event_bus: mpsc::Sender<AgentEvent>,
    pub identity_manager: Arc<dyn IdentityManager>,
    pub inventory_manager: Arc<InventoryManager>,
    pub executor: Arc<dyn Executor>,
    pub bandwidth_rate_limiter: BandwidthRateLimiter,
}

/// Sentinel key for a MeasureBandwidth caller this handler could not
/// identify via its mTLS certificate (peer_certs() returned nothing, or
/// its leaf certificate isn't a parseable Ed25519 certificate). Every
/// unidentifiable caller shares this one bucket, so it still gets rate
/// limited rather than bypassing the limiter entirely -- not a claim that
/// this is any real caller's identity (an all-zero byte string is not a
/// valid Ed25519 public key any real handshake would present).
const UNKNOWN_CALLER: [u8; 32] = [0u8; 32];

/// Per-caller rate limiter for MeasureBandwidth (ADR-015 §3), keyed by
/// the caller's raw 32-byte Ed25519 public key extracted from its mTLS
/// leaf certificate (`caller_public_key`) -- the same identity agent-cli's
/// `mtls.rs` allowlist verifier already establishes trust on (ADR-013
/// §3), reused here purely as a rate-limiting key, not as a second trust
/// decision. A plain fixed window per caller: bounded, simple, and
/// sufficient for this MVP's "cap one caller's worst-case sustained
/// traffic" goal -- see the constants' doc comments for the exact
/// numbers and reasoning.
#[derive(Default)]
pub struct BandwidthRateLimiter {
    windows: Mutex<HashMap<[u8; 32], (u32, Instant)>>,
}

impl BandwidthRateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns true and records one call if `key` is still under budget
    /// for the current window; false (and records nothing) once the
    /// window's budget is exhausted. A stale window (its start is older
    /// than BANDWIDTH_RATE_LIMIT_WINDOW) resets rather than accumulating
    /// forever.
    fn allow(&self, key: [u8; 32]) -> bool {
        let mut windows = self
            .windows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Instant::now();
        let entry = windows.entry(key).or_insert((0, now));
        if now.duration_since(entry.1) >= BANDWIDTH_RATE_LIMIT_WINDOW {
            *entry = (0, now);
        }
        if entry.0 >= BANDWIDTH_RATE_LIMIT_MAX_CALLS {
            return false;
        }
        entry.0 += 1;
        true
    }
}

/// Extracts the calling client's raw 32-byte Ed25519 public key from the
/// leaf certificate of its mTLS connection, for use as
/// `BandwidthRateLimiter`'s per-caller key. `None` when no peer
/// certificate is available at all -- e.g. this crate exercised outside
/// a real TLS connection (a unit test), or (defense in depth) built
/// without tonic's "tls" feature active in this compilation unit; the
/// caller falls back to the shared `UNKNOWN_CALLER` bucket rather than
/// skipping rate limiting entirely. This does not perform authorization:
/// by the time any Agent RPC handler runs, the mTLS layer (ADR-013 §3)
/// has already decided whether to accept the connection at all.
fn caller_public_key<T>(request: &Request<T>) -> [u8; 32] {
    request
        .peer_certs()
        .and_then(|certs| certs.first().map(|cert| cert.get_ref().to_vec()))
        .and_then(|der| extract_ed25519_raw_public_key(&der))
        .unwrap_or(UNKNOWN_CALLER)
}

/// Parses `der` as an X.509 certificate and returns its raw 32-byte
/// Ed25519 SubjectPublicKeyInfo, or `None` if it isn't a parseable
/// Ed25519 certificate. Byte-for-byte the same approach as agent-cli's
/// `mtls::extract_ed25519_raw_public_key` (duplicated rather than
/// shared -- agent-api cannot depend on agent-cli).
fn extract_ed25519_raw_public_key(der: &[u8]) -> Option<[u8; 32]> {
    let (_, certificate) = x509_parser::parse_x509_certificate(der).ok()?;
    let spki = certificate.public_key();
    if spki.algorithm.algorithm != x509_parser::oid_registry::OID_SIG_ED25519 {
        return None;
    }
    <[u8; 32]>::try_from(spki.subject_public_key.data.as_ref()).ok()
}

/// Builds the exact byte sequence signed for a MeasureBandwidth response
/// (ADR-015 §4), deliberately mirroring `solve_challenge`'s existing
/// signing convention -- a domain constant, then fields in a documented,
/// unambiguous order -- rather than inventing a second, differently
/// shaped construction:
///
/// ```text
/// BANDWIDTH_PROBE_DOMAIN
///   ++ be_u32(len(probe_id)) ++ probe_id
///   ++ upload_payload_hash                       (32 bytes, fixed width: SHA256 output)
///   ++ be_u32(len(download_payload)) ++ download_payload
///   ++ be_u32(server_processing_ms)               (4 bytes, fixed width)
/// ```
///
/// `probe_id` and `download_payload` are variable-length and each get an
/// explicit big-endian u32 length prefix (matching how `solve_challenge`
/// frames `challenge_id`); `upload_payload_hash` is always exactly 32
/// bytes (SHA256's fixed output size) so it needs no length prefix to
/// stay unambiguous; `server_processing_ms` is already a fixed-width u32.
fn bandwidth_signed_bytes(
    probe_id: &str,
    upload_payload_hash: &[u8],
    download_payload: &[u8],
    server_processing_ms: u32,
) -> Vec<u8> {
    let mut signed = Vec::with_capacity(
        BANDWIDTH_PROBE_DOMAIN.len()
            + 4
            + probe_id.len()
            + upload_payload_hash.len()
            + 4
            + download_payload.len()
            + 4,
    );
    signed.extend_from_slice(BANDWIDTH_PROBE_DOMAIN);
    signed.extend_from_slice(&(probe_id.len() as u32).to_be_bytes());
    signed.extend_from_slice(probe_id.as_bytes());
    signed.extend_from_slice(upload_payload_hash);
    signed.extend_from_slice(&(download_payload.len() as u32).to_be_bytes());
    signed.extend_from_slice(download_payload);
    signed.extend_from_slice(&server_processing_ms.to_be_bytes());
    signed
}

/// Builds the exact byte sequence signed (and, hashed, correlated as
/// `evidence_hash`) for a `GetUsageSummary` response (ADR-029 §6, issue
/// #20). Mirrored byte-for-byte in Go by
/// `control-plane/internal/metering`'s verification code -- a mismatch
/// there means every metering signature fails verification.
///
/// ```text
/// METERING_DOMAIN
///   ++ be_u32(len(workload_id)) ++ workload_id
///   ++ be_u32(len(lease_id)) ++ lease_id
///   ++ be_u64(sequence)
///   ++ be_u64(period_start)
///   ++ be_u64(period_end)
///   ++ be_u32(metering_schema_version)
///   ++ be_u64(cpu_core_seconds)
///   ++ be_u64(ram_mb_seconds)
///   ++ be_u64(storage_gb_seconds)
///   ++ be_u64(network_egress_mb)
///   ++ be_u64(network_ingress_mb)
///   ++ be_u64(gpu_seconds)
/// ```
///
/// `workload_id`/`lease_id` are variable-length and get an explicit
/// big-endian u32 length prefix (matching `solve_challenge`'s and
/// `bandwidth_signed_bytes`'s existing framing convention for
/// variable-length fields); every counter is already fixed-width.
fn metering_signed_bytes(summary: &MeteringSummary) -> Vec<u8> {
    let mut signed = Vec::with_capacity(
        METERING_DOMAIN.len()
            + 4
            + summary.workload_id.len()
            + 4
            + summary.lease_id.len()
            + 8 * 8
            + 4,
    );
    signed.extend_from_slice(METERING_DOMAIN);
    signed.extend_from_slice(&(summary.workload_id.len() as u32).to_be_bytes());
    signed.extend_from_slice(summary.workload_id.as_bytes());
    signed.extend_from_slice(&(summary.lease_id.len() as u32).to_be_bytes());
    signed.extend_from_slice(summary.lease_id.as_bytes());
    signed.extend_from_slice(&summary.sequence.to_be_bytes());
    signed.extend_from_slice(&summary.period_start.to_be_bytes());
    signed.extend_from_slice(&summary.period_end.to_be_bytes());
    signed.extend_from_slice(&summary.metering_schema_version.to_be_bytes());
    signed.extend_from_slice(&summary.cpu_core_seconds.to_be_bytes());
    signed.extend_from_slice(&summary.ram_mb_seconds.to_be_bytes());
    signed.extend_from_slice(&summary.storage_gb_seconds.to_be_bytes());
    signed.extend_from_slice(&summary.network_egress_mb.to_be_bytes());
    signed.extend_from_slice(&summary.network_ingress_mb.to_be_bytes());
    signed.extend_from_slice(&summary.gpu_seconds.to_be_bytes());
    signed
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
            // ADR-013 slice 4 (issue #78): a Network Validator's challenge
            // loop also scores these two dimensions. Identical logic to
            // the three above -- this handler is generic over challenge
            // type, only the label differs.
            solve_challenge_request::Type::Network => "network",
            solve_challenge_request::Type::Reliability => "reliability",
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

    async fn measure_bandwidth(
        &self,
        request: Request<MeasureBandwidthRequest>,
    ) -> Result<Response<MeasureBandwidthResponse>, Status> {
        // Rate-limit before doing any real work, keyed off the caller
        // identity extracted from the still-intact request (peer_certs()
        // reads connection metadata that into_inner() below discards).
        let caller = caller_public_key(&request);
        if !self.bandwidth_rate_limiter.allow(caller) {
            return Err(Status::resource_exhausted(
                "MeasureBandwidth rate limit exceeded for this caller",
            ));
        }

        let request = request.into_inner();
        if request.probe_id.is_empty() || request.probe_id.len() > MAX_CHALLENGE_ID {
            return Err(Status::invalid_argument("probe_id is empty or too long"));
        }
        if request.upload_payload.len() > MAX_BANDWIDTH_PROBE_BYTES {
            return Err(Status::resource_exhausted("upload_payload is too large"));
        }
        if request.requested_download_bytes as usize > MAX_BANDWIDTH_PROBE_BYTES {
            return Err(Status::resource_exhausted(
                "requested_download_bytes exceeds the maximum probe size",
            ));
        }

        // ADR-015 §1: server_processing_ms measures processing only, not
        // request deserialization/queueing -- the clock starts here, right
        // after into_inner(), and stops just before the response is built.
        let started = Instant::now();

        let mut hasher = Sha256::new();
        hasher.update(&request.upload_payload);
        let upload_payload_hash = hasher.finalize().to_vec();

        // Random, not zeroed: an all-zero download_payload would let a
        // lazy/malicious Agent implementation skip real work (and real
        // bytes-on-the-wire) while still satisfying a naive length check.
        let mut download_payload = vec![0u8; request.requested_download_bytes as usize];
        rand::thread_rng().fill_bytes(&mut download_payload);

        let server_processing_ms = started.elapsed().as_millis().min(u128::from(u32::MAX)) as u32;

        let signed = bandwidth_signed_bytes(
            &request.probe_id,
            &upload_payload_hash,
            &download_payload,
            server_processing_ms,
        );
        let signature = self
            .identity_manager
            .sign(&signed)
            .await
            .map_err(|error| Status::internal(format!("identity signing failed: {error}")))?;

        Ok(Response::new(MeasureBandwidthResponse {
            probe_id: request.probe_id,
            upload_payload_hash,
            download_payload,
            server_processing_ms,
            signature,
        }))
    }

    async fn get_usage_summary(
        &self,
        request: Request<GetUsageSummaryRequest>,
    ) -> Result<Response<GetUsageSummaryResponse>, Status> {
        let req = request.into_inner();
        if req.workload_id.is_empty() || req.workload_id.len() > MAX_CHALLENGE_ID {
            return Err(Status::invalid_argument("workload_id is empty or too long"));
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        let sample = self
            .executor
            .usage_summary(&req.workload_id, now, MAX_METERING_PERIOD_SECONDS)
            .await
            .map_err(executor_status_error)?;

        let summary = MeteringSummary {
            workload_id: req.workload_id,
            lease_id: sample.lease_id,
            sequence: sample.sequence,
            period_start: sample.period_start,
            period_end: sample.period_end,
            metering_schema_version: METERING_SCHEMA_VERSION,
            cpu_core_seconds: sample.cpu_core_seconds,
            ram_mb_seconds: sample.ram_mb_seconds,
            storage_gb_seconds: sample.storage_gb_seconds,
            network_egress_mb: sample.network_egress_mb,
            network_ingress_mb: sample.network_ingress_mb,
            gpu_seconds: sample.gpu_seconds,
        };
        let signed = metering_signed_bytes(&summary);
        let signature = self
            .identity_manager
            .sign(&signed)
            .await
            .map_err(|error| Status::internal(format!("identity signing failed: {error}")))?;
        let mut hasher = Sha256::new();
        hasher.update(&signed);
        let evidence_hash = hex::encode(hasher.finalize());

        Ok(Response::new(GetUsageSummaryResponse {
            summary: Some(summary),
            signature,
            evidence_hash,
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
    use agent_core::identity::Ed25519IdentityManager;
    use proto::provider_agent_service_server::ProviderAgentService;

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

    struct NoopExecutor;

    #[async_trait]
    impl Executor for NoopExecutor {
        async fn deploy(&self, _req: DeployRequest) -> anyhow::Result<String> {
            unimplemented!("not exercised by MeasureBandwidth tests")
        }
        async fn stop(&self, _workload_id: &str) -> anyhow::Result<()> {
            unimplemented!("not exercised by MeasureBandwidth tests")
        }
        async fn get_status(&self, _workload_id: &str) -> anyhow::Result<WorkloadStatus> {
            unimplemented!("not exercised by MeasureBandwidth tests")
        }
        async fn usage_summary(
            &self,
            _workload_id: &str,
            _now: u64,
            _max_period_seconds: u64,
        ) -> anyhow::Result<UsageSample> {
            unimplemented!("not exercised by MeasureBandwidth tests")
        }
    }

    /// A minimal Executor double for GetUsageSummary tests: always
    /// returns a fixed UsageSample regardless of input, so the RPC
    /// handler's own signing/hashing/response-shaping logic can be
    /// exercised without a real DockerExecutor/LocalState.
    struct FixedUsageExecutor(UsageSample);

    #[async_trait]
    impl Executor for FixedUsageExecutor {
        async fn deploy(&self, _req: DeployRequest) -> anyhow::Result<String> {
            unimplemented!("not exercised by GetUsageSummary tests")
        }
        async fn stop(&self, _workload_id: &str) -> anyhow::Result<()> {
            unimplemented!("not exercised by GetUsageSummary tests")
        }
        async fn get_status(&self, _workload_id: &str) -> anyhow::Result<WorkloadStatus> {
            unimplemented!("not exercised by GetUsageSummary tests")
        }
        async fn usage_summary(
            &self,
            _workload_id: &str,
            _now: u64,
            _max_period_seconds: u64,
        ) -> anyhow::Result<UsageSample> {
            Ok(self.0.clone())
        }
    }

    /// A real generated Ed25519 identity, backed by a temp key file --
    /// exercising the same production `IdentityManager` implementation
    /// `solve_challenge`/`measure_bandwidth` sign through, not a fake.
    /// The returned `TempDir` must outlive its use (the key file is read
    /// once at generation and then held in memory, but keeping the
    /// directory alive avoids relying on that implementation detail).
    fn test_identity() -> (Arc<dyn IdentityManager>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let identity = Ed25519IdentityManager::generate(dir.path().join("identity.key"))
            .expect("generate identity");
        (Arc::new(identity), dir)
    }

    fn test_server(identity_manager: Arc<dyn IdentityManager>) -> AgentGrpcServer {
        test_server_with_executor(identity_manager, Arc::new(NoopExecutor))
    }

    fn test_server_with_executor(
        identity_manager: Arc<dyn IdentityManager>,
        executor: Arc<dyn Executor>,
    ) -> AgentGrpcServer {
        let (event_bus, _receiver) = mpsc::channel(1);
        AgentGrpcServer {
            config: AgentConfig::default(),
            event_bus,
            identity_manager,
            inventory_manager: Arc::new(InventoryManager::new()),
            executor,
            bandwidth_rate_limiter: BandwidthRateLimiter::new(),
        }
    }

    #[tokio::test]
    async fn valid_probe_succeeds_and_hash_and_signature_verify() {
        let (identity, _dir) = test_identity();
        let server = test_server(identity.clone());

        let upload_payload = vec![7u8; 1024];
        let request = Request::new(MeasureBandwidthRequest {
            probe_id: "probe-1".to_string(),
            upload_payload: upload_payload.clone(),
            requested_download_bytes: 512,
        });

        let response = server
            .measure_bandwidth(request)
            .await
            .expect("measure_bandwidth")
            .into_inner();

        let mut hasher = Sha256::new();
        hasher.update(&upload_payload);
        assert_eq!(response.upload_payload_hash, hasher.finalize().to_vec());
        assert_eq!(response.download_payload.len(), 512);
        assert_eq!(response.probe_id, "probe-1");

        let signed = bandwidth_signed_bytes(
            &response.probe_id,
            &response.upload_payload_hash,
            &response.download_payload,
            response.server_processing_ms,
        );
        let public_key_hex = identity.get_public_key().await.expect("public key");
        let public_key = hex::decode(public_key_hex).expect("hex decode public key");
        assert!(identity
            .verify(&signed, &response.signature, &public_key)
            .await
            .expect("verify signature"));

        // A tampered signature must not verify -- confirms the check above
        // is actually exercising real verification, not vacuously true.
        let mut tampered = response.signature.clone();
        tampered[0] ^= 0xFF;
        assert!(!identity
            .verify(&signed, &tampered, &public_key)
            .await
            .expect("verify tampered signature"));
    }

    #[tokio::test]
    async fn oversized_upload_payload_is_rejected() {
        let (identity, _dir) = test_identity();
        let server = test_server(identity);

        let request = Request::new(MeasureBandwidthRequest {
            probe_id: "probe-oversized-upload".to_string(),
            upload_payload: vec![0u8; MAX_BANDWIDTH_PROBE_BYTES + 1],
            requested_download_bytes: 0,
        });

        let status = server
            .measure_bandwidth(request)
            .await
            .expect_err("oversized upload_payload must be rejected");
        assert_eq!(status.code(), tonic::Code::ResourceExhausted);
    }

    #[tokio::test]
    async fn oversized_requested_download_bytes_is_rejected() {
        let (identity, _dir) = test_identity();
        let server = test_server(identity);

        let request = Request::new(MeasureBandwidthRequest {
            probe_id: "probe-oversized-download".to_string(),
            upload_payload: vec![],
            requested_download_bytes: (MAX_BANDWIDTH_PROBE_BYTES + 1) as u32,
        });

        let status = server
            .measure_bandwidth(request)
            .await
            .expect_err("oversized requested_download_bytes must be rejected");
        assert_eq!(status.code(), tonic::Code::ResourceExhausted);
    }

    #[tokio::test]
    async fn empty_probe_id_is_rejected() {
        let (identity, _dir) = test_identity();
        let server = test_server(identity);

        let request = Request::new(MeasureBandwidthRequest {
            probe_id: String::new(),
            upload_payload: vec![],
            requested_download_bytes: 0,
        });

        let status = server
            .measure_bandwidth(request)
            .await
            .expect_err("empty probe_id must be rejected");
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn download_payload_length_exactly_matches_the_request() {
        let (identity, _dir) = test_identity();
        let server = test_server(identity);

        let request = Request::new(MeasureBandwidthRequest {
            probe_id: "probe-exact-length".to_string(),
            upload_payload: vec![],
            requested_download_bytes: 12_345,
        });

        let response = server
            .measure_bandwidth(request)
            .await
            .expect("measure_bandwidth")
            .into_inner();
        assert_eq!(response.download_payload.len(), 12_345);
    }

    /// Two concurrent calls sharing the same probe_id must not corrupt
    /// each other's result -- a concurrency-safety check (the handler has
    /// no business-logic reason to reject a repeated probe_id; the server
    /// deliberately does not enforce probe_id uniqueness).
    #[tokio::test]
    async fn concurrent_calls_with_the_same_probe_id_do_not_cross_talk() {
        let (identity, _dir) = test_identity();
        let server = Arc::new(test_server(identity));

        let upload_a = vec![1u8; 4096];
        let upload_b = vec![2u8; 8192];

        let server_a = server.clone();
        let upload_a_clone = upload_a.clone();
        let task_a = tokio::spawn(async move {
            let request = Request::new(MeasureBandwidthRequest {
                probe_id: "shared-probe-id".to_string(),
                upload_payload: upload_a_clone,
                requested_download_bytes: 256,
            });
            server_a
                .measure_bandwidth(request)
                .await
                .expect("measure_bandwidth a")
                .into_inner()
        });

        let server_b = server.clone();
        let upload_b_clone = upload_b.clone();
        let task_b = tokio::spawn(async move {
            let request = Request::new(MeasureBandwidthRequest {
                probe_id: "shared-probe-id".to_string(),
                upload_payload: upload_b_clone,
                requested_download_bytes: 512,
            });
            server_b
                .measure_bandwidth(request)
                .await
                .expect("measure_bandwidth b")
                .into_inner()
        });

        let response_a = task_a.await.expect("task a joined");
        let response_b = task_b.await.expect("task b joined");

        let mut hasher_a = Sha256::new();
        hasher_a.update(&upload_a);
        assert_eq!(response_a.upload_payload_hash, hasher_a.finalize().to_vec());
        assert_eq!(response_a.download_payload.len(), 256);

        let mut hasher_b = Sha256::new();
        hasher_b.update(&upload_b);
        assert_eq!(response_b.upload_payload_hash, hasher_b.finalize().to_vec());
        assert_eq!(response_b.download_payload.len(), 512);
    }

    #[test]
    fn rate_limiter_blocks_a_caller_once_its_window_budget_is_exhausted() {
        let limiter = BandwidthRateLimiter::new();
        let caller = [7u8; 32];
        for _ in 0..BANDWIDTH_RATE_LIMIT_MAX_CALLS {
            assert!(
                limiter.allow(caller),
                "expected a call under budget to be allowed"
            );
        }
        assert!(
            !limiter.allow(caller),
            "expected a call over budget to be rejected"
        );
        // A different caller has its own independent budget.
        assert!(limiter.allow([9u8; 32]));
    }

    #[tokio::test]
    async fn rate_limit_exceeded_is_reported_as_resource_exhausted() {
        let (identity, _dir) = test_identity();
        let server = test_server(identity);

        let make_request = || {
            Request::new(MeasureBandwidthRequest {
                probe_id: "probe-rate-limit".to_string(),
                upload_payload: vec![],
                requested_download_bytes: 0,
            })
        };
        for _ in 0..BANDWIDTH_RATE_LIMIT_MAX_CALLS {
            server
                .measure_bandwidth(make_request())
                .await
                .expect("call under budget must succeed");
        }
        let status = server
            .measure_bandwidth(make_request())
            .await
            .expect_err("call over budget must be rejected");
        assert_eq!(status.code(), tonic::Code::ResourceExhausted);
    }

    #[test]
    fn caller_public_key_falls_back_to_unknown_when_no_peer_certificate_is_present() {
        let request: Request<MeasureBandwidthRequest> =
            Request::new(MeasureBandwidthRequest::default());
        assert_eq!(caller_public_key(&request), UNKNOWN_CALLER);
    }

    #[test]
    fn extract_ed25519_raw_public_key_matches_a_real_self_signed_certificate() {
        use rcgen::{CertificateParams, DnType, KeyPair, PKCS_ED25519};

        let key_pair = KeyPair::generate_for(&PKCS_ED25519).expect("generate key");
        let raw_key: [u8; 32] = key_pair
            .public_key_raw()
            .try_into()
            .expect("32-byte raw key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params
            .distinguished_name
            .push(DnType::CommonName, "bandwidth-probe-test");
        let cert = params.self_signed(&key_pair).expect("self-sign");

        let extracted =
            extract_ed25519_raw_public_key(&cert.der()[..]).expect("parse Ed25519 certificate");
        assert_eq!(extracted, raw_key);
    }

    #[test]
    fn bandwidth_signed_bytes_changes_when_any_field_changes() {
        let base = bandwidth_signed_bytes("probe", &[1u8; 32], b"payload", 42);
        assert_ne!(
            base,
            bandwidth_signed_bytes("other", &[1u8; 32], b"payload", 42)
        );
        assert_ne!(
            base,
            bandwidth_signed_bytes("probe", &[2u8; 32], b"payload", 42)
        );
        assert_ne!(
            base,
            bandwidth_signed_bytes("probe", &[1u8; 32], b"different", 42)
        );
        assert_ne!(
            base,
            bandwidth_signed_bytes("probe", &[1u8; 32], b"payload", 43)
        );
    }

    fn fixed_usage_sample() -> UsageSample {
        UsageSample {
            lease_id: "lease-1".to_string(),
            sequence: 1,
            period_start: 1_700_000_000,
            period_end: 1_700_000_900,
            cpu_core_seconds: 0,
            ram_mb_seconds: 0,
            storage_gb_seconds: 0,
            network_egress_mb: 0,
            network_ingress_mb: 0,
            gpu_seconds: 0,
        }
    }

    #[tokio::test]
    async fn get_usage_summary_returns_a_signature_that_verifies_against_the_response() {
        let (identity, _dir) = test_identity();
        let server = test_server_with_executor(
            identity.clone(),
            Arc::new(FixedUsageExecutor(fixed_usage_sample())),
        );

        let response = server
            .get_usage_summary(Request::new(GetUsageSummaryRequest {
                workload_id: "workload-1".to_string(),
            }))
            .await
            .expect("get_usage_summary")
            .into_inner();

        let summary = response.summary.expect("summary is present");
        assert_eq!(summary.workload_id, "workload-1");
        assert_eq!(summary.lease_id, "lease-1");
        assert_eq!(summary.sequence, 1);
        assert_eq!(summary.metering_schema_version, METERING_SCHEMA_VERSION);

        let signed = metering_signed_bytes(&summary);
        let public_key_hex = identity.get_public_key().await.expect("public key");
        let public_key = hex::decode(public_key_hex).expect("hex decode public key");
        assert!(identity
            .verify(&signed, &response.signature, &public_key)
            .await
            .expect("verify signature"));

        let mut hasher = Sha256::new();
        hasher.update(&signed);
        assert_eq!(response.evidence_hash, hex::encode(hasher.finalize()));

        // A tampered signature must not verify.
        let mut tampered = response.signature.clone();
        tampered[0] ^= 0xFF;
        assert!(!identity
            .verify(&signed, &tampered, &public_key)
            .await
            .expect("verify tampered signature"));
    }

    #[tokio::test]
    async fn get_usage_summary_rejects_empty_workload_id() {
        let (identity, _dir) = test_identity();
        let server =
            test_server_with_executor(identity, Arc::new(FixedUsageExecutor(fixed_usage_sample())));
        let status = server
            .get_usage_summary(Request::new(GetUsageSummaryRequest {
                workload_id: String::new(),
            }))
            .await
            .expect_err("empty workload_id must be rejected");
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn get_usage_summary_maps_unknown_workload_to_not_found() {
        struct MissingWorkloadExecutor;
        #[async_trait]
        impl Executor for MissingWorkloadExecutor {
            async fn deploy(&self, _req: DeployRequest) -> anyhow::Result<String> {
                unimplemented!()
            }
            async fn stop(&self, _workload_id: &str) -> anyhow::Result<()> {
                unimplemented!()
            }
            async fn get_status(&self, _workload_id: &str) -> anyhow::Result<WorkloadStatus> {
                unimplemented!()
            }
            async fn usage_summary(
                &self,
                workload_id: &str,
                _now: u64,
                _max_period_seconds: u64,
            ) -> anyhow::Result<UsageSample> {
                Err(LocalStateError::WorkloadNotFound(workload_id.to_string()).into())
            }
        }
        let (identity, _dir) = test_identity();
        let server = test_server_with_executor(identity, Arc::new(MissingWorkloadExecutor));
        let status = server
            .get_usage_summary(Request::new(GetUsageSummaryRequest {
                workload_id: "missing".to_string(),
            }))
            .await
            .expect_err("unknown workload must be rejected");
        assert_eq!(status.code(), tonic::Code::NotFound);
    }

    // ADR-029 §6's cross-language pin, the same convention
    // heartbeat_signing_payload_wire_bytes_are_a_pinned_cross_language_fixture
    // (agent-cli/src/main.rs) already established: a fixed-field summary,
    // its pinned canonical-byte hex, and the Ed25519 signature over it
    // with a fixed 32-byte seed key. Mirrored byte-for-byte in
    // control-plane/internal/metering/signing_test.go -- a mismatch there
    // means Go's verification has drifted from this encoding.
    #[tokio::test]
    async fn metering_signed_bytes_are_a_pinned_cross_language_fixture() {
        let summary = MeteringSummary {
            workload_id: "22222222-2222-2222-2222-222222222222".to_string(),
            lease_id: "42".to_string(),
            sequence: 7,
            period_start: 1_700_000_000,
            period_end: 1_700_003_600,
            metering_schema_version: 1,
            cpu_core_seconds: 3600,
            ram_mb_seconds: 16_384_000,
            storage_gb_seconds: 100,
            network_egress_mb: 512,
            network_ingress_mb: 256,
            gpu_seconds: 0,
        };
        let signed = metering_signed_bytes(&summary);

        const EXPECTED_WIRE_BYTES_HEX: &str = "6f70656e696e6672612d6d65746572696e672d7631000000002432323232323232322d323232322d323232322d323232322d3232323232323232323232320000000234320000000000000007000000006553f100000000006553ff10000000010000000000000e100000000000fa00000000000000000064000000000000020000000000000001000000000000000000";
        assert_eq!(
            hex::encode(&signed),
            EXPECTED_WIRE_BYTES_HEX,
            "encoded signed bytes changed -- update this fixture and the \
             mirrored one in signing_test.go together"
        );

        let directory = tempfile::tempdir().expect("temp dir");
        let key_path = directory.path().join("identity.key");
        std::fs::write(&key_path, [0x02u8; 32]).expect("write fixed key");
        let identity = Ed25519IdentityManager::new(key_path).expect("load fixed-seed identity");
        let public_key = identity.get_public_key().await.expect("public key");
        let signature = identity.sign(&signed).await.expect("sign fixture");
        assert!(identity
            .verify(
                &signed,
                &signature,
                &hex::decode(&public_key).expect("hex decode")
            )
            .await
            .expect("verify fixture signature"));
        // Pinned for signing_test.go's mirrored Go-side verification
        // fixture (Ed25519 signature over EXPECTED_WIRE_BYTES_HEX with
        // seed key [0x02; 32]) -- asserted here too so a future change to
        // either side's Ed25519 stack is caught locally, not only in Go.
        assert_eq!(
            public_key,
            "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394"
        );
        assert_eq!(
            hex::encode(&signature),
            "58698a07b133dae02aad9eda2d3ce20991cfeae5fcad6b380f7fe0074233826\
             f7181d50929242193ffb3ef0dd8dd0ec717143282e3e6798534f64678342b74\
             0e"
        );
    }
}
