package providerjoin

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/openinfra/network/internal/eventlog"
	"github.com/openinfra/network/internal/pki"
	controlplanev1 "github.com/openinfra/network/protocol/generated/go/controlplane/v1"
	sharedv1 "github.com/openinfra/network/protocol/generated/go/shared/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	joinDomain               = "openinfra-join-v1\x00"
	heartbeatDomain          = "openinfra-heartbeat-v1\x00"
	defaultChallengeTTL      = 2 * time.Minute
	defaultHeartbeatInterval = 15 * time.Second
	defaultHeartbeatTTL      = 45 * time.Second
	maxHeartbeatClockSkew    = 2 * time.Minute
)

var (
	ErrConflict          = errors.New("idempotency conflict")
	ErrChallengeNotFound = errors.New("challenge not found")
	ErrChallengeExpired  = errors.New("challenge expired")
	ErrChallengeConsumed = errors.New("challenge consumed")
	ErrProviderNotFound  = errors.New("provider not found")
	ErrHeartbeatReplay   = errors.New("heartbeat sequence is not increasing")
)

type Challenge struct {
	ChallengeID     string
	BeginRequestID  string
	RequestHash     [32]byte
	PublicKey       []byte
	ProtocolVersion string
	AgentVersion    string
	AgentEndpoint   string
	Nonce           []byte
	ExpiresAt       time.Time
}

type Completion struct {
	RequestID    string
	RequestHash  [32]byte
	Challenge    Challenge
	ProviderID   string
	Capabilities []byte
	RegisteredAt time.Time
	Status       sharedv1.NodeStatus
}

type ChainFinalization struct {
	ExtrinsicHash        []byte
	FinalizedBlockHash   []byte
	FinalizedBlockNumber uint64
}

type ProviderIdentity struct {
	PublicKey []byte
	Status    sharedv1.NodeStatus
}

type Repository interface {
	CreateOrGetChallenge(context.Context, Challenge) (Challenge, error)
	GetChallenge(context.Context, string) (Challenge, error)
	CompleteJoin(context.Context, Completion) (Completion, error)
	ActivateProvider(context.Context, string, ChainFinalization) (Completion, error)
	ProviderIdentity(context.Context, string) (ProviderIdentity, error)
}

type ProviderRegistrar interface {
	EnsureActive(context.Context, [ed25519.PublicKeySize]byte) ([]byte, []byte, uint64, error)
}

type HeartbeatStore interface {
	Accept(context.Context, string, string, uint64, [32]byte, []byte, time.Duration) error
}

type WorkloadService interface {
	SubmitWorkload(context.Context, *controlplanev1.SubmitWorkloadRequest) (*controlplanev1.SubmitWorkloadResponse, error)
	GetWorkload(context.Context, *controlplanev1.GetWorkloadRequest) (*controlplanev1.GetWorkloadResponse, error)
	StopWorkload(context.Context, *controlplanev1.StopWorkloadRequest) (*controlplanev1.StopWorkloadResponse, error)
}

// WorkloadReconciler reconciles this heartbeat's Agent-reported
// workload_status against the Control Plane's own authoritative workload
// state (ADR-028 §4). Optional, like ValidatorSource/BandwidthUsageStore:
// SetWorkloadReconciler may be left unset, and a reconciliation failure
// degrades to a warning log inside ReportHeartbeat rather than failing the
// whole heartbeat -- liveness (this RPC's core job) must not depend on
// reconciliation succeeding, the same fail-open posture every other
// optional heartbeat side-effect in this file already uses.
type WorkloadReconciler interface {
	ReconcileWorkloadStatus(ctx context.Context, providerID string, statuses []*controlplanev1.WorkloadStatusSummary) error
}

// ValidatorSource reads the current active Network Validator set (raw
// 32-byte Ed25519 public keys) so ReportHeartbeat can push it to the Agent
// every ~15s (ADR-013 §3). Optional, like orchestrator's ReputationSource:
// SetValidatorSource may be left unset, and a read failure once set must
// degrade to an empty allowlist rather than fail the heartbeat -- liveness
// must never depend on the chain being reachable.
type ValidatorSource interface {
	LatestActiveNetworkValidators(ctx context.Context) ([][32]byte, error)
}

// EventExporter is SubscribeEvents' (ADR-039 §10, issue #33) read
// dependency: eventlog.PostgresRepository's ExportSubject implements this
// directly. Optional, like ValidatorSource/WorkloadReconciler:
// SetEventExporter may be left unset, in which case SubscribeEvents fails
// loudly with Unavailable (matching SubmitWorkload/GetWorkload/
// StopWorkload's own nil-guard convention just below) rather than
// silently streaming nothing -- a witness getting an explicit "not
// configured" error is very different from a witness that believes it
// received a subject's complete (empty) history.
type EventExporter interface {
	ExportSubject(ctx context.Context, subjectType eventlog.SubjectType, subjectID []byte, sinceSequence uint64, limit int) ([]eventlog.Entry, error)
}

type Service struct {
	controlplanev1.UnimplementedControlPlaneServiceServer
	repository         Repository
	heartbeats         HeartbeatStore
	registrar          ProviderRegistrar
	now                func() time.Time
	challengeTTL       time.Duration
	heartbeatInterval  time.Duration
	workloads          WorkloadService
	validators         ValidatorSource
	bandwidthUsage     BandwidthUsageStore
	workloadReconciler WorkloadReconciler
	ca                 *pki.CA
	renewalNonces      RenewalNonceStore
	eventExporter      EventExporter
}

func (s *Service) SetWorkloadService(workloads WorkloadService) { s.workloads = workloads }

// SetValidatorSource enables pushing the active Network Validator allowlist
// on every heartbeat response. See ValidatorSource's doc comment for the
// degraded-mode behavior when unset or when a read fails.
func (s *Service) SetValidatorSource(validators ValidatorSource) { s.validators = validators }

// SetWorkloadReconciler enables ADR-028 §4 status-first reconciliation on
// every heartbeat. See WorkloadReconciler's doc comment for the
// degraded-mode behavior when unset or when reconciliation fails.
func (s *Service) SetWorkloadReconciler(reconciler WorkloadReconciler) {
	s.workloadReconciler = reconciler
}

// SetCertificateAuthority enables ADR-027 mTLS PKI enrollment
// (CompleteJoin) and renewal (RenewCertificate). Left unset, CompleteJoin
// silently skips issuance for a caller that doesn't set tls_public_key
// (legacy Agents on the pre-ADR-027 static-cert path keep working
// unaffected, matching the ADR §6 migration sequencing), and both
// RenewCertificate and a CompleteJoin that DOES set tls_public_key fail
// loudly with Unavailable rather than silently omitting a certificate the
// caller explicitly asked for.
func (s *Service) SetCertificateAuthority(ca *pki.CA) { s.ca = ca }

// SetRenewalNonceStore enables RenewCertificate's replay protection (the
// nonce half of ADR-027 §3's timestamp+nonce shape, mirroring
// ReportHeartbeat's sequence check). Required whenever a CA is configured;
// RenewCertificate returns Unavailable without it rather than accepting a
// renewal with no replay protection at all.
func (s *Service) SetRenewalNonceStore(store RenewalNonceStore) { s.renewalNonces = store }

// SetEventExporter enables SubscribeEvents (ADR-039 §10). See
// EventExporter's own doc comment for the fail-loud behavior when unset.
func (s *Service) SetEventExporter(exporter EventExporter) { s.eventExporter = exporter }

func (s *Service) SubmitWorkload(ctx context.Context, request *controlplanev1.SubmitWorkloadRequest) (*controlplanev1.SubmitWorkloadResponse, error) {
	if s.workloads == nil {
		return nil, status.Error(codes.Unavailable, "workload service is unavailable")
	}
	return s.workloads.SubmitWorkload(ctx, request)
}

func (s *Service) GetWorkload(ctx context.Context, request *controlplanev1.GetWorkloadRequest) (*controlplanev1.GetWorkloadResponse, error) {
	if s.workloads == nil {
		return nil, status.Error(codes.Unavailable, "workload service is unavailable")
	}
	return s.workloads.GetWorkload(ctx, request)
}

func (s *Service) StopWorkload(ctx context.Context, request *controlplanev1.StopWorkloadRequest) (*controlplanev1.StopWorkloadResponse, error) {
	if s.workloads == nil {
		return nil, status.Error(codes.Unavailable, "workload service is unavailable")
	}
	return s.workloads.StopWorkload(ctx, request)
}

func NewService(repository Repository, heartbeats HeartbeatStore, registrar ProviderRegistrar) *Service {
	return &Service{
		repository:        repository,
		heartbeats:        heartbeats,
		registrar:         registrar,
		now:               time.Now,
		challengeTTL:      defaultChallengeTTL,
		heartbeatInterval: defaultHeartbeatInterval,
	}
}

func (s *Service) BeginJoin(ctx context.Context, request *controlplanev1.BeginJoinRequest) (*controlplanev1.BeginJoinResponse, error) {
	if err := validateBeginJoin(request); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, status.Error(codes.Internal, "challenge generation failed")
	}
	challenge := Challenge{
		ChallengeID:     uuid.NewString(),
		BeginRequestID:  request.RequestId,
		RequestHash:     beginRequestHash(request),
		PublicKey:       bytes.Clone(request.PublicKey),
		ProtocolVersion: request.ProtocolVersion,
		AgentVersion:    request.AgentVersion,
		AgentEndpoint:   request.AgentEndpoint,
		Nonce:           nonce,
		ExpiresAt:       s.now().UTC().Add(s.challengeTTL),
	}
	stored, err := s.repository.CreateOrGetChallenge(ctx, challenge)
	if err != nil {
		return nil, repositoryError(err)
	}
	return &controlplanev1.BeginJoinResponse{
		ChallengeId:    stored.ChallengeID,
		ChallengeNonce: bytes.Clone(stored.Nonce),
		ExpiresAt:      timestamppb.New(stored.ExpiresAt),
	}, nil
}

func (s *Service) CompleteJoin(ctx context.Context, request *controlplanev1.CompleteJoinRequest) (*controlplanev1.CompleteJoinResponse, error) {
	if err := validateCompleteJoin(request); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	challenge, err := s.repository.GetChallenge(ctx, request.ChallengeId)
	if err != nil {
		return nil, repositoryError(err)
	}
	signed := append([]byte(joinDomain), challenge.Nonce...)
	if !ed25519.Verify(ed25519.PublicKey(challenge.PublicKey), signed, request.ChallengeSignature) {
		return nil, status.Error(codes.Unauthenticated, "invalid challenge signature")
	}
	capabilities, err := proto.Marshal(request.Capabilities)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid capabilities")
	}
	now := s.now().UTC()
	providerDigest := sha256.Sum256(challenge.PublicKey)
	completed, err := s.repository.CompleteJoin(ctx, Completion{
		RequestID:    request.RequestId,
		RequestHash:  completeRequestHash(request, capabilities),
		Challenge:    challenge,
		ProviderID:   hex.EncodeToString(providerDigest[:]),
		Capabilities: capabilities,
		RegisteredAt: now,
		Status:       sharedv1.NodeStatus_NODE_STATUS_PENDING,
	})
	if err != nil {
		return nil, repositoryError(err)
	}
	if completed.Status != sharedv1.NodeStatus_NODE_STATUS_ACTIVE {
		if s.registrar == nil {
			return nil, status.Error(codes.Unavailable, "blockchain registrar is unavailable")
		}
		var publicKey [ed25519.PublicKeySize]byte
		copy(publicKey[:], challenge.PublicKey)
		extrinsicHash, blockHash, blockNumber, registerErr := s.registrar.EnsureActive(ctx, publicKey)
		if registerErr != nil {
			slog.Error("provider blockchain registration failed", "provider_id", completed.ProviderID, "error", registerErr)
			return nil, status.Error(codes.Unavailable, "provider registration is not finalized")
		}
		completed, err = s.repository.ActivateProvider(ctx, completed.ProviderID, ChainFinalization{
			ExtrinsicHash: extrinsicHash, FinalizedBlockHash: blockHash, FinalizedBlockNumber: blockNumber,
		})
		if err != nil {
			return nil, repositoryError(err)
		}
	}
	response := &controlplanev1.CompleteJoinResponse{
		ProviderId:               completed.ProviderID,
		Status:                   completed.Status,
		RegisteredAt:             timestamppb.New(completed.RegisteredAt),
		HeartbeatIntervalSeconds: uint32(s.heartbeatInterval / time.Second),
	}
	// ADR-027 §2: enrollment extends CompleteJoin rather than adding a new
	// step. tls_public_key is optional on the wire (a caller that doesn't
	// ask for mTLS enrollment isn't issued a certificate), but a caller
	// that DOES ask and finds no CA configured gets a loud error, not a
	// silently empty certificate_pem it would only discover was missing
	// once it tries to dial with it.
	if len(request.TlsPublicKey) == ed25519.PublicKeySize {
		if s.ca == nil {
			return nil, status.Error(codes.Unavailable, "certificate issuance is unavailable")
		}
		issued, err := s.ca.IssueLeaf(completed.ProviderID, ed25519.PublicKey(request.TlsPublicKey), now, pki.DefaultLeafTTL)
		if err != nil {
			slog.Error("leaf certificate issuance failed", "provider_id", completed.ProviderID, "error", err)
			return nil, status.Error(codes.Internal, "certificate issuance failed")
		}
		response.CertificatePem = issued.CertificatePEM
		response.CertificateExpiresAt = timestamppb.New(issued.ExpiresAt)
	}
	return response, nil
}

func (s *Service) ReportHeartbeat(ctx context.Context, request *controlplanev1.ReportHeartbeatRequest) (*controlplanev1.ReportHeartbeatResponse, error) {
	if s.heartbeats == nil {
		return nil, status.Error(codes.Unavailable, "heartbeat cache is unavailable")
	}
	if err := validateHeartbeat(request, s.now().UTC()); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	identity, err := s.repository.ProviderIdentity(ctx, request.Payload.ProviderId)
	if err != nil {
		return nil, repositoryError(err)
	}
	payloadBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(request.Payload)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid heartbeat payload")
	}
	signed := append([]byte(heartbeatDomain), payloadBytes...)
	if identity.Status != sharedv1.NodeStatus_NODE_STATUS_ACTIVE {
		return nil, status.Error(codes.FailedPrecondition, "provider is not active")
	}
	if !ed25519.Verify(ed25519.PublicKey(identity.PublicKey), signed, request.Signature) {
		return nil, status.Error(codes.Unauthenticated, "invalid heartbeat signature")
	}
	payloadHash := sha256.Sum256(payloadBytes)
	if err := s.heartbeats.Accept(ctx, request.Payload.ProviderId, request.Payload.RequestId, request.Payload.Sequence, payloadHash, payloadBytes, defaultHeartbeatTTL); err != nil {
		return nil, repositoryError(err)
	}
	s.recordBandwidthUsage(ctx, request.Payload.ProviderId, request.Payload.WorkloadBandwidth)
	// ADR-028 §4: reconciled synchronously, before this RPC returns its
	// response -- not a separate async pass -- so "the Control Plane
	// never dispatches a new command against stale state" holds by
	// construction: internal/orchestrator's dispatch path only ever acts
	// on the Postgres state this call just updated.
	s.reconcileWorkloadStatus(ctx, request.Payload.ProviderId, request.Payload.WorkloadStatus)
	now := s.now().UTC()
	return &controlplanev1.ReportHeartbeatResponse{
		Status:               sharedv1.NodeStatus_NODE_STATUS_ACTIVE,
		AcceptedAt:           timestamppb.New(now),
		NextHeartbeatSeconds: uint32(s.heartbeatInterval / time.Second),
		ActiveValidators:     s.activeValidators(ctx),
	}, nil
}

// activeValidators reads the current active Network Validator set for the
// heartbeat response. A read failure (chain unreachable, RPC error) or an
// unset source degrades to an empty list rather than failing the
// heartbeat -- liveness (this RPC's core job) must not depend on chain
// availability. Logged at warn, not error: an Agent temporarily missing a
// refreshed allowlist is a availability/degraded-mode concern, not a bug.
func (s *Service) activeValidators(ctx context.Context) [][]byte {
	if s.validators == nil {
		return nil
	}
	accounts, err := s.validators.LatestActiveNetworkValidators(ctx)
	if err != nil {
		slog.Warn("active validator set unavailable; pushing empty allowlist", "error", err)
		return nil
	}
	keys := make([][]byte, len(accounts))
	for i, account := range accounts {
		keys[i] = bytes.Clone(account[:])
	}
	return keys
}

// reconcileWorkloadStatus is ReportHeartbeat's ADR-028 §4 side-effect: a
// reconciliation failure (Postgres error, etc.) is logged at warn and does
// not fail the heartbeat -- see WorkloadReconciler's doc comment for the
// reasoning. Skipped entirely when unset (nil workloadReconciler), the
// same optional-dependency shape as activeValidators/recordBandwidthUsage
// above.
func (s *Service) reconcileWorkloadStatus(ctx context.Context, providerID string, statuses []*controlplanev1.WorkloadStatusSummary) {
	if s.workloadReconciler == nil || len(statuses) == 0 {
		return
	}
	if err := s.workloadReconciler.ReconcileWorkloadStatus(ctx, providerID, statuses); err != nil {
		slog.Warn("workload status reconciliation failed", "provider_id", providerID, "error", err)
	}
}

// maxWorkloadStatusEntriesPerHeartbeat mirrors
// maxWorkloadBandwidthEntriesPerHeartbeat's reasoning (bandwidth.go):
// bounded by the Agent's own max_workloads setting (default 8), but the
// Control Plane enforces its own generous ceiling regardless, so a
// legitimate Agent with a higher configured limit is never rejected while
// a wildly out-of-proportion payload (bug or abuse) still is.
const maxWorkloadStatusEntriesPerHeartbeat = 256

// validateWorkloadStatus checks the structural shape of each
// workload_status entry ADR-028 §4 adds to the heartbeat payload. Mirrors
// validateWorkloadBandwidth's shape and reasoning (bandwidth.go):
// malformed entries fail the whole heartbeat up front, the same way any
// other malformed top-level field already does.
func validateWorkloadStatus(entries []*controlplanev1.WorkloadStatusSummary) error {
	if len(entries) > maxWorkloadStatusEntriesPerHeartbeat {
		return errors.New("workload_status exceeds the maximum entries per heartbeat")
	}
	for _, entry := range entries {
		if entry == nil {
			return errors.New("workload_status entries must not be nil")
		}
		if _, err := uuid.Parse(entry.WorkloadId); err != nil {
			return errors.New("workload_status[].workload_id must be a UUID")
		}
	}
	return nil
}

func validateHeartbeat(request *controlplanev1.ReportHeartbeatRequest, now time.Time) error {
	if request == nil || request.Payload == nil {
		return errors.New("payload is required")
	}
	if len(request.Payload.ProtoReflect().GetUnknown()) != 0 {
		return errors.New("payload contains unknown fields")
	}
	if _, err := uuid.Parse(request.Payload.RequestId); err != nil {
		return errors.New("request_id must be a UUID")
	}
	if len(request.Payload.ProviderId) != sha256.Size*2 {
		return errors.New("provider_id must be a 64-character hexadecimal identifier")
	}
	if _, err := hex.DecodeString(request.Payload.ProviderId); err != nil {
		return errors.New("provider_id must be lowercase hexadecimal")
	}
	if request.Payload.ProviderId != string(bytes.ToLower([]byte(request.Payload.ProviderId))) {
		return errors.New("provider_id must be lowercase hexadecimal")
	}
	if request.Payload.Sequence == 0 {
		return errors.New("sequence must be positive")
	}
	if err := request.Payload.ObservedAt.CheckValid(); err != nil {
		return errors.New("observed_at must be a valid timestamp")
	}
	observedAt := request.Payload.ObservedAt.AsTime()
	if observedAt.Before(now.Add(-maxHeartbeatClockSkew)) || observedAt.After(now.Add(maxHeartbeatClockSkew)) {
		return errors.New("observed_at is outside the allowed clock skew")
	}
	if request.Payload.Capabilities == nil {
		return errors.New("capabilities are required")
	}
	if err := validateCapabilities(request.Payload.Capabilities); err != nil {
		return err
	}
	if err := validateWorkloadBandwidth(request.Payload.WorkloadBandwidth); err != nil {
		return err
	}
	if err := validateWorkloadStatus(request.Payload.WorkloadStatus); err != nil {
		return err
	}
	if len(request.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("signature must be %d bytes", ed25519.SignatureSize)
	}
	return nil
}

func validateBeginJoin(request *controlplanev1.BeginJoinRequest) error {
	if request == nil {
		return errors.New("request is required")
	}
	if _, err := uuid.Parse(request.RequestId); err != nil {
		return errors.New("request_id must be a UUID")
	}
	if len(request.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("public_key must be %d bytes", ed25519.PublicKeySize)
	}
	if request.ProtocolVersion != "1" {
		return errors.New("unsupported protocol_version")
	}
	if request.AgentVersion == "" || len(request.AgentVersion) > 64 {
		return errors.New("agent_version must contain 1 to 64 characters")
	}
	if request.AgentEndpoint != "" {
		endpoint, err := url.Parse(request.AgentEndpoint)
		if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.Port() == "" || endpoint.User != nil || endpoint.Path != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" || len(request.AgentEndpoint) > 256 {
			return errors.New("agent_endpoint must be an HTTPS host and explicit port without credentials or path")
		}
	}
	return nil
}

func validateCompleteJoin(request *controlplanev1.CompleteJoinRequest) error {
	if request == nil {
		return errors.New("request is required")
	}
	if _, err := uuid.Parse(request.RequestId); err != nil {
		return errors.New("request_id must be a UUID")
	}
	if _, err := uuid.Parse(request.ChallengeId); err != nil {
		return errors.New("challenge_id must be a UUID")
	}
	if len(request.ChallengeSignature) != ed25519.SignatureSize {
		return fmt.Errorf("challenge_signature must be %d bytes", ed25519.SignatureSize)
	}
	if request.Capabilities == nil {
		return errors.New("capabilities are required")
	}
	if err := validateCapabilities(request.Capabilities); err != nil {
		return err
	}
	// ADR-027 §2: optional -- a caller not asking for mTLS enrollment
	// leaves this empty. When set, it must be exactly a raw Ed25519 public
	// key; anything else is a malformed request, not "no key requested."
	if len(request.TlsPublicKey) != 0 && len(request.TlsPublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("tls_public_key must be empty or %d bytes", ed25519.PublicKeySize)
	}
	return nil
}

func validateCapabilities(capabilities *sharedv1.ResourceCapability) error {
	if math.IsNaN(float64(capabilities.CpuTotal)) || math.IsInf(float64(capabilities.CpuTotal), 0) || capabilities.CpuTotal <= 0 {
		return errors.New("cpu_total must be a finite positive value")
	}
	if math.IsNaN(float64(capabilities.CpuAvailable)) || math.IsInf(float64(capabilities.CpuAvailable), 0) || capabilities.CpuAvailable < 0 || capabilities.CpuAvailable > capabilities.CpuTotal {
		return errors.New("cpu_available must be finite and between zero and cpu_total")
	}
	if capabilities.RamTotalMb <= 0 || capabilities.RamAvailableMb < 0 || capabilities.RamAvailableMb > capabilities.RamTotalMb {
		return errors.New("RAM values are inconsistent")
	}
	if capabilities.StorageTotalGb < 0 || capabilities.StorageAvailableGb < 0 || capabilities.StorageAvailableGb > capabilities.StorageTotalGb {
		return errors.New("storage values are inconsistent")
	}
	return nil
}

func beginRequestHash(request *controlplanev1.BeginJoinRequest) [32]byte {
	hash := sha256.New()
	hash.Write(request.PublicKey)
	hash.Write([]byte{0})
	hash.Write([]byte(request.ProtocolVersion))
	hash.Write([]byte{0})
	hash.Write([]byte(request.AgentVersion))
	hash.Write([]byte{0})
	hash.Write([]byte(request.AgentEndpoint))
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func completeRequestHash(request *controlplanev1.CompleteJoinRequest, capabilities []byte) [32]byte {
	hash := sha256.New()
	hash.Write([]byte(request.ChallengeId))
	hash.Write([]byte{0})
	hash.Write(request.ChallengeSignature)
	hash.Write([]byte{0})
	hash.Write(capabilities)
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func repositoryError(err error) error {
	switch {
	case errors.Is(err, ErrConflict), errors.Is(err, ErrChallengeConsumed):
		return status.Error(codes.AlreadyExists, err.Error())
	case errors.Is(err, ErrChallengeNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, ErrProviderNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, ErrHeartbeatReplay):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, ErrChallengeExpired):
		return status.Error(codes.DeadlineExceeded, err.Error())
	default:
		return status.Error(codes.Internal, "provider join persistence failed")
	}
}
