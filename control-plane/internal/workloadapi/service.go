package workloadapi

import (
	"context"
	"crypto/sha256"
	"errors"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/openinfra/network/internal/userauth"
	controlplanev1 "github.com/openinfra/network/protocol/generated/go/controlplane/v1"
	sharedv1 "github.com/openinfra/network/protocol/generated/go/shared/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	ErrNotFound = errors.New("workload not found")
	ErrConflict = errors.New("workload idempotency conflict")
	// ErrCapacityExceeded means the chosen provider's declared total
	// capacity is already fully claimed by other open workloads at the
	// moment of commit. Distinct from ErrConflict (an optimistic-lock or
	// idempotency mismatch) so callers can retry against a different
	// provider rather than treating it as a stale-read bug.
	ErrCapacityExceeded = errors.New("provider capacity exceeded")
	digestImage         = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]*(?::[A-Za-z0-9._-]+)?@sha256:[a-f0-9]{64}$`)
	// ADR-033 §4: exactly 64 lowercase hex characters, matching
	// agent-executor's own `image::validate_sha256_hex` shape on the
	// Agent side of this same digest.
	vmImageDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

type Workload struct {
	WorkloadID, RequestID, Image, State string
	// VmImageSha256 is set only for a VM workload
	// (Definition.Constraints.RequiresVm = true, ADR-033 §4/§9, issues
	// #166/#168): the pinned SHA-256 digest of the qcow2 blob at Image,
	// verified by the Agent before it is ever booted. Empty for an
	// ordinary container workload.
	VmImageSha256 string
	// OwnerID is the authenticated tenant this workload belongs to (see
	// internal/userauth). Empty for workloads created before migration
	// 000009 -- those are permanently unreachable through the
	// authenticated user API by design, not a bug; see that migration's
	// comment.
	OwnerID                                     string
	StopRequestID                               string
	RequestHash                                 [32]byte
	ResourceHash                                [32]byte
	Definition                                  []byte
	ProviderID, LeaseID, ContainerID, ErrorCode string
	CreatedAt, UpdatedAt                        time.Time
	WorkerID                                    string
	WorkerLeaseUntil                            time.Time
	Version                                     int64
	AttemptCount                                int
	// ReservedCPUMillicores/RAMMB/StorageGB/IngressMbps/EgressMbps are this
	// workload's claim on its eventual provider's declared total
	// capacity, fixed at creation time from validated
	// ResourceRequirements. See migrations 000008 and 000010.
	ReservedCPUMillicores                   int64
	ReservedRAMMB, ReservedStorageGB        int64
	ReservedIngressMbps, ReservedEgressMbps int64
}

// ProviderCapacity is the hard ceiling AssignLease checks reservations
// against -- not the provider's live "available" figure, which lives only
// in Redis (reconstructible, not authoritative for an atomic Postgres
// check; see AssignLease's doc comment in postgres.go for the reasoning).
// TotalCPUMillicores/TotalRAMMB/TotalStorageGB are the provider's declared
// total capacity verbatim -- stable hardware facts. TotalIngressMbps/
// TotalEgressMbps are also the declared total, *except* when the caller
// building this struct knows a WireGuard overlay is active for the
// workload's traffic: orchestrator.Worker.rankableCandidates then applies
// scheduler.WireGuardEffectiveMbps first, since the ledger otherwise
// admits reservations the overlay's own per-packet overhead can never
// actually deliver (issue #115). This is why the field is "the ceiling
// this transaction should enforce," not "the provider's declared total" --
// the two agree exactly when there's no overlay, and diverge by ~4% when
// there is. TotalIngressMbps/TotalEgressMbps are 0 for a provider that
// hasn't operator-configured a bandwidth capacity (see agent-core's
// AgentSettings doc comment) -- a workload with a nonzero bandwidth
// requirement simply cannot fit such a provider, the same as any other
// zero-capacity dimension.
type ProviderCapacity struct {
	TotalCPUMillicores                int64
	TotalRAMMB, TotalStorageGB        int64
	TotalIngressMbps, TotalEgressMbps int64
}

// CPUCoresToMillicores converts a validated ResourceCapability/
// ResourceRequirements CPU float (already checked positive, finite) into
// an integer millicore count, so the reservation ledger never depends on
// floating-point comparisons.
func CPUCoresToMillicores(cores float32) int64 {
	return int64(math.Round(float64(cores) * 1000))
}

type Repository interface {
	CreateOrGet(context.Context, Workload) (Workload, error)
	// Get and RequestStop both take ownerID and enforce it as part of the
	// lookup itself (not a fetch-then-compare in the Service layer), so a
	// non-owner's request is indistinguishable in every way -- including
	// SQL-level row locking in RequestStop's implementation -- from the
	// workload simply not existing. See postgres.go.
	Get(ctx context.Context, workloadID, ownerID string) (Workload, error)
	RequestStop(ctx context.Context, workloadID, requestID, ownerID string, now time.Time) (Workload, error)
	// ReconcileFromAgent applies an ADR-028 §4 Agent-reported state
	// transition, but only if the row still matches every one of
	// providerID (an Agent may only ever reconcile its own workloads) and
	// fromStates (the transition's own precondition -- see
	// reconciliationTransition). A row that no longer matches (already
	// advanced past this transition by the worker, or reconciled by an
	// earlier entry in the same heartbeat) is a silent no-op, not an
	// error: reconciliation must be safe to apply against state that has
	// already moved on. Deliberately does not gate on worker_id/version
	// the way the worker's own Mark* methods do -- a heartbeat is not a
	// claimed-row operation, and must be able to apply even while a
	// worker currently holds an unrelated claim on the same row (the
	// state-match precondition alone is what keeps this safe: whichever
	// writer's precondition still holds when it commits, wins; the loser
	// simply no-ops and is retried, from fresh state, on the next
	// heartbeat or worker tick).
	ReconcileFromAgent(ctx context.Context, workloadID, providerID string, fromStates []string, toState, containerID, errorCode string) (applied bool, err error)
}

type Service struct {
	repository Repository
	now        func() time.Time
}

func NewService(repository Repository) *Service {
	return &Service{repository: repository, now: time.Now}
}

func (s *Service) SubmitWorkload(ctx context.Context, request *controlplanev1.SubmitWorkloadRequest) (*controlplanev1.SubmitWorkloadResponse, error) {
	ownerID, err := requireOwner(ctx)
	if err != nil {
		return nil, err
	}
	definitionBytes, requestHash, err := validateSubmission(request)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	now := s.now().UTC()
	requirements := request.Definition.Requirements
	var ingressMbps, egressMbps int64
	if requirements.Bandwidth != nil {
		ingressMbps = int64(requirements.Bandwidth.IngressMbps)
		egressMbps = int64(requirements.Bandwidth.EgressMbps)
	}
	stored, err := s.repository.CreateOrGet(ctx, Workload{
		WorkloadID:            request.Definition.WorkloadId,
		RequestID:             request.RequestId,
		OwnerID:               ownerID,
		RequestHash:           requestHash,
		Definition:            definitionBytes,
		Image:                 request.Image,
		VmImageSha256:         request.VmImageSha256,
		State:                 "REQUESTED",
		CreatedAt:             now,
		UpdatedAt:             now,
		ReservedCPUMillicores: CPUCoresToMillicores(requirements.Cpu),
		ReservedRAMMB:         requirements.RamMb,
		ReservedStorageGB:     requirements.StorageGb,
		ReservedIngressMbps:   ingressMbps,
		ReservedEgressMbps:    egressMbps,
	})
	if err != nil {
		return nil, repositoryError(err)
	}
	return &controlplanev1.SubmitWorkloadResponse{WorkloadId: stored.WorkloadID, State: stateToProto(stored.State), CreatedAt: timestamppb.New(stored.CreatedAt)}, nil
}

func (s *Service) GetWorkload(ctx context.Context, request *controlplanev1.GetWorkloadRequest) (*controlplanev1.GetWorkloadResponse, error) {
	ownerID, err := requireOwner(ctx)
	if err != nil {
		return nil, err
	}
	if request == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	if _, err := uuid.Parse(request.WorkloadId); err != nil {
		return nil, status.Error(codes.InvalidArgument, "workload_id must be a UUID")
	}
	stored, err := s.repository.Get(ctx, request.WorkloadId, ownerID)
	if err != nil {
		return nil, repositoryError(err)
	}
	return &controlplanev1.GetWorkloadResponse{WorkloadId: stored.WorkloadID, State: stateToProto(stored.State), ProviderId: stored.ProviderID, LeaseId: stored.LeaseID, ContainerId: stored.ContainerID, ErrorCode: stored.ErrorCode, CreatedAt: timestamppb.New(stored.CreatedAt), UpdatedAt: timestamppb.New(stored.UpdatedAt)}, nil
}

// ReconcileWorkloadStatus implements providerjoin.WorkloadReconciler
// (ADR-028 §4): for each workload the Agent reported this heartbeat,
// applies the transition reconciliationTransition selects for its
// phase -- a no-op for a phase not in that table (Provisioning/Starting/
// Unspecified: nothing for the Control Plane to act on yet). One entry
// failing does not abort the rest of the batch, matching this ADR's "one
// bad workload must not block reconciling every other one" pattern seen
// elsewhere (collect_workload_bandwidth, activeValidators); the first
// error encountered is still returned so the caller can log it.
func (s *Service) ReconcileWorkloadStatus(ctx context.Context, providerID string, statuses []*controlplanev1.WorkloadStatusSummary) error {
	var firstErr error
	for _, entry := range statuses {
		if entry == nil {
			continue
		}
		fromStates, toState, errorCode, ok := reconciliationTransition(entry.Phase)
		if !ok {
			continue
		}
		if _, err := s.repository.ReconcileFromAgent(ctx, entry.WorkloadId, providerID, fromStates, toState, entry.ContainerId, errorCode); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// reconciliationTransition is ADR-028 §4's conflict-resolution table: what
// the Control Plane's own WorkloadState should become when the Agent's
// heartbeat reports a given AgentWorkloadPhase, and from which of the
// Control Plane's own states that transition is accepted. Deliberately
// narrow -- only the transitions the ADR actually calls for, not a general
// mapping of every phase combination:
//
//   - DEPLOYING -> RUNNING: the Control Plane's own dispatch believed the
//     workload was still being deployed; the Agent's own heartbeat is now
//     the authoritative confirmation it is actually running (the same
//     meaning DeployAndConfirm's synchronous confirmation already carries,
//     just arriving asynchronously via heartbeat instead).
//   - DEPLOYING or RUNNING -> FAILED: the Agent lost or failed the
//     container. An explicit, honest terminal state -- never silently
//     dropped -- mirroring agent-core's own WorkloadPhase::Lost handling.
//   - RUNNING, DEPLOYING, or STOPPING -> STOPPED: the Agent already
//     stopped the workload on its own (most commonly ADR-028 §3's local
//     lease-expiry enforcement while disconnected) before the Control
//     Plane's own STOPPING/StopAndConfirm flow got there -- this is the
//     "expired lease" conflict case: the Agent's local action is
//     authoritative, since it already actually happened.
//
// Every other phase (Provisioning, Starting, Unspecified) reports
// something the Control Plane's own coarser state machine has no matching
// action for yet -- reconciliation intentionally does nothing for those.
func reconciliationTransition(phase controlplanev1.AgentWorkloadPhase) (fromStates []string, toState, errorCode string, ok bool) {
	switch phase {
	case controlplanev1.AgentWorkloadPhase_AGENT_WORKLOAD_PHASE_RUNNING:
		return []string{"DEPLOYING"}, "RUNNING", "", true
	case controlplanev1.AgentWorkloadPhase_AGENT_WORKLOAD_PHASE_FAILED:
		return []string{"DEPLOYING", "RUNNING"}, "FAILED", "AGENT_REPORTED_FAILED", true
	case controlplanev1.AgentWorkloadPhase_AGENT_WORKLOAD_PHASE_LOST:
		return []string{"DEPLOYING", "RUNNING"}, "FAILED", "AGENT_REPORTED_LOST", true
	case controlplanev1.AgentWorkloadPhase_AGENT_WORKLOAD_PHASE_STOPPED:
		return []string{"RUNNING", "DEPLOYING", "STOPPING"}, "STOPPED", "", true
	default:
		return nil, "", "", false
	}
}

func (s *Service) StopWorkload(ctx context.Context, request *controlplanev1.StopWorkloadRequest) (*controlplanev1.StopWorkloadResponse, error) {
	ownerID, err := requireOwner(ctx)
	if err != nil {
		return nil, err
	}
	if request == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	if _, err := uuid.Parse(request.RequestId); err != nil {
		return nil, status.Error(codes.InvalidArgument, "request_id must be a UUID")
	}
	if _, err := uuid.Parse(request.WorkloadId); err != nil {
		return nil, status.Error(codes.InvalidArgument, "workload_id must be a UUID")
	}
	stored, err := s.repository.RequestStop(ctx, request.WorkloadId, request.RequestId, ownerID, s.now().UTC())
	if err != nil {
		return nil, repositoryError(err)
	}
	return &controlplanev1.StopWorkloadResponse{
		WorkloadId: stored.WorkloadID,
		State:      stateToProto(stored.State),
		UpdatedAt:  timestamppb.New(stored.UpdatedAt),
	}, nil
}

// requireOwner reads the authenticated caller injected by
// userauth.NewUnaryInterceptor. Checking again here, rather than trusting
// the interceptor unconditionally, means a future wiring mistake (a new
// entry point that forgets the interceptor, a test that calls the Service
// directly) fails closed instead of silently operating without tenancy.
func requireOwner(ctx context.Context) (string, error) {
	ownerID, ok := userauth.UserIDFromContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "an authenticated caller is required")
	}
	return ownerID, nil
}

func validateSubmission(request *controlplanev1.SubmitWorkloadRequest) ([]byte, [32]byte, error) {
	if request == nil || request.Definition == nil {
		return nil, [32]byte{}, errors.New("definition is required")
	}
	if _, err := uuid.Parse(request.RequestId); err != nil {
		return nil, [32]byte{}, errors.New("request_id must be a UUID")
	}
	if _, err := uuid.Parse(request.Definition.WorkloadId); err != nil {
		return nil, [32]byte{}, errors.New("workload_id must be a UUID")
	}
	definition := request.Definition
	// ADR-033 §4/§9, issues #166/#168: a VM workload has no OCI registry
	// concept to pin a digest against -- `image` is instead an HTTPS URL
	// to a qcow2 blob, paired with the required vm_image_sha256 the Agent
	// verifies before ever booting it (mirroring issue #154/PR #155's
	// "never run before the artifact matches what was promised"
	// discipline for the container path). An ordinary container workload
	// is unaffected and keeps the existing OCI-digest requirement.
	if definition.GetConstraints().GetRequiresVm() {
		if !strings.HasPrefix(request.Image, "https://") {
			return nil, [32]byte{}, errors.New("a VM workload's image must be an https:// URL")
		}
		if !vmImageDigest.MatchString(request.VmImageSha256) {
			return nil, [32]byte{}, errors.New("vm_image_sha256 must be exactly 64 lowercase hex characters")
		}
	} else {
		if !digestImage.MatchString(request.Image) {
			return nil, [32]byte{}, errors.New("image must be an OCI reference pinned by a lowercase sha256 digest")
		}
		if request.VmImageSha256 != "" {
			return nil, [32]byte{}, errors.New("vm_image_sha256 must not be set for a container workload")
		}
	}
	if definition.Profile == sharedv1.WorkloadProfile_WORKLOAD_PROFILE_UNSPECIFIED {
		return nil, [32]byte{}, errors.New("workload profile is required")
	}
	if definition.Requirements == nil {
		return nil, [32]byte{}, errors.New("resource requirements are required")
	}
	requirements := definition.Requirements
	if requirements.Cpu <= 0 || math.IsNaN(float64(requirements.Cpu)) || math.IsInf(float64(requirements.Cpu), 0) {
		return nil, [32]byte{}, errors.New("CPU must be finite and positive")
	}
	if requirements.RamMb <= 0 || requirements.StorageGb < 0 || requirements.GpuCount != 0 {
		return nil, [32]byte{}, errors.New("RAM must be positive, storage non-negative, and GPU unsupported in MVP")
	}
	if bandwidth := requirements.Bandwidth; bandwidth != nil {
		if bandwidth.IngressMbps < 0 || bandwidth.EgressMbps < 0 {
			return nil, [32]byte{}, errors.New("bandwidth ingress/egress must be non-negative")
		}
	}
	if definition.DurationSeconds <= 0 || definition.DurationSeconds > 30*24*60*60 {
		return nil, [32]byte{}, errors.New("duration_seconds must be between 1 and 2592000")
	}
	definitionBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(definition)
	if err != nil {
		return nil, [32]byte{}, errors.New("definition cannot be encoded")
	}
	hash := sha256.New()
	hash.Write([]byte("openinfra-workload-request-v1\x00"))
	hash.Write(definitionBytes)
	hash.Write([]byte{0})
	hash.Write([]byte(request.Image))
	hash.Write([]byte{0})
	hash.Write([]byte(request.VmImageSha256))
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return definitionBytes, result, nil
}

func stateToProto(state string) controlplanev1.WorkloadState {
	values := map[string]controlplanev1.WorkloadState{"REQUESTED": controlplanev1.WorkloadState_WORKLOAD_STATE_REQUESTED, "SCHEDULING": controlplanev1.WorkloadState_WORKLOAD_STATE_SCHEDULING, "LEASE_PENDING": controlplanev1.WorkloadState_WORKLOAD_STATE_LEASE_PENDING, "LEASED": controlplanev1.WorkloadState_WORKLOAD_STATE_LEASED, "DEPLOYING": controlplanev1.WorkloadState_WORKLOAD_STATE_DEPLOYING, "RUNNING": controlplanev1.WorkloadState_WORKLOAD_STATE_RUNNING, "STOPPING": controlplanev1.WorkloadState_WORKLOAD_STATE_STOPPING, "STOPPED": controlplanev1.WorkloadState_WORKLOAD_STATE_STOPPED, "COMPLETED": controlplanev1.WorkloadState_WORKLOAD_STATE_COMPLETED, "FAILED": controlplanev1.WorkloadState_WORKLOAD_STATE_FAILED}
	return values[state]
}

func repositoryError(err error) error {
	if errors.Is(err, ErrNotFound) {
		return status.Error(codes.NotFound, err.Error())
	}
	if errors.Is(err, ErrConflict) {
		return status.Error(codes.AlreadyExists, err.Error())
	}
	return status.Error(codes.Internal, "workload persistence failed")
}
