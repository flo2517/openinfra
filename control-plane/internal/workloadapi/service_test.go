package workloadapi

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/openinfra/network/internal/userauth"
	controlplanev1 "github.com/openinfra/network/protocol/generated/go/controlplane/v1"
	sharedv1 "github.com/openinfra/network/protocol/generated/go/shared/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	testOwner      = "owner-1"
	otherTestOwner = "owner-2"
)

func ownerCtx() context.Context { return userauth.WithUserID(context.Background(), testOwner) }
func otherOwnerCtx() context.Context {
	return userauth.WithUserID(context.Background(), otherTestOwner)
}

type memoryRepository struct {
	byRequest map[string]Workload
	byID      map[string]Workload
}

func newMemoryRepository() *memoryRepository {
	return &memoryRepository{byRequest: map[string]Workload{}, byID: map[string]Workload{}}
}
func (r *memoryRepository) CreateOrGet(_ context.Context, candidate Workload) (Workload, error) {
	if w, ok := r.byRequest[candidate.RequestID]; ok {
		if w.RequestHash != candidate.RequestHash || w.OwnerID != candidate.OwnerID {
			return Workload{}, ErrConflict
		}
		return w, nil
	}
	if _, ok := r.byID[candidate.WorkloadID]; ok {
		return Workload{}, ErrConflict
	}
	r.byRequest[candidate.RequestID] = candidate
	r.byID[candidate.WorkloadID] = candidate
	return candidate, nil
}
func (r *memoryRepository) Get(_ context.Context, id, ownerID string) (Workload, error) {
	w, ok := r.byID[id]
	if !ok || w.OwnerID != ownerID {
		return Workload{}, ErrNotFound
	}
	return w, nil
}
func (r *memoryRepository) RequestStop(_ context.Context, workloadID, requestID, ownerID string, now time.Time) (Workload, error) {
	w, ok := r.byID[workloadID]
	if !ok || w.OwnerID != ownerID {
		return Workload{}, ErrNotFound
	}
	if w.StopRequestID != "" && w.StopRequestID != requestID {
		return Workload{}, ErrConflict
	}
	if w.StopRequestID == "" {
		w.StopRequestID = requestID
		switch w.State {
		case "STOPPED", "COMPLETED", "FAILED":
		default:
			w.State = "STOPPING"
		}
		w.UpdatedAt = now
		r.byID[workloadID] = w
		r.byRequest[w.RequestID] = w
	}
	return w, nil
}

// ReconcileFromAgent mirrors PostgresRepository.ReconcileFromAgent's
// precondition semantics (providerID and current state must both match)
// closely enough for ReconcileWorkloadStatus's unit tests below --
// applied==false for a state/provider mismatch, not an error.
func (r *memoryRepository) ReconcileFromAgent(_ context.Context, workloadID, providerID string, fromStates []string, toState, containerID, errorCode string) (bool, error) {
	w, ok := r.byID[workloadID]
	if !ok || w.ProviderID != providerID {
		return false, nil
	}
	matched := false
	for _, state := range fromStates {
		if w.State == state {
			matched = true
			break
		}
	}
	if !matched {
		return false, nil
	}
	w.State = toState
	if containerID != "" {
		w.ContainerID = containerID
	}
	w.ErrorCode = errorCode
	r.byID[workloadID] = w
	r.byRequest[w.RequestID] = w
	return true, nil
}

func validRequest() *controlplanev1.SubmitWorkloadRequest {
	return &controlplanev1.SubmitWorkloadRequest{RequestId: uuid.NewString(), Image: "redis@sha256:987c376c727652f99625c7d205a1cba3cb2c53b92b0b62aade2bd48ee1593232", Definition: &sharedv1.WorkloadDefinition{WorkloadId: uuid.NewString(), Profile: sharedv1.WorkloadProfile_WORKLOAD_PROFILE_COMPUTE_INTENSIVE, Requirements: &sharedv1.ResourceRequirements{Cpu: 1, RamMb: 256}, DurationSeconds: 300}}
}

func TestSubmitIsDurableAndIdempotent(t *testing.T) {
	service := NewService(newMemoryRepository())
	service.now = func() time.Time { return time.Unix(1700000000, 0) }
	request := validRequest()
	first, err := service.SubmitWorkload(ownerCtx(), request)
	if err != nil {
		t.Fatal(err)
	}
	if first.State != controlplanev1.WorkloadState_WORKLOAD_STATE_REQUESTED {
		t.Fatalf("state=%s", first.State)
	}
	second, err := service.SubmitWorkload(ownerCtx(), request)
	if err != nil {
		t.Fatal(err)
	}
	if second.WorkloadId != first.WorkloadId {
		t.Fatal("retry returned another workload")
	}
	request.Image = "redis@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	_, err = service.SubmitWorkload(ownerCtx(), request)
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("code=%s", status.Code(err))
	}
}

func TestSubmitRejectsUnpinnedImageAndInvalidResources(t *testing.T) {
	service := NewService(newMemoryRepository())
	request := validRequest()
	request.Image = "redis:latest"
	_, err := service.SubmitWorkload(ownerCtx(), request)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code=%s", status.Code(err))
	}
	request = validRequest()
	request.Definition.Requirements.Cpu = 0
	_, err = service.SubmitWorkload(ownerCtx(), request)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code=%s", status.Code(err))
	}
}

func TestSubmitWorkloadDeniesCrossTenantRequestIDReuse(t *testing.T) {
	service := NewService(newMemoryRepository())
	request := validRequest()
	if _, err := service.SubmitWorkload(ownerCtx(), request); err != nil {
		t.Fatal(err)
	}
	// A different tenant reusing the same request_id (observed, guessed,
	// or coincidental) must never be handed back the first tenant's
	// workload as if it were their own idempotent replay.
	_, err := service.SubmitWorkload(otherOwnerCtx(), request)
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("code=%s, want AlreadyExists", status.Code(err))
	}
}

func TestSubmitRejectsAnUnauthenticatedCaller(t *testing.T) {
	service := NewService(newMemoryRepository())
	_, err := service.SubmitWorkload(context.Background(), validRequest())
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code=%s, want Unauthenticated", status.Code(err))
	}
}

func TestGetDoesNotInventRuntimeState(t *testing.T) {
	service := NewService(newMemoryRepository())
	request := validRequest()
	_, err := service.SubmitWorkload(ownerCtx(), request)
	if err != nil {
		t.Fatal(err)
	}
	got, err := service.GetWorkload(ownerCtx(), &controlplanev1.GetWorkloadRequest{WorkloadId: request.Definition.WorkloadId})
	if err != nil {
		t.Fatal(err)
	}
	if got.State != controlplanev1.WorkloadState_WORKLOAD_STATE_REQUESTED || got.ProviderId != "" || got.LeaseId != "" || got.ContainerId != "" {
		t.Fatalf("unexpected state: %+v", got)
	}
}

func TestGetWorkloadDeniesACrossTenantRead(t *testing.T) {
	service := NewService(newMemoryRepository())
	request := validRequest()
	if _, err := service.SubmitWorkload(ownerCtx(), request); err != nil {
		t.Fatal(err)
	}
	_, err := service.GetWorkload(otherOwnerCtx(), &controlplanev1.GetWorkloadRequest{WorkloadId: request.Definition.WorkloadId})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("code=%s, want NotFound (a non-owner must see the same response as a nonexistent workload)", status.Code(err))
	}
}

func TestGetWorkloadRejectsAnUnauthenticatedCaller(t *testing.T) {
	service := NewService(newMemoryRepository())
	_, err := service.GetWorkload(context.Background(), &controlplanev1.GetWorkloadRequest{WorkloadId: uuid.NewString()})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code=%s, want Unauthenticated", status.Code(err))
	}
}

func TestStopWorkloadIsPersistentAndIdempotent(t *testing.T) {
	repository := newMemoryRepository()
	service := NewService(repository)
	stopTime := time.Unix(1700000300, 0).UTC()
	service.now = func() time.Time { return stopTime }
	submit := validRequest()
	if _, err := service.SubmitWorkload(ownerCtx(), submit); err != nil {
		t.Fatal(err)
	}
	stop := &controlplanev1.StopWorkloadRequest{RequestId: uuid.NewString(), WorkloadId: submit.Definition.WorkloadId}
	first, err := service.StopWorkload(ownerCtx(), stop)
	if err != nil {
		t.Fatal(err)
	}
	if first.State != controlplanev1.WorkloadState_WORKLOAD_STATE_STOPPING || !first.UpdatedAt.AsTime().Equal(stopTime) {
		t.Fatalf("unexpected stop response: %+v", first)
	}
	second, err := service.StopWorkload(ownerCtx(), stop)
	if err != nil {
		t.Fatal(err)
	}
	if second.State != first.State || !second.UpdatedAt.AsTime().Equal(stopTime) {
		t.Fatalf("retry changed response: %+v", second)
	}

	_, err = service.StopWorkload(ownerCtx(), &controlplanev1.StopWorkloadRequest{RequestId: uuid.NewString(), WorkloadId: stop.WorkloadId})
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("conflicting stop code=%s", status.Code(err))
	}
}

// --- ADR-028 §4: ReconcileWorkloadStatus / reconciliationTransition ---

func seedWorkload(t *testing.T, repository *memoryRepository, workloadID, providerID, state string) {
	t.Helper()
	repository.byID[workloadID] = Workload{
		WorkloadID: workloadID,
		RequestID:  uuid.NewString(),
		OwnerID:    testOwner,
		ProviderID: providerID,
		State:      state,
	}
}

// TestReconcileWorkloadStatusAdvancesDeployingToRunning is the
// straightforward, non-conflicting case: the Control Plane's own dispatch
// believed DEPLOYING, the Agent's heartbeat confirms RUNNING.
func TestReconcileWorkloadStatusAdvancesDeployingToRunning(t *testing.T) {
	repository := newMemoryRepository()
	service := NewService(repository)
	workloadID := uuid.NewString()
	seedWorkload(t, repository, workloadID, "provider-1", "DEPLOYING")

	err := service.ReconcileWorkloadStatus(context.Background(), "provider-1", []*controlplanev1.WorkloadStatusSummary{
		{WorkloadId: workloadID, Phase: controlplanev1.AgentWorkloadPhase_AGENT_WORKLOAD_PHASE_RUNNING, ContainerId: "container-1"},
	})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	stored := repository.byID[workloadID]
	if stored.State != "RUNNING" || stored.ContainerID != "container-1" {
		t.Fatalf("stored = %+v, want RUNNING with container-1", stored)
	}
}

// TestReconcileWorkloadStatusConflictHandling is the acceptance
// criterion's "conflict handling" case, verified against ADR-028 §4's own
// specified resolution (agent-reported state wins, since it already
// actually happened): the Control Plane believes RUNNING, but the Agent's
// heartbeat reports the container Lost -- the Control Plane's view must
// be corrected to FAILED, with an explicit error_code recording why.
func TestReconcileWorkloadStatusConflictHandling(t *testing.T) {
	repository := newMemoryRepository()
	service := NewService(repository)
	workloadID := uuid.NewString()
	seedWorkload(t, repository, workloadID, "provider-1", "RUNNING")

	err := service.ReconcileWorkloadStatus(context.Background(), "provider-1", []*controlplanev1.WorkloadStatusSummary{
		{WorkloadId: workloadID, Phase: controlplanev1.AgentWorkloadPhase_AGENT_WORKLOAD_PHASE_LOST},
	})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	stored := repository.byID[workloadID]
	if stored.State != "FAILED" {
		t.Fatalf("state = %s, want FAILED", stored.State)
	}
	if stored.ErrorCode != "AGENT_REPORTED_LOST" {
		t.Fatalf("error_code = %s, want AGENT_REPORTED_LOST", stored.ErrorCode)
	}
}

// TestReconcileWorkloadStatusExpiredLease is the acceptance criterion's
// "expired lease" case from the Control-Plane side: the Agent already
// stopped the workload locally (ADR-028 §3's lease-expiry enforcement,
// most likely while disconnected) before the Control Plane's own
// STOPPING/StopAndConfirm flow got there -- reconciliation must catch the
// Control Plane's view up to STOPPED rather than leaving it stuck at
// RUNNING forever.
func TestReconcileWorkloadStatusExpiredLease(t *testing.T) {
	repository := newMemoryRepository()
	service := NewService(repository)
	workloadID := uuid.NewString()
	seedWorkload(t, repository, workloadID, "provider-1", "RUNNING")

	err := service.ReconcileWorkloadStatus(context.Background(), "provider-1", []*controlplanev1.WorkloadStatusSummary{
		{WorkloadId: workloadID, Phase: controlplanev1.AgentWorkloadPhase_AGENT_WORKLOAD_PHASE_STOPPED},
	})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if stored := repository.byID[workloadID]; stored.State != "STOPPED" {
		t.Fatalf("state = %s, want STOPPED", stored.State)
	}
}

// TestReconcileWorkloadStatusDuplicateReportIsANoOp is the acceptance
// criterion's "duplicate command" case applied to reconciliation itself:
// replaying the exact same workload_status entry (e.g. the same heartbeat
// redelivered, or two consecutive heartbeats both reporting RUNNING)
// must not double-apply or error the second time -- the row has already
// moved past the DEPLOYING precondition, so the second call is a
// documented no-op.
func TestReconcileWorkloadStatusDuplicateReportIsANoOp(t *testing.T) {
	repository := newMemoryRepository()
	service := NewService(repository)
	workloadID := uuid.NewString()
	seedWorkload(t, repository, workloadID, "provider-1", "DEPLOYING")
	entry := []*controlplanev1.WorkloadStatusSummary{
		{WorkloadId: workloadID, Phase: controlplanev1.AgentWorkloadPhase_AGENT_WORKLOAD_PHASE_RUNNING, ContainerId: "container-1"},
	}

	if err := service.ReconcileWorkloadStatus(context.Background(), "provider-1", entry); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	if err := service.ReconcileWorkloadStatus(context.Background(), "provider-1", entry); err != nil {
		t.Fatalf("duplicate reconcile must not error: %v", err)
	}
	stored := repository.byID[workloadID]
	if stored.State != "RUNNING" || stored.ContainerID != "container-1" {
		t.Fatalf("stored = %+v, want unchanged RUNNING with container-1", stored)
	}
}

// TestReconcileWorkloadStatusIgnoresAnotherProvidersWorkload is a safety
// property, not named directly by the acceptance criteria but implied by
// them: an Agent's heartbeat must never be able to reconcile a workload
// belonging to a different provider, even if it happens to guess a valid
// workload_id.
func TestReconcileWorkloadStatusIgnoresAnotherProvidersWorkload(t *testing.T) {
	repository := newMemoryRepository()
	service := NewService(repository)
	workloadID := uuid.NewString()
	seedWorkload(t, repository, workloadID, "provider-1", "DEPLOYING")

	err := service.ReconcileWorkloadStatus(context.Background(), "provider-2", []*controlplanev1.WorkloadStatusSummary{
		{WorkloadId: workloadID, Phase: controlplanev1.AgentWorkloadPhase_AGENT_WORKLOAD_PHASE_RUNNING, ContainerId: "container-1"},
	})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if stored := repository.byID[workloadID]; stored.State != "DEPLOYING" {
		t.Fatalf("state = %s, want unchanged DEPLOYING", stored.State)
	}
}

// TestReconcileWorkloadStatusIgnoresPhasesWithNoControlPlaneAction covers
// Provisioning/Starting/Unspecified -- reconciliationTransition
// deliberately has no entry for these, so ReconcileWorkloadStatus must
// leave the Control Plane's own state untouched.
func TestReconcileWorkloadStatusIgnoresPhasesWithNoControlPlaneAction(t *testing.T) {
	repository := newMemoryRepository()
	service := NewService(repository)
	workloadID := uuid.NewString()
	seedWorkload(t, repository, workloadID, "provider-1", "DEPLOYING")

	err := service.ReconcileWorkloadStatus(context.Background(), "provider-1", []*controlplanev1.WorkloadStatusSummary{
		{WorkloadId: workloadID, Phase: controlplanev1.AgentWorkloadPhase_AGENT_WORKLOAD_PHASE_STARTING},
	})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if stored := repository.byID[workloadID]; stored.State != "DEPLOYING" {
		t.Fatalf("state = %s, want unchanged DEPLOYING", stored.State)
	}
}

func TestStopWorkloadDeniesACrossTenantStop(t *testing.T) {
	repository := newMemoryRepository()
	service := NewService(repository)
	submit := validRequest()
	if _, err := service.SubmitWorkload(ownerCtx(), submit); err != nil {
		t.Fatal(err)
	}
	stop := &controlplanev1.StopWorkloadRequest{RequestId: uuid.NewString(), WorkloadId: submit.Definition.WorkloadId}
	_, err := service.StopWorkload(otherOwnerCtx(), stop)
	if status.Code(err) != codes.NotFound {
		t.Fatalf("code=%s, want NotFound", status.Code(err))
	}
	// The denied attempt must not have mutated the workload -- the real
	// owner can still stop it afterward.
	if _, err := service.StopWorkload(ownerCtx(), stop); err != nil {
		t.Fatalf("owner's stop after a denied cross-tenant attempt: %v", err)
	}
}

func TestStopWorkloadRejectsAnUnauthenticatedCaller(t *testing.T) {
	service := NewService(newMemoryRepository())
	_, err := service.StopWorkload(context.Background(), &controlplanev1.StopWorkloadRequest{RequestId: uuid.NewString(), WorkloadId: uuid.NewString()})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code=%s, want Unauthenticated", status.Code(err))
	}
}

func TestStopWorkloadValidatesInputAndPreservesTerminalState(t *testing.T) {
	repository := newMemoryRepository()
	service := NewService(repository)
	_, err := service.StopWorkload(ownerCtx(), nil)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("nil request code=%s", status.Code(err))
	}
	_, err = service.StopWorkload(ownerCtx(), &controlplanev1.StopWorkloadRequest{RequestId: "invalid", WorkloadId: uuid.NewString()})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("invalid request ID code=%s", status.Code(err))
	}
	_, err = service.StopWorkload(ownerCtx(), &controlplanev1.StopWorkloadRequest{RequestId: uuid.NewString(), WorkloadId: uuid.NewString()})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("missing workload code=%s", status.Code(err))
	}

	submit := validRequest()
	if _, err = service.SubmitWorkload(ownerCtx(), submit); err != nil {
		t.Fatal(err)
	}
	w := repository.byID[submit.Definition.WorkloadId]
	w.State = "COMPLETED"
	repository.byID[w.WorkloadID] = w
	response, err := service.StopWorkload(ownerCtx(), &controlplanev1.StopWorkloadRequest{RequestId: uuid.NewString(), WorkloadId: w.WorkloadID})
	if err != nil {
		t.Fatal(err)
	}
	if response.State != controlplanev1.WorkloadState_WORKLOAD_STATE_COMPLETED {
		t.Fatalf("terminal state changed: %s", response.State)
	}
}
