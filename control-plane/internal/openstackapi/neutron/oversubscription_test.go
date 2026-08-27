package neutron_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/openinfra/network/internal/workloadapi"
)

// insertSchedulingWorkloadWithBandwidth mirrors
// workloadapi/postgres_capacity_test.go's own helper of the same name
// (unexported there, so re-derived here rather than imported) --
// project-scoped, so the neutron QoS surface being tested against this
// same pool can find it once (and only if) AssignLease actually commits
// it.
func insertSchedulingWorkloadWithBandwidth(t *testing.T, ctx context.Context, pool *pgxpool.Pool, projectID string, ingressMbps, egressMbps int64) workloadapi.Workload {
	t.Helper()
	ownerID := insertOwner(t, ctx, pool)
	workloadID, requestID := uuid.NewString(), uuid.NewString()
	image := "example.invalid/image@sha256:" + fmt.Sprintf("%064d", 0)
	_, err := pool.Exec(ctx, `
		INSERT INTO workloads (workload_id, request_id, owner_id, request_hash, definition, image, state,
		                        project_id, reserved_cpu_millicores, reserved_ram_mb, reserved_storage_gb,
		                        reserved_ingress_mbps, reserved_egress_mbps)
		VALUES ($1,$2,$3,$4,$5,$6,'SCHEDULING',$7,100,128,1,$8,$9)`,
		workloadID, requestID, ownerID, make([]byte, 32), []byte{1}, image, projectID, ingressMbps, egressMbps)
	if err != nil {
		t.Fatal(err)
	}
	repository := workloadapi.NewPostgresRepository(pool)
	claimed, err := repository.ClaimNext(ctx, "neutron-oversubscription-test-"+workloadID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	claimed.ReservedIngressMbps, claimed.ReservedEgressMbps = ingressMbps, egressMbps
	return claimed
}

// TestQoSSurfaceCannotReportAReservationTheRealCapacityCheckRejected is
// this PR's central oversubscription-safety proof: it drives
// internal/workloadapi.PostgresRepository.AssignLease -- the actual,
// production capacity check (a Serializable-transaction ledger sum
// against ProviderCapacity, the same code path
// internal/orchestrator.Worker calls) -- directly, not a
// reimplementation or approximation of it, then asserts the Neutron QoS
// surface only ever reflects what that real check let through.
func TestQoSSurfaceCannotReportAReservationTheRealCapacityCheckRejected(t *testing.T) {
	ctx, server := newTestServer(t, &fakeZoneLister{})
	project := createTestProject(t, ctx, server.pool)
	insertProvider(t, ctx, server.pool, "provider-a")
	repository := workloadapi.NewPostgresRepository(server.pool)
	capacity := workloadapi.ProviderCapacity{
		TotalCPUMillicores: 100_000, TotalRAMMB: 100_000, TotalStorageGB: 100_000,
		TotalIngressMbps: 200, TotalEgressMbps: 100,
	}

	// Both claimed (ClaimNext'd) before either is assigned: ClaimNext
	// picks the oldest unclaimed dispatchable row across the *whole*
	// table (it is the worker's generic dispatcher, not a
	// claim-this-specific-workload call) -- calling AssignLease on the
	// first between the two ClaimNext calls would clear its
	// worker_lease_until back to NULL and make it look "unclaimed"
	// again, so a later ClaimNext could wrongly re-select it instead of
	// the newly inserted row. Claiming both up front (the same order
	// workloadapi's own TestAssignLeaseConcurrentRaceNeverOvercommits
	// uses) avoids that entirely.
	accepted := insertSchedulingWorkloadWithBandwidth(t, ctx, server.pool, project, 50, 60)
	rejected := insertSchedulingWorkloadWithBandwidth(t, ctx, server.pool, project, 10, 60)

	// Fits within provider-a's 100 Mbps egress ceiling on its own --
	// AssignLease must accept it.
	if _, err := repository.AssignLease(ctx, accepted, "provider-a", [32]byte{1}, capacity); err != nil {
		t.Fatalf("AssignLease (should fit): %v", err)
	}

	// Would push committed egress to 60+60=120 > 100 Mbps -- the real
	// capacity check must reject this one.
	_, err := repository.AssignLease(ctx, rejected, "provider-a", [32]byte{2}, capacity)
	if !errors.Is(err, workloadapi.ErrCapacityExceeded) {
		t.Fatalf("AssignLease (should be rejected): got %v, want ErrCapacityExceeded", err)
	}

	token := mintProjectScopedToken(t, ctx, server.pool, server.users, project)
	request := httptest.NewRequest(http.MethodGet, "/v2.0/qos/policies", nil)
	request.Header.Set("X-Auth-Token", token)
	recorder := httptest.NewRecorder()
	server.handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Policies []qosPolicyResponse `json:"policies"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}

	// Exactly the accepted workload's policy must be reported -- the
	// rejected workload's 60 Mbps egress claim must never surface here,
	// because AssignLease never let it become a committed row.
	if len(body.Policies) != 1 || body.Policies[0].ID != accepted.WorkloadID {
		t.Fatalf("expected exactly the accepted workload's policy, got %+v", body.Policies)
	}
	var totalReportedEgressKbps int64
	for _, rule := range body.Policies[0].Rules {
		if rule.Direction == "egress" {
			totalReportedEgressKbps += rule.MaxKbps
		}
	}
	if want := int64(60_000); totalReportedEgressKbps != want {
		t.Fatalf("reported egress max_kbps = %d, want %d", totalReportedEgressKbps, want)
	}
	if totalReportedEgressKbps > capacity.TotalEgressMbps*1000 {
		t.Fatalf("QoS surface reported %d kbps, which exceeds the provider's real %d kbps ceiling -- oversubscription leaked through", totalReportedEgressKbps, capacity.TotalEgressMbps*1000)
	}

	// Directly cross-check against the real ledger, independent of this
	// package's own query, to prove the report and the ledger agree
	// exactly -- not merely both "look small enough."
	var committedEgress int64
	if err := server.pool.QueryRow(ctx, `
		SELECT COALESCE(SUM(reserved_egress_mbps), 0) FROM workloads
		WHERE provider_id = 'provider-a' AND state IN ('LEASE_PENDING','LEASED','DEPLOYING','RUNNING')`,
	).Scan(&committedEgress); err != nil {
		t.Fatal(err)
	}
	if committedEgress*1000 != totalReportedEgressKbps {
		t.Fatalf("QoS surface (%d kbps) disagrees with the real committed ledger (%d Mbps): a second, drifted source of truth", totalReportedEgressKbps, committedEgress)
	}

	// The rejected workload must still be exactly where AssignLease left
	// it: SCHEDULING, unassigned -- available for a future retry, not
	// silently mutated by anything this package did.
	rejectedStored, err := workloadapi.NewPostgresRepository(server.pool).Get(ctx, rejected.WorkloadID, rejected.OwnerID)
	if err != nil {
		t.Fatal(err)
	}
	if rejectedStored.State != "SCHEDULING" || rejectedStored.ProviderID != "" {
		t.Fatalf("rejected workload was mutated: %+v", rejectedStored)
	}
}

// TestQoSSurfaceNeverExceedsProviderCapacityUnderConcurrentAssignment is
// the concurrent-race variant of the same property, mirroring
// workloadapi's own
// TestAssignLeaseConcurrentRaceNeverOvercommits/TestAssignLeaseConcurrentBandwidthRaceNeverOvercommits:
// two workloads that each individually fit provider-a's declared egress
// capacity, but whose combined demand does not, race their real
// AssignLease calls -- exactly one must win, and the QoS surface must
// only ever be able to report that one.
func TestQoSSurfaceNeverExceedsProviderCapacityUnderConcurrentAssignment(t *testing.T) {
	ctx, server := newTestServer(t, &fakeZoneLister{})
	project := createTestProject(t, ctx, server.pool)
	insertProvider(t, ctx, server.pool, "provider-a")
	repository := workloadapi.NewPostgresRepository(server.pool)
	capacity := workloadapi.ProviderCapacity{
		TotalCPUMillicores: 100_000, TotalRAMMB: 100_000, TotalStorageGB: 100_000,
		TotalIngressMbps: 200, TotalEgressMbps: 100,
	}
	itemA := insertSchedulingWorkloadWithBandwidth(t, ctx, server.pool, project, 10, 70)
	itemB := insertSchedulingWorkloadWithBandwidth(t, ctx, server.pool, project, 10, 70)

	results := make(chan error, 2)
	for _, item := range []workloadapi.Workload{itemA, itemB} {
		go func(w workloadapi.Workload) {
			_, err := repository.AssignLease(ctx, w, "provider-a", [32]byte{1}, capacity)
			results <- err
		}(item)
	}
	successes := 0
	for i := 0; i < 2; i++ {
		if err := <-results; err == nil {
			successes++
		} else if !errors.Is(err, workloadapi.ErrCapacityExceeded) && !errors.Is(err, workloadapi.ErrConflict) {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("expected exactly one winner under a real race, got %d", successes)
	}

	token := mintProjectScopedToken(t, ctx, server.pool, server.users, project)
	request := httptest.NewRequest(http.MethodGet, "/v2.0/qos/policies", nil)
	request.Header.Set("X-Auth-Token", token)
	recorder := httptest.NewRecorder()
	server.handler.ServeHTTP(recorder, request)
	var body struct {
		Policies []qosPolicyResponse `json:"policies"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Policies) != 1 {
		t.Fatalf("expected exactly 1 reported policy (the sole winner), got %d: %+v", len(body.Policies), body.Policies)
	}
	var totalEgressKbps int64
	for _, rule := range body.Policies[0].Rules {
		if rule.Direction == "egress" {
			totalEgressKbps += rule.MaxKbps
		}
	}
	if totalEgressKbps > capacity.TotalEgressMbps*1000 {
		t.Fatalf("reported %d kbps exceeds the provider's %d kbps ceiling", totalEgressKbps, capacity.TotalEgressMbps*1000)
	}
}
