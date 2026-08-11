package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/openinfra/network/internal/userauth"
)

// insertMinimalWorkload inserts the smallest row workloads' CHECK
// constraints allow for a given state -- REQUESTED needs no
// provider_id/lease_id/container_id, so tests that only care about
// state/attempt_count/worker_id use this rather than the heavier
// provider+lease fixtures internal/workloadapi's own tests need.
func insertMinimalWorkload(t *testing.T, ctx context.Context, pool *pgxpool.Pool, state string, attemptCount int, workerID *string, workerLeaseUntil *time.Time) {
	t.Helper()
	workloadID, requestID := uuid.NewString(), uuid.NewString()
	image := "example.invalid/image@sha256:" + fmt.Sprintf("%064d", 0)
	_, err := pool.Exec(ctx, `
		INSERT INTO workloads (workload_id, request_id, request_hash, definition, image, state, attempt_count, worker_id, worker_lease_until)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		workloadID, requestID, make([]byte, 32), []byte{1}, image, state, attemptCount, workerID, workerLeaseUntil)
	if err != nil {
		t.Fatal(err)
	}
}

func strPtr(s string) *string { return &s }

func doAuthedGet(t *testing.T, handler http.Handler, path, rawKey string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.Header.Set("Authorization", "Bearer "+rawKey)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func TestOperatorQueueRejectsATenant(t *testing.T) {
	_, server, _ := newAuthTestServer(t)
	rawKey := issueSessionKey(t, server, userauth.RoleTenant)

	recorder := doAuthedGet(t, server.Handler(), "/api/v1/operator/queue", rawKey)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a tenant calling an operator_readonly-gated route", recorder.Code)
	}
}

func TestOperatorQueueReportsCountsByStateAndAttemptBuckets(t *testing.T) {
	ctx, server, pool := newAuthTestServer(t)
	insertMinimalWorkload(t, ctx, pool, "REQUESTED", 0, nil, nil)
	insertMinimalWorkload(t, ctx, pool, "REQUESTED", 0, nil, nil)
	insertMinimalWorkload(t, ctx, pool, "FAILED", 7, nil, nil)
	insertMinimalWorkload(t, ctx, pool, "SCHEDULING", 2, nil, nil)

	rawKey := issueSessionKey(t, server, userauth.RoleOperatorReadOnly)
	recorder := doAuthedGet(t, server.Handler(), "/api/v1/operator/queue", rawKey)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}

	var body OperatorQueue
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.States) != len(operatorWorkloadStates) {
		t.Fatalf("len(States) = %d, want %d (every known state reported, including zero-count ones)", len(body.States), len(operatorWorkloadStates))
	}
	byState := map[string]QueueStateCount{}
	for _, entry := range body.States {
		byState[entry.State] = entry
	}
	if byState["REQUESTED"].Count != 2 {
		t.Fatalf("REQUESTED count = %d, want 2", byState["REQUESTED"].Count)
	}
	if byState["FAILED"].Count != 1 {
		t.Fatalf("FAILED count = %d, want 1", byState["FAILED"].Count)
	}
	if byState["RUNNING"].Count != 0 {
		t.Fatalf("RUNNING count = %d, want 0 (explicit zero, not omitted)", byState["RUNNING"].Count)
	}
	if body.AttemptCountBuckets["0"] != 2 {
		t.Fatalf("bucket 0 = %d, want 2", body.AttemptCountBuckets["0"])
	}
	if body.AttemptCountBuckets["6+"] != 1 {
		t.Fatalf("bucket 6+ = %d, want 1", body.AttemptCountBuckets["6+"])
	}
	if body.AttemptCountBuckets["1-2"] != 1 {
		t.Fatalf("bucket 1-2 = %d, want 1", body.AttemptCountBuckets["1-2"])
	}
}

func TestOperatorWorkersReportsClaimsAndExpiredLeases(t *testing.T) {
	ctx, server, pool := newAuthTestServer(t)
	future := time.Now().Add(time.Hour)
	past := time.Now().Add(-time.Hour)
	// REQUESTED/SCHEDULING only: workloads' CHECK constraints require a
	// provider_id for LEASE_PENDING and above, and a lease_id for LEASED
	// and above (migrations/000004_workloads.sql). This view only cares
	// about worker_id/worker_lease_until, which every state carries, so
	// the fixture stays on the two states that need no provider or lease
	// rather than inventing them just to satisfy a constraint.
	insertMinimalWorkload(t, ctx, pool, "SCHEDULING", 0, strPtr("worker-a"), &future)
	insertMinimalWorkload(t, ctx, pool, "SCHEDULING", 0, strPtr("worker-a"), &future)
	insertMinimalWorkload(t, ctx, pool, "REQUESTED", 0, strPtr("worker-b"), &past)
	insertMinimalWorkload(t, ctx, pool, "REQUESTED", 0, nil, nil) // unclaimed, must not appear

	rawKey := issueSessionKey(t, server, userauth.RoleOperatorAdmin) // admin satisfies a readonly gate too
	recorder := doAuthedGet(t, server.Handler(), "/api/v1/operator/workers", rawKey)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}

	var body OperatorWorkers
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Workers) != 2 {
		t.Fatalf("len(Workers) = %d, want 2 (worker-a, worker-b; unclaimed rows excluded)", len(body.Workers))
	}
	byWorker := map[string]WorkerClaim{}
	for _, w := range body.Workers {
		byWorker[w.WorkerID] = w
	}
	if byWorker["worker-a"].ClaimedWorkloads != 2 {
		t.Fatalf("worker-a claimed = %d, want 2", byWorker["worker-a"].ClaimedWorkloads)
	}
	if byWorker["worker-a"].LeaseExpired {
		t.Fatal("worker-a's lease is in the future, must not be reported expired")
	}
	if !byWorker["worker-b"].LeaseExpired {
		t.Fatal("worker-b's lease is in the past, must be reported expired (a stuck-claim signal, not filtered out)")
	}
}
