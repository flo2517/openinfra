package workloadapi_test

// ADR-028 §4: PostgresRepository.ReconcileFromAgent integration tests,
// against a real disposable Postgres schema (the same isolation pattern
// postgres_capacity_test.go's newCapacityTestPool/insertProvider already
// use) -- these exercise the actual SQL CAS semantics
// (provider_id/state-precondition WHERE clause), not just the in-memory
// fake service_test.go's ReconcileWorkloadStatus tests already cover at
// the Service layer.

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/openinfra/network/internal/workloadapi"
)

// insertReconcilableWorkload seeds a workload already committed to
// provider in the given state, returning its workload_id -- like
// insertOpenWorkload in postgres_capacity_test.go, but returning the
// generated id so these tests can reconcile against it by name.
func insertReconcilableWorkload(t *testing.T, ctx context.Context, pool *pgxpool.Pool, provider, state string) string {
	t.Helper()
	insertProvider(t, ctx, pool, provider)
	workloadID, requestID := uuid.NewString(), uuid.NewString()
	image := "example.invalid/image@sha256:" + fmt.Sprintf("%064d", 0)
	_, err := pool.Exec(ctx, `
		INSERT INTO workloads (workload_id, request_id, request_hash, definition, image, state,
		                        provider_id, lease_id, container_id, reserved_cpu_millicores, reserved_ram_mb, reserved_storage_gb)
		VALUES ($1,$2,$3,$4,$5,$6,$7,nextval('workload_lease_id_seq'),'container-original',1,1,0)`,
		workloadID, requestID, make([]byte, 32), []byte{1}, image, state, provider)
	if err != nil {
		t.Fatal(err)
	}
	return workloadID
}

func TestPostgresReconcileFromAgentAdvancesOnMatchingProviderAndState(t *testing.T) {
	ctx, pool := newCapacityTestPool(t)
	repository := workloadapi.NewPostgresRepository(pool)
	workloadID := insertReconcilableWorkload(t, ctx, pool, "provider-a", "DEPLOYING")

	applied, err := repository.ReconcileFromAgent(ctx, workloadID, "provider-a", []string{"DEPLOYING"}, "RUNNING", "container-new", "")
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if !applied {
		t.Fatal("expected the transition to apply")
	}
	// Get is owner-scoped (this seeded row has no owner_id); read the row
	// directly instead to verify state/container.
	var state, containerID string
	if err := pool.QueryRow(ctx, `SELECT state, container_id FROM workloads WHERE workload_id=$1`, workloadID).Scan(&state, &containerID); err != nil {
		t.Fatal(err)
	}
	if state != "RUNNING" || containerID != "container-new" {
		t.Fatalf("state=%s container_id=%s, want RUNNING/container-new", state, containerID)
	}
}

// TestPostgresReconcileFromAgentIsANoOpForAWrongProvider is the
// provider-isolation safety property: a state-matching row belonging to a
// *different* provider must never be reconciled.
func TestPostgresReconcileFromAgentIsANoOpForAWrongProvider(t *testing.T) {
	ctx, pool := newCapacityTestPool(t)
	repository := workloadapi.NewPostgresRepository(pool)
	workloadID := insertReconcilableWorkload(t, ctx, pool, "provider-a", "DEPLOYING")

	applied, err := repository.ReconcileFromAgent(ctx, workloadID, "provider-b", []string{"DEPLOYING"}, "RUNNING", "container-new", "")
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if applied {
		t.Fatal("expected no-op for a mismatched provider_id")
	}
	var state string
	if err := pool.QueryRow(ctx, `SELECT state FROM workloads WHERE workload_id=$1`, workloadID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "DEPLOYING" {
		t.Fatalf("state = %s, want unchanged DEPLOYING", state)
	}
}

// TestPostgresReconcileFromAgentIsANoOpWhenStateAlreadyMoved is the
// "duplicate command"/already-advanced-row acceptance case at the SQL
// layer: replaying the same reconciliation after the row already left its
// precondition state (e.g. a worker's own Mark* already advanced it, or an
// earlier heartbeat entry already reconciled it) must not error and must
// not touch the row.
func TestPostgresReconcileFromAgentIsANoOpWhenStateAlreadyMoved(t *testing.T) {
	ctx, pool := newCapacityTestPool(t)
	repository := workloadapi.NewPostgresRepository(pool)
	workloadID := insertReconcilableWorkload(t, ctx, pool, "provider-a", "RUNNING")

	applied, err := repository.ReconcileFromAgent(ctx, workloadID, "provider-a", []string{"DEPLOYING"}, "RUNNING", "container-new", "")
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if applied {
		t.Fatal("expected no-op: the row is already RUNNING, not DEPLOYING")
	}
}

// TestPostgresReconcileFromAgentSetsErrorCodeOnFailedTransition is the
// conflict-handling case at the SQL layer: a FAILED transition persists
// the caller's errorCode and clears any stale next_attempt_at.
func TestPostgresReconcileFromAgentSetsErrorCodeOnFailedTransition(t *testing.T) {
	ctx, pool := newCapacityTestPool(t)
	repository := workloadapi.NewPostgresRepository(pool)
	workloadID := insertReconcilableWorkload(t, ctx, pool, "provider-a", "RUNNING")

	applied, err := repository.ReconcileFromAgent(ctx, workloadID, "provider-a", []string{"DEPLOYING", "RUNNING"}, "FAILED", "", "AGENT_REPORTED_LOST")
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if !applied {
		t.Fatal("expected the transition to apply")
	}
	var state, errorCode string
	if err := pool.QueryRow(ctx, `SELECT state, COALESCE(error_code,'') FROM workloads WHERE workload_id=$1`, workloadID).Scan(&state, &errorCode); err != nil {
		t.Fatal(err)
	}
	if state != "FAILED" || errorCode != "AGENT_REPORTED_LOST" {
		t.Fatalf("state=%s error_code=%s, want FAILED/AGENT_REPORTED_LOST", state, errorCode)
	}
}
