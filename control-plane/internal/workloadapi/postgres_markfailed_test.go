package workloadapi_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/openinfra/network/internal/workloadapi"
)

// TestMarkFailedTransitionsToFailedAndClearsRetryState is orchestrator's
// retry cap exhaustion path (issue #138): once RetryPolicy.MaxAttempts is
// reached, worker.retry calls MarkFailed instead of RetryLater. This
// confirms the row lands in FAILED with the failure reason recorded and
// every retry-scheduling field cleared, the same "terminal, not still
// queued" shape RequestStop already produces for STOPPED/COMPLETED/FAILED.
func TestMarkFailedTransitionsToFailedAndClearsRetryState(t *testing.T) {
	ctx, pool := newCapacityTestPool(t)
	repository := workloadapi.NewPostgresRepository(pool)
	item := insertSchedulingWorkload(t, ctx, pool, 1000, 512, 10)

	if err := repository.MarkFailed(ctx, item, "NO_CAPACITY", "giving up after 10 attempts"); err != nil {
		t.Fatalf("MarkFailed: %v", err)
	}

	state, errorCode, lastError, nextAttemptAt, workerID, attemptCount := readFailureFields(t, ctx, pool, item.WorkloadID)
	if state != "FAILED" {
		t.Fatalf("state = %q, want FAILED", state)
	}
	if errorCode != "NO_CAPACITY" {
		t.Fatalf("error_code = %q, want NO_CAPACITY", errorCode)
	}
	if lastError != "giving up after 10 attempts" {
		t.Fatalf("last_error = %q, want the exhaustion message", lastError)
	}
	if nextAttemptAt.Valid {
		t.Fatalf("next_attempt_at = %v, want NULL for a terminal workload", nextAttemptAt)
	}
	if workerID.Valid {
		t.Fatalf("worker_id = %v, want NULL after a terminal transition", workerID)
	}
	if attemptCount != 1 {
		t.Fatalf("attempt_count = %d, want 1 (MarkFailed itself counts as an attempt)", attemptCount)
	}

	// Terminal really means terminal: ClaimNext must never pick this row
	// back up.
	if _, err := repository.ClaimNext(ctx, "any-worker", 0); err == nil {
		t.Fatal("expected ClaimNext to find nothing to claim once the only workload is FAILED")
	}
}

// TestMarkFailedRespectsOptimisticConcurrency mirrors every other Mark*
// method's CAS guard: a worker that no longer holds the current
// version/claim must not be able to terminate a workload another worker
// has since picked back up (e.g. after this worker's claim lease expired
// and a second worker already reclaimed and mutated the row).
func TestMarkFailedRespectsOptimisticConcurrency(t *testing.T) {
	ctx, pool := newCapacityTestPool(t)
	repository := workloadapi.NewPostgresRepository(pool)
	item := insertSchedulingWorkload(t, ctx, pool, 1000, 512, 10)

	stale := item
	stale.Version = item.Version + 1 // pretend a concurrent writer already moved it on

	err := repository.MarkFailed(ctx, stale, "NO_CAPACITY", "stale claim")
	if err != workloadapi.ErrConflict {
		t.Fatalf("MarkFailed with a stale version = %v, want ErrConflict", err)
	}

	state, _, _, _, _, _ := readFailureFields(t, ctx, pool, item.WorkloadID)
	if state != "SCHEDULING" {
		t.Fatalf("state = %q, want SCHEDULING (a stale MarkFailed must not have mutated the row)", state)
	}
}

// TestRetryLaterBeforeMarkFailedStillSucceeds is the "a retry that
// succeeds before the cap doesn't get incorrectly terminated" case at the
// storage layer: RetryLater keeps a workload retryable (state unchanged,
// next_attempt_at set, worker released) right up until a caller decides
// to call MarkFailed instead -- the two are independent transitions, not
// a shared counter that forces termination on its own.
func TestRetryLaterBeforeMarkFailedStillSucceeds(t *testing.T) {
	ctx, pool := newCapacityTestPool(t)
	repository := workloadapi.NewPostgresRepository(pool)
	item := insertSchedulingWorkload(t, ctx, pool, 1000, 512, 10)

	if err := repository.RetryLater(ctx, item, "NO_CAPACITY", "transient", 0); err != nil {
		t.Fatalf("RetryLater: %v", err)
	}

	state, errorCode, _, nextAttemptAt, workerID, attemptCount := readFailureFields(t, ctx, pool, item.WorkloadID)
	if state != "SCHEDULING" {
		t.Fatalf("state = %q, want SCHEDULING (RetryLater must not itself terminate the workload)", state)
	}
	if errorCode != "NO_CAPACITY" || attemptCount != 1 {
		t.Fatalf("error_code=%q attempt_count=%d, want NO_CAPACITY/1", errorCode, attemptCount)
	}
	if !nextAttemptAt.Valid {
		t.Fatal("next_attempt_at = NULL, want a scheduled retry")
	}
	if workerID.Valid {
		t.Fatal("worker_id still set after RetryLater released the claim")
	}

	// A later successful claim+MarkRunning-style progression should still
	// be possible: RetryLater does not poison the row.
	reclaimed, err := repository.ClaimNext(ctx, "second-worker", time.Minute)
	if err != nil {
		t.Fatalf("ClaimNext after RetryLater: %v", err)
	}
	if reclaimed.WorkloadID != item.WorkloadID {
		t.Fatalf("reclaimed %q, want %q", reclaimed.WorkloadID, item.WorkloadID)
	}
}

func readFailureFields(t *testing.T, ctx context.Context, pool *pgxpool.Pool, workloadID string) (state, errorCode, lastError string, nextAttemptAt sql.NullTime, workerID sql.NullString, attemptCount int) {
	t.Helper()
	row := pool.QueryRow(ctx, `SELECT state, COALESCE(error_code,''), COALESCE(last_error,''), next_attempt_at, worker_id, attempt_count FROM workloads WHERE workload_id=$1`, workloadID)
	if err := row.Scan(&state, &errorCode, &lastError, &nextAttemptAt, &workerID, &attemptCount); err != nil {
		t.Fatalf("read back workload row: %v", err)
	}
	return state, errorCode, lastError, nextAttemptAt, workerID, attemptCount
}
