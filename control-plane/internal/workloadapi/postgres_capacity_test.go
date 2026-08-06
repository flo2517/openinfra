package workloadapi_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/openinfra/network/internal/workloadapi"
	"github.com/openinfra/network/migrations"
)

// newCapacityTestPool creates an isolated schema against
// OPENINFRA_TEST_DATABASE_URL, applies every migration into it, and
// returns a ready pool plus its cleanup -- the same isolation pattern
// TestPostgresClaims uses, so this can also run safely against the local
// dev stack.
func newCapacityTestPool(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	databaseURL := os.Getenv("OPENINFRA_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("OPENINFRA_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "capacity_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, fmt.Sprintf(`CREATE SCHEMA %q`, schema)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(ctx, fmt.Sprintf(`DROP SCHEMA %q CASCADE`, schema)) })

	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := migrations.Apply(ctx, pool); err != nil {
		t.Fatal(err)
	}
	return ctx, pool
}

// insertOwner seeds a minimal users row so workloads.owner_id's foreign key
// can reference it, and returns its user_id.
func insertOwner(t *testing.T, ctx context.Context, pool *pgxpool.Pool) string {
	t.Helper()
	userID := uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO users (user_id, display_name) VALUES ($1, 'capacity-test-owner')`, userID); err != nil {
		t.Fatal(err)
	}
	return userID
}

func insertSchedulingWorkload(t *testing.T, ctx context.Context, pool *pgxpool.Pool, cpuMilli, ramMB, storageGB int64) workloadapi.Workload {
	t.Helper()
	workloadID, requestID := uuid.NewString(), uuid.NewString()
	ownerID := insertOwner(t, ctx, pool)
	image := "example.invalid/image@sha256:" + fmt.Sprintf("%064d", 0)
	_, err := pool.Exec(ctx, `
		INSERT INTO workloads (workload_id, request_id, owner_id, request_hash, definition, image, state,
		                        reserved_cpu_millicores, reserved_ram_mb, reserved_storage_gb)
		VALUES ($1,$2,$3,$4,$5,$6,'SCHEDULING',$7,$8,$9)`,
		workloadID, requestID, ownerID, make([]byte, 32), []byte{1}, image, cpuMilli, ramMB, storageGB)
	if err != nil {
		t.Fatal(err)
	}
	repository := workloadapi.NewPostgresRepository(pool)
	claimed, err := repository.ClaimNext(ctx, "test-worker-"+workloadID, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	claimed.ReservedCPUMillicores, claimed.ReservedRAMMB, claimed.ReservedStorageGB = cpuMilli, ramMB, storageGB
	return claimed
}

// insertProvider seeds the minimum valid providers row so workloads.
// provider_id's foreign key can reference it.
func insertProvider(t *testing.T, ctx context.Context, pool *pgxpool.Pool, providerID string) {
	t.Helper()
	var publicKey [32]byte
	copy(publicKey[:], providerID)
	_, err := pool.Exec(ctx, `
		INSERT INTO providers (provider_id, public_key, protocol_version, agent_version, capabilities, status, registered_at)
		VALUES ($1,$2,'1','test',$3,2,now())
		ON CONFLICT (provider_id) DO NOTHING`,
		providerID, publicKey[:], []byte{},
	)
	if err != nil {
		t.Fatal(err)
	}
}

// insertOpenWorkload seeds a workload already committed to provider,
// bypassing AssignLease, so tests can set up "this much capacity is
// already reserved" preconditions directly. container_id is required by
// the RUNNING/COMPLETED check constraint, so a placeholder is always set.
func insertOpenWorkload(t *testing.T, ctx context.Context, pool *pgxpool.Pool, provider, state string, cpuMilli, ramMB, storageGB int64) {
	t.Helper()
	insertProvider(t, ctx, pool, provider)
	workloadID, requestID := uuid.NewString(), uuid.NewString()
	image := "example.invalid/image@sha256:" + fmt.Sprintf("%064d", 0)
	_, err := pool.Exec(ctx, `
		INSERT INTO workloads (workload_id, request_id, request_hash, definition, image, state,
		                        provider_id, lease_id, container_id, reserved_cpu_millicores, reserved_ram_mb, reserved_storage_gb)
		VALUES ($1,$2,$3,$4,$5,$6,$7,nextval('workload_lease_id_seq'),'container',$8,$9,$10)`,
		workloadID, requestID, make([]byte, 32), []byte{1}, image, state, provider, cpuMilli, ramMB, storageGB)
	if err != nil {
		t.Fatal(err)
	}
}

func TestAssignLeaseSucceedsWithinCapacityAndCommitsTheReservation(t *testing.T) {
	ctx, pool := newCapacityTestPool(t)
	repository := workloadapi.NewPostgresRepository(pool)

	insertProvider(t, ctx, pool, "provider-a")
	item := insertSchedulingWorkload(t, ctx, pool, 1000, 1024, 10)
	capacity := workloadapi.ProviderCapacity{TotalCPUMillicores: 4000, TotalRAMMB: 8192, TotalStorageGB: 100}

	leaseID, err := repository.AssignLease(ctx, item, "provider-a", [32]byte{1}, capacity)
	if err != nil {
		t.Fatalf("AssignLease: %v", err)
	}
	if leaseID == 0 {
		t.Fatal("expected a non-zero lease id")
	}
	stored, err := repository.Get(ctx, item.WorkloadID, item.OwnerID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != "LEASE_PENDING" || stored.ProviderID != "provider-a" {
		t.Fatalf("unexpected state after assignment: %+v", stored)
	}
}

func TestAssignLeaseRejectsWhenProviderCapacityIsAlreadyClaimed(t *testing.T) {
	ctx, pool := newCapacityTestPool(t)
	repository := workloadapi.NewPostgresRepository(pool)

	// provider-a's total is 4000 millicores; 3500 already committed via an
	// open (RUNNING) workload.
	insertOpenWorkload(t, ctx, pool, "provider-a", "RUNNING", 3500, 4096, 10)
	item := insertSchedulingWorkload(t, ctx, pool, 1000, 512, 5) // would push total to 4500 > 4000
	capacity := workloadapi.ProviderCapacity{TotalCPUMillicores: 4000, TotalRAMMB: 8192, TotalStorageGB: 100}

	_, err := repository.AssignLease(ctx, item, "provider-a", [32]byte{1}, capacity)
	if !errors.Is(err, workloadapi.ErrCapacityExceeded) {
		t.Fatalf("expected ErrCapacityExceeded, got %v", err)
	}
	// The rejected attempt must not have mutated the row: it is still
	// SCHEDULING and unassigned, so a later retry (possibly against a
	// different provider) can still claim and process it.
	stored, err := repository.Get(ctx, item.WorkloadID, item.OwnerID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.State != "SCHEDULING" || stored.ProviderID != "" {
		t.Fatalf("a rejected AssignLease must not mutate the row: %+v", stored)
	}
}

func TestAssignLeaseIgnoresCompletedAndFailedReservationsWhenSummingCapacity(t *testing.T) {
	ctx, pool := newCapacityTestPool(t)
	repository := workloadapi.NewPostgresRepository(pool)

	// A COMPLETED and a FAILED workload both claimed most of provider-a's
	// capacity in the past, but neither is "open" any more -- they must
	// not count against a new reservation.
	insertOpenWorkload(t, ctx, pool, "provider-a", "COMPLETED", 3500, 4096, 10)
	insertOpenWorkload(t, ctx, pool, "provider-a", "FAILED", 3500, 4096, 10)
	item := insertSchedulingWorkload(t, ctx, pool, 1000, 512, 5)
	capacity := workloadapi.ProviderCapacity{TotalCPUMillicores: 4000, TotalRAMMB: 8192, TotalStorageGB: 100}

	if _, err := repository.AssignLease(ctx, item, "provider-a", [32]byte{1}, capacity); err != nil {
		t.Fatalf("AssignLease must ignore COMPLETED/FAILED reservations: %v", err)
	}
}

// TestAssignLeaseConcurrentRaceNeverOvercommits is the acceptance
// criterion's "test concurrent submissions" case, run against a real
// Postgres: two workloads each individually fit provider-a's declared
// capacity, but their combined demand does not. Racing their AssignLease
// calls must produce exactly one winner, never both -- the property a
// naive "read available, then write" implementation (without the
// Serializable transaction) would violate under real concurrency, not
// just in theory.
func TestAssignLeaseConcurrentRaceNeverOvercommits(t *testing.T) {
	ctx, pool := newCapacityTestPool(t)
	repository := workloadapi.NewPostgresRepository(pool)

	insertProvider(t, ctx, pool, "provider-a")
	capacity := workloadapi.ProviderCapacity{TotalCPUMillicores: 4000, TotalRAMMB: 8192, TotalStorageGB: 100}
	itemA := insertSchedulingWorkload(t, ctx, pool, 3000, 1024, 10)
	itemB := insertSchedulingWorkload(t, ctx, pool, 3000, 1024, 10)

	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, item := range []workloadapi.Workload{itemA, itemB} {
		wg.Add(1)
		go func(w workloadapi.Workload) {
			defer wg.Done()
			_, err := repository.AssignLease(ctx, w, "provider-a", [32]byte{1}, capacity)
			results <- err
		}(item)
	}
	wg.Wait()
	close(results)

	successes, rejections := 0, 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, workloadapi.ErrCapacityExceeded), errors.Is(err, workloadapi.ErrConflict):
			rejections++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if successes != 1 || rejections != 1 {
		t.Fatalf("expected exactly one winner and one rejection under a real race, got successes=%d rejections=%d", successes, rejections)
	}

	// Directly verify the invariant the whole mechanism exists for: sum
	// of reserved capacity on provider-a, across open workloads, never
	// exceeds its declared total.
	var totalCPU int64
	if err := pool.QueryRow(ctx, `
		SELECT COALESCE(SUM(reserved_cpu_millicores), 0) FROM workloads
		WHERE provider_id = 'provider-a' AND state IN ('LEASE_PENDING','LEASED','DEPLOYING','RUNNING')`,
	).Scan(&totalCPU); err != nil {
		t.Fatal(err)
	}
	if totalCPU > capacity.TotalCPUMillicores {
		t.Fatalf("overcommitted: reserved %d millicores against a %d ceiling", totalCPU, capacity.TotalCPUMillicores)
	}
}
