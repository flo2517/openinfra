package workloadapi_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/openinfra/network/internal/testsupport"
	"github.com/openinfra/network/internal/workloadapi"
	"github.com/openinfra/network/migrations"
)

// TestPostgresClaims requires a disposable PostgreSQL database. It creates and
// drops an isolated schema, so it can also run safely against the local stack.
func TestPostgresClaims(t *testing.T) {
	databaseURL := testsupport.RequireDatabaseURL(t)
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "claim_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, fmt.Sprintf(`CREATE SCHEMA %q`, schema)); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = admin.Exec(ctx, fmt.Sprintf(`DROP SCHEMA %q CASCADE`, schema)) }()

	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := migrations.Apply(ctx, pool); err != nil {
		t.Fatal(err)
	}

	workloadID, requestID := uuid.NewString(), uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO workloads (workload_id,request_id,request_hash,definition,image,state) VALUES ($1,$2,$3,$4,$5,'REQUESTED')`, workloadID, requestID, make([]byte, 32), []byte{1}, "example.invalid/image@sha256:"+fmt.Sprintf("%064d", 0)); err != nil {
		t.Fatal(err)
	}
	repository := workloadapi.NewPostgresRepository(pool)

	var wg sync.WaitGroup
	claims := make(chan workloadapi.Workload, 2)
	errs := make(chan error, 2)
	for _, workerID := range []string{"worker-a", "worker-b"} {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			claimed, claimErr := repository.ClaimNext(ctx, id, time.Minute)
			if claimErr != nil {
				errs <- claimErr
				return
			}
			claims <- claimed
		}(workerID)
	}
	wg.Wait()
	close(claims)
	close(errs)
	if len(claims) != 1 || len(errs) != 1 {
		t.Fatalf("one winner required, got claims=%d errors=%d", len(claims), len(errs))
	}
	for claimErr := range errs {
		if !errors.Is(claimErr, workloadapi.ErrNotFound) {
			t.Fatalf("losing worker: %v", claimErr)
		}
	}
	stale := <-claims
	if stale.Version != 2 || stale.WorkerID == "" {
		t.Fatalf("claim did not advance version and record owner: %+v", stale)
	}

	if _, err := pool.Exec(ctx, `UPDATE workloads SET worker_lease_until=now()-interval '1 second' WHERE workload_id=$1`, workloadID); err != nil {
		t.Fatal(err)
	}
	recovered, err := repository.ClaimNext(ctx, "recovery-worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.WorkerID != "recovery-worker" || recovered.Version != stale.Version+1 {
		t.Fatalf("expired claim was not recovered with a new CAS version: %+v", recovered)
	}
	if err := repository.BeginScheduling(ctx, stale); !errors.Is(err, workloadapi.ErrConflict) {
		t.Fatalf("stale owner must lose CAS, got %v", err)
	}
	if err := repository.BeginScheduling(ctx, recovered); err != nil {
		t.Fatalf("current owner transition: %v", err)
	}
}
