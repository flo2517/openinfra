package migrations_test

// Package migrations_test, not migrations, so this only ever exercises
// Apply() the same way every real caller does (cmd/controlplane,
// cmd/controlplane-admin) -- through the public API, against a real
// Postgres schema, never a package-internal shortcut.

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/openinfra/network/internal/testsupport"
	"github.com/openinfra/network/migrations"
)

// newScratchSchema isolates this test into its own schema against
// OPENINFRA_TEST_DATABASE_URL, the same convention every other Postgres
// integration test in this module uses (see e.g.
// internal/walletlogin/postgres_test.go's newTestPool) -- except this one
// deliberately does *not* call migrations.Apply for its caller, since
// applying it (repeatedly, and observing the ledger) is exactly what is
// under test here.
func newScratchSchema(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	databaseURL := testsupport.RequireDatabaseURL(t)
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "migrations_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
	return ctx, pool
}

// TestApplyIsIdempotent is issue #17's database-migration acceptance
// criterion at unit scope: every embedded .sql file must be safe to
// re-run against a schema that already has it applied. Apply() achieves
// this with a schema_migrations ledger (skip a name once its row exists)
// -- this test is the guard that a future migration author does not
// accidentally break that ledger, or write DDL that isn't itself
// re-run-safe (every statement in migrations/*.sql already uses IF NOT
// EXISTS / IF EXISTS for exactly this reason -- see e.g.
// 000006_workload_stop.sql's DROP CONSTRAINT IF EXISTS + re-ADD pattern).
//
// The rollback half of the acceptance criterion (documented, reversible
// DDL per migration) is exercised separately against a real Compose
// Postgres in tests/e2e/suites/30-migrations-rollback.sh, which actually
// runs ROLLBACK.md's SQL and checks the schema returns to its prior
// shape -- a scratch-schema unit test has no "prior shape" to return to.
func TestApplyIsIdempotent(t *testing.T) {
	ctx, pool := newScratchSchema(t)

	if err := migrations.Apply(ctx, pool); err != nil {
		t.Fatalf("first Apply(): %v", err)
	}
	var firstCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&firstCount); err != nil {
		t.Fatalf("count schema_migrations after first Apply(): %v", err)
	}
	if firstCount == 0 {
		t.Fatal("first Apply() recorded zero migrations -- migrations/*.sql is unexpectedly empty")
	}

	if err := migrations.Apply(ctx, pool); err != nil {
		t.Fatalf("second Apply() against an already-migrated schema: %v", err)
	}
	var secondCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&secondCount); err != nil {
		t.Fatalf("count schema_migrations after second Apply(): %v", err)
	}
	if secondCount != firstCount {
		t.Fatalf("second Apply() changed the migration ledger: %d rows -> %d rows (want unchanged)", firstCount, secondCount)
	}

	// A third Apply(), from a brand new pool/connection against the same
	// schema, rules out any per-connection state (e.g. a prepared
	// statement cache) masking a real non-idempotence.
	freshPool, dialErr := pgxpool.NewWithConfig(ctx, pool.Config())
	if dialErr != nil {
		t.Fatalf("open a second pool against the same schema: %v", dialErr)
	}
	defer freshPool.Close()
	if err := migrations.Apply(ctx, freshPool); err != nil {
		t.Fatalf("third Apply() from a fresh connection pool: %v", err)
	}
}
