package neutron_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/openinfra/network/internal/agentmanager"
	"github.com/openinfra/network/internal/openstackapi/neutron"
	"github.com/openinfra/network/internal/testsupport"
	"github.com/openinfra/network/internal/userauth"
	"github.com/openinfra/network/internal/workloadapi"
	"github.com/openinfra/network/migrations"
)

// newTestPool isolates each test run into its own schema against
// OPENINFRA_TEST_DATABASE_URL -- the same convention every other
// Postgres-backed test package in this module uses
// (keystone_test.go/projects/postgres_test.go/
// workloadapi/postgres_capacity_test.go).
func newTestPool(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	databaseURL := testsupport.RequireDatabaseURL(t)
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "neutron_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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

// errBoom is a generic sentinel used by tests that only need "the
// dependency failed," not a specific error identity.
var errBoom = errors.New("boom")

// fakeZoneLister is availability_zone_test.go's ZoneLister fake --
// availability zones don't need a real Postgres/Redis heartbeat round
// trip to test the handler's own logic (dedup, sort, wire shape), the
// same "narrow interface, narrow fake" precedent
// keystone_test.go/osauth_test.go already use for their own dependencies.
type fakeZoneLister struct {
	providers []agentmanager.SchedulableProvider
	err       error
}

func (f *fakeZoneLister) ListSchedulableProviders(context.Context) ([]agentmanager.SchedulableProvider, error) {
	return f.providers, f.err
}

// testServer wires a real Postgres-backed neutron.Server exactly the
// way internal/openstackapi.New does, plus the userauth/workloadapi
// repositories tests need to set up fixtures and mint tokens.
type testServer struct {
	handler http.Handler
	pool    *pgxpool.Pool
	users   *userauth.PostgresRepository
}

func newTestServer(t *testing.T, zones neutron.ZoneLister) (context.Context, testServer) {
	t.Helper()
	ctx, pool := newTestPool(t)
	users := userauth.NewPostgresRepository(pool)
	server := neutron.New(users, neutron.NewPostgresBandwidthRepository(pool), neutron.NewPostgresUsageRepository(pool), zones,
		neutron.NewPostgresNetworkRepository(pool), neutron.NewPostgresPortRepository(pool), neutron.NewPostgresSecurityGroupRepository(pool),
		workloadapi.NewPostgresRepository(pool))
	mux := http.NewServeMux()
	server.Register(mux)
	return ctx, testServer{handler: mux, pool: pool, users: users}
}

// mintProjectScopedToken creates a user and a project-scoped API key in
// one call -- most handler tests need exactly this and nothing more.
func mintProjectScopedToken(t *testing.T, ctx context.Context, pool *pgxpool.Pool, users *userauth.PostgresRepository, projectID string) string {
	t.Helper()
	user, err := users.CreateUser(ctx, "neutron-test-user-"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	key, err := users.CreateAPIKeyForProject(ctx, user.UserID, projectID, nil)
	if err != nil {
		t.Fatal(err)
	}
	return key.Raw
}

func mintUnscopedToken(t *testing.T, ctx context.Context, users *userauth.PostgresRepository) string {
	t.Helper()
	user, err := users.CreateUser(ctx, "neutron-test-unscoped-"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	key, err := users.CreateAPIKey(ctx, user.UserID)
	if err != nil {
		t.Fatal(err)
	}
	return key.Raw
}

// createTestProject seeds a minimal projects row directly (this test
// package must not import internal/openstackapi/keystone, which would
// be a needless coupling for a fixture) -- mirrors
// internal/projects/postgres_test.go's own direct-SQL fixture style.
func createTestProject(t *testing.T, ctx context.Context, pool *pgxpool.Pool) string {
	t.Helper()
	projectID := uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO projects (project_id, name) VALUES ($1, $2)`, projectID, "project-"+projectID); err != nil {
		t.Fatal(err)
	}
	return projectID
}

// insertProvider seeds the minimum valid providers row so workloads.
// provider_id's foreign key can reference it -- the same helper shape
// workloadapi/postgres_capacity_test.go's own insertProvider uses.
func insertProvider(t *testing.T, ctx context.Context, pool *pgxpool.Pool, providerID string) {
	t.Helper()
	var publicKey [32]byte
	copy(publicKey[:], providerID)
	if _, err := pool.Exec(ctx, `
		INSERT INTO providers (provider_id, public_key, protocol_version, agent_version, capabilities, status, registered_at)
		VALUES ($1,$2,'1','test',$3,2,now())
		ON CONFLICT (provider_id) DO NOTHING`,
		providerID, publicKey[:], []byte{}); err != nil {
		t.Fatal(err)
	}
}

// insertOwner seeds a minimal users row so workloads.owner_id's foreign
// key can reference it.
func insertOwner(t *testing.T, ctx context.Context, pool *pgxpool.Pool) string {
	t.Helper()
	userID := uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO users (user_id, display_name) VALUES ($1, 'neutron-test-owner')`, userID); err != nil {
		t.Fatal(err)
	}
	return userID
}

// insertOpenWorkload seeds a workload already committed to provider,
// project-scoped, with a bandwidth reservation -- bypassing AssignLease,
// for tests that only need "this reservation already exists" as a
// precondition rather than exercising the capacity check itself (see
// oversubscription_test.go for the tests that do exercise it).
func insertOpenWorkload(t *testing.T, ctx context.Context, pool *pgxpool.Pool, providerID, projectID, state string, ingressMbps, egressMbps int64) string {
	t.Helper()
	insertProvider(t, ctx, pool, providerID)
	ownerID := insertOwner(t, ctx, pool)
	workloadID, requestID := uuid.NewString(), uuid.NewString()
	image := "example.invalid/image@sha256:" + fmt.Sprintf("%064d", 0)
	_, err := pool.Exec(ctx, `
		INSERT INTO workloads (workload_id, request_id, owner_id, request_hash, definition, image, state,
		                        provider_id, lease_id, container_id, project_id,
		                        reserved_cpu_millicores, reserved_ram_mb, reserved_storage_gb,
		                        reserved_ingress_mbps, reserved_egress_mbps)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,nextval('workload_lease_id_seq'),'container',$9,100,128,1,$10,$11)`,
		workloadID, requestID, ownerID, make([]byte, 32), []byte{1}, image, state, providerID, projectID, ingressMbps, egressMbps)
	if err != nil {
		t.Fatal(err)
	}
	return workloadID
}

// insertBandwidthUsage seeds a workload_bandwidth_usage row directly,
// the way internal/providerjoin.PostgresBandwidthUsageStore.RecordUsage
// would after a signature-verified heartbeat.
func insertBandwidthUsage(t *testing.T, ctx context.Context, pool *pgxpool.Pool, providerID, workloadID string, ingress, egress int64) {
	t.Helper()
	now := time.Now().UTC()
	_, err := pool.Exec(ctx, `
		INSERT INTO workload_bandwidth_usage (provider_id, workload_id, ingress_bytes_total, egress_bytes_total, window_started_at, last_reported_at)
		VALUES ($1,$2,$3,$4,$5,$5)`,
		providerID, workloadID, ingress, egress, now)
	if err != nil {
		t.Fatal(err)
	}
}
