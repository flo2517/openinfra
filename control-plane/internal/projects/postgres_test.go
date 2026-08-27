package projects_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/openinfra/network/internal/projects"
	"github.com/openinfra/network/internal/testsupport"
	"github.com/openinfra/network/internal/userauth"
	"github.com/openinfra/network/migrations"
)

// newTestPool isolates each test run into its own schema against
// OPENINFRA_TEST_DATABASE_URL, the same convention
// userauth.newTestPool/workloadapi.newCapacityTestPool use.
func newTestPool(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	databaseURL := testsupport.RequireDatabaseURL(t)
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "projects_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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

func createTestUser(t *testing.T, ctx context.Context, pool *pgxpool.Pool, displayName string) string {
	t.Helper()
	user, err := userauth.NewPostgresRepository(pool).CreateUser(ctx, displayName)
	if err != nil {
		t.Fatal(err)
	}
	return user.UserID
}

// insertWorkload writes a minimal workloads row directly (bypassing
// internal/workloadapi, which this package must not import -- that would
// be a circular dependency once workloadapi/#24 calls into projects),
// with the reservation columns CommittedUsage sums, so CheckQuota's "does
// this count real, already-committed usage" behavior is exercised
// against the actual table shape, not a mock. provider_id/lease_id/
// container_id are always populated (a fresh provider row per call) so
// the same helper works for every state workloads.state's CHECK
// constraints care about (000004/000006), the same
// insertOpenWorkload-style approach internal/workloadapi's own capacity
// tests already use.
func insertWorkload(t *testing.T, ctx context.Context, pool *pgxpool.Pool, projectID, state string, cpuMillicores, ramMB, storageGB int64) {
	t.Helper()
	providerID := "provider-" + uuid.NewString()
	var publicKey [32]byte
	copy(publicKey[:], providerID)
	if _, err := pool.Exec(ctx, `
		INSERT INTO providers (provider_id, public_key, protocol_version, agent_version, capabilities, status, registered_at)
		VALUES ($1,$2,'1','test',$3,2,now())
		ON CONFLICT (provider_id) DO NOTHING`,
		providerID, publicKey[:], []byte{}); err != nil {
		t.Fatal(err)
	}
	workloadID, requestID := uuid.NewString(), uuid.NewString()
	image := "example.invalid/image@sha256:" + fmt.Sprintf("%064d", 0)
	_, err := pool.Exec(ctx, `
		INSERT INTO workloads (workload_id, request_id, request_hash, definition, image, state,
		                        provider_id, lease_id, container_id, project_id,
		                        reserved_cpu_millicores, reserved_ram_mb, reserved_storage_gb)
		VALUES ($1,$2,$3,$4,$5,$6,$7,nextval('workload_lease_id_seq'),'container',$8,$9,$10,$11)`,
		workloadID, requestID, make([]byte, 32), []byte{1}, image, state, providerID, projectID, cpuMillicores, ramMB, storageGB)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCreateProjectAndAddMembershipRoundTrip(t *testing.T) {
	ctx, pool := newTestPool(t)
	repository := projects.NewPostgresRepository(pool)
	userID := createTestUser(t, ctx, pool, "alice")

	project, err := repository.CreateProject(ctx, "alpha", "first project")
	if err != nil {
		t.Fatalf("CreateProject(): %v", err)
	}
	if project.ProjectID == "" || !project.Enabled {
		t.Fatalf("CreateProject() returned %+v, want a non-empty, enabled project", project)
	}

	if err := repository.AddMembership(ctx, project.ProjectID, userID, projects.RoleMember); err != nil {
		t.Fatalf("AddMembership(): %v", err)
	}
	membership, err := repository.GetMembership(ctx, project.ProjectID, userID)
	if err != nil {
		t.Fatalf("GetMembership(): %v", err)
	}
	if membership.Role != projects.RoleMember {
		t.Fatalf("GetMembership().Role = %q, want %q", membership.Role, projects.RoleMember)
	}

	got, err := repository.GetProject(ctx, project.ProjectID)
	if err != nil {
		t.Fatalf("GetProject(): %v", err)
	}
	if got.Name != "alpha" {
		t.Fatalf("GetProject().Name = %q, want %q", got.Name, "alpha")
	}
	byName, err := repository.GetProjectByName(ctx, "alpha")
	if err != nil || byName.ProjectID != project.ProjectID {
		t.Fatalf("GetProjectByName() = %+v, %v, want project %q", byName, err, project.ProjectID)
	}
}

func TestCreateProjectRejectsADuplicateName(t *testing.T) {
	ctx, pool := newTestPool(t)
	repository := projects.NewPostgresRepository(pool)

	if _, err := repository.CreateProject(ctx, "dup", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.CreateProject(ctx, "dup", ""); !errors.Is(err, projects.ErrProjectNameTaken) {
		t.Fatalf("CreateProject() with a duplicate name = %v, want ErrProjectNameTaken", err)
	}
}

func TestGetProjectReturnsNotFoundForAnUnknownID(t *testing.T) {
	ctx, pool := newTestPool(t)
	repository := projects.NewPostgresRepository(pool)

	if _, err := repository.GetProject(ctx, uuid.NewString()); !errors.Is(err, projects.ErrProjectNotFound) {
		t.Fatalf("GetProject() for an unknown ID = %v, want ErrProjectNotFound", err)
	}
}

// TestGetMembershipDeniesACrossProjectUser is the cross-project denial
// test ADR-031's threat model section explicitly calls for: a user who is
// a member of one project must not be treated as a member of another.
func TestGetMembershipDeniesACrossProjectUser(t *testing.T) {
	ctx, pool := newTestPool(t)
	repository := projects.NewPostgresRepository(pool)
	userID := createTestUser(t, ctx, pool, "alice")

	projectA, err := repository.CreateProject(ctx, "project-a", "")
	if err != nil {
		t.Fatal(err)
	}
	projectB, err := repository.CreateProject(ctx, "project-b", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.AddMembership(ctx, projectA.ProjectID, userID, projects.RoleMember); err != nil {
		t.Fatal(err)
	}

	if _, err := repository.GetMembership(ctx, projectB.ProjectID, userID); !errors.Is(err, projects.ErrNotAMember) {
		t.Fatalf("GetMembership() for project B (user only belongs to A) = %v, want ErrNotAMember", err)
	}
	// And an entirely unknown project must fail identically, not leak
	// "this project doesn't exist" as a distinguishable error.
	if _, err := repository.GetMembership(ctx, uuid.NewString(), userID); !errors.Is(err, projects.ErrNotAMember) {
		t.Fatalf("GetMembership() for an unknown project = %v, want ErrNotAMember (same as not-a-member)", err)
	}
}

func TestAddMembershipIsAnUpsertOnRepeatGrant(t *testing.T) {
	ctx, pool := newTestPool(t)
	repository := projects.NewPostgresRepository(pool)
	userID := createTestUser(t, ctx, pool, "alice")
	project, err := repository.CreateProject(ctx, "alpha", "")
	if err != nil {
		t.Fatal(err)
	}

	if err := repository.AddMembership(ctx, project.ProjectID, userID, projects.RoleMember); err != nil {
		t.Fatal(err)
	}
	if err := repository.AddMembership(ctx, project.ProjectID, userID, projects.RoleAdmin); err != nil {
		t.Fatalf("AddMembership() re-grant: %v", err)
	}
	membership, err := repository.GetMembership(ctx, project.ProjectID, userID)
	if err != nil {
		t.Fatal(err)
	}
	if membership.Role != projects.RoleAdmin {
		t.Fatalf("Role after re-grant = %q, want %q", membership.Role, projects.RoleAdmin)
	}
}

func TestAddMembershipRejectsAnUnknownProject(t *testing.T) {
	ctx, pool := newTestPool(t)
	repository := projects.NewPostgresRepository(pool)
	userID := createTestUser(t, ctx, pool, "alice")

	if err := repository.AddMembership(ctx, uuid.NewString(), userID, projects.RoleMember); !errors.Is(err, projects.ErrProjectNotFound) {
		t.Fatalf("AddMembership() for an unknown project = %v, want ErrProjectNotFound", err)
	}
}

func TestSetQuotaAndGetQuotaRoundTrip(t *testing.T) {
	ctx, pool := newTestPool(t)
	repository := projects.NewPostgresRepository(pool)
	project, err := repository.CreateProject(ctx, "alpha", "")
	if err != nil {
		t.Fatal(err)
	}

	if _, ok, err := repository.GetQuota(ctx, project.ProjectID); err != nil || ok {
		t.Fatalf("GetQuota() before SetQuota = ok=%v, err=%v, want ok=false, err=nil (unbounded)", ok, err)
	}

	quota := projects.Quota{ProjectID: project.ProjectID, MaxCPUMillicores: 4000, MaxRAMMB: 8192, MaxStorageGB: 100, MaxWorkloads: 5}
	if err := repository.SetQuota(ctx, quota); err != nil {
		t.Fatalf("SetQuota(): %v", err)
	}
	got, ok, err := repository.GetQuota(ctx, project.ProjectID)
	if err != nil || !ok {
		t.Fatalf("GetQuota() after SetQuota = %+v, ok=%v, err=%v", got, ok, err)
	}
	if got != quota {
		t.Fatalf("GetQuota() = %+v, want %+v", got, quota)
	}

	// SetQuota is an upsert -- a second call changes the existing row.
	quota.MaxWorkloads = 10
	if err := repository.SetQuota(ctx, quota); err != nil {
		t.Fatalf("SetQuota() update: %v", err)
	}
	got, _, err = repository.GetQuota(ctx, project.ProjectID)
	if err != nil || got.MaxWorkloads != 10 {
		t.Fatalf("GetQuota() after update = %+v, %v, want MaxWorkloads=10", got, err)
	}
}

func TestSetQuotaRejectsANonPositiveValueAtTheDatabaseConstraint(t *testing.T) {
	ctx, pool := newTestPool(t)
	repository := projects.NewPostgresRepository(pool)
	project, err := repository.CreateProject(ctx, "alpha", "")
	if err != nil {
		t.Fatal(err)
	}

	cases := []projects.Quota{
		{ProjectID: project.ProjectID, MaxCPUMillicores: 0, MaxRAMMB: 8192, MaxStorageGB: 100, MaxWorkloads: 5},
		{ProjectID: project.ProjectID, MaxCPUMillicores: -1, MaxRAMMB: 8192, MaxStorageGB: 100, MaxWorkloads: 5},
		{ProjectID: project.ProjectID, MaxCPUMillicores: 4000, MaxRAMMB: -8192, MaxStorageGB: 100, MaxWorkloads: 5},
		{ProjectID: project.ProjectID, MaxCPUMillicores: 4000, MaxRAMMB: 8192, MaxStorageGB: 0, MaxWorkloads: 5},
		{ProjectID: project.ProjectID, MaxCPUMillicores: 4000, MaxRAMMB: 8192, MaxStorageGB: 100, MaxWorkloads: -5},
	}
	for _, quota := range cases {
		if err := repository.SetQuota(ctx, quota); err == nil {
			t.Fatalf("SetQuota(%+v) succeeded, want a CHECK-constraint failure (non-positive quota value)", quota)
		}
	}
}

func TestCheckQuotaIsUnboundedWithNoQuotaRow(t *testing.T) {
	ctx, pool := newTestPool(t)
	repository := projects.NewPostgresRepository(pool)
	project, err := repository.CreateProject(ctx, "alpha", "")
	if err != nil {
		t.Fatal(err)
	}

	// An absurdly large request against a project with no quota row must
	// still succeed -- ADR-031 §3's deliberate fail-open default on the
	// quota dimension specifically.
	if err := projects.CheckQuota(ctx, repository, project.ProjectID, projects.Usage{CPUMillicores: 1_000_000, RAMMB: 1_000_000, StorageGB: 1_000_000, Workloads: 1000}); err != nil {
		t.Fatalf("CheckQuota() with no quota row = %v, want nil (unbounded)", err)
	}
}

func TestCheckQuotaAllowsARequestWithinBounds(t *testing.T) {
	ctx, pool := newTestPool(t)
	repository := projects.NewPostgresRepository(pool)
	project, err := repository.CreateProject(ctx, "alpha", "")
	if err != nil {
		t.Fatal(err)
	}
	quota := projects.Quota{ProjectID: project.ProjectID, MaxCPUMillicores: 4000, MaxRAMMB: 8192, MaxStorageGB: 100, MaxWorkloads: 5}
	if err := repository.SetQuota(ctx, quota); err != nil {
		t.Fatal(err)
	}

	if err := projects.CheckQuota(ctx, repository, project.ProjectID, projects.Usage{CPUMillicores: 2000, RAMMB: 4096, StorageGB: 50, Workloads: 1}); err != nil {
		t.Fatalf("CheckQuota() within bounds = %v, want nil", err)
	}
}

// TestCheckQuotaRejectsARequestExceedingBounds is the adversarial case
// the task calls for: a quota-exceeding request is rejected with a
// specific, inspectable error, not a generic failure.
func TestCheckQuotaRejectsARequestExceedingBounds(t *testing.T) {
	ctx, pool := newTestPool(t)
	repository := projects.NewPostgresRepository(pool)
	project, err := repository.CreateProject(ctx, "alpha", "")
	if err != nil {
		t.Fatal(err)
	}
	quota := projects.Quota{ProjectID: project.ProjectID, MaxCPUMillicores: 4000, MaxRAMMB: 8192, MaxStorageGB: 100, MaxWorkloads: 5}
	if err := repository.SetQuota(ctx, quota); err != nil {
		t.Fatal(err)
	}

	err = projects.CheckQuota(ctx, repository, project.ProjectID, projects.Usage{CPUMillicores: 5000})
	if !errors.Is(err, projects.ErrQuotaExceeded) {
		t.Fatalf("CheckQuota() over the CPU limit = %v, want ErrQuotaExceeded", err)
	}
	dimension, requested, limit, ok := projects.QuotaErrorDetail(err)
	if !ok || dimension != "cpu_millicores" || requested != 5000 || limit != 4000 {
		t.Fatalf("QuotaErrorDetail(%v) = %q, %d, %d, %v, want cpu_millicores, 5000, 4000, true", err, dimension, requested, limit, ok)
	}
}

// TestCheckQuotaCountsAlreadyCommittedUsage proves CheckQuota is a real
// reservation ledger, not a stateless per-request bounds check: existing
// open workloads scoped to the project count against the ceiling, the
// same way internal/workloadapi's provider-capacity check already counts
// existing open workloads against a provider's declared total.
func TestCheckQuotaCountsAlreadyCommittedUsage(t *testing.T) {
	ctx, pool := newTestPool(t)
	repository := projects.NewPostgresRepository(pool)
	project, err := repository.CreateProject(ctx, "alpha", "")
	if err != nil {
		t.Fatal(err)
	}
	quota := projects.Quota{ProjectID: project.ProjectID, MaxCPUMillicores: 4000, MaxRAMMB: 8192, MaxStorageGB: 100, MaxWorkloads: 2}
	if err := repository.SetQuota(ctx, quota); err != nil {
		t.Fatal(err)
	}

	// An open (RUNNING) workload already claims 3000m -- only 1000m of
	// headroom remains.
	insertWorkload(t, ctx, pool, project.ProjectID, "RUNNING", 3000, 2048, 10)
	// A COMPLETED workload's reservation must NOT count -- it has left
	// the open-state set.
	insertWorkload(t, ctx, pool, project.ProjectID, "COMPLETED", 3000, 2048, 10)

	if err := projects.CheckQuota(ctx, repository, project.ProjectID, projects.Usage{CPUMillicores: 1000, Workloads: 1}); err != nil {
		t.Fatalf("CheckQuota() within remaining headroom (ignoring the COMPLETED workload) = %v, want nil", err)
	}
	err = projects.CheckQuota(ctx, repository, project.ProjectID, projects.Usage{CPUMillicores: 1500, Workloads: 1})
	if !errors.Is(err, projects.ErrQuotaExceeded) {
		t.Fatalf("CheckQuota() exceeding remaining headroom (3000 committed + 1500 requested > 4000) = %v, want ErrQuotaExceeded", err)
	}
}

func TestCommittedUsageSumsOnlyOpenStateWorkloads(t *testing.T) {
	ctx, pool := newTestPool(t)
	repository := projects.NewPostgresRepository(pool)
	project, err := repository.CreateProject(ctx, "alpha", "")
	if err != nil {
		t.Fatal(err)
	}

	insertWorkload(t, ctx, pool, project.ProjectID, "RUNNING", 1000, 512, 5)
	insertWorkload(t, ctx, pool, project.ProjectID, "DEPLOYING", 500, 256, 2)
	insertWorkload(t, ctx, pool, project.ProjectID, "FAILED", 9999, 9999, 9999)

	usage, err := repository.CommittedUsage(ctx, project.ProjectID)
	if err != nil {
		t.Fatalf("CommittedUsage(): %v", err)
	}
	if usage.CPUMillicores != 1500 || usage.RAMMB != 768 || usage.StorageGB != 7 || usage.Workloads != 2 {
		t.Fatalf("CommittedUsage() = %+v, want {1500 768 7 2}", usage)
	}
}
