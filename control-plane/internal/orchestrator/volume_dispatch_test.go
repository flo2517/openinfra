package orchestrator

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/openinfra/network/internal/agentmanager"
	"github.com/openinfra/network/internal/openstackapi/cinder"
	"github.com/openinfra/network/internal/projects"
	"github.com/openinfra/network/internal/testsupport"
	"github.com/openinfra/network/internal/workloadapi"
	"github.com/openinfra/network/migrations"
	sharedv1 "github.com/openinfra/network/protocol/generated/go/shared/v1"
	"google.golang.org/protobuf/proto"
)

// newVolumeDispatchTestPool isolates each test run into its own schema
// against OPENINFRA_TEST_DATABASE_URL, the same convention every other
// Postgres-backed test in this module uses (see e.g.
// internal/openstackapi/cinder/cinder_test.go's identically-named
// helper). worker_test.go's own fakes (staticDirectory, successfulLeases,
// capturingDispatcher) are pure in-memory doubles and never needed a real
// database; this file adds the one orchestrator test that does, to prove
// the actual production wiring (issue #26 security review's Problem 1)
// end to end against real cinder_volumes/workloads/project_quotas rows,
// not just a hand-rolled VolumeAttachments fake.
func newVolumeDispatchTestPool(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	databaseURL := testsupport.RequireDatabaseURL(t)
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "orchestrator_volume_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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

// TestDeployingDispatchPopulatesVolumesFromRealAttachedCinderVolumes is
// the issue #26 security review's Problem 1 regression test: a workload
// with a Cinder volume already attached to it (via a real
// cinder.PostgresRepository.AttachVolume call against real Postgres, the
// exact row internal/openstackapi/cinder's HTTP handler itself would
// write) must have that attachment show up in the DeployRequest the
// orchestrator's own DEPLOYING dispatch sends to the Agent. Before this
// fix, worker.go's DEPLOYING case never set DeployRequest.Volumes at all
// -- this test fails against that old code (Volumes would be nil/empty
// here) and passes against the fix in worker.go's DEPLOYING case plus
// cinder.PostgresRepository.ListAttachedForWorkload.
func TestDeployingDispatchPopulatesVolumesFromRealAttachedCinderVolumes(t *testing.T) {
	ctx, pool := newVolumeDispatchTestPool(t)
	projectsRepo := projects.NewPostgresRepository(pool)
	cinderRepo := cinder.NewPostgresRepository(pool)
	workloadRepo := workloadapi.NewPostgresRepository(pool)

	project, err := projectsRepo.CreateProject(ctx, "alpha", "")
	if err != nil {
		t.Fatal(err)
	}

	const providerID = "provider-1"
	publicKey := make([]byte, 32)
	if _, err := pool.Exec(ctx, `
		INSERT INTO providers (provider_id, public_key, protocol_version, agent_version, capabilities, status, registered_at, agent_endpoint)
		VALUES ($1,$2,'v1','v1','\x'::bytea,2,now(),'https://agent:50052')`,
		providerID, publicKey); err != nil {
		t.Fatal(err)
	}

	definition, err := proto.Marshal(&sharedv1.WorkloadDefinition{
		Requirements: &sharedv1.ResourceRequirements{Cpu: 1, RamMb: 256},
	})
	if err != nil {
		t.Fatal(err)
	}
	workloadID := uuid.NewString()
	const leaseID = 42
	// Seeded directly in 'DEPLOYING' (bypassing REQUESTED/SCHEDULING/
	// LEASE_PENDING/LEASED, none of which this test needs to exercise --
	// migration 000004's own CHECK constraints require only provider_id
	// and lease_id for 'DEPLOYING', not container_id) so the very next
	// processOne call below claims it and takes the DEPLOYING branch
	// directly.
	if _, err := pool.Exec(ctx, `
		INSERT INTO workloads (workload_id, request_id, request_hash, definition, image, state, provider_id, project_id, lease_id)
		VALUES ($1,$2,$3,$4,$5,'DEPLOYING',$6,$7,$8)`,
		workloadID, uuid.NewString(), make([]byte, 32), definition,
		"busybox@sha256:"+strings.Repeat("b", 64), providerID, project.ProjectID, leaseID); err != nil {
		t.Fatal(err)
	}

	// The real attach path: create then attach, exactly what
	// internal/openstackapi/cinder's HTTP handlers do -- this test
	// deliberately calls the repository directly (not through HTTP)
	// since only the resulting row matters here, not the transport.
	volume, err := cinderRepo.CreateVolume(ctx, cinder.Volume{ProjectID: project.ProjectID, Name: "data", SizeGB: 5})
	if err != nil {
		t.Fatal(err)
	}
	attached, err := cinderRepo.AttachVolume(ctx, volume.VolumeID, project.ProjectID, providerID, workloadID, "/data", true)
	if err != nil {
		t.Fatal(err)
	}
	if attached.State != cinder.StateInUse {
		t.Fatalf("attached.State = %q, want %q", attached.State, cinder.StateInUse)
	}

	provider := agentmanager.SchedulableProvider{RegisteredProvider: agentmanager.RegisteredProvider{ProviderID: providerID, AgentEndpoint: "https://agent:50052"}}
	dispatcher := &capturingDispatcher{}
	worker := NewWorker(workloadRepo, staticDirectory{provider}, successfulLeases{}, dispatcher, testRanker())
	worker.SetVolumeAttachments(cinderRepo)

	if err := worker.processOne(ctx); err != nil {
		t.Fatal(err)
	}
	if dispatcher.request == nil {
		t.Fatal("no DeployRequest captured")
	}
	if len(dispatcher.request.Volumes) != 1 {
		t.Fatalf("DeployRequest.Volumes = %+v, want exactly 1 entry", dispatcher.request.Volumes)
	}
	got := dispatcher.request.Volumes[0]
	if got.VolumeId != volume.VolumeID {
		t.Fatalf("VolumeId = %q, want %q", got.VolumeId, volume.VolumeID)
	}
	if got.MountPath != "/data" {
		t.Fatalf("MountPath = %q, want %q", got.MountPath, "/data")
	}
	if !got.ReadOnly {
		t.Fatal("ReadOnly = false, want true")
	}
}
