package nova_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/openinfra/network/internal/agentmanager"
	"github.com/openinfra/network/internal/blockchainbridge"
	"github.com/openinfra/network/internal/openstackapi/nova"
	"github.com/openinfra/network/internal/orchestrator"
	"github.com/openinfra/network/internal/projects"
	"github.com/openinfra/network/internal/scheduler"
	"github.com/openinfra/network/internal/testsupport"
	"github.com/openinfra/network/internal/userauth"
	"github.com/openinfra/network/internal/workloadapi"
	"github.com/openinfra/network/migrations"
	agentv1 "github.com/openinfra/network/protocol/generated/go/agent/v1"
	sharedv1 "github.com/openinfra/network/protocol/generated/go/shared/v1"
)

// newTestPool isolates each test run into its own schema against
// OPENINFRA_TEST_DATABASE_URL, the same convention every other
// Postgres-backed test in this module uses (see e.g.
// internal/openstackapi/keystone/keystone_test.go's identically-named
// helper).
func newTestPool(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	databaseURL := testsupport.RequireDatabaseURL(t)
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "nova_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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

// fakeDirectory is a static orchestrator.ProviderDirectory /
// nova.ProviderDirectory double -- both packages declare their own
// narrow, structurally-identical interface (see nova.ProviderDirectory's
// doc comment on why nova does not import internal/orchestrator), and a
// single fake here satisfies both, since real Postgres/Redis-backed
// scheduling has nothing to do with what this test exercises.
type fakeDirectory struct {
	providers []agentmanager.SchedulableProvider
}

func (f *fakeDirectory) ListSchedulableProviders(context.Context) ([]agentmanager.SchedulableProvider, error) {
	return f.providers, nil
}

func testProvider() agentmanager.SchedulableProvider {
	return agentmanager.SchedulableProvider{
		RegisteredProvider: agentmanager.RegisteredProvider{
			ProviderID:    "provider-1",
			AgentEndpoint: "https://agent:50052",
			PublicKey:     make([]byte, 32),
		},
		Capabilities: &sharedv1.ResourceCapability{
			CpuTotal: 8, CpuAvailable: 8,
			RamTotalMb: 16384, RamAvailableMb: 16384,
			StorageTotalGb: 200, StorageAvailableGb: 200,
		},
	}
}

// successfulLeases/successfulDispatcher are minimal, always-succeeding
// orchestrator.LeaseRegistrar/AgentDispatcher doubles -- this test does
// not exercise chain finalization or a real Agent, only that
// internal/openstackapi/nova's create-server path produces a workload row
// internal/orchestrator's own, completely unmodified state machine can
// drive to RUNNING.
type successfulLeases struct{}

func (successfulLeases) EnsureLeaseActive(_ context.Context, leaseID uint64, provider, resourceHash [32]byte, _ uint32) (blockchainbridge.FinalizedLease, error) {
	return blockchainbridge.FinalizedLease{LeaseID: leaseID, Provider: provider, ResourceHash: resourceHash}, nil
}
func (successfulLeases) EnsureLeaseCompleted(_ context.Context, leaseID uint64) (blockchainbridge.FinalizedLease, error) {
	return blockchainbridge.FinalizedLease{LeaseID: leaseID}, nil
}

type successfulDispatcher struct{}

func (successfulDispatcher) DeployAndConfirm(_ context.Context, _ agentmanager.RegisteredProvider, request *agentv1.DeployRequest) (string, error) {
	return "container-" + request.WorkloadId, nil
}
func (successfulDispatcher) StopAndConfirm(_ context.Context, _ agentmanager.RegisteredProvider, _ string) error {
	return nil
}

type testServer struct {
	handler      http.Handler
	pool         *pgxpool.Pool
	users        *userauth.PostgresRepository
	projects     *projects.PostgresRepository
	workloadRepo *workloadapi.PostgresRepository
	directory    *fakeDirectory
}

// newTestServer builds a nova.Server backed entirely by real Postgres
// repositories (the same discipline
// internal/openstackapi/keystone/keystone_test.go uses) plus a static
// fakeDirectory -- the only double in this test, standing in for live
// Redis heartbeat data neither this package nor internal/orchestrator's
// own worker_test.go depends on for correctness.
func newTestServer(t *testing.T) (context.Context, testServer) {
	t.Helper()
	ctx, pool := newTestPool(t)
	users := userauth.NewPostgresRepository(pool)
	projectsRepo := projects.NewPostgresRepository(pool)
	workloadRepo := workloadapi.NewPostgresRepository(pool)
	workloadService := workloadapi.NewService(workloadRepo)
	directory := &fakeDirectory{providers: []agentmanager.SchedulableProvider{testProvider()}}
	// AssignLease's UPDATE (workloadapi/postgres.go) writes
	// workloads.provider_id under a real foreign key against providers --
	// a durable row is required for the orchestrator's real SCHEDULING ->
	// LEASE_PENDING transition to succeed against the fakeDirectory's
	// provider above, exactly as it would for a real, joined Agent.
	if _, err := pool.Exec(ctx, `
		INSERT INTO providers (provider_id, public_key, protocol_version, agent_version, capabilities, status, registered_at, agent_endpoint)
		VALUES ($1,$2,'v1','v1','\x'::bytea,2,now(),$3)`, // status=2 is shared/v1.NodeStatus_NODE_STATUS_ACTIVE
		testProvider().ProviderID, make([]byte, 32), testProvider().AgentEndpoint); err != nil {
		t.Fatal(err)
	}
	server := nova.New(pool, users, projectsRepo, workloadService, workloadRepo, directory, nova.DefaultFlavors)
	mux := http.NewServeMux()
	server.Register(mux)
	return ctx, testServer{handler: mux, pool: pool, users: users, projects: projectsRepo, workloadRepo: workloadRepo, directory: directory}
}

// newWorker builds an internal/orchestrator.Worker against the exact same
// *workloadapi.PostgresRepository and fakeDirectory a testServer's
// nova.Server was built with, so a server this test creates through HTTP
// is the very row the worker claims and advances -- proving nova's
// create path and the orchestrator's existing lifecycle are the same
// pipeline, not two independent mechanisms that happen to agree.
func newWorker(s testServer) *orchestrator.Worker {
	ranker := scheduler.NewRanker(scheduler.DefaultMaxReputationScore, scheduler.DefaultDefaultReputationScore)
	return orchestrator.NewWorker(s.workloadRepo, s.directory, successfulLeases{}, successfulDispatcher{}, ranker)
}

type actor struct {
	userID    string
	projectID string
	token     string
}

// newProjectActor mints a real user, a real project, a real
// project_memberships row, and a real project-scoped API key (bridged
// onto the exact X-Auth-Token bearer format osauth.RequireToken expects)
// -- going through the real userauth/projects persistence layer end to
// end, the same discipline keystone_test.go's own tests use, rather than
// a token-authenticator fake.
func newProjectActor(t *testing.T, ctx context.Context, s testServer, projectName, role string) actor {
	t.Helper()
	user, err := s.users.CreateUser(ctx, "user-"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	project, err := s.projects.CreateProject(ctx, projectName, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.projects.AddMembership(ctx, project.ProjectID, user.UserID, role); err != nil {
		t.Fatal(err)
	}
	key, err := s.users.CreateAPIKeyForProject(ctx, user.UserID, project.ProjectID, nil)
	if err != nil {
		t.Fatal(err)
	}
	return actor{userID: user.UserID, projectID: project.ProjectID, token: key.Raw}
}

func doRequest(handler http.Handler, method, path, token string, body []byte) *httptest.ResponseRecorder {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request := httptest.NewRequest(method, path, reader)
	if token != "" {
		request.Header.Set("X-Auth-Token", token)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func createServerBody(name, imageRef, flavorRef string, metadata map[string]string) []byte {
	body := map[string]any{"server": map[string]any{
		"name": name, "imageRef": imageRef, "flavorRef": flavorRef, "metadata": metadata,
	}}
	encoded, _ := json.Marshal(body)
	return encoded
}

const testImageRef = "example.com/app@sha256:" +
	"1111111111111111111111111111111111111111111111111111111111111111"

// waitForWorkloadState polls the real Postgres row (through the
// project-scoped GetByProject path, the exact one nova's own showServer
// handler reads) until it reaches want or fails outright -- driven by a
// real internal/orchestrator.Worker running in the background against
// the fakes above, not a simulated/short-circuited transition.
func waitForWorkloadState(t *testing.T, ctx context.Context, s testServer, projectID, workloadID, want string, timeout time.Duration) workloadapi.Workload {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		workload, err := s.workloadRepo.GetByProject(ctx, workloadID, projectID)
		if err != nil {
			t.Fatalf("GetByProject: %v", err)
		}
		if workload.State == want {
			return workload
		}
		if workload.State == "FAILED" {
			t.Fatalf("workload reached FAILED while waiting for %q: error_code=%q", want, workload.ErrorCode)
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for state %q, last observed state %q", want, workload.State)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestServerLifecycleReachesRunningListsGetsAndDeletes is the task's own
// "create a server, see it reach RUNNING via the existing orchestrator
// flow, list/get/delete it" acceptance criterion, exercised end to end:
// real Postgres, a real internal/orchestrator.Worker, real
// internal/workloadapi validation/reservation/state-machine code -- the
// only doubles are the provider directory and the Agent/chain calls a
// real Docker/Substrate stack would otherwise require.
func TestServerLifecycleReachesRunningListsGetsAndDeletes(t *testing.T) {
	ctx, s := newTestServer(t)
	actor := newProjectActor(t, ctx, s, "alpha", projects.RoleMember)

	worker := newWorker(s)
	workerCtx, cancelWorker := context.WithCancel(ctx)
	go worker.Run(workerCtx)
	defer cancelWorker()

	createRecorder := doRequest(s.handler, http.MethodPost, "/v2.1/"+actor.projectID+"/servers", actor.token,
		createServerBody("web-1", testImageRef, "1", map[string]string{"env": "test"}))
	if createRecorder.Code != http.StatusAccepted {
		t.Fatalf("create status = %d, want %d; body=%s", createRecorder.Code, http.StatusAccepted, createRecorder.Body.String())
	}
	var created struct {
		Server struct {
			ID     string `json:"id"`
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"server"`
	}
	if err := json.Unmarshal(createRecorder.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Server.ID == "" || created.Server.Name != "web-1" {
		t.Fatalf("created server = %+v, want a non-empty id and name web-1", created.Server)
	}
	serverID := created.Server.ID

	// Drive the real orchestrator state machine to RUNNING.
	waitForWorkloadState(t, ctx, s, actor.projectID, serverID, "RUNNING", 20*time.Second)

	// GET reflects ACTIVE (Nova's mapping of workloadapi's RUNNING).
	showRecorder := doRequest(s.handler, http.MethodGet, "/v2.1/"+actor.projectID+"/servers/"+serverID, actor.token, nil)
	if showRecorder.Code != http.StatusOK {
		t.Fatalf("show status = %d, want %d; body=%s", showRecorder.Code, http.StatusOK, showRecorder.Body.String())
	}
	var shown struct {
		Server struct {
			ID       string            `json:"id"`
			Name     string            `json:"name"`
			Status   string            `json:"status"`
			Metadata map[string]string `json:"metadata"`
			Flavor   map[string]string `json:"flavor"`
		} `json:"server"`
	}
	if err := json.Unmarshal(showRecorder.Body.Bytes(), &shown); err != nil {
		t.Fatal(err)
	}
	if shown.Server.Status != "ACTIVE" {
		t.Fatalf("shown server status = %q, want ACTIVE", shown.Server.Status)
	}
	if shown.Server.Metadata["env"] != "test" {
		t.Fatalf("shown server metadata = %+v, want env=test", shown.Server.Metadata)
	}
	if shown.Server.Flavor["id"] != "1" {
		t.Fatalf("shown server flavor = %+v, want id=1", shown.Server.Flavor)
	}

	// LIST includes it.
	listRecorder := doRequest(s.handler, http.MethodGet, "/v2.1/"+actor.projectID+"/servers", actor.token, nil)
	if listRecorder.Code != http.StatusOK {
		t.Fatalf("list status = %d, want %d", listRecorder.Code, http.StatusOK)
	}
	var listed struct {
		Servers []struct {
			ID string `json:"id"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(listRecorder.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, entry := range listed.Servers {
		if entry.ID == serverID {
			found = true
		}
	}
	if !found {
		t.Fatalf("list did not include server %q: %+v", serverID, listed.Servers)
	}

	// DELETE stops it -- through the exact RequestStopByProject/orchestrator
	// STOPPING->STOPPED path, real state machine again.
	deleteRecorder := doRequest(s.handler, http.MethodDelete, "/v2.1/"+actor.projectID+"/servers/"+serverID, actor.token, nil)
	if deleteRecorder.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d, want %d; body=%s", deleteRecorder.Code, http.StatusNoContent, deleteRecorder.Body.String())
	}
	waitForWorkloadState(t, ctx, s, actor.projectID, serverID, "STOPPED", 20*time.Second)

	// A second GET after delete still finds it (workloads rows are never
	// hard-deleted), now reporting SHUTOFF.
	afterDeleteRecorder := doRequest(s.handler, http.MethodGet, "/v2.1/"+actor.projectID+"/servers/"+serverID, actor.token, nil)
	if afterDeleteRecorder.Code != http.StatusOK {
		t.Fatalf("post-delete show status = %d, want %d", afterDeleteRecorder.Code, http.StatusOK)
	}
	var afterDelete struct {
		Server struct {
			Status string `json:"status"`
		} `json:"server"`
	}
	if err := json.Unmarshal(afterDeleteRecorder.Body.Bytes(), &afterDelete); err != nil {
		t.Fatal(err)
	}
	if afterDelete.Server.Status != "SHUTOFF" {
		t.Fatalf("post-delete status = %q, want SHUTOFF", afterDelete.Server.Status)
	}
}

// TestCreateServerRejectsWithoutAValidToken is the task's explicit "401
// without a valid token" acceptance criterion.
func TestCreateServerRejectsWithoutAValidToken(t *testing.T) {
	_, s := newTestServer(t)
	recorder := doRequest(s.handler, http.MethodPost, "/v2.1/"+uuid.NewString()+"/servers", "", createServerBody("x", testImageRef, "1", nil))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusUnauthorized, recorder.Body.String())
	}
	var decoded struct {
		Error struct {
			Code    int    `json:"code"`
			Title   string `json:"title"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("401 body is not the Keystone error shape (osauth.RequireToken's own layer): %v (%s)", err, recorder.Body.Bytes())
	}
}

// TestCreateServerRejectsAnInvalidToken proves a syntactically-present
// but unknown/never-issued token is rejected identically to a missing
// one.
func TestCreateServerRejectsAnInvalidToken(t *testing.T) {
	_, s := newTestServer(t)
	recorder := doRequest(s.handler, http.MethodPost, "/v2.1/"+uuid.NewString()+"/servers", "oiu_never-issued", createServerBody("x", testImageRef, "1", nil))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
}

// TestServerRoutesRejectAcrossAProjectBoundary is the task's explicit
// "403 across a project boundary" acceptance criterion: a caller with a
// validly-scoped token for project A, addressing project B's URL,
// is denied with Nova's own fault shape (requireProjectScope), not the
// osauth 401 layer -- proving this is a real, distinguishable
// authorization decision, not authentication failure in disguise.
func TestServerRoutesRejectAcrossAProjectBoundary(t *testing.T) {
	ctx, s := newTestServer(t)
	actor := newProjectActor(t, ctx, s, "alpha", projects.RoleMember)
	otherProject, err := s.projects.CreateProject(ctx, "beta", "")
	if err != nil {
		t.Fatal(err)
	}

	recorder := doRequest(s.handler, http.MethodGet, "/v2.1/"+otherProject.ProjectID+"/servers", actor.token, nil)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusForbidden, recorder.Body.String())
	}
	var decoded map[string]struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("403 body is not Nova's own fault shape: %v (%s)", err, recorder.Body.Bytes())
	}
	if _, ok := decoded["forbidden"]; !ok {
		t.Fatalf("403 body missing the \"forbidden\" fault wrapper: %+v", decoded)
	}
}

// TestCreateServerRejectsAnUnscopedToken proves a valid-but-unscoped
// token (no project) cannot reach a project-scoped route at all.
func TestCreateServerRejectsAnUnscopedToken(t *testing.T) {
	ctx, s := newTestServer(t)
	user, err := s.users.CreateUser(ctx, "unscoped-user")
	if err != nil {
		t.Fatal(err)
	}
	key, err := s.users.CreateAPIKey(ctx, user.UserID)
	if err != nil {
		t.Fatal(err)
	}
	recorder := doRequest(s.handler, http.MethodPost, "/v2.1/"+uuid.NewString()+"/servers", key.Raw, createServerBody("x", testImageRef, "1", nil))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusForbidden, recorder.Body.String())
	}
}

// TestCreateServerRejectsWhenProjectQuotaIsExceeded is the task's
// explicit "quota rejection when a project's reservation is exceeded"
// acceptance criterion, exercised against internal/projects.CheckQuota
// for real (not mocked): a quota tight enough that the requested flavor
// alone cannot fit.
func TestCreateServerRejectsWhenProjectQuotaIsExceeded(t *testing.T) {
	ctx, s := newTestServer(t)
	actor := newProjectActor(t, ctx, s, "quota-bound", projects.RoleMember)
	if err := s.projects.SetQuota(ctx, projects.Quota{
		ProjectID: actor.projectID,
		// oi.small (flavor "1") needs 1000 CPU millicores; this quota
		// allows only 500 -- deliberately too small for even the smallest
		// flavor, so CheckQuota's CPU dimension is what actually trips.
		MaxCPUMillicores: 500, MaxRAMMB: 100_000, MaxStorageGB: 100_000, MaxWorkloads: 100,
	}); err != nil {
		t.Fatal(err)
	}

	recorder := doRequest(s.handler, http.MethodPost, "/v2.1/"+actor.projectID+"/servers", actor.token,
		createServerBody("too-big", testImageRef, "1", nil))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusForbidden, recorder.Body.String())
	}
	var decoded map[string]struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	fault, ok := decoded["forbidden"]
	if !ok || !strings.Contains(fault.Message, "cpu_millicores") {
		t.Fatalf("expected a forbidden fault naming cpu_millicores, got: %+v", decoded)
	}

	// The workload must not have been created at all -- a quota rejection
	// is not a partial success.
	listRecorder := doRequest(s.handler, http.MethodGet, "/v2.1/"+actor.projectID+"/servers", actor.token, nil)
	var listed struct {
		Servers []map[string]any `json:"servers"`
	}
	if err := json.Unmarshal(listRecorder.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Servers) != 0 {
		t.Fatalf("expected no servers after a quota-rejected create, got %d", len(listed.Servers))
	}
}

// TestCreateServerAllowsAProjectWithNoConfiguredQuota proves ADR-031 §3's
// deliberate fail-open default (a project with no quota row is
// unbounded on the quota dimension) is honored end to end through this
// package, not just at the internal/projects.CheckQuota unit-test layer.
func TestCreateServerAllowsAProjectWithNoConfiguredQuota(t *testing.T) {
	ctx, s := newTestServer(t)
	actor := newProjectActor(t, ctx, s, "unbounded", projects.RoleMember)

	recorder := doRequest(s.handler, http.MethodPost, "/v2.1/"+actor.projectID+"/servers", actor.token,
		createServerBody("fine", testImageRef, "4", nil)) // largest default flavor
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusAccepted, recorder.Body.String())
	}
}

// TestCreateServerRejectsAnUnknownFlavor proves a client that supplies a
// flavorRef this deployment's catalog does not recognize gets a real
// error, not a silently-substituted default.
func TestCreateServerRejectsAnUnknownFlavor(t *testing.T) {
	ctx, s := newTestServer(t)
	actor := newProjectActor(t, ctx, s, "flavor-check", projects.RoleMember)

	recorder := doRequest(s.handler, http.MethodPost, "/v2.1/"+actor.projectID+"/servers", actor.token,
		createServerBody("x", testImageRef, "does-not-exist", nil))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
	}
}

// TestGetServerReturns404ForANonexistentServer proves GetByProject's
// existence-oracle-avoidance carries through this handler (see
// requireProjectScope's doc comment: within an already-correctly-scoped
// project, a resource-level miss is 404, not 403).
func TestGetServerReturns404ForANonexistentServer(t *testing.T) {
	ctx, s := newTestServer(t)
	actor := newProjectActor(t, ctx, s, "gamma", projects.RoleMember)

	recorder := doRequest(s.handler, http.MethodGet, "/v2.1/"+actor.projectID+"/servers/"+uuid.NewString(), actor.token, nil)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusNotFound, recorder.Body.String())
	}
}

// TestFlavorsListingIsProjectScopedButNotProjectSpecific proves the
// static flavor catalog is reachable by any correctly-scoped project
// (there is nothing project-specific about a flavor's definition).
func TestFlavorsListingIsProjectScopedButNotProjectSpecific(t *testing.T) {
	ctx, s := newTestServer(t)
	actor := newProjectActor(t, ctx, s, "flavors", projects.RoleMember)

	recorder := doRequest(s.handler, http.MethodGet, "/v2.1/"+actor.projectID+"/flavors", actor.token, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var decoded struct {
		Flavors []struct {
			ID string `json:"id"`
		} `json:"flavors"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Flavors) != len(nova.DefaultFlavors) {
		t.Fatalf("flavors = %d, want %d", len(decoded.Flavors), len(nova.DefaultFlavors))
	}
}

// TestMicroversionHeaderIsNegotiatedAndEchoedBack is the task's "API
// microversion header handling" acceptance criterion: an explicit,
// in-range request is echoed back on both the modern and legacy header
// names; no header at all defaults to the minimum.
func TestMicroversionHeaderIsNegotiatedAndEchoedBack(t *testing.T) {
	ctx, s := newTestServer(t)
	actor := newProjectActor(t, ctx, s, "microversion", projects.RoleMember)

	request := httptest.NewRequest(http.MethodGet, "/v2.1/"+actor.projectID+"/flavors", nil)
	request.Header.Set("X-Auth-Token", actor.token)
	request.Header.Set("OpenStack-API-Version", "compute 2.1")
	recorder := httptest.NewRecorder()
	s.handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if got := recorder.Header().Get("OpenStack-API-Version"); got != "compute 2.1" {
		t.Fatalf("OpenStack-API-Version = %q, want %q", got, "compute 2.1")
	}
	if got := recorder.Header().Get("X-OpenStack-Nova-API-Version"); got != "2.1" {
		t.Fatalf("X-OpenStack-Nova-API-Version = %q, want %q", got, "2.1")
	}
}

// TestMicroversionHeaderRejectsAnOutOfRangeVersion proves an explicit
// request for a microversion this deployment does not serve is rejected
// with 406, not silently downgraded/upgraded.
func TestMicroversionHeaderRejectsAnOutOfRangeVersion(t *testing.T) {
	ctx, s := newTestServer(t)
	actor := newProjectActor(t, ctx, s, "microversion-oor", projects.RoleMember)

	request := httptest.NewRequest(http.MethodGet, "/v2.1/"+actor.projectID+"/flavors", nil)
	request.Header.Set("X-Auth-Token", actor.token)
	request.Header.Set("OpenStack-API-Version", "compute 9.9")
	recorder := httptest.NewRecorder()
	s.handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNotAcceptable {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusNotAcceptable, recorder.Body.String())
	}
}

// TestMicroversionHeaderDefaultsWithoutAnyHeader proves an unversioned
// request still succeeds, negotiated at the minimum microversion.
func TestMicroversionHeaderDefaultsWithoutAnyHeader(t *testing.T) {
	ctx, s := newTestServer(t)
	actor := newProjectActor(t, ctx, s, "microversion-default", projects.RoleMember)

	recorder := doRequest(s.handler, http.MethodGet, "/v2.1/"+actor.projectID+"/flavors", actor.token, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if got := recorder.Header().Get("OpenStack-API-Version"); got != "compute "+nova.MinMicroversion {
		t.Fatalf("OpenStack-API-Version = %q, want %q", got, "compute "+nova.MinMicroversion)
	}
}
