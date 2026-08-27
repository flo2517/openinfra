package cinder_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/openinfra/network/internal/openstackapi/cinder"
	"github.com/openinfra/network/internal/projects"
	"github.com/openinfra/network/internal/testsupport"
	"github.com/openinfra/network/internal/userauth"
	"github.com/openinfra/network/internal/workloadapi"
	"github.com/openinfra/network/migrations"
)

// newTestPool isolates each test run into its own schema against
// OPENINFRA_TEST_DATABASE_URL, the same convention every other
// Postgres-backed test in this module uses (see e.g.
// internal/openstackapi/glance/glance_test.go's identically-named
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
	schema := "cinder_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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

// fakeDispatcher is a VolumeDispatcher double that records every call and
// can be configured to fail -- lets tests assert deleteVolume both
// invokes the Agent-facing dispatch for a provider-bound volume and
// handles a dispatch failure by rolling the row back to 'available'
// rather than losing it in 'deleting' or falsely marking it deleted.
type fakeDispatcher struct {
	mu    sync.Mutex
	calls []struct{ providerID, volumeID string }
	fail  error
}

func (f *fakeDispatcher) DeleteVolume(_ context.Context, providerID, volumeID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, struct{ providerID, volumeID string }{providerID, volumeID})
	return f.fail
}

func (f *fakeDispatcher) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

type testServer struct {
	handler      http.Handler
	pool         *pgxpool.Pool
	users        *userauth.PostgresRepository
	projects     *projects.PostgresRepository
	workloadRepo *workloadapi.PostgresRepository
	dispatcher   *fakeDispatcher
}

func newTestServer(t *testing.T) (context.Context, testServer) {
	t.Helper()
	ctx, pool := newTestPool(t)
	users := userauth.NewPostgresRepository(pool)
	projectsRepo := projects.NewPostgresRepository(pool)
	workloadRepo := workloadapi.NewPostgresRepository(pool)
	dispatcher := &fakeDispatcher{}
	server := cinder.New(users, cinder.NewPostgresRepository(pool), workloadRepo, dispatcher, projectsRepo, nil)
	mux := http.NewServeMux()
	server.Register(mux)
	return ctx, testServer{handler: mux, pool: pool, users: users, projects: projectsRepo, workloadRepo: workloadRepo, dispatcher: dispatcher}
}

type actor struct {
	userID    string
	projectID string
	token     string
}

func newProjectActor(t *testing.T, ctx context.Context, s testServer, projectName string) actor {
	t.Helper()
	user, err := s.users.CreateUser(ctx, "user-"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	project, err := s.projects.CreateProject(ctx, projectName, "")
	if err != nil {
		t.Fatal(err)
	}
	key, err := s.users.CreateAPIKeyForProject(ctx, user.UserID, project.ProjectID, nil)
	if err != nil {
		t.Fatal(err)
	}
	return actor{userID: user.UserID, projectID: project.ProjectID, token: key.Raw}
}

func unscopedToken(t *testing.T, ctx context.Context, s testServer) string {
	t.Helper()
	user, err := s.users.CreateUser(ctx, "user-"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	key, err := s.users.CreateAPIKey(ctx, user.UserID)
	if err != nil {
		t.Fatal(err)
	}
	return key.Raw
}

// seedScheduledWorkload inserts a workloads row directly, bypassing full
// submission/scheduling (neither of which this package's own tests need
// to exercise) -- LEASE_PENDING is the least-privileged state whose own
// CHECK constraint (migration 000004) requires provider_id, without
// additionally requiring lease_id/container_id the way
// LEASED/DEPLOYING/RUNNING would.
func seedScheduledWorkload(t *testing.T, ctx context.Context, pool *pgxpool.Pool, providerID, projectID string) string {
	t.Helper()
	// public_key carries a real UNIQUE constraint (migration 000001) --
	// derived from providerID (not a fixed all-zero value) so seeding two
	// distinct providers in the same test never collides.
	publicKey := sha256.Sum256([]byte(providerID))
	if _, err := pool.Exec(ctx, `
		INSERT INTO providers (provider_id, public_key, protocol_version, agent_version, capabilities, status, registered_at, agent_endpoint)
		VALUES ($1,$2,'v1','v1','\x'::bytea,2,now(),'https://agent:50052')
		ON CONFLICT (provider_id) DO NOTHING`,
		providerID, publicKey[:]); err != nil {
		t.Fatal(err)
	}
	workloadID := uuid.NewString()
	if _, err := pool.Exec(ctx, `
		INSERT INTO workloads (workload_id, request_id, request_hash, definition, image, state, provider_id, project_id)
		VALUES ($1,$2,$3,$4,'test-image','LEASE_PENDING',$5,$6)`,
		workloadID, uuid.NewString(), make([]byte, 32), []byte{}, providerID, projectID); err != nil {
		t.Fatal(err)
	}
	return workloadID
}

func createVolumeBody(name string, sizeGB int64) []byte {
	body := map[string]any{"volume": map[string]any{"name": name, "size": sizeGB}}
	encoded, _ := json.Marshal(body)
	return encoded
}

func attachActionBody(instanceUUID, mountpoint string) []byte {
	body := map[string]any{"os-attach": map[string]any{"instance_uuid": instanceUUID, "mountpoint": mountpoint}}
	encoded, _ := json.Marshal(body)
	return encoded
}

func detachActionBody() []byte {
	body := map[string]any{"os-detach": map[string]any{}}
	encoded, _ := json.Marshal(body)
	return encoded
}

type volumeBody struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Size        int64  `json:"size"`
	Status      string `json:"status"`
	Attachments []struct {
		ServerID string `json:"server_id"`
		Device   string `json:"device"`
	} `json:"attachments"`
}

func decodeVolume(t *testing.T, body []byte) volumeBody {
	t.Helper()
	var decoded struct {
		Volume volumeBody `json:"volume"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("response is not a {\"volume\": ...} body: %v (%s)", err, body)
	}
	return decoded.Volume
}

func decodeFault(t *testing.T, body []byte) (status int, message string) {
	t.Helper()
	var decoded map[string]struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("response is not the Cinder fault shape: %v (%s)", err, body)
	}
	for _, fault := range decoded {
		return fault.Code, fault.Message
	}
	return 0, ""
}

func doRequest(t *testing.T, s testServer, method, path, token string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	if token != "" {
		request.Header.Set("X-Auth-Token", token)
	}
	recorder := httptest.NewRecorder()
	s.handler.ServeHTTP(recorder, request)
	return recorder
}

func TestCreateVolumeRegistersAWellFormedVolume(t *testing.T) {
	ctx, s := newTestServer(t)
	actor := newProjectActor(t, ctx, s, "alpha")

	recorder := doRequest(t, s, http.MethodPost, "/v3/"+actor.projectID+"/volumes", actor.token, createVolumeBody("data-volume", 10))
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusAccepted, recorder.Body.String())
	}
	volume := decodeVolume(t, recorder.Body.Bytes())
	if _, err := uuid.Parse(volume.ID); err != nil {
		t.Fatalf("id = %q is not a UUID", volume.ID)
	}
	if volume.Size != 10 || volume.Status != "available" || len(volume.Attachments) != 0 {
		t.Fatalf("unexpected volume = %+v", volume)
	}
}

func TestCreateVolumeRejectsAnUnauthenticatedRequest(t *testing.T) {
	_, s := newTestServer(t)
	recorder := doRequest(t, s, http.MethodPost, "/v3/"+uuid.NewString()+"/volumes", "", createVolumeBody("x", 1))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusUnauthorized, recorder.Body.String())
	}
}

func TestCreateVolumeRejectsAnUnscopedToken(t *testing.T) {
	ctx, s := newTestServer(t)
	token := unscopedToken(t, ctx, s)
	recorder := doRequest(t, s, http.MethodPost, "/v3/"+uuid.NewString()+"/volumes", token, createVolumeBody("x", 1))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusForbidden, recorder.Body.String())
	}
}

// TestCreateVolumeRejectsAMismatchedProjectPath is the task's explicit
// "cross-project access denial" case applied to the URL itself: a
// correctly project-scoped token may not act as a different project
// simply by naming it in the path.
func TestCreateVolumeRejectsAMismatchedProjectPath(t *testing.T) {
	ctx, s := newTestServer(t)
	actor := newProjectActor(t, ctx, s, "alpha")
	recorder := doRequest(t, s, http.MethodPost, "/v3/"+uuid.NewString()+"/volumes", actor.token, createVolumeBody("x", 1))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusForbidden, recorder.Body.String())
	}
}

// TestCreateVolumeEnforcesProjectQuota is the task's explicit "quota
// enforcement via internal/projects.CheckQuota" case.
func TestCreateVolumeEnforcesProjectQuota(t *testing.T) {
	ctx, s := newTestServer(t)
	actor := newProjectActor(t, ctx, s, "alpha")
	if err := s.projects.SetQuota(ctx, projects.Quota{ProjectID: actor.projectID, MaxCPUMillicores: 1000, MaxRAMMB: 1000, MaxStorageGB: 20, MaxWorkloads: 10}); err != nil {
		t.Fatal(err)
	}

	// Within quota: succeeds.
	ok := doRequest(t, s, http.MethodPost, "/v3/"+actor.projectID+"/volumes", actor.token, createVolumeBody("first", 15))
	if ok.Code != http.StatusAccepted {
		t.Fatalf("first create status = %d, want %d; body=%s", ok.Code, http.StatusAccepted, ok.Body.String())
	}

	// A second volume that would push committed storage past 20GB total
	// is rejected -- proves CheckQuota is evaluated against *cumulative*
	// committed volume storage (internal/projects.PostgresRepository.
	// CommittedUsage's cinder_volumes contribution), not just this
	// request's own size in isolation.
	over := doRequest(t, s, http.MethodPost, "/v3/"+actor.projectID+"/volumes", actor.token, createVolumeBody("second", 10))
	if over.Code != http.StatusForbidden {
		t.Fatalf("over-quota status = %d, want %d; body=%s", over.Code, http.StatusForbidden, over.Body.String())
	}
	_, message := decodeFault(t, over.Body.Bytes())
	if !strings.Contains(message, "storage_gb") {
		t.Fatalf("fault message = %q, want it to name storage_gb", message)
	}
}

func TestGetVolumeRejectsAnUnknownID(t *testing.T) {
	ctx, s := newTestServer(t)
	actor := newProjectActor(t, ctx, s, "alpha")
	recorder := doRequest(t, s, http.MethodGet, "/v3/"+actor.projectID+"/volumes/"+uuid.NewString(), actor.token, nil)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNotFound)
	}
}

// TestGetVolumeDeniesCrossProjectAccess is the task's explicit
// "cross-project access denial" case for reads: unlike glance's images,
// a Cinder volume has no public-visibility escape hatch at all
// (ADR-034 §8) -- a different project's volume is always 404, never
// reachable under any circumstance.
func TestGetVolumeDeniesCrossProjectAccess(t *testing.T) {
	ctx, s := newTestServer(t)
	owner := newProjectActor(t, ctx, s, "alpha")
	other := newProjectActor(t, ctx, s, "beta")

	created := decodeVolume(t, doRequest(t, s, http.MethodPost, "/v3/"+owner.projectID+"/volumes", owner.token, createVolumeBody("private", 5)).Body.Bytes())

	recorder := doRequest(t, s, http.MethodGet, "/v3/"+other.projectID+"/volumes/"+created.ID, other.token, nil)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d (not found, not forbidden -- no enumeration oracle); body=%s", recorder.Code, http.StatusNotFound, recorder.Body.String())
	}
}

func TestListVolumesReturnsOnlyThisProjectsVolumes(t *testing.T) {
	ctx, s := newTestServer(t)
	alpha := newProjectActor(t, ctx, s, "alpha")
	beta := newProjectActor(t, ctx, s, "beta")

	doRequest(t, s, http.MethodPost, "/v3/"+alpha.projectID+"/volumes", alpha.token, createVolumeBody("alpha-vol", 5))
	doRequest(t, s, http.MethodPost, "/v3/"+beta.projectID+"/volumes", beta.token, createVolumeBody("beta-vol", 5))

	recorder := doRequest(t, s, http.MethodGet, "/v3/"+alpha.projectID+"/volumes", alpha.token, nil)
	var decoded struct {
		Volumes []volumeBody `json:"volumes"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Volumes) != 1 || decoded.Volumes[0].Name != "alpha-vol" {
		t.Fatalf("alpha's listing = %+v, want exactly its own one volume", decoded.Volumes)
	}
}

// attachVolume is a small helper wrapping the create -> attach round
// trip most of the tests below need.
func attachVolume(t *testing.T, ctx context.Context, s testServer, actor actor, providerID string) (volumeID, workloadID string) {
	t.Helper()
	created := decodeVolume(t, doRequest(t, s, http.MethodPost, "/v3/"+actor.projectID+"/volumes", actor.token, createVolumeBody("attachable", 5)).Body.Bytes())
	workloadID = seedScheduledWorkload(t, ctx, s.pool, providerID, actor.projectID)
	recorder := doRequest(t, s, http.MethodPost, "/v3/"+actor.projectID+"/volumes/"+created.ID+"/action", actor.token, attachActionBody(workloadID, "/data"))
	if recorder.Code != http.StatusOK {
		t.Fatalf("attach status = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	return created.ID, workloadID
}

func TestAttachVolumeBindsToTheWorkloadsProvider(t *testing.T) {
	ctx, s := newTestServer(t)
	actor := newProjectActor(t, ctx, s, "alpha")

	volumeID, workloadID := attachVolume(t, ctx, s, actor, "provider-1")

	recorder := doRequest(t, s, http.MethodGet, "/v3/"+actor.projectID+"/volumes/"+volumeID, actor.token, nil)
	volume := decodeVolume(t, recorder.Body.Bytes())
	if volume.Status != "in-use" || len(volume.Attachments) != 1 || volume.Attachments[0].ServerID != workloadID || volume.Attachments[0].Device != "/data" {
		t.Fatalf("unexpected volume after attach = %+v", volume)
	}
}

// TestAttachVolumeRejectsADoubleAttachment is the task's explicit
// "double-attachment prevention" acceptance criterion.
func TestAttachVolumeRejectsADoubleAttachment(t *testing.T) {
	ctx, s := newTestServer(t)
	actor := newProjectActor(t, ctx, s, "alpha")
	volumeID, _ := attachVolume(t, ctx, s, actor, "provider-1")

	secondWorkload := seedScheduledWorkload(t, ctx, s.pool, "provider-1", actor.projectID)
	recorder := doRequest(t, s, http.MethodPost, "/v3/"+actor.projectID+"/volumes/"+volumeID+"/action", actor.token, attachActionBody(secondWorkload, "/data"))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("second attach status = %d, want %d (already attached); body=%s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
	}

	// The original attachment must be completely unaffected by the
	// rejected second attempt.
	getRecorder := doRequest(t, s, http.MethodGet, "/v3/"+actor.projectID+"/volumes/"+volumeID, actor.token, nil)
	volume := decodeVolume(t, getRecorder.Body.Bytes())
	if volume.Status != "in-use" || len(volume.Attachments) != 1 {
		t.Fatalf("original attachment was disturbed by the rejected second attempt: %+v", volume)
	}
}

// TestAttachVolumeRejectsAWorkloadFromAnotherProject is the task's
// explicit "cross-project access denial" case for the attach target: a
// caller must not be able to attach their own volume to a workload they
// do not own.
func TestAttachVolumeRejectsAWorkloadFromAnotherProject(t *testing.T) {
	ctx, s := newTestServer(t)
	owner := newProjectActor(t, ctx, s, "alpha")
	other := newProjectActor(t, ctx, s, "beta")

	created := decodeVolume(t, doRequest(t, s, http.MethodPost, "/v3/"+owner.projectID+"/volumes", owner.token, createVolumeBody("v", 5)).Body.Bytes())
	otherWorkload := seedScheduledWorkload(t, ctx, s.pool, "provider-1", other.projectID)

	recorder := doRequest(t, s, http.MethodPost, "/v3/"+owner.projectID+"/volumes/"+created.ID+"/action", owner.token, attachActionBody(otherWorkload, "/data"))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (instance not found in this project); body=%s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
	}
}

func TestAttachVolumeRejectsAConflictingProvider(t *testing.T) {
	ctx, s := newTestServer(t)
	actor := newProjectActor(t, ctx, s, "alpha")
	volumeID, _ := attachVolume(t, ctx, s, actor, "provider-1")
	// Detach so the volume is 'available' again, but its provider_id
	// stays permanently bound to provider-1 (ADR-034 §1).
	doRequest(t, s, http.MethodPost, "/v3/"+actor.projectID+"/volumes/"+volumeID+"/action", actor.token, detachActionBody())

	otherProviderWorkload := seedScheduledWorkload(t, ctx, s.pool, "provider-2", actor.projectID)
	recorder := doRequest(t, s, http.MethodPost, "/v3/"+actor.projectID+"/volumes/"+volumeID+"/action", actor.token, attachActionBody(otherProviderWorkload, "/data"))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (provider mismatch); body=%s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
	}
}

func TestDetachVolumeReturnsToAvailableAndAllowsReattachOnTheSameProvider(t *testing.T) {
	ctx, s := newTestServer(t)
	actor := newProjectActor(t, ctx, s, "alpha")
	volumeID, _ := attachVolume(t, ctx, s, actor, "provider-1")

	detachRecorder := doRequest(t, s, http.MethodPost, "/v3/"+actor.projectID+"/volumes/"+volumeID+"/action", actor.token, detachActionBody())
	if detachRecorder.Code != http.StatusOK {
		t.Fatalf("detach status = %d, want %d; body=%s", detachRecorder.Code, http.StatusOK, detachRecorder.Body.String())
	}
	detached := decodeVolume(t, detachRecorder.Body.Bytes())
	if detached.Status != "available" || len(detached.Attachments) != 0 {
		t.Fatalf("unexpected volume after detach = %+v", detached)
	}

	// ADR-034 §2: reattachment to a new workload on the same provider is
	// a normal, supported operation.
	newWorkload := seedScheduledWorkload(t, ctx, s.pool, "provider-1", actor.projectID)
	reattach := doRequest(t, s, http.MethodPost, "/v3/"+actor.projectID+"/volumes/"+volumeID+"/action", actor.token, attachActionBody(newWorkload, "/data2"))
	if reattach.Code != http.StatusOK {
		t.Fatalf("reattach status = %d, want %d; body=%s", reattach.Code, http.StatusOK, reattach.Body.String())
	}
}

func TestDeleteVolumeRemovesAnUnattachedVolume(t *testing.T) {
	ctx, s := newTestServer(t)
	actor := newProjectActor(t, ctx, s, "alpha")
	created := decodeVolume(t, doRequest(t, s, http.MethodPost, "/v3/"+actor.projectID+"/volumes", actor.token, createVolumeBody("to-delete", 5)).Body.Bytes())

	deleteRecorder := doRequest(t, s, http.MethodDelete, "/v3/"+actor.projectID+"/volumes/"+created.ID, actor.token, nil)
	if deleteRecorder.Code != http.StatusAccepted {
		t.Fatalf("delete status = %d, want %d; body=%s", deleteRecorder.Code, http.StatusAccepted, deleteRecorder.Body.String())
	}
	if s.dispatcher.callCount() != 0 {
		t.Fatal("a volume that was never attached has no Docker-level state; the dispatcher must not have been called")
	}

	getRecorder := doRequest(t, s, http.MethodGet, "/v3/"+actor.projectID+"/volumes/"+created.ID, actor.token, nil)
	if getRecorder.Code != http.StatusNotFound {
		t.Fatalf("get-after-delete status = %d, want %d", getRecorder.Code, http.StatusNotFound)
	}
}

func TestDeleteVolumeRejectsAnInUseVolume(t *testing.T) {
	ctx, s := newTestServer(t)
	actor := newProjectActor(t, ctx, s, "alpha")
	volumeID, _ := attachVolume(t, ctx, s, actor, "provider-1")

	recorder := doRequest(t, s, http.MethodDelete, "/v3/"+actor.projectID+"/volumes/"+volumeID, actor.token, nil)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (must detach first); body=%s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
	}
}

// TestDeleteVolumeDispatchesSecureDeletionForAProviderBoundVolume proves
// a volume that was attached at least once (so it has real Docker-level
// state on a provider, ADR-034 §6) routes its delete through
// VolumeDispatcher -- the Agent-facing secure-deletion half, not just a
// Postgres row removal.
func TestDeleteVolumeDispatchesSecureDeletionForAProviderBoundVolume(t *testing.T) {
	ctx, s := newTestServer(t)
	actor := newProjectActor(t, ctx, s, "alpha")
	volumeID, _ := attachVolume(t, ctx, s, actor, "provider-1")
	doRequest(t, s, http.MethodPost, "/v3/"+actor.projectID+"/volumes/"+volumeID+"/action", actor.token, detachActionBody())

	recorder := doRequest(t, s, http.MethodDelete, "/v3/"+actor.projectID+"/volumes/"+volumeID, actor.token, nil)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("delete status = %d, want %d; body=%s", recorder.Code, http.StatusAccepted, recorder.Body.String())
	}
	if s.dispatcher.callCount() != 1 {
		t.Fatalf("dispatcher call count = %d, want exactly 1", s.dispatcher.callCount())
	}
	s.dispatcher.mu.Lock()
	call := s.dispatcher.calls[0]
	s.dispatcher.mu.Unlock()
	if call.providerID != "provider-1" || call.volumeID != volumeID {
		t.Fatalf("dispatched call = %+v, want provider-1/%s", call, volumeID)
	}
}

// TestDeleteVolumeFailsClosedAndRecoversWhenDispatchFails is this
// package's "orphaned-volume-after-crash reconciliation" coverage: if
// the owning provider cannot be reached to run secure deletion (a
// crashed or partitioned Agent, the exact scenario ADR-034's Threat
// model section names), the volume must never be silently marked
// deleted, and must not be permanently stranded in 'deleting' either --
// a retried delete (e.g. once the provider is reachable again) must
// still be possible.
func TestDeleteVolumeFailsClosedAndRecoversWhenDispatchFails(t *testing.T) {
	ctx, s := newTestServer(t)
	actor := newProjectActor(t, ctx, s, "alpha")
	volumeID, _ := attachVolume(t, ctx, s, actor, "provider-1")
	doRequest(t, s, http.MethodPost, "/v3/"+actor.projectID+"/volumes/"+volumeID+"/action", actor.token, detachActionBody())

	s.dispatcher.fail = fmt.Errorf("provider unreachable")
	recorder := doRequest(t, s, http.MethodDelete, "/v3/"+actor.projectID+"/volumes/"+volumeID, actor.token, nil)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusServiceUnavailable, recorder.Body.String())
	}

	// Never silently marked deleted: still reachable via GET.
	getRecorder := doRequest(t, s, http.MethodGet, "/v3/"+actor.projectID+"/volumes/"+volumeID, actor.token, nil)
	if getRecorder.Code != http.StatusOK {
		t.Fatalf("volume must still exist after a failed delete dispatch; get status = %d", getRecorder.Code)
	}
	stillThere := decodeVolume(t, getRecorder.Body.Bytes())
	if stillThere.Status != "available" {
		t.Fatalf("status = %q, want 'available' (rolled back, not stuck in 'deleting')", stillThere.Status)
	}

	// Not permanently stranded: the provider recovers, and a retried
	// delete now succeeds.
	s.dispatcher.fail = nil
	retryRecorder := doRequest(t, s, http.MethodDelete, "/v3/"+actor.projectID+"/volumes/"+volumeID, actor.token, nil)
	if retryRecorder.Code != http.StatusAccepted {
		t.Fatalf("retried delete status = %d, want %d; body=%s", retryRecorder.Code, http.StatusAccepted, retryRecorder.Body.String())
	}
}

// TestDeleteVolumeFailsClosedWithNoDispatcherConfigured proves a nil
// VolumeDispatcher (a deployment that has not wired one up) fails a
// provider-bound volume's delete closed rather than silently skipping
// secure deletion -- only an unattached volume can be deleted with no
// dispatcher at all (TestDeleteVolumeRemovesAnUnattachedVolume, above).
func TestDeleteVolumeFailsClosedWithNoDispatcherConfigured(t *testing.T) {
	ctx, s := newTestServer(t)
	actor := newProjectActor(t, ctx, s, "alpha")
	volumeID, _ := attachVolume(t, ctx, s, actor, "provider-1")
	doRequest(t, s, http.MethodPost, "/v3/"+actor.projectID+"/volumes/"+volumeID+"/action", actor.token, detachActionBody())

	users := userauth.NewPostgresRepository(s.pool)
	noDispatcherServer := cinder.New(users, cinder.NewPostgresRepository(s.pool), s.workloadRepo, nil, s.projects, nil)
	mux := http.NewServeMux()
	noDispatcherServer.Register(mux)

	request := httptest.NewRequest(http.MethodDelete, "/v3/"+actor.projectID+"/volumes/"+volumeID, nil)
	request.Header.Set("X-Auth-Token", actor.token)
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusServiceUnavailable, recorder.Body.String())
	}

	getRecorder := doRequest(t, s, http.MethodGet, "/v3/"+actor.projectID+"/volumes/"+volumeID, actor.token, nil)
	if getRecorder.Code != http.StatusOK {
		t.Fatalf("volume must still exist; get status = %d", getRecorder.Code)
	}
}
