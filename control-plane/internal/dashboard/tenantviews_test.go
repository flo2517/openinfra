package dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/openinfra/network/internal/userauth"
	sharedv1 "github.com/openinfra/network/protocol/generated/go/shared/v1"
	"google.golang.org/protobuf/proto"
)

// doAuthedJSONPost is doAuthedPost's sibling for endpoints that need a
// JSON request body -- submitMyWorkload is the first tenant-tier POST
// handler that decodes one.
func doAuthedJSONPost(t *testing.T, handler http.Handler, path, rawKey string, body any) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(encoded))
	request.Header.Set("Authorization", "Bearer "+rawKey)
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

// validSubmitWorkloadBody is a minimal, valid submitWorkloadRequestBody --
// its image field passes validateSubmission's digest-pinned-reference
// regex, so tests that don't care about validation specifics can start
// from a body they know will be accepted.
func validSubmitWorkloadBody() submitWorkloadRequestBody {
	return submitWorkloadRequestBody{
		Image:           "example.invalid/image@sha256:" + fmt.Sprintf("%064d", 0),
		CPUCores:        1,
		RAMMB:           512,
		StorageGB:       5,
		DurationSeconds: 600,
	}
}

// issueSessionKeyForUser is issueSessionKey's variant that also returns
// the user_id, so tenant-isolation tests can insert workloads owned by a
// specific user and then authenticate as a different one.
func issueSessionKeyForUser(t *testing.T, server *Server, role string) (userID, rawKey string) {
	t.Helper()
	user, err := server.users.CreateUser(t.Context(), "tenant-test-user")
	if err != nil {
		t.Fatal(err)
	}
	if role != userauth.RoleTenant {
		if err := server.users.SetRole(t.Context(), user.UserID, role); err != nil {
			t.Fatal(err)
		}
	}
	key, err := server.users.CreateAPIKey(t.Context(), user.UserID)
	if err != nil {
		t.Fatal(err)
	}
	return user.UserID, key.Raw
}

// insertOwnedWorkload inserts a REQUESTED workload owned by ownerID with
// a real marshalled WorkloadDefinition, so decodeRequirements is
// exercised against the same bytes SubmitWorkload would have stored
// rather than a hand-rolled blob.
func insertOwnedWorkload(t *testing.T, ctx context.Context, pool *pgxpool.Pool, ownerID string, cpu float32, ramMB int64) string {
	t.Helper()
	workloadID, requestID := uuid.NewString(), uuid.NewString()
	definition := &sharedv1.WorkloadDefinition{
		WorkloadId: workloadID,
		Profile:    sharedv1.WorkloadProfile_WORKLOAD_PROFILE_COMPUTE_INTENSIVE,
		Requirements: &sharedv1.ResourceRequirements{
			Cpu:       cpu,
			RamMb:     ramMB,
			StorageGb: 10,
		},
		DurationSeconds: 600,
	}
	definitionBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(definition)
	if err != nil {
		t.Fatal(err)
	}
	image := "example.invalid/image@sha256:" + fmt.Sprintf("%064d", 0)
	_, err = pool.Exec(ctx, `
		INSERT INTO workloads (workload_id, request_id, owner_id, request_hash, definition, image, state, error_code, last_error)
		VALUES ($1,$2,$3,$4,$5,$6,'REQUESTED','E_TEST','boom')`,
		workloadID, requestID, ownerID, make([]byte, 32), definitionBytes, image)
	if err != nil {
		t.Fatal(err)
	}
	return workloadID
}

func TestMyWorkloadsRequiresAuthentication(t *testing.T) {
	_, server, _ := newAuthTestServer(t)
	recorder := doAuthedGet(t, server.Handler(), "/api/v1/my/workloads", "not-a-real-key")
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", recorder.Code)
	}
}

func TestMyWorkloadsReturnsOnlyTheCallersOwnWorkloads(t *testing.T) {
	ctx, server, pool := newAuthTestServer(t)
	aliceID, aliceKey := issueSessionKeyForUser(t, server, userauth.RoleTenant)
	bobID, bobKey := issueSessionKeyForUser(t, server, userauth.RoleTenant)

	aliceWorkload := insertOwnedWorkload(t, ctx, pool, aliceID, 2, 512)
	insertOwnedWorkload(t, ctx, pool, bobID, 4, 1024)
	insertOwnedWorkload(t, ctx, pool, bobID, 8, 2048)

	recorder := doAuthedGet(t, server.Handler(), "/api/v1/my/workloads", aliceKey)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	var body TenantWorkloads
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Total != 1 {
		t.Fatalf("Total = %d, want 1 (alice owns exactly one workload; the count must be owner-scoped too, not a global COUNT(*))", body.Total)
	}
	if len(body.Workloads) != 1 {
		t.Fatalf("len(Workloads) = %d, want 1", len(body.Workloads))
	}
	if body.Workloads[0].WorkloadID != aliceWorkload {
		t.Fatalf("returned workload %q, want alice's %q", body.Workloads[0].WorkloadID, aliceWorkload)
	}

	// The reciprocal direction, so this test cannot pass by returning an
	// empty list for everyone.
	bobRecorder := doAuthedGet(t, server.Handler(), "/api/v1/my/workloads", bobKey)
	var bobBody TenantWorkloads
	if err := json.Unmarshal(bobRecorder.Body.Bytes(), &bobBody); err != nil {
		t.Fatal(err)
	}
	if bobBody.Total != 2 {
		t.Fatalf("bob's Total = %d, want 2", bobBody.Total)
	}
	for _, workload := range bobBody.Workloads {
		if workload.WorkloadID == aliceWorkload {
			t.Fatal("bob's list must never contain alice's workload")
		}
	}
}

// TestMyWorkloadReturns404ForAnotherTenantsWorkload is ADR-016 §2's
// existence-oracle requirement: a workload that exists but isn't the
// caller's must be indistinguishable from one that doesn't exist.
func TestMyWorkloadReturns404ForAnotherTenantsWorkload(t *testing.T) {
	ctx, server, pool := newAuthTestServer(t)
	aliceID, _ := issueSessionKeyForUser(t, server, userauth.RoleTenant)
	_, bobKey := issueSessionKeyForUser(t, server, userauth.RoleTenant)
	aliceWorkload := insertOwnedWorkload(t, ctx, pool, aliceID, 2, 512)

	existing := doAuthedGet(t, server.Handler(), "/api/v1/my/workloads/"+aliceWorkload, bobKey)
	if existing.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for another tenant's real workload (403 would confirm it exists)", existing.Code)
	}

	absent := doAuthedGet(t, server.Handler(), "/api/v1/my/workloads/"+uuid.NewString(), bobKey)
	if absent.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for a workload that does not exist", absent.Code)
	}
	if existing.Body.String() != absent.Body.String() {
		t.Fatalf("response bodies must be identical for 'someone else's workload' (%s) and 'no such workload' (%s), or the difference is itself an oracle", existing.Body.String(), absent.Body.String())
	}
}

func TestMyWorkloadReturnsDecodedRequirementsAndOwnErrors(t *testing.T) {
	ctx, server, pool := newAuthTestServer(t)
	aliceID, aliceKey := issueSessionKeyForUser(t, server, userauth.RoleTenant)
	workloadID := insertOwnedWorkload(t, ctx, pool, aliceID, 2.5, 512)

	recorder := doAuthedGet(t, server.Handler(), "/api/v1/my/workloads/"+workloadID, aliceKey)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	var body TenantWorkload
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Requirements == nil {
		t.Fatal("Requirements must be decoded from the stored definition")
	}
	if body.Requirements.CPUCores != 2.5 || body.Requirements.RAMMB != 512 || body.Requirements.StorageGB != 10 {
		t.Fatalf("Requirements = %+v, want cpu=2.5 ram=512 storage=10", *body.Requirements)
	}
	if body.Requirements.Profile != "COMPUTE_INTENSIVE" {
		t.Fatalf("Profile = %q, want COMPUTE_INTENSIVE", body.Requirements.Profile)
	}
	// ADR-016 §7 question 2: the owning tenant sees their own workload's
	// failure detail.
	if body.ErrorCode != "E_TEST" || body.LastError != "boom" {
		t.Fatalf("ErrorCode/LastError = %q/%q, want the owner to see their own workload's error detail", body.ErrorCode, body.LastError)
	}

	// The raw definition bytes must never appear in the response, whatever
	// else it contains -- the conservative half of §7 question 1's answer.
	if _, present := rawJSONField(t, recorder.Body.Bytes(), "definition"); present {
		t.Fatal("the raw definition bytes must never be serialized to a tenant")
	}
}

func TestMyWorkloadRejectsAMalformedWorkloadID(t *testing.T) {
	_, server, _ := newAuthTestServer(t)
	_, aliceKey := issueSessionKeyForUser(t, server, userauth.RoleTenant)
	recorder := doAuthedGet(t, server.Handler(), "/api/v1/my/workloads/not-a-uuid", aliceKey)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a non-UUID workload_id", recorder.Code)
	}
}

// TestOperatorCanReachTenantEndpoints pins ADR-016 §1's ranking: the
// operator tiers sit above tenant, so an operator session satisfies a
// tenant-tier gate (and sees its own -- empty -- workload list, not
// everyone's).
func TestOperatorCanReachTenantEndpointsAndSeesOnlyItsOwn(t *testing.T) {
	ctx, server, pool := newAuthTestServer(t)
	aliceID, _ := issueSessionKeyForUser(t, server, userauth.RoleTenant)
	insertOwnedWorkload(t, ctx, pool, aliceID, 2, 512)
	_, operatorKey := issueSessionKeyForUser(t, server, userauth.RoleOperatorAdmin)

	recorder := doAuthedGet(t, server.Handler(), "/api/v1/my/workloads", operatorKey)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (an operator satisfies a tenant-tier gate)", recorder.Code)
	}
	var body TenantWorkloads
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Total != 0 {
		t.Fatalf("Total = %d, want 0 -- /my/workloads is always the *caller's* own, even for an operator; cross-tenant visibility belongs to the operator-tier endpoints", body.Total)
	}
}

func TestDecodeRequirementsReportsUndecodableDefinitionAsNil(t *testing.T) {
	if got := decodeRequirements(nil); got != nil {
		t.Fatalf("decodeRequirements(nil) = %+v, want nil", got)
	}
	// Deliberately invalid protobuf wire format: field 1 with wire type 7
	// (undefined) -- must report "unknown," never a zero-valued ask that
	// renders as a real 0-CPU request.
	if got := decodeRequirements([]byte{0x0f, 0xff}); got != nil {
		t.Fatalf("decodeRequirements(garbage) = %+v, want nil", got)
	}
}

// rawJSONField reports whether key is present at the top level of the
// encoded object, without assuming anything about the rest of its shape.
func rawJSONField(t *testing.T, encoded []byte, key string) (json.RawMessage, bool) {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	value, present := fields[key]
	return value, present
}

func TestSubmitMyWorkloadRequiresAuthentication(t *testing.T) {
	_, server, _ := newAuthTestServer(t)
	recorder := doAuthedJSONPost(t, server.Handler(), "/api/v1/my/workloads", "not-a-real-key", validSubmitWorkloadBody())
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", recorder.Code)
	}
}

// TestSubmitMyWorkloadCreatesAnOwnedWorkloadAndAuditsIt is this feature's
// core claim: submitting through the dashboard's HTTP surface must reach
// the exact same persisted state a gRPC SubmitWorkload call would --
// owner_id set to the authenticated caller, state REQUESTED, reservation
// columns populated from the submitted requirements -- because both paths
// share the same *workloadapi.Service instance (dashboard.go's
// s.workloads).
func TestSubmitMyWorkloadCreatesAnOwnedWorkloadAndAuditsIt(t *testing.T) {
	ctx, server, pool := newAuthTestServer(t)
	aliceID, aliceKey := issueSessionKeyForUser(t, server, userauth.RoleTenant)

	recorder := doAuthedJSONPost(t, server.Handler(), "/api/v1/my/workloads", aliceKey, validSubmitWorkloadBody())
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		WorkloadID string `json:"workload_id"`
		State      string `json:"state"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if _, err := uuid.Parse(response.WorkloadID); err != nil {
		t.Fatalf("workload_id = %q, want a UUID minted server-side", response.WorkloadID)
	}
	if response.State != "REQUESTED" {
		t.Fatalf("state = %q, want REQUESTED", response.State)
	}

	var ownerID, state string
	var reservedCPU, reservedRAM, reservedStorage int64
	err := pool.QueryRow(ctx, `SELECT COALESCE(owner_id::text,''), state, reserved_cpu_millicores, reserved_ram_mb, reserved_storage_gb FROM workloads WHERE workload_id=$1`, response.WorkloadID).
		Scan(&ownerID, &state, &reservedCPU, &reservedRAM, &reservedStorage)
	if err != nil {
		t.Fatalf("the submitted workload must actually be persisted: %v", err)
	}
	if ownerID != aliceID {
		t.Fatalf("owner_id = %q, want alice's %q", ownerID, aliceID)
	}
	if state != "REQUESTED" {
		t.Fatalf("stored state = %q, want REQUESTED", state)
	}
	if reservedCPU != 1000 || reservedRAM != 512 || reservedStorage != 5 {
		t.Fatalf("reservations = (%d, %d, %d), want (1000, 512, 5) -- the submitted requirements must reach the reservation ledger", reservedCPU, reservedRAM, reservedStorage)
	}

	var actorUserID, action, targetID, outcome string
	auditErr := pool.QueryRow(ctx, `SELECT actor_user_id::text, action, target_id, outcome FROM audit_events`).
		Scan(&actorUserID, &action, &targetID, &outcome)
	if auditErr != nil {
		t.Fatalf("expected exactly one audit row: %v", auditErr)
	}
	if actorUserID != aliceID || action != auditActionWorkloadSubmit || targetID != response.WorkloadID || outcome != auditOutcomeSuccess {
		t.Fatalf("audit row = (%q, %q, %q, %q), want (%q, %q, %q, %q)",
			actorUserID, action, targetID, outcome, aliceID, auditActionWorkloadSubmit, response.WorkloadID, auditOutcomeSuccess)
	}
}

// TestSubmitMyWorkloadThenListedInMyWorkloads proves the two handlers
// agree with each other end to end, not just with the database directly.
func TestSubmitMyWorkloadThenListedInMyWorkloads(t *testing.T) {
	_, server, _ := newAuthTestServer(t)
	_, aliceKey := issueSessionKeyForUser(t, server, userauth.RoleTenant)

	submit := doAuthedJSONPost(t, server.Handler(), "/api/v1/my/workloads", aliceKey, validSubmitWorkloadBody())
	if submit.Code != http.StatusAccepted {
		t.Fatalf("submit status = %d, want 202: %s", submit.Code, submit.Body.String())
	}
	var submitted struct {
		WorkloadID string `json:"workload_id"`
	}
	if err := json.Unmarshal(submit.Body.Bytes(), &submitted); err != nil {
		t.Fatal(err)
	}

	list := doAuthedGet(t, server.Handler(), "/api/v1/my/workloads", aliceKey)
	if list.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", list.Code, list.Body.String())
	}
	var body TenantWorkloads
	if err := json.Unmarshal(list.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, workload := range body.Workloads {
		if workload.WorkloadID == submitted.WorkloadID {
			found = true
			if workload.Requirements == nil || workload.Requirements.CPUCores != 1 {
				t.Fatalf("Requirements = %+v, want cpu=1 decoded from the submitted definition", workload.Requirements)
			}
		}
	}
	if !found {
		t.Fatalf("submitted workload %q not found in the caller's own /api/v1/my/workloads list", submitted.WorkloadID)
	}
}

// TestSubmitMyWorkloadRejectsInvalidInputWithoutPersisting pins that
// validateSubmission's own checks -- not a weaker, dashboard-local
// duplicate -- gate this endpoint too: a malformed request must fail the
// same way it would over gRPC, and must not leave a row behind.
func TestSubmitMyWorkloadRejectsInvalidInputWithoutPersisting(t *testing.T) {
	ctx, server, pool := newAuthTestServer(t)
	_, aliceKey := issueSessionKeyForUser(t, server, userauth.RoleTenant)

	cases := []struct {
		name string
		body submitWorkloadRequestBody
	}{
		{"image without a digest", func() submitWorkloadRequestBody {
			b := validSubmitWorkloadBody()
			b.Image = "example.invalid/image:latest"
			return b
		}()},
		{"non-positive cpu", func() submitWorkloadRequestBody {
			b := validSubmitWorkloadBody()
			b.CPUCores = 0
			return b
		}()},
		{"non-positive ram", func() submitWorkloadRequestBody {
			b := validSubmitWorkloadBody()
			b.RAMMB = 0
			return b
		}()},
		{"zero duration", func() submitWorkloadRequestBody {
			b := validSubmitWorkloadBody()
			b.DurationSeconds = 0
			return b
		}()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			recorder := doAuthedJSONPost(t, server.Handler(), "/api/v1/my/workloads", aliceKey, c.body)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", recorder.Code, recorder.Body.String())
			}
		})
	}

	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM workloads`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("workloads table has %d rows, want 0 -- an invalid submission must not persist anything", count)
	}

	var auditCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE outcome=$1`, auditOutcomeDenied).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != len(cases) {
		t.Fatalf("denied audit rows = %d, want %d (one per rejected attempt)", auditCount, len(cases))
	}
}

// TestOperatorCanSubmitButOnlyOwnsWhatItSubmits pins ADR-016 §1's ranking
// for the write path too: an operator session satisfies the tenant-tier
// gate on POST /api/v1/my/workloads, and the workload it creates is owned
// by the operator's own user_id, exactly like any other tenant caller.
func TestOperatorCanSubmitButOnlyOwnsWhatItSubmits(t *testing.T) {
	ctx, server, pool := newAuthTestServer(t)
	operatorID, operatorKey := issueSessionKeyForUser(t, server, userauth.RoleOperatorAdmin)

	recorder := doAuthedJSONPost(t, server.Handler(), "/api/v1/my/workloads", operatorKey, validSubmitWorkloadBody())
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		WorkloadID string `json:"workload_id"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	var ownerID string
	if err := pool.QueryRow(ctx, `SELECT COALESCE(owner_id::text,'') FROM workloads WHERE workload_id=$1`, response.WorkloadID).Scan(&ownerID); err != nil {
		t.Fatal(err)
	}
	if ownerID != operatorID {
		t.Fatalf("owner_id = %q, want the operator's own %q", ownerID, operatorID)
	}
}
