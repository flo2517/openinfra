package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/openinfra/network/internal/userauth"
	sharedv1 "github.com/openinfra/network/protocol/generated/go/shared/v1"
	"google.golang.org/protobuf/proto"
)

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
