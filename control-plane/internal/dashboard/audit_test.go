package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/openinfra/network/internal/userauth"
)

func doAuthedPost(t *testing.T, handler http.Handler, path, rawKey string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, path, nil)
	request.Header.Set("Authorization", "Bearer "+rawKey)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func TestStopMyWorkloadStopsOwnWorkloadAndAuditsIt(t *testing.T) {
	ctx, server, pool := newAuthTestServer(t)
	aliceID, aliceKey := issueSessionKeyForUser(t, server, userauth.RoleTenant)
	workloadID := insertOwnedWorkload(t, ctx, pool, aliceID, 2, 512)

	recorder := doAuthedPost(t, server.Handler(), "/api/v1/my/workloads/"+workloadID+"/stop", aliceKey)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202: %s", recorder.Code, recorder.Body.String())
	}

	var state string
	if err := pool.QueryRow(ctx, `SELECT state FROM workloads WHERE workload_id=$1`, workloadID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "STOPPING" {
		t.Fatalf("stored state = %q, want STOPPING -- the HTTP wrapper must actually drive workloadapi's RequestStop, not just return 202", state)
	}

	// The audit row must exist, name the real actor, and record success.
	var actorUserID, actorRole, action, targetID, outcome string
	err := pool.QueryRow(ctx, `SELECT actor_user_id::text, actor_role, action, target_id, outcome FROM audit_events`).
		Scan(&actorUserID, &actorRole, &action, &targetID, &outcome)
	if err != nil {
		t.Fatalf("expected exactly one audit row: %v", err)
	}
	if actorUserID != aliceID {
		t.Fatalf("actor_user_id = %q, want alice's %q", actorUserID, aliceID)
	}
	if actorRole != userauth.RoleTenant {
		t.Fatalf("actor_role = %q, want %q", actorRole, userauth.RoleTenant)
	}
	if action != auditActionWorkloadStop || targetID != workloadID || outcome != auditOutcomeSuccess {
		t.Fatalf("audit row = (%q, %q, %q), want (%q, %q, %q)", action, targetID, outcome, auditActionWorkloadStop, workloadID, auditOutcomeSuccess)
	}
}

// TestStopMyWorkloadRefusesAnotherTenantsWorkloadAndAuditsTheDenial pins
// both halves: the refusal itself, and that a refused attempt is
// recorded -- a burst of denials is exactly what an operator needs to
// see, so it must not be silently dropped.
func TestStopMyWorkloadRefusesAnotherTenantsWorkloadAndAuditsTheDenial(t *testing.T) {
	ctx, server, pool := newAuthTestServer(t)
	aliceID, _ := issueSessionKeyForUser(t, server, userauth.RoleTenant)
	bobID, bobKey := issueSessionKeyForUser(t, server, userauth.RoleTenant)
	aliceWorkload := insertOwnedWorkload(t, ctx, pool, aliceID, 2, 512)

	recorder := doAuthedPost(t, server.Handler(), "/api/v1/my/workloads/"+aliceWorkload+"/stop", bobKey)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for another tenant's workload", recorder.Code)
	}

	// Alice's workload must be untouched.
	var state string
	if err := pool.QueryRow(ctx, `SELECT state FROM workloads WHERE workload_id=$1`, aliceWorkload).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "REQUESTED" {
		t.Fatalf("alice's workload state = %q, want REQUESTED (untouched by bob's attempt)", state)
	}

	var actorUserID, outcome string
	if err := pool.QueryRow(ctx, `SELECT actor_user_id::text, outcome FROM audit_events`).Scan(&actorUserID, &outcome); err != nil {
		t.Fatalf("expected the denied attempt to be audited: %v", err)
	}
	if actorUserID != bobID || outcome != auditOutcomeDenied {
		t.Fatalf("audit row = (%q, %q), want (bob=%q, %q)", actorUserID, outcome, bobID, auditOutcomeDenied)
	}
}

func TestStopMyWorkloadIsAConflictOnASecondStop(t *testing.T) {
	ctx, server, pool := newAuthTestServer(t)
	aliceID, aliceKey := issueSessionKeyForUser(t, server, userauth.RoleTenant)
	workloadID := insertOwnedWorkload(t, ctx, pool, aliceID, 2, 512)

	first := doAuthedPost(t, server.Handler(), "/api/v1/my/workloads/"+workloadID+"/stop", aliceKey)
	if first.Code != http.StatusAccepted {
		t.Fatalf("first stop status = %d, want 202", first.Code)
	}
	second := doAuthedPost(t, server.Handler(), "/api/v1/my/workloads/"+workloadID+"/stop", aliceKey)
	if second.Code != http.StatusConflict {
		t.Fatalf("second stop status = %d, want 409 (a stop request already exists)", second.Code)
	}
}

func TestOperatorAuditRejectsATenant(t *testing.T) {
	_, server, _ := newAuthTestServer(t)
	_, tenantKey := issueSessionKeyForUser(t, server, userauth.RoleTenant)
	recorder := doAuthedGet(t, server.Handler(), "/api/v1/operator/audit", tenantKey)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 -- the audit log is cross-tenant by nature and must never be tenant-readable", recorder.Code)
	}
}

func TestOperatorAuditReturnsRecordedEventsNewestFirst(t *testing.T) {
	ctx, server, pool := newAuthTestServer(t)
	aliceID, aliceKey := issueSessionKeyForUser(t, server, userauth.RoleTenant)
	first := insertOwnedWorkload(t, ctx, pool, aliceID, 2, 512)
	second := insertOwnedWorkload(t, ctx, pool, aliceID, 4, 1024)

	if code := doAuthedPost(t, server.Handler(), "/api/v1/my/workloads/"+first+"/stop", aliceKey).Code; code != http.StatusAccepted {
		t.Fatalf("first stop status = %d, want 202", code)
	}
	if code := doAuthedPost(t, server.Handler(), "/api/v1/my/workloads/"+second+"/stop", aliceKey).Code; code != http.StatusAccepted {
		t.Fatalf("second stop status = %d, want 202", code)
	}

	_, operatorKey := issueSessionKeyForUser(t, server, userauth.RoleOperatorReadOnly)
	recorder := doAuthedGet(t, server.Handler(), "/api/v1/operator/audit", operatorKey)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	var body AuditEvents
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Total != 2 {
		t.Fatalf("Total = %d, want 2", body.Total)
	}
	if len(body.Events) != 2 {
		t.Fatalf("len(Events) = %d, want 2", len(body.Events))
	}
	if body.Events[0].OccurredAt.Before(body.Events[1].OccurredAt) {
		t.Fatal("events must be newest-first")
	}
	for _, event := range body.Events {
		if event.ActorUserID != aliceID {
			t.Fatalf("actor = %q, want alice %q", event.ActorUserID, aliceID)
		}
		if event.Action != auditActionWorkloadStop {
			t.Fatalf("action = %q, want %q", event.Action, auditActionWorkloadStop)
		}
	}
}

// TestAuditRowSurvivesActorDeletion pins migration 000014's deliberate
// omission of a foreign key: deleting a user must not erase the record
// of what that user did.
func TestAuditRowSurvivesActorDeletion(t *testing.T) {
	ctx, server, pool := newAuthTestServer(t)
	aliceID, aliceKey := issueSessionKeyForUser(t, server, userauth.RoleTenant)
	workloadID := insertOwnedWorkload(t, ctx, pool, aliceID, 2, 512)
	if code := doAuthedPost(t, server.Handler(), "/api/v1/my/workloads/"+workloadID+"/stop", aliceKey).Code; code != http.StatusAccepted {
		t.Fatalf("stop status = %d, want 202", code)
	}

	// Detach the workload first: workloads.owner_id *is* a foreign key,
	// unlike audit_events.actor_user_id, and this test is about the
	// latter.
	if _, err := pool.Exec(ctx, `UPDATE workloads SET owner_id = NULL WHERE owner_id = $1`, aliceID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM api_keys WHERE user_id = $1`, aliceID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM users WHERE user_id = $1`, aliceID); err != nil {
		t.Fatalf("deleting the actor must be possible (no audit FK blocking it): %v", err)
	}

	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE actor_user_id = $1`, aliceID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("audit rows for the deleted actor = %d, want 1 -- deleting a user must never erase what they did", count)
	}
}

func TestStopMyWorkloadRejectsAMalformedWorkloadID(t *testing.T) {
	_, server, _ := newAuthTestServer(t)
	_, aliceKey := issueSessionKeyForUser(t, server, userauth.RoleTenant)
	recorder := doAuthedPost(t, server.Handler(), "/api/v1/my/workloads/not-a-uuid/stop", aliceKey)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", recorder.Code)
	}
}

func TestStopMyWorkloadReturns404ForAnAbsentWorkload(t *testing.T) {
	_, server, _ := newAuthTestServer(t)
	_, aliceKey := issueSessionKeyForUser(t, server, userauth.RoleTenant)
	recorder := doAuthedPost(t, server.Handler(), "/api/v1/my/workloads/"+uuid.NewString()+"/stop", aliceKey)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", recorder.Code)
	}
}
