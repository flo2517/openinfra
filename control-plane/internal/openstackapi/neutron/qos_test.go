package neutron_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type qosPolicyResponse struct {
	ID    string `json:"id"`
	Rules []struct {
		ID                 string `json:"id"`
		Direction          string `json:"direction"`
		MaxKbps            int64  `json:"max_kbps"`
		MaxBurstKbps       int64  `json:"max_burst_kbps"`
		XOpeninfraEnforced bool   `json:"x_openinfra_enforced"`
	} `json:"rules"`
}

func TestListPoliciesReturnsOnlyTheCallersProjectsCommittedReservations(t *testing.T) {
	ctx, server := newTestServer(t, &fakeZoneLister{})
	projectA := createTestProject(t, ctx, server.pool)
	projectB := createTestProject(t, ctx, server.pool)
	insertOpenWorkload(t, ctx, server.pool, "provider-a", projectA, "RUNNING", 10, 20)
	insertOpenWorkload(t, ctx, server.pool, "provider-b", projectB, "RUNNING", 30, 40)
	token := mintProjectScopedToken(t, ctx, server.pool, server.users, projectA)

	request := httptest.NewRequest(http.MethodGet, "/v2.0/qos/policies", nil)
	request.Header.Set("X-Auth-Token", token)
	recorder := httptest.NewRecorder()
	server.handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var body struct {
		Policies []qosPolicyResponse `json:"policies"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Policies) != 1 {
		t.Fatalf("expected exactly 1 policy (project A's own), got %d: %+v", len(body.Policies), body.Policies)
	}
}

func TestListPoliciesRejectsAnUnscopedToken(t *testing.T) {
	ctx, server := newTestServer(t, &fakeZoneLister{})
	token := mintUnscopedToken(t, ctx, server.users)

	request := httptest.NewRequest(http.MethodGet, "/v2.0/qos/policies", nil)
	request.Header.Set("X-Auth-Token", token)
	recorder := httptest.NewRecorder()
	server.handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusForbidden, recorder.Body.String())
	}
}

func TestListPoliciesRejectsAMissingToken(t *testing.T) {
	_, server := newTestServer(t, &fakeZoneLister{})

	request := httptest.NewRequest(http.MethodGet, "/v2.0/qos/policies", nil)
	recorder := httptest.NewRecorder()
	server.handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusUnauthorized, recorder.Body.String())
	}
}

// TestShowPolicyReportsTheExactMaxKbpsTheLedgerCommitted is the core
// "cannot report a falsified reservation" property for the show path:
// the max_kbps this handler reports for each direction is an exact,
// mechanical transform (Mbps -> kbps, *1000) of
// workloads.reserved_ingress_mbps/reserved_egress_mbps -- the same
// columns AssignLease's capacity check reads and writes, never a
// separately maintained figure.
func TestShowPolicyReportsTheExactMaxKbpsTheLedgerCommitted(t *testing.T) {
	ctx, server := newTestServer(t, &fakeZoneLister{})
	project := createTestProject(t, ctx, server.pool)
	workloadID := insertOpenWorkload(t, ctx, server.pool, "provider-a", project, "RUNNING", 25, 75)
	token := mintProjectScopedToken(t, ctx, server.pool, server.users, project)

	request := httptest.NewRequest(http.MethodGet, "/v2.0/qos/policies/"+workloadID, nil)
	request.Header.Set("X-Auth-Token", token)
	recorder := httptest.NewRecorder()
	server.handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var body struct {
		Policy qosPolicyResponse `json:"policy"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Policy.ID != workloadID {
		t.Fatalf("policy.id = %q, want %q", body.Policy.ID, workloadID)
	}
	if len(body.Policy.Rules) != 2 {
		t.Fatalf("expected 2 rules (ingress + egress), got %d: %+v", len(body.Policy.Rules), body.Policy.Rules)
	}
	for _, rule := range body.Policy.Rules {
		switch rule.Direction {
		case "ingress":
			if rule.MaxKbps != 25_000 {
				t.Fatalf("ingress max_kbps = %d, want %d", rule.MaxKbps, 25_000)
			}
			if rule.XOpeninfraEnforced {
				t.Fatal("ingress is not kernel-enforced today (ADR-025 §3) and must not claim to be")
			}
		case "egress":
			if rule.MaxKbps != 75_000 {
				t.Fatalf("egress max_kbps = %d, want %d", rule.MaxKbps, 75_000)
			}
			if !rule.XOpeninfraEnforced {
				t.Fatal("egress IS kernel-enforced (ADR-025 §3's tc ceiling) and must say so")
			}
			if rule.MaxBurstKbps != 262 {
				t.Fatalf("egress max_burst_kbps = %d, want 262 (rate_limit.rs's TBF_BURST_BYTES=32KiB in kbit)", rule.MaxBurstKbps)
			}
		default:
			t.Fatalf("unexpected rule direction %q", rule.Direction)
		}
	}
}

func TestShowPolicyReturnsNotFoundForAnotherProjectsWorkload(t *testing.T) {
	ctx, server := newTestServer(t, &fakeZoneLister{})
	ownProject := createTestProject(t, ctx, server.pool)
	otherProject := createTestProject(t, ctx, server.pool)
	otherWorkloadID := insertOpenWorkload(t, ctx, server.pool, "provider-a", otherProject, "RUNNING", 10, 10)
	token := mintProjectScopedToken(t, ctx, server.pool, server.users, ownProject)

	request := httptest.NewRequest(http.MethodGet, "/v2.0/qos/policies/"+otherWorkloadID, nil)
	request.Header.Set("X-Auth-Token", token)
	recorder := httptest.NewRecorder()
	server.handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d (cross-project lookup must fail exactly like a nonexistent one); body=%s", recorder.Code, http.StatusNotFound, recorder.Body.String())
	}
}

// TestShowPolicyOmitsAWorkloadWithNoBandwidthReservation: a workload
// with 0/0 has no meaningful QoS policy to describe (scheduler.fitBps's
// own "a zero requirement is always satisfied" convention) -- this
// handler must not invent one.
func TestShowPolicyOmitsAWorkloadWithNoBandwidthReservation(t *testing.T) {
	ctx, server := newTestServer(t, &fakeZoneLister{})
	project := createTestProject(t, ctx, server.pool)
	workloadID := insertOpenWorkload(t, ctx, server.pool, "provider-a", project, "RUNNING", 0, 0)
	token := mintProjectScopedToken(t, ctx, server.pool, server.users, project)

	request := httptest.NewRequest(http.MethodGet, "/v2.0/qos/policies/"+workloadID, nil)
	request.Header.Set("X-Auth-Token", token)
	recorder := httptest.NewRecorder()
	server.handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d for a zero-bandwidth workload", recorder.Code, http.StatusNotFound)
	}
}

// TestShowPolicyOmitsAWorkloadStillInScheduling proves this surface
// cannot report a reservation that never became -- or was rejected from
// becoming -- a real, capacity-checked commitment: a SCHEDULING-state
// workload (AssignLease not yet run, or run and rejected -- either way
// the row is untouched, per AssignLease's own doc comment) never appears
// as a QoS policy.
func TestShowPolicyOmitsAWorkloadStillInScheduling(t *testing.T) {
	ctx, server := newTestServer(t, &fakeZoneLister{})
	project := createTestProject(t, ctx, server.pool)
	workloadID := insertOpenWorkload(t, ctx, server.pool, "provider-a", project, "SCHEDULING", 50, 50)
	token := mintProjectScopedToken(t, ctx, server.pool, server.users, project)

	request := httptest.NewRequest(http.MethodGet, "/v2.0/qos/policies/"+workloadID, nil)
	request.Header.Set("X-Auth-Token", token)
	recorder := httptest.NewRecorder()
	server.handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d for a SCHEDULING (not yet committed) workload", recorder.Code, http.StatusNotFound)
	}
}

func TestBandwidthLimitRuleIDsAreStableAcrossRepeatedRequests(t *testing.T) {
	ctx, server := newTestServer(t, &fakeZoneLister{})
	project := createTestProject(t, ctx, server.pool)
	workloadID := insertOpenWorkload(t, ctx, server.pool, "provider-a", project, "RUNNING", 10, 20)
	token := mintProjectScopedToken(t, ctx, server.pool, server.users, project)

	get := func() qosPolicyResponse {
		request := httptest.NewRequest(http.MethodGet, "/v2.0/qos/policies/"+workloadID, nil)
		request.Header.Set("X-Auth-Token", token)
		recorder := httptest.NewRecorder()
		server.handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d; body=%s", recorder.Code, recorder.Body.String())
		}
		var body struct {
			Policy qosPolicyResponse `json:"policy"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body.Policy
	}

	first, second := get(), get()
	if len(first.Rules) != 2 || len(second.Rules) != 2 {
		t.Fatalf("expected 2 rules both times, got %d and %d", len(first.Rules), len(second.Rules))
	}
	for i := range first.Rules {
		if first.Rules[i].ID != second.Rules[i].ID {
			t.Fatalf("rule id changed across requests: %q != %q", first.Rules[i].ID, second.Rules[i].ID)
		}
	}
}

func TestShowBandwidthLimitRuleReturnsNotFoundForAnUnknownRuleID(t *testing.T) {
	ctx, server := newTestServer(t, &fakeZoneLister{})
	project := createTestProject(t, ctx, server.pool)
	workloadID := insertOpenWorkload(t, ctx, server.pool, "provider-a", project, "RUNNING", 10, 20)
	token := mintProjectScopedToken(t, ctx, server.pool, server.users, project)

	request := httptest.NewRequest(http.MethodGet, "/v2.0/qos/policies/"+workloadID+"/bandwidth_limit_rules/00000000-0000-0000-0000-000000000000", nil)
	request.Header.Set("X-Auth-Token", token)
	recorder := httptest.NewRecorder()
	server.handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNotFound)
	}
}
