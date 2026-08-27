package neutron_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type bandwidthUsageRecordResponse struct {
	WorkloadID        string `json:"workload_id"`
	ProviderID        string `json:"provider_id"`
	IngressBytesTotal int64  `json:"ingress_bytes_total"`
	EgressBytesTotal  int64  `json:"egress_bytes_total"`
}

func TestListBandwidthUsageReturnsOnlyTheCallersProjectsReports(t *testing.T) {
	ctx, server := newTestServer(t, &fakeZoneLister{})
	projectA := createTestProject(t, ctx, server.pool)
	projectB := createTestProject(t, ctx, server.pool)
	workloadA := insertOpenWorkload(t, ctx, server.pool, "provider-a", projectA, "RUNNING", 10, 10)
	workloadB := insertOpenWorkload(t, ctx, server.pool, "provider-b", projectB, "RUNNING", 10, 10)
	insertBandwidthUsage(t, ctx, server.pool, "provider-a", workloadA, 1000, 2000)
	insertBandwidthUsage(t, ctx, server.pool, "provider-b", workloadB, 3000, 4000)
	token := mintProjectScopedToken(t, ctx, server.pool, server.users, projectA)

	request := httptest.NewRequest(http.MethodGet, "/v2.0/metering/bandwidth_usage", nil)
	request.Header.Set("X-Auth-Token", token)
	recorder := httptest.NewRecorder()
	server.handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var body struct {
		BandwidthUsageRecords []bandwidthUsageRecordResponse `json:"bandwidth_usage_records"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.BandwidthUsageRecords) != 1 || body.BandwidthUsageRecords[0].WorkloadID != workloadA {
		t.Fatalf("expected exactly project A's own record, got %+v", body.BandwidthUsageRecords)
	}
	if body.BandwidthUsageRecords[0].IngressBytesTotal != 1000 || body.BandwidthUsageRecords[0].EgressBytesTotal != 2000 {
		t.Fatalf("usage counters did not round-trip verbatim: %+v", body.BandwidthUsageRecords[0])
	}
}

// TestShowBandwidthUsageReturnsNotFoundNotZero is ADR-025 §5's explicit
// requirement made concrete: a workload that has never reported usage
// must render as absent (404, "no data"), never as a fabricated
// zero-valued record.
func TestShowBandwidthUsageReturnsNotFoundNotZero(t *testing.T) {
	ctx, server := newTestServer(t, &fakeZoneLister{})
	project := createTestProject(t, ctx, server.pool)
	workloadID := insertOpenWorkload(t, ctx, server.pool, "provider-a", project, "RUNNING", 10, 10)
	token := mintProjectScopedToken(t, ctx, server.pool, server.users, project)

	request := httptest.NewRequest(http.MethodGet, "/v2.0/metering/bandwidth_usage/"+workloadID, nil)
	request.Header.Set("X-Auth-Token", token)
	recorder := httptest.NewRecorder()
	server.handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d (must be 'no data,' not a zeroed record); body=%s", recorder.Code, http.StatusNotFound, recorder.Body.String())
	}
}

func TestShowBandwidthUsageReturnsNotFoundForAnotherProjectsWorkload(t *testing.T) {
	ctx, server := newTestServer(t, &fakeZoneLister{})
	ownProject := createTestProject(t, ctx, server.pool)
	otherProject := createTestProject(t, ctx, server.pool)
	otherWorkloadID := insertOpenWorkload(t, ctx, server.pool, "provider-a", otherProject, "RUNNING", 10, 10)
	insertBandwidthUsage(t, ctx, server.pool, "provider-a", otherWorkloadID, 111, 222)
	token := mintProjectScopedToken(t, ctx, server.pool, server.users, ownProject)

	request := httptest.NewRequest(http.MethodGet, "/v2.0/metering/bandwidth_usage/"+otherWorkloadID, nil)
	request.Header.Set("X-Auth-Token", token)
	recorder := httptest.NewRecorder()
	server.handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNotFound)
	}
}

func TestListBandwidthUsageRejectsAnUnscopedToken(t *testing.T) {
	ctx, server := newTestServer(t, &fakeZoneLister{})
	token := mintUnscopedToken(t, ctx, server.users)

	request := httptest.NewRequest(http.MethodGet, "/v2.0/metering/bandwidth_usage", nil)
	request.Header.Set("X-Auth-Token", token)
	recorder := httptest.NewRecorder()
	server.handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
}
