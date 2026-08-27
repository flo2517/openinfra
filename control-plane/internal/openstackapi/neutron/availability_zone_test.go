package neutron_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openinfra/network/internal/agentmanager"
	sharedv1 "github.com/openinfra/network/protocol/generated/go/shared/v1"
)

type availabilityZonesResponse struct {
	AvailabilityZones []struct {
		Name     string `json:"name"`
		State    string `json:"state"`
		Resource string `json:"resource"`
	} `json:"availability_zones"`
}

func schedulableProvider(providerID, zone string) agentmanager.SchedulableProvider {
	return agentmanager.SchedulableProvider{
		RegisteredProvider: agentmanager.RegisteredProvider{ProviderID: providerID, AgentEndpoint: "https://" + providerID + ".invalid:9443"},
		Capabilities:       &sharedv1.ResourceCapability{Zone: zone},
	}
}

// TestListAvailabilityZonesReflectsOnlyActuallyDeclaredZones is ADR-026's
// own discipline applied to this read surface: no invented zone name,
// deduplicated, and a provider with no declared zone (Capabilities.Zone
// == "") contributes nothing.
func TestListAvailabilityZonesReflectsOnlyActuallyDeclaredZones(t *testing.T) {
	zones := &fakeZoneLister{providers: []agentmanager.SchedulableProvider{
		schedulableProvider("provider-a", "us-east"),
		schedulableProvider("provider-b", "us-east"), // duplicate zone
		schedulableProvider("provider-c", "eu-central"),
		schedulableProvider("provider-d", ""), // undeclared -- must not appear
	}}
	ctx, server := newTestServer(t, zones)
	token := mintUnscopedToken(t, ctx, server.users) // AZ listing needs no project scope

	request := httptest.NewRequest(http.MethodGet, "/v2.0/availability_zones", nil)
	request.Header.Set("X-Auth-Token", token)
	recorder := httptest.NewRecorder()
	server.handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var body availabilityZonesResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.AvailabilityZones) != 2 {
		t.Fatalf("expected exactly 2 distinct zones, got %d: %+v", len(body.AvailabilityZones), body.AvailabilityZones)
	}
	// Deterministic, sorted order.
	if body.AvailabilityZones[0].Name != "eu-central" || body.AvailabilityZones[1].Name != "us-east" {
		t.Fatalf("unexpected zone order: %+v", body.AvailabilityZones)
	}
	for _, zone := range body.AvailabilityZones {
		if zone.State != "available" || zone.Resource != "network" {
			t.Fatalf("unexpected zone shape: %+v", zone)
		}
	}
}

func TestListAvailabilityZonesReturnsAnEmptyListWhenNoProviderHasDeclaredAZone(t *testing.T) {
	zones := &fakeZoneLister{providers: []agentmanager.SchedulableProvider{schedulableProvider("provider-a", "")}}
	ctx, server := newTestServer(t, zones)
	token := mintUnscopedToken(t, ctx, server.users)

	request := httptest.NewRequest(http.MethodGet, "/v2.0/availability_zones", nil)
	request.Header.Set("X-Auth-Token", token)
	recorder := httptest.NewRecorder()
	server.handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	var body availabilityZonesResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.AvailabilityZones) != 0 {
		t.Fatalf("expected 0 zones, got %+v", body.AvailabilityZones)
	}
}

func TestListAvailabilityZonesFailsClosedOnADirectoryError(t *testing.T) {
	zones := &fakeZoneLister{err: errBoom}
	ctx, server := newTestServer(t, zones)
	token := mintUnscopedToken(t, ctx, server.users)

	request := httptest.NewRequest(http.MethodGet, "/v2.0/availability_zones", nil)
	request.Header.Set("X-Auth-Token", token)
	recorder := httptest.NewRecorder()
	server.handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d (a directory error must fail closed, never report an empty/stale zone list as if it were current)", recorder.Code, http.StatusServiceUnavailable)
	}
}
