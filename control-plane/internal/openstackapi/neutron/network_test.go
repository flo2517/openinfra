package neutron_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// doJSON issues req against handler with token in X-Auth-Token (if
// non-empty) and body JSON-encoded, returning the decoded response body
// and status code.
func doJSON(t *testing.T, handler http.Handler, method, path, token string, body any) (int, map[string]any) {
	t.Helper()
	var reader *strings.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = strings.NewReader(string(encoded))
	} else {
		reader = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, reader)
	if token != "" {
		req.Header.Set("X-Auth-Token", token)
	}
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	result := recorder.Result()
	defer result.Body.Close()
	var decoded map[string]any
	if result.ContentLength != 0 {
		_ = json.NewDecoder(result.Body).Decode(&decoded)
	}
	return result.StatusCode, decoded
}

func TestCreateNetworkRejectsAnUnauthenticatedRequest(t *testing.T) {
	_, server := newTestServer(t, &fakeZoneLister{})

	status, _ := doJSON(t, server.handler, "POST", "/v2.0/networks", "", map[string]any{
		"network": map[string]any{"name": "net-1"},
	})

	if status != http.StatusUnauthorized {
		t.Fatalf("expected 401 for an unauthenticated request, got %d", status)
	}
}

func TestCreateNetworkRejectsAnUnscopedToken(t *testing.T) {
	ctx, server := newTestServer(t, &fakeZoneLister{})
	token := mintUnscopedToken(t, ctx, server.users)

	status, _ := doJSON(t, server.handler, "POST", "/v2.0/networks", token, map[string]any{
		"network": map[string]any{"name": "net-1"},
	})

	if status != http.StatusForbidden {
		t.Fatalf("expected 403 for an unscoped token, got %d", status)
	}
}

func TestCreateAndShowNetworkRoundTrips(t *testing.T) {
	ctx, server := newTestServer(t, &fakeZoneLister{})
	projectID := createTestProject(t, ctx, server.pool)
	token := mintProjectScopedToken(t, ctx, server.pool, server.users, projectID)

	status, body := doJSON(t, server.handler, "POST", "/v2.0/networks", token, map[string]any{
		"network": map[string]any{"name": "net-1", "shared": false},
	})
	if status != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %v", status, body)
	}
	network := body["network"].(map[string]any)
	networkID := network["id"].(string)
	if network["project_id"] != projectID {
		t.Fatalf("expected project_id %s, got %v", projectID, network["project_id"])
	}

	status, body = doJSON(t, server.handler, "GET", "/v2.0/networks/"+networkID, token, nil)
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d: %v", status, body)
	}
}

func TestGetNetworkFromAnotherProjectIsNotFoundUnlessShared(t *testing.T) {
	ctx, server := newTestServer(t, &fakeZoneLister{})
	ownerProject := createTestProject(t, ctx, server.pool)
	ownerToken := mintProjectScopedToken(t, ctx, server.pool, server.users, ownerProject)
	otherProject := createTestProject(t, ctx, server.pool)
	otherToken := mintProjectScopedToken(t, ctx, server.pool, server.users, otherProject)

	_, body := doJSON(t, server.handler, "POST", "/v2.0/networks", ownerToken, map[string]any{
		"network": map[string]any{"name": "private-net", "shared": false},
	})
	networkID := body["network"].(map[string]any)["id"].(string)

	status, _ := doJSON(t, server.handler, "GET", "/v2.0/networks/"+networkID, otherToken, nil)
	if status != http.StatusNotFound {
		t.Fatalf("a private network must be invisible to another project: got %d", status)
	}

	// A shared network, by contrast, must be visible (read-only) to the
	// other project -- ADR-035 §4's "read-attach, not co-write".
	_, sharedBody := doJSON(t, server.handler, "POST", "/v2.0/networks", ownerToken, map[string]any{
		"network": map[string]any{"name": "shared-net", "shared": true},
	})
	sharedNetworkID := sharedBody["network"].(map[string]any)["id"].(string)

	status, _ = doJSON(t, server.handler, "GET", "/v2.0/networks/"+sharedNetworkID, otherToken, nil)
	if status != http.StatusOK {
		t.Fatalf("a shared network must be readable by another project: got %d", status)
	}
}

func TestOnlyTheOwningProjectMayAddASubnetToAScrutinizedSharedNetwork(t *testing.T) {
	// ADR-035 §4: "a shared network can be attached to by other
	// projects' ports, but its subnets/security-groups remain owned and
	// mutable only by the creating project."
	ctx, server := newTestServer(t, &fakeZoneLister{})
	ownerProject := createTestProject(t, ctx, server.pool)
	ownerToken := mintProjectScopedToken(t, ctx, server.pool, server.users, ownerProject)
	otherProject := createTestProject(t, ctx, server.pool)
	otherToken := mintProjectScopedToken(t, ctx, server.pool, server.users, otherProject)

	_, netBody := doJSON(t, server.handler, "POST", "/v2.0/networks", ownerToken, map[string]any{
		"network": map[string]any{"name": "shared-net", "shared": true},
	})
	networkID := netBody["network"].(map[string]any)["id"].(string)

	status, body := doJSON(t, server.handler, "POST", "/v2.0/subnets", otherToken, map[string]any{
		"subnet": map[string]any{"network_id": networkID, "cidr": "10.10.0.0/24"},
	})
	if status != http.StatusForbidden {
		t.Fatalf("a non-owning project must not be able to add a subnet to a shared network: got %d: %v", status, body)
	}

	status, body = doJSON(t, server.handler, "POST", "/v2.0/subnets", ownerToken, map[string]any{
		"subnet": map[string]any{"network_id": networkID, "cidr": "10.10.0.0/24"},
	})
	if status != http.StatusCreated {
		t.Fatalf("the owning project must be able to add a subnet: got %d: %v", status, body)
	}
}

func TestCreateSubnetRejectsOverlapWithTheLegacyOverlayRange(t *testing.T) {
	ctx, server := newTestServer(t, &fakeZoneLister{})
	projectID := createTestProject(t, ctx, server.pool)
	token := mintProjectScopedToken(t, ctx, server.pool, server.users, projectID)
	_, netBody := doJSON(t, server.handler, "POST", "/v2.0/networks", token, map[string]any{
		"network": map[string]any{"name": "net-1"},
	})
	networkID := netBody["network"].(map[string]any)["id"].(string)

	status, body := doJSON(t, server.handler, "POST", "/v2.0/subnets", token, map[string]any{
		"subnet": map[string]any{"network_id": networkID, "cidr": "10.254.1.0/24"},
	})

	if status != http.StatusBadRequest {
		t.Fatalf("a subnet overlapping 10.254.0.0/16 must be rejected: got %d: %v", status, body)
	}
}

func TestCreateSubnetRejectsADuplicateOrOverlappingCIDRAcrossProjects(t *testing.T) {
	// ADR-035 §2's conservative first slice: subnet CIDRs are globally
	// unique, not just per-tenant-unique.
	ctx, server := newTestServer(t, &fakeZoneLister{})
	firstProject := createTestProject(t, ctx, server.pool)
	firstToken := mintProjectScopedToken(t, ctx, server.pool, server.users, firstProject)
	secondProject := createTestProject(t, ctx, server.pool)
	secondToken := mintProjectScopedToken(t, ctx, server.pool, server.users, secondProject)

	_, firstNetBody := doJSON(t, server.handler, "POST", "/v2.0/networks", firstToken, map[string]any{"network": map[string]any{"name": "net-a"}})
	firstNetworkID := firstNetBody["network"].(map[string]any)["id"].(string)
	status, body := doJSON(t, server.handler, "POST", "/v2.0/subnets", firstToken, map[string]any{
		"subnet": map[string]any{"network_id": firstNetworkID, "cidr": "192.168.50.0/24"},
	})
	if status != http.StatusCreated {
		t.Fatalf("first subnet creation must succeed: got %d: %v", status, body)
	}

	_, secondNetBody := doJSON(t, server.handler, "POST", "/v2.0/networks", secondToken, map[string]any{"network": map[string]any{"name": "net-b"}})
	secondNetworkID := secondNetBody["network"].(map[string]any)["id"].(string)
	status, body = doJSON(t, server.handler, "POST", "/v2.0/subnets", secondToken, map[string]any{
		"subnet": map[string]any{"network_id": secondNetworkID, "cidr": "192.168.50.0/25"},
	})
	if status != http.StatusConflict {
		t.Fatalf("an overlapping CIDR from a different project must be rejected: got %d: %v", status, body)
	}
}

func TestDeleteNetworkFailsWhileALiveSubnetExists(t *testing.T) {
	ctx, server := newTestServer(t, &fakeZoneLister{})
	projectID := createTestProject(t, ctx, server.pool)
	token := mintProjectScopedToken(t, ctx, server.pool, server.users, projectID)
	_, netBody := doJSON(t, server.handler, "POST", "/v2.0/networks", token, map[string]any{"network": map[string]any{"name": "net-1"}})
	networkID := netBody["network"].(map[string]any)["id"].(string)
	_, subnetBody := doJSON(t, server.handler, "POST", "/v2.0/subnets", token, map[string]any{
		"subnet": map[string]any{"network_id": networkID, "cidr": "10.20.0.0/24"},
	})
	subnetID := subnetBody["subnet"].(map[string]any)["id"].(string)

	status, _ := doJSON(t, server.handler, "DELETE", "/v2.0/networks/"+networkID, token, nil)
	if status != http.StatusConflict {
		t.Fatalf("deleting a network with a live subnet must fail: got %d", status)
	}

	status, _ = doJSON(t, server.handler, "DELETE", "/v2.0/subnets/"+subnetID, token, nil)
	if status != http.StatusNoContent {
		t.Fatalf("deleting the subnet must succeed: got %d", status)
	}
	status, _ = doJSON(t, server.handler, "DELETE", "/v2.0/networks/"+networkID, token, nil)
	if status != http.StatusNoContent {
		t.Fatalf("deleting the now-empty network must succeed: got %d", status)
	}
}
