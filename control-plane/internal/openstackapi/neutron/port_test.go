package neutron_test

import (
	"net/http"
	"testing"
)

// createNetworkAndSubnet is a small fixture helper shared by port.go and
// securitygroup.go's own tests -- both need a real network+subnet to
// create a port against.
func createNetworkAndSubnet(t *testing.T, server testServer, token, cidr string) (networkID, subnetID string) {
	t.Helper()
	_, netBody := doJSON(t, server.handler, "POST", "/v2.0/networks", token, map[string]any{"network": map[string]any{"name": "net"}})
	networkID = netBody["network"].(map[string]any)["id"].(string)
	_, subnetBody := doJSON(t, server.handler, "POST", "/v2.0/subnets", token, map[string]any{
		"subnet": map[string]any{"network_id": networkID, "cidr": cidr},
	})
	subnetID = subnetBody["subnet"].(map[string]any)["id"].(string)
	return networkID, subnetID
}

func TestCreatePortAllocatesTheLowestAvailableAddressInTheSubnet(t *testing.T) {
	ctx, server := newTestServer(t, &fakeZoneLister{})
	projectID := createTestProject(t, ctx, server.pool)
	token := mintProjectScopedToken(t, ctx, server.pool, server.users, projectID)
	networkID, subnetID := createNetworkAndSubnet(t, server, token, "10.30.0.0/29")

	status, first := doJSON(t, server.handler, "POST", "/v2.0/ports", token, map[string]any{
		"port": map[string]any{"network_id": networkID, "subnet_id": subnetID},
	})
	if status != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %v", status, first)
	}
	firstIP := first["port"].(map[string]any)["fixed_ip"].(string)
	if firstIP != "10.30.0.1" {
		t.Fatalf("expected the lowest available address 10.30.0.1, got %s", firstIP)
	}

	_, second := doJSON(t, server.handler, "POST", "/v2.0/ports", token, map[string]any{
		"port": map[string]any{"network_id": networkID, "subnet_id": subnetID},
	})
	secondIP := second["port"].(map[string]any)["fixed_ip"].(string)
	if secondIP != "10.30.0.2" {
		t.Fatalf("expected the next available address 10.30.0.2, got %s", secondIP)
	}
}

func TestCreatePortExcludesTheGatewayAddress(t *testing.T) {
	ctx, server := newTestServer(t, &fakeZoneLister{})
	projectID := createTestProject(t, ctx, server.pool)
	token := mintProjectScopedToken(t, ctx, server.pool, server.users, projectID)
	_, netBody := doJSON(t, server.handler, "POST", "/v2.0/networks", token, map[string]any{"network": map[string]any{"name": "net"}})
	networkID := netBody["network"].(map[string]any)["id"].(string)
	_, subnetBody := doJSON(t, server.handler, "POST", "/v2.0/subnets", token, map[string]any{
		"subnet": map[string]any{"network_id": networkID, "cidr": "10.31.0.0/29", "gateway_ip": "10.31.0.1"},
	})
	subnetID := subnetBody["subnet"].(map[string]any)["id"].(string)

	_, portBody := doJSON(t, server.handler, "POST", "/v2.0/ports", token, map[string]any{
		"port": map[string]any{"network_id": networkID, "subnet_id": subnetID},
	})
	fixedIP := portBody["port"].(map[string]any)["fixed_ip"].(string)
	if fixedIP == "10.31.0.1" {
		t.Fatalf("the gateway address must never be allocated to a port, got %s", fixedIP)
	}
	if fixedIP != "10.31.0.2" {
		t.Fatalf("expected 10.31.0.2 (the first non-gateway address), got %s", fixedIP)
	}
}

func TestCreatePortFailsWhenTheSubnetPoolIsExhausted(t *testing.T) {
	// A /29 subnet (this package's own minimum allowed subnet size) has
	// exactly 6 usable host addresses (network .0/broadcast .7 excluded)
	// -- the 7th CreatePort must fail with 409, not silently allocate a
	// network/broadcast address or an address outside the CIDR.
	ctx, server := newTestServer(t, &fakeZoneLister{})
	projectID := createTestProject(t, ctx, server.pool)
	token := mintProjectScopedToken(t, ctx, server.pool, server.users, projectID)
	networkID, subnetID := createNetworkAndSubnet(t, server, token, "10.32.0.0/29")

	for i := 0; i < 6; i++ {
		status, body := doJSON(t, server.handler, "POST", "/v2.0/ports", token, map[string]any{
			"port": map[string]any{"network_id": networkID, "subnet_id": subnetID},
		})
		if status != http.StatusCreated {
			t.Fatalf("port %d: expected 201, got %d: %v", i, status, body)
		}
	}

	status, body := doJSON(t, server.handler, "POST", "/v2.0/ports", token, map[string]any{
		"port": map[string]any{"network_id": networkID, "subnet_id": subnetID},
	})
	if status != http.StatusConflict {
		t.Fatalf("expected 409 once the pool is exhausted, got %d: %v", status, body)
	}
}

func TestBindPortSetsDeviceIDAndUnbindClearsIt(t *testing.T) {
	ctx, server := newTestServer(t, &fakeZoneLister{})
	projectID := createTestProject(t, ctx, server.pool)
	token := mintProjectScopedToken(t, ctx, server.pool, server.users, projectID)
	networkID, subnetID := createNetworkAndSubnet(t, server, token, "10.33.0.0/29")
	_, portBody := doJSON(t, server.handler, "POST", "/v2.0/ports", token, map[string]any{
		"port": map[string]any{"network_id": networkID, "subnet_id": subnetID},
	})
	portID := portBody["port"].(map[string]any)["id"].(string)
	workloadID := insertOpenWorkload(t, ctx, server.pool, "provider-bind-1", projectID, "RUNNING", 0, 0)

	status, body := doJSON(t, server.handler, "PUT", "/v2.0/ports/"+portID, token, map[string]any{
		"port": map[string]any{"device_id": workloadID},
	})
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d: %v", status, body)
	}
	if body["port"].(map[string]any)["device_id"] != workloadID {
		t.Fatalf("device_id must be set to %s, got %v", workloadID, body["port"])
	}

	status, body = doJSON(t, server.handler, "PUT", "/v2.0/ports/"+portID, token, map[string]any{
		"port": map[string]any{"device_id": ""},
	})
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d: %v", status, body)
	}
	if body["port"].(map[string]any)["device_id"] != "" {
		t.Fatalf("device_id must be cleared by an empty-string update, got %v", body["port"])
	}
}

func TestBindPortRejectsASecondPortForAWorkloadAlreadyBoundElsewhere(t *testing.T) {
	ctx, server := newTestServer(t, &fakeZoneLister{})
	projectID := createTestProject(t, ctx, server.pool)
	token := mintProjectScopedToken(t, ctx, server.pool, server.users, projectID)
	networkID, subnetID := createNetworkAndSubnet(t, server, token, "10.34.0.0/28")
	_, firstPortBody := doJSON(t, server.handler, "POST", "/v2.0/ports", token, map[string]any{
		"port": map[string]any{"network_id": networkID, "subnet_id": subnetID},
	})
	firstPortID := firstPortBody["port"].(map[string]any)["id"].(string)
	_, secondPortBody := doJSON(t, server.handler, "POST", "/v2.0/ports", token, map[string]any{
		"port": map[string]any{"network_id": networkID, "subnet_id": subnetID},
	})
	secondPortID := secondPortBody["port"].(map[string]any)["id"].(string)
	workloadID := insertOpenWorkload(t, ctx, server.pool, "provider-bind-2", projectID, "RUNNING", 0, 0)

	status, _ := doJSON(t, server.handler, "PUT", "/v2.0/ports/"+firstPortID, token, map[string]any{
		"port": map[string]any{"device_id": workloadID},
	})
	if status != http.StatusOK {
		t.Fatalf("first bind must succeed, got %d", status)
	}

	status, _ = doJSON(t, server.handler, "PUT", "/v2.0/ports/"+secondPortID, token, map[string]any{
		"port": map[string]any{"device_id": workloadID},
	})
	if status != http.StatusConflict {
		t.Fatalf("binding the same workload to a second port must be rejected: got %d", status)
	}
}

// TestBindPortRejectsAWorkloadOwnedByAnotherProject reproduces the
// internal security review's own PR #195 Finding 1 scenario: project A
// creates its own port, then tries to PUT it with device_id set to
// project B's workload_id, hoping the orchestrator will later apply
// project A's fixed_ip and security-group rules to project B's workload
// at deploy dispatch. Before the fix, BindPort's repository query only
// checked the PORT's project_id, never the WORKLOAD's, so this bind
// succeeded. It must now be rejected before the port row is ever
// touched.
func TestBindPortRejectsAWorkloadOwnedByAnotherProject(t *testing.T) {
	ctx, server := newTestServer(t, &fakeZoneLister{})
	projectA := createTestProject(t, ctx, server.pool)
	projectB := createTestProject(t, ctx, server.pool)
	tokenA := mintProjectScopedToken(t, ctx, server.pool, server.users, projectA)
	networkID, subnetID := createNetworkAndSubnet(t, server, tokenA, "10.36.0.0/29")
	_, portBody := doJSON(t, server.handler, "POST", "/v2.0/ports", tokenA, map[string]any{
		"port": map[string]any{"network_id": networkID, "subnet_id": subnetID},
	})
	portID := portBody["port"].(map[string]any)["id"].(string)

	// Project B's own workload -- project A must never be able to bind
	// its port to this.
	victimWorkloadID := insertOpenWorkload(t, ctx, server.pool, "provider-hijack-victim", projectB, "RUNNING", 0, 0)

	status, body := doJSON(t, server.handler, "PUT", "/v2.0/ports/"+portID, tokenA, map[string]any{
		"port": map[string]any{"device_id": victimWorkloadID},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("binding a port to another project's workload must be rejected, got %d: %v", status, body)
	}

	// The port must still be unbound -- the rejected bind must never
	// have reached the write.
	status, showBody := doJSON(t, server.handler, "GET", "/v2.0/ports/"+portID, tokenA, nil)
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d: %v", status, showBody)
	}
	if deviceID := showBody["port"].(map[string]any)["device_id"]; deviceID != "" {
		t.Fatalf("port must remain unbound after a rejected cross-project bind attempt, got device_id=%v", deviceID)
	}

	// And project B's own view of its workload's port must still show
	// no binding -- PortForWorkload (the orchestrator's own read path)
	// must never resolve project A's port for project B's workload.
	status, listBody := doJSON(t, server.handler, "GET", "/v2.0/ports", tokenA, nil)
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d: %v", status, listBody)
	}
	for _, p := range listBody["ports"].([]any) {
		if p.(map[string]any)["device_id"] == victimWorkloadID {
			t.Fatalf("no port owned by project A may be bound to project B's workload: %v", p)
		}
	}
}

func TestDeletePortFailsWhileBoundAndSucceedsAfterUnbind(t *testing.T) {
	ctx, server := newTestServer(t, &fakeZoneLister{})
	projectID := createTestProject(t, ctx, server.pool)
	token := mintProjectScopedToken(t, ctx, server.pool, server.users, projectID)
	networkID, subnetID := createNetworkAndSubnet(t, server, token, "10.35.0.0/29")
	_, portBody := doJSON(t, server.handler, "POST", "/v2.0/ports", token, map[string]any{
		"port": map[string]any{"network_id": networkID, "subnet_id": subnetID},
	})
	portID := portBody["port"].(map[string]any)["id"].(string)
	workloadID := insertOpenWorkload(t, ctx, server.pool, "provider-bind-3", projectID, "RUNNING", 0, 0)
	doJSON(t, server.handler, "PUT", "/v2.0/ports/"+portID, token, map[string]any{"port": map[string]any{"device_id": workloadID}})

	status, _ := doJSON(t, server.handler, "DELETE", "/v2.0/ports/"+portID, token, nil)
	if status != http.StatusConflict {
		t.Fatalf("deleting a bound port must fail: got %d", status)
	}

	doJSON(t, server.handler, "PUT", "/v2.0/ports/"+portID, token, map[string]any{"port": map[string]any{"device_id": ""}})
	status, _ = doJSON(t, server.handler, "DELETE", "/v2.0/ports/"+portID, token, nil)
	if status != http.StatusNoContent {
		t.Fatalf("deleting an unbound port must succeed: got %d", status)
	}
}
