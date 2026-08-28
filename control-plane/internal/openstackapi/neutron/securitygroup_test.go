package neutron_test

import (
	"net/http"
	"testing"

	"github.com/openinfra/network/internal/openstackapi/neutron"
)

func TestFailClosedDefaultANewlyCreatedSecurityGroupHasNoRules(t *testing.T) {
	ctx, server := newTestServer(t, &fakeZoneLister{})
	projectID := createTestProject(t, ctx, server.pool)
	token := mintProjectScopedToken(t, ctx, server.pool, server.users, projectID)

	status, body := doJSON(t, server.handler, "POST", "/v2.0/security-groups", token, map[string]any{
		"security_group": map[string]any{"name": "empty-group"},
	})
	if status != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %v", status, body)
	}
	rules := body["security_group"].(map[string]any)["security_group_rules"].([]any)
	if len(rules) != 0 {
		t.Fatalf("a freshly-created security group must have zero rules (fail-closed by construction), got %d", len(rules))
	}
}

func TestFailClosedDefaultAPortWithNoAttachedGroupResolvesToNoRulesButHasPortTrue(t *testing.T) {
	// The central ADR-035 §3 assertion, at the exact seam
	// internal/orchestrator.Worker consumes: a port that exists but has
	// no security group attached at all must still report hasPort=true
	// with an empty rule set -- distinct from "no port" (hasPort=false),
	// which is the only case that means "no enforcement at all."
	ctx, server := newTestServer(t, &fakeZoneLister{})
	projectID := createTestProject(t, ctx, server.pool)
	token := mintProjectScopedToken(t, ctx, server.pool, server.users, projectID)
	networkID, subnetID := createNetworkAndSubnet(t, server, token, "10.40.0.0/29")
	_, portBody := doJSON(t, server.handler, "POST", "/v2.0/ports", token, map[string]any{
		"port": map[string]any{"network_id": networkID, "subnet_id": subnetID},
	})
	portID := portBody["port"].(map[string]any)["id"].(string)
	workloadID := insertOpenWorkload(t, ctx, server.pool, "provider-fc-1", projectID, "RUNNING", 0, 0)
	status, _ := doJSON(t, server.handler, "PUT", "/v2.0/ports/"+portID, token, map[string]any{"port": map[string]any{"device_id": workloadID}})
	if status != http.StatusOK {
		t.Fatalf("bind must succeed: got %d", status)
	}

	resolver := neutron.NewPostgresPortSecurityResolver(neutron.NewPostgresPortRepository(server.pool), neutron.NewPostgresSecurityGroupRepository(server.pool))
	rules, fixedIP, hasPort, err := resolver.ResolveForWorkload(ctx, workloadID)
	if err != nil {
		t.Fatal(err)
	}
	if !hasPort {
		t.Fatal("a bound port must resolve hasPort=true even with no attached security group")
	}
	if len(rules) != 0 {
		t.Fatalf("a port with no attached security group must resolve to zero rules (fail-closed), got %d", len(rules))
	}
	if fixedIP == "" {
		t.Fatal("a bound port must resolve its fixed_ip")
	}
}

func TestUnboundWorkloadResolvesHasPortFalse(t *testing.T) {
	// ADR-035 §1's backward-compatibility guarantee, at the resolver
	// seam: a workload_id with no bound Neutron port at all must resolve
	// hasPort=false -- the signal agent-executor treats as "no
	// enforcement," not "enforce with zero rules."
	ctx, server := newTestServer(t, &fakeZoneLister{})
	projectID := createTestProject(t, ctx, server.pool)
	workloadID := insertOpenWorkload(t, ctx, server.pool, "provider-nb-1", projectID, "RUNNING", 0, 0)

	resolver := neutron.NewPostgresPortSecurityResolver(neutron.NewPostgresPortRepository(server.pool), neutron.NewPostgresSecurityGroupRepository(server.pool))
	_, _, hasPort, err := resolver.ResolveForWorkload(ctx, workloadID)
	if err != nil {
		t.Fatal(err)
	}
	if hasPort {
		t.Fatal("a workload with no bound port must resolve hasPort=false")
	}
}

func TestSecurityGroupRuleCRUD(t *testing.T) {
	ctx, server := newTestServer(t, &fakeZoneLister{})
	projectID := createTestProject(t, ctx, server.pool)
	token := mintProjectScopedToken(t, ctx, server.pool, server.users, projectID)
	_, groupBody := doJSON(t, server.handler, "POST", "/v2.0/security-groups", token, map[string]any{"security_group": map[string]any{"name": "web"}})
	groupID := groupBody["security_group"].(map[string]any)["id"].(string)

	status, ruleBody := doJSON(t, server.handler, "POST", "/v2.0/security-group-rules", token, map[string]any{
		"security_group_rule": map[string]any{
			"security_group_id": groupID,
			"direction":         "ingress",
			"protocol":          "tcp",
			"port_range_min":    443,
			"port_range_max":    443,
			"remote_ip_prefix":  "0.0.0.0/0",
		},
	})
	if status != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %v", status, ruleBody)
	}
	ruleID := ruleBody["security_group_rule"].(map[string]any)["id"].(string)

	status, listBody := doJSON(t, server.handler, "GET", "/v2.0/security-group-rules?security_group_id="+groupID, token, nil)
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d", status)
	}
	rules := listBody["security_group_rules"].([]any)
	if len(rules) != 1 {
		t.Fatalf("expected exactly 1 rule listed, got %d", len(rules))
	}

	status, _ = doJSON(t, server.handler, "GET", "/v2.0/security-group-rules/"+ruleID, token, nil)
	if status != http.StatusOK {
		t.Fatalf("expected 200 for show, got %d", status)
	}

	status, _ = doJSON(t, server.handler, "DELETE", "/v2.0/security-group-rules/"+ruleID, token, nil)
	if status != http.StatusNoContent {
		t.Fatalf("expected 204 for delete, got %d", status)
	}
	status, _ = doJSON(t, server.handler, "GET", "/v2.0/security-group-rules/"+ruleID, token, nil)
	if status != http.StatusNotFound {
		t.Fatalf("a deleted rule must 404, got %d", status)
	}
}

func TestSecurityGroupRuleRejectsAnExactDuplicate(t *testing.T) {
	ctx, server := newTestServer(t, &fakeZoneLister{})
	projectID := createTestProject(t, ctx, server.pool)
	token := mintProjectScopedToken(t, ctx, server.pool, server.users, projectID)
	_, groupBody := doJSON(t, server.handler, "POST", "/v2.0/security-groups", token, map[string]any{"security_group": map[string]any{"name": "web"}})
	groupID := groupBody["security_group"].(map[string]any)["id"].(string)
	rule := map[string]any{
		"security_group_id": groupID,
		"direction":         "egress",
		"protocol":          "any",
		"remote_ip_prefix":  "10.0.0.0/8",
	}

	status, _ := doJSON(t, server.handler, "POST", "/v2.0/security-group-rules", token, map[string]any{"security_group_rule": rule})
	if status != http.StatusCreated {
		t.Fatalf("first create must succeed, got %d", status)
	}
	status, _ = doJSON(t, server.handler, "POST", "/v2.0/security-group-rules", token, map[string]any{"security_group_rule": rule})
	if status != http.StatusConflict {
		t.Fatalf("an exact duplicate rule must be rejected, got %d", status)
	}
}

func TestAttachAndDetachSecurityGroupToAPortViaReplace(t *testing.T) {
	ctx, server := newTestServer(t, &fakeZoneLister{})
	projectID := createTestProject(t, ctx, server.pool)
	token := mintProjectScopedToken(t, ctx, server.pool, server.users, projectID)
	networkID, subnetID := createNetworkAndSubnet(t, server, token, "10.41.0.0/29")
	_, portBody := doJSON(t, server.handler, "POST", "/v2.0/ports", token, map[string]any{
		"port": map[string]any{"network_id": networkID, "subnet_id": subnetID},
	})
	portID := portBody["port"].(map[string]any)["id"].(string)
	_, groupBody := doJSON(t, server.handler, "POST", "/v2.0/security-groups", token, map[string]any{"security_group": map[string]any{"name": "web"}})
	groupID := groupBody["security_group"].(map[string]any)["id"].(string)
	doJSON(t, server.handler, "POST", "/v2.0/security-group-rules", token, map[string]any{
		"security_group_rule": map[string]any{"security_group_id": groupID, "direction": "ingress", "protocol": "any", "remote_ip_prefix": "0.0.0.0/0"},
	})

	status, body := doJSON(t, server.handler, "PUT", "/v2.0/ports/"+portID, token, map[string]any{
		"port": map[string]any{"security_groups": []string{groupID}},
	})
	if status != http.StatusOK {
		t.Fatalf("attach must succeed, got %d: %v", status, body)
	}
	groups := body["port"].(map[string]any)["security_groups"].([]any)
	if len(groups) != 1 || groups[0] != groupID {
		t.Fatalf("expected security_groups=[%s], got %v", groupID, groups)
	}

	workloadID := insertOpenWorkload(t, ctx, server.pool, "provider-attach-1", projectID, "RUNNING", 0, 0)
	doJSON(t, server.handler, "PUT", "/v2.0/ports/"+portID, token, map[string]any{"port": map[string]any{"device_id": workloadID}})
	resolver := neutron.NewPostgresPortSecurityResolver(neutron.NewPostgresPortRepository(server.pool), neutron.NewPostgresSecurityGroupRepository(server.pool))
	rules, _, hasPort, err := resolver.ResolveForWorkload(ctx, workloadID)
	if err != nil {
		t.Fatal(err)
	}
	if !hasPort || len(rules) != 1 {
		t.Fatalf("expected hasPort=true with 1 rule after attach, got hasPort=%v rules=%d", hasPort, len(rules))
	}

	// Detach: replace with an empty set.
	status, body = doJSON(t, server.handler, "PUT", "/v2.0/ports/"+portID, token, map[string]any{
		"port": map[string]any{"security_groups": []string{}},
	})
	if status != http.StatusOK {
		t.Fatalf("detach must succeed, got %d: %v", status, body)
	}
	groups = body["port"].(map[string]any)["security_groups"].([]any)
	if len(groups) != 0 {
		t.Fatalf("expected no security_groups after detach, got %v", groups)
	}
	rules, _, hasPort, err = resolver.ResolveForWorkload(ctx, workloadID)
	if err != nil {
		t.Fatal(err)
	}
	if !hasPort || len(rules) != 0 {
		t.Fatalf("expected hasPort=true with 0 rules after detach (fail-closed, not no-enforcement), got hasPort=%v rules=%d", hasPort, len(rules))
	}
}

func TestReplacingPortGroupsWithTheSameSetTwiceIsIdempotent(t *testing.T) {
	ctx, server := newTestServer(t, &fakeZoneLister{})
	projectID := createTestProject(t, ctx, server.pool)
	token := mintProjectScopedToken(t, ctx, server.pool, server.users, projectID)
	networkID, subnetID := createNetworkAndSubnet(t, server, token, "10.42.0.0/29")
	_, portBody := doJSON(t, server.handler, "POST", "/v2.0/ports", token, map[string]any{
		"port": map[string]any{"network_id": networkID, "subnet_id": subnetID},
	})
	portID := portBody["port"].(map[string]any)["id"].(string)
	_, groupBody := doJSON(t, server.handler, "POST", "/v2.0/security-groups", token, map[string]any{"security_group": map[string]any{"name": "web"}})
	groupID := groupBody["security_group"].(map[string]any)["id"].(string)

	for i := 0; i < 2; i++ {
		status, body := doJSON(t, server.handler, "PUT", "/v2.0/ports/"+portID, token, map[string]any{
			"port": map[string]any{"security_groups": []string{groupID}},
		})
		if status != http.StatusOK {
			t.Fatalf("attempt %d: expected 200, got %d: %v", i, status, body)
		}
		groups := body["port"].(map[string]any)["security_groups"].([]any)
		if len(groups) != 1 {
			t.Fatalf("attempt %d: expected exactly 1 attached group, got %d", i, len(groups))
		}
	}
}

func TestCrossProjectSecurityGroupAttachmentIsRejected(t *testing.T) {
	// ADR-035 §4/§5's tenant-isolation requirement: a port can only
	// attach a security group belonging to its own project.
	ctx, server := newTestServer(t, &fakeZoneLister{})
	ownerProject := createTestProject(t, ctx, server.pool)
	ownerToken := mintProjectScopedToken(t, ctx, server.pool, server.users, ownerProject)
	otherProject := createTestProject(t, ctx, server.pool)
	otherToken := mintProjectScopedToken(t, ctx, server.pool, server.users, otherProject)

	networkID, subnetID := createNetworkAndSubnet(t, server, ownerToken, "10.43.0.0/29")
	_, portBody := doJSON(t, server.handler, "POST", "/v2.0/ports", ownerToken, map[string]any{
		"port": map[string]any{"network_id": networkID, "subnet_id": subnetID},
	})
	portID := portBody["port"].(map[string]any)["id"].(string)

	_, foreignGroupBody := doJSON(t, server.handler, "POST", "/v2.0/security-groups", otherToken, map[string]any{"security_group": map[string]any{"name": "foreign"}})
	foreignGroupID := foreignGroupBody["security_group"].(map[string]any)["id"].(string)

	status, body := doJSON(t, server.handler, "PUT", "/v2.0/ports/"+portID, ownerToken, map[string]any{
		"port": map[string]any{"security_groups": []string{foreignGroupID}},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("attaching another project's security group must be rejected: got %d: %v", status, body)
	}
}

func TestCrossProjectPortAttachmentByASecurityGroupOwnerIsAlsoRejected(t *testing.T) {
	// The mirror case: a project cannot attach its own security group to
	// a port it does not own either (GetPort's own project scoping
	// rejects this before ReplacePortGroups is even reached).
	ctx, server := newTestServer(t, &fakeZoneLister{})
	ownerProject := createTestProject(t, ctx, server.pool)
	ownerToken := mintProjectScopedToken(t, ctx, server.pool, server.users, ownerProject)
	otherProject := createTestProject(t, ctx, server.pool)
	otherToken := mintProjectScopedToken(t, ctx, server.pool, server.users, otherProject)

	networkID, subnetID := createNetworkAndSubnet(t, server, ownerToken, "10.44.0.0/29")
	_, portBody := doJSON(t, server.handler, "POST", "/v2.0/ports", ownerToken, map[string]any{
		"port": map[string]any{"network_id": networkID, "subnet_id": subnetID},
	})
	portID := portBody["port"].(map[string]any)["id"].(string)
	_, groupBody := doJSON(t, server.handler, "POST", "/v2.0/security-groups", otherToken, map[string]any{"security_group": map[string]any{"name": "mine"}})
	groupID := groupBody["security_group"].(map[string]any)["id"].(string)

	status, _ := doJSON(t, server.handler, "PUT", "/v2.0/ports/"+portID, otherToken, map[string]any{
		"port": map[string]any{"security_groups": []string{groupID}},
	})
	if status != http.StatusNotFound {
		t.Fatalf("attaching to another project's port must 404 (not-found, matching this codebase's no-enumeration-oracle posture), got %d", status)
	}
}

func TestDeleteSecurityGroupFailsWhileAttachedToALivePort(t *testing.T) {
	ctx, server := newTestServer(t, &fakeZoneLister{})
	projectID := createTestProject(t, ctx, server.pool)
	token := mintProjectScopedToken(t, ctx, server.pool, server.users, projectID)
	networkID, subnetID := createNetworkAndSubnet(t, server, token, "10.45.0.0/29")
	_, portBody := doJSON(t, server.handler, "POST", "/v2.0/ports", token, map[string]any{
		"port": map[string]any{"network_id": networkID, "subnet_id": subnetID},
	})
	portID := portBody["port"].(map[string]any)["id"].(string)
	_, groupBody := doJSON(t, server.handler, "POST", "/v2.0/security-groups", token, map[string]any{"security_group": map[string]any{"name": "web"}})
	groupID := groupBody["security_group"].(map[string]any)["id"].(string)
	doJSON(t, server.handler, "PUT", "/v2.0/ports/"+portID, token, map[string]any{"port": map[string]any{"security_groups": []string{groupID}}})

	status, _ := doJSON(t, server.handler, "DELETE", "/v2.0/security-groups/"+groupID, token, nil)
	if status != http.StatusConflict {
		t.Fatalf("deleting an attached security group must fail: got %d", status)
	}

	doJSON(t, server.handler, "PUT", "/v2.0/ports/"+portID, token, map[string]any{"port": map[string]any{"security_groups": []string{}}})
	status, _ = doJSON(t, server.handler, "DELETE", "/v2.0/security-groups/"+groupID, token, nil)
	if status != http.StatusNoContent {
		t.Fatalf("deleting a now-detached security group must succeed: got %d", status)
	}
}

func TestSecurityGroupEndpointsRejectAnUnauthenticatedRequest(t *testing.T) {
	_, server := newTestServer(t, &fakeZoneLister{})

	for _, call := range []struct{ method, path string }{
		{"POST", "/v2.0/security-groups"},
		{"GET", "/v2.0/security-groups"},
		{"POST", "/v2.0/security-group-rules"},
	} {
		status, _ := doJSON(t, server.handler, call.method, call.path, "", map[string]any{})
		if status != http.StatusUnauthorized {
			t.Fatalf("%s %s: expected 401 unauthenticated, got %d", call.method, call.path, status)
		}
	}
}
