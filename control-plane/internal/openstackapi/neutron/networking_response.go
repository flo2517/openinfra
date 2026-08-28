package neutron

import (
	"context"
	"log/slog"
)

type networkResponseBody struct {
	ID        string `json:"id"`
	ProjectID string `json:"project_id"`
	TenantID  string `json:"tenant_id"`
	Name      string `json:"name"`
	Shared    bool   `json:"shared"`
}

func networkBody(network Network) networkResponseBody {
	return networkResponseBody{ID: network.NetworkID, ProjectID: network.ProjectID, TenantID: network.ProjectID, Name: network.Name, Shared: network.Shared}
}

type subnetResponseBody struct {
	ID        string  `json:"id"`
	NetworkID string  `json:"network_id"`
	ProjectID string  `json:"project_id"`
	TenantID  string  `json:"tenant_id"`
	CIDR      string  `json:"cidr"`
	GatewayIP *string `json:"gateway_ip"`
	IPVersion int     `json:"ip_version"`
}

func subnetBody(subnet Subnet) subnetResponseBody {
	return subnetResponseBody{ID: subnet.SubnetID, NetworkID: subnet.NetworkID, ProjectID: subnet.ProjectID, TenantID: subnet.ProjectID, CIDR: subnet.CIDR, GatewayIP: subnet.GatewayIP, IPVersion: 4}
}

// portResponseBody's DeviceID is real Neutron's own field name for a
// port's bound instance -- Port.WorkloadID translated here, at the wire
// boundary only (see Port's own doc comment on why the Go type keeps this
// codebase's own vocabulary internally). QosPolicyID is always null in
// this slice (ADR-035 §5: "the actual rate-limit mechanism underneath
// remains exactly ADR-025 §3's existing tc implementation... not re-keyed
// by port") -- present for wire-shape completeness only, exactly as that
// section specifies.
type portResponseBody struct {
	ID             string   `json:"id"`
	NetworkID      string   `json:"network_id"`
	ProjectID      string   `json:"project_id"`
	TenantID       string   `json:"tenant_id"`
	FixedIP        string   `json:"fixed_ip"`
	DeviceID       string   `json:"device_id"`
	MacAddress     *string  `json:"mac_address"`
	QosPolicyID    *string  `json:"qos_policy_id"`
	SecurityGroups []string `json:"security_groups"`
}

func portBody(port Port, securityGroups []string) portResponseBody {
	deviceID := ""
	if port.WorkloadID != nil {
		deviceID = *port.WorkloadID
	}
	if securityGroups == nil {
		securityGroups = []string{}
	}
	return portResponseBody{
		ID: port.PortID, NetworkID: port.NetworkID, ProjectID: port.ProjectID, TenantID: port.ProjectID,
		FixedIP: port.FixedIP, DeviceID: deviceID, MacAddress: nil, QosPolicyID: nil, SecurityGroups: securityGroups,
	}
}

// portBodyWithGroups looks up port's currently-attached security-group
// ids (via ListGroupIDsForPort, not derived from ListForPort's rule-shaped
// output -- a group attached with zero rules of its own must still be
// reported here) for the response body's own security_groups list -- a
// lookup failure is logged and degrades to an empty list rather than
// failing the whole request, matching this codebase's established "one
// bad dependency must not blank out an otherwise-successful response"
// posture (agent-executor's collect_workload_bandwidth, e.g.).
func (s *Server) portBodyWithGroups(ctx context.Context, port Port) portResponseBody {
	groupIDs, err := s.securityGroups.ListGroupIDsForPort(ctx, port.PortID)
	if err != nil {
		slog.Error("neutron: security-group lookup for port response failed", "port_id", port.PortID, "error", err)
		return portBody(port, nil)
	}
	return portBody(port, groupIDs)
}

type securityGroupResponseBody struct {
	ID          string                          `json:"id"`
	ProjectID   string                          `json:"project_id"`
	TenantID    string                          `json:"tenant_id"`
	Name        string                          `json:"name"`
	Description string                          `json:"description"`
	Rules       []securityGroupRuleResponseBody `json:"security_group_rules"`
}

func (s *Server) securityGroupBody(ctx context.Context, group SecurityGroup) securityGroupResponseBody {
	rules, err := s.securityGroups.ListRules(ctx, group.SecurityGroupID, group.ProjectID)
	if err != nil {
		slog.Error("neutron: rule lookup for security-group response failed", "security_group_id", group.SecurityGroupID, "error", err)
		rules = nil
	}
	bodies := make([]securityGroupRuleResponseBody, 0, len(rules))
	for _, rule := range rules {
		bodies = append(bodies, securityGroupRuleBody(rule))
	}
	return securityGroupResponseBody{ID: group.SecurityGroupID, ProjectID: group.ProjectID, TenantID: group.ProjectID, Name: group.Name, Description: group.Description, Rules: bodies}
}

type securityGroupRuleResponseBody struct {
	ID              string `json:"id"`
	SecurityGroupID string `json:"security_group_id"`
	ProjectID       string `json:"project_id"`
	TenantID        string `json:"tenant_id"`
	Direction       string `json:"direction"`
	Protocol        string `json:"protocol"`
	PortRangeMin    *int32 `json:"port_range_min"`
	PortRangeMax    *int32 `json:"port_range_max"`
	RemoteIPPrefix  string `json:"remote_ip_prefix"`
}

func securityGroupRuleBody(rule SecurityGroupRule) securityGroupRuleResponseBody {
	return securityGroupRuleResponseBody{
		ID: rule.RuleID, SecurityGroupID: rule.SecurityGroupID, ProjectID: rule.ProjectID, TenantID: rule.ProjectID,
		Direction: rule.Direction, Protocol: rule.Protocol, PortRangeMin: rule.PortRangeMin, PortRangeMax: rule.PortRangeMax,
		RemoteIPPrefix: rule.RemoteIPPrefix,
	}
}
