// ADR-035 §3, the security-critical half of this package: security
// groups and their rules. "Fail-safe default, stated as the load-bearing
// rule first: a port with no security group attached, or a security
// group with zero rules, denies ALL traffic, both directions" (ADR-035
// §3). This file's Repository never stores or exposes any kind of
// "allow" sentinel/default -- the only thing a caller can ever add is an
// explicit, auditable, individually revocable accept rule
// (SecurityGroupRule row). Absence of rows is the only way traffic is
// ever denied, and there is no code path anywhere in this file that
// treats "no rows" as "allow" -- ResolveForWorkload (this file) and
// ListForPort both return an *empty slice*, never a nil-means-allow
// sentinel, for a port with nothing attached; agent-executor's
// security_group.rs (the Agent-side enforcement point, ADR-035 §3) is
// the component that turns "empty rule list" into an actual nftables
// default-drop chain with zero accept rules.
package neutron

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/openinfra/network/internal/openstackapi/osauth"
)

// Direction and Protocol are the exact vocabulary migration 000022's
// CHECK constraints allow -- ADR-035 §3's deliberately narrow rule
// vocabulary ("remote_ip_prefix-only... this slice's complete rule
// vocabulary").
const (
	DirectionIngress = "ingress"
	DirectionEgress  = "egress"

	ProtocolTCP  = "tcp"
	ProtocolUDP  = "udp"
	ProtocolICMP = "icmp"
	ProtocolAny  = "any"
)

var (
	ErrSecurityGroupNotFound = errors.New("security group not found")
	// ErrSecurityGroupInUse is DeleteSecurityGroup's failure when the
	// group is still attached to a live port.
	ErrSecurityGroupInUse = errors.New("security group is still attached to a port")
	ErrRuleNotFound       = errors.New("security group rule not found")
	// ErrDuplicateRule is CreateRule's failure on an exact-duplicate rule
	// (migration 000022's neutron_security_group_rules_dedup_idx), real
	// Neutron's own SecurityGroupRuleExists behavior.
	ErrDuplicateRule = errors.New("an identical security group rule already exists")
	// ErrInvalidRule is CreateRule's failure for a structurally invalid
	// rule (bad direction/protocol/port range/CIDR) caught before ever
	// reaching the repository.
	ErrInvalidRule = errors.New("invalid security group rule")
)

// SecurityGroup is one durable neutron_security_groups row.
type SecurityGroup struct {
	SecurityGroupID string
	ProjectID       string
	Name            string
	Description     string
	CreatedAt       time.Time
}

// SecurityGroupRule is one durable neutron_security_group_rules row.
// PortRangeMin/Max are nil for protocol icmp/any (migration 000022's own
// CHECK constraint enforces this same shape at the database boundary).
// This is also, field-for-field, the shape carried to the Agent as
// agent.proto's SecurityGroupRule message (internal/orchestrator's
// worker.go is the translation point) -- kept as this package's own
// plain Go type rather than a re-export of the generated proto type, the
// same "never a borrowed proto type" precedent
// agent_core::local_state::VolumeMount already establishes on the Rust
// side for the identical reason.
type SecurityGroupRule struct {
	RuleID          string
	SecurityGroupID string
	ProjectID       string
	Direction       string
	Protocol        string
	PortRangeMin    *int32
	PortRangeMax    *int32
	RemoteIPPrefix  string
}

// SecurityGroupRepository is the persistence surface securitygroup.go
// needs. Every method scopes by projectID as part of the query itself
// (ADR-035 §4) -- there is no method anywhere on this interface that
// returns a security group, rule, or port-attachment belonging to a
// project other than the one the caller supplied, and no method that
// treats "belongs to a different project" any differently from "does not
// exist" (the same no-enumeration-oracle posture
// internal/openstackapi/cinder.ErrNotFound already documents).
type SecurityGroupRepository interface {
	CreateSecurityGroup(ctx context.Context, group SecurityGroup) (SecurityGroup, error)
	GetSecurityGroup(ctx context.Context, groupID, projectID string) (SecurityGroup, error)
	ListSecurityGroups(ctx context.Context, projectID string) ([]SecurityGroup, error)
	// DeleteSecurityGroup returns ErrSecurityGroupInUse if the group is
	// still attached to any live port -- deleting it out from under an
	// attached port would silently change that port's effective rule set
	// (and, if it was the port's only group, silently flip it from
	// enforced-but-permitted to the fail-closed empty-group default,
	// which must always be an explicit choice, never an accidental side
	// effect of an unrelated delete).
	DeleteSecurityGroup(ctx context.Context, groupID, projectID string) error

	// CreateRule inserts a new rule. Returns ErrDuplicateRule on an exact
	// duplicate (migration 000022's dedup index).
	CreateRule(ctx context.Context, rule SecurityGroupRule) (SecurityGroupRule, error)
	GetRule(ctx context.Context, ruleID, projectID string) (SecurityGroupRule, error)
	ListRules(ctx context.Context, groupID, projectID string) ([]SecurityGroupRule, error)
	DeleteRule(ctx context.Context, ruleID, projectID string) error

	// ReplacePortGroups atomically replaces the full set of security
	// groups attached to portID with groupIDs -- real Neutron's own
	// port.security_groups full-replace update semantics (port.go's
	// updatePort is this method's only caller). Both portID and every id
	// in groupIDs must resolve to a live row owned by projectID; returns
	// ErrPortNotFound or ErrSecurityGroupNotFound (never distinguishing
	// "does not exist" from "belongs to a different project" -- ADR-035
	// §5's tenant-isolation requirement) if any does not. An empty
	// groupIDs detaches every group from the port -- fail-closed by
	// construction (§3), not a special case this method needs to guard
	// against.
	ReplacePortGroups(ctx context.Context, portID, projectID string, groupIDs []string) error
	// ListForPort returns the unioned (never intersected, ADR-035 §3
	// point 2) set of rules across every security group currently
	// attached to portID -- a port with no attached group, or whose
	// attached group(s) have zero rules, returns an empty (never nil in
	// meaning -- see this file's own package doc comment) slice. No
	// project scoping: called by PortForWorkload's own resolution path
	// and by orchestrator's Deploy dispatch, both of which already
	// resolved portID through a project-scoped lookup upstream.
	ListForPort(ctx context.Context, portID string) ([]SecurityGroupRule, error)
	// ListGroupIDsForPort returns the security_group_id of every group
	// currently attached to portID, directly from
	// neutron_port_security_groups -- distinct from ListForPort, which
	// only surfaces a group's *rules*: a group attached with zero rules
	// of its own (real Neutron's own "empty group, still attached, still
	// membership-visible" shape) would be entirely invisible to a caller
	// that tried to derive "which groups are attached" from ListForPort's
	// output alone. response.go's portBodyWithGroups is this method's
	// only caller.
	ListGroupIDsForPort(ctx context.Context, portID string) ([]string, error)
}

func (s *Server) createSecurityGroup(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	identity, ok := requireProjectID(w, r)
	if !ok {
		return
	}
	var body struct {
		SecurityGroup struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"security_group"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxNetworkingRequestBodyBytes)).Decode(&body); err != nil {
		osauth.WriteError(w, http.StatusBadRequest, "Bad Request", "invalid request body")
		return
	}
	name := strings.TrimSpace(body.SecurityGroup.Name)
	if name == "" || len(name) > 255 {
		osauth.WriteError(w, http.StatusBadRequest, "Bad Request", "security_group.name must be between 1 and 255 characters")
		return
	}
	if len(body.SecurityGroup.Description) > 2000 {
		osauth.WriteError(w, http.StatusBadRequest, "Bad Request", "security_group.description must be at most 2000 characters")
		return
	}
	group, err := s.securityGroups.CreateSecurityGroup(ctx, SecurityGroup{SecurityGroupID: uuid.NewString(), ProjectID: identity, Name: name, Description: body.SecurityGroup.Description})
	if err != nil {
		slog.Error("neutron: security group creation failed", "error", err)
		osauth.WriteError(w, http.StatusServiceUnavailable, "Service Unavailable", "security group creation unavailable")
		return
	}
	// A freshly-created security group has zero rules -- fail-closed by
	// construction (§3), reported here via securityGroupBody's own rules
	// lookup rather than asserted separately.
	writeJSON(w, http.StatusCreated, map[string]any{"security_group": s.securityGroupBody(ctx, group)})
}

func (s *Server) listSecurityGroups(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	identity, ok := requireProjectID(w, r)
	if !ok {
		return
	}
	groups, err := s.securityGroups.ListSecurityGroups(ctx, identity)
	if err != nil {
		slog.Error("neutron: security group listing failed", "error", err)
		osauth.WriteError(w, http.StatusServiceUnavailable, "Service Unavailable", "security group listing unavailable")
		return
	}
	bodies := make([]securityGroupResponseBody, 0, len(groups))
	for _, group := range groups {
		bodies = append(bodies, s.securityGroupBody(ctx, group))
	}
	writeJSON(w, http.StatusOK, map[string]any{"security_groups": bodies})
}

func (s *Server) showSecurityGroup(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	identity, ok := requireProjectID(w, r)
	if !ok {
		return
	}
	group, err := s.securityGroups.GetSecurityGroup(ctx, r.PathValue("security_group_id"), identity)
	if errors.Is(err, ErrSecurityGroupNotFound) {
		osauth.WriteError(w, http.StatusNotFound, "Not Found", "security group not found")
		return
	}
	if err != nil {
		slog.Error("neutron: security group lookup failed", "error", err)
		osauth.WriteError(w, http.StatusServiceUnavailable, "Service Unavailable", "security group lookup unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"security_group": s.securityGroupBody(ctx, group)})
}

func (s *Server) deleteSecurityGroup(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	identity, ok := requireProjectID(w, r)
	if !ok {
		return
	}
	err := s.securityGroups.DeleteSecurityGroup(ctx, r.PathValue("security_group_id"), identity)
	switch {
	case errors.Is(err, ErrSecurityGroupNotFound):
		osauth.WriteError(w, http.StatusNotFound, "Not Found", "security group not found")
	case errors.Is(err, ErrSecurityGroupInUse):
		osauth.WriteError(w, http.StatusConflict, "Conflict", "security group is still attached to a port; detach it first")
	case err != nil:
		slog.Error("neutron: security group delete failed", "error", err)
		osauth.WriteError(w, http.StatusServiceUnavailable, "Service Unavailable", "security group deletion unavailable")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) createSecurityGroupRule(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	identity, ok := requireProjectID(w, r)
	if !ok {
		return
	}
	var body struct {
		SecurityGroupRule struct {
			SecurityGroupID string `json:"security_group_id"`
			Direction       string `json:"direction"`
			Protocol        string `json:"protocol"`
			PortRangeMin    *int32 `json:"port_range_min"`
			PortRangeMax    *int32 `json:"port_range_max"`
			RemoteIPPrefix  string `json:"remote_ip_prefix"`
		} `json:"security_group_rule"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxNetworkingRequestBodyBytes)).Decode(&body); err != nil {
		osauth.WriteError(w, http.StatusBadRequest, "Bad Request", "invalid request body")
		return
	}
	// The target group must already be owned by the caller's own project
	// -- GetSecurityGroup's project-scoped lookup is what prevents a
	// caller from adding a rule to a group it does not own, the same
	// ownership-via-query pattern every other write in this file uses.
	group, err := s.securityGroups.GetSecurityGroup(ctx, body.SecurityGroupRule.SecurityGroupID, identity)
	if errors.Is(err, ErrSecurityGroupNotFound) {
		osauth.WriteError(w, http.StatusBadRequest, "Bad Request", "security_group_rule.security_group_id does not name a security group owned by this project")
		return
	}
	if err != nil {
		slog.Error("neutron: security group lookup for rule create failed", "error", err)
		osauth.WriteError(w, http.StatusServiceUnavailable, "Service Unavailable", "security group rule creation unavailable")
		return
	}
	rule, validationErr := validateSecurityGroupRule(body.SecurityGroupRule.Direction, body.SecurityGroupRule.Protocol, body.SecurityGroupRule.PortRangeMin, body.SecurityGroupRule.PortRangeMax, body.SecurityGroupRule.RemoteIPPrefix)
	if validationErr != nil {
		osauth.WriteError(w, http.StatusBadRequest, "Bad Request", validationErr.Error())
		return
	}
	rule.RuleID = uuid.NewString()
	rule.SecurityGroupID = group.SecurityGroupID
	rule.ProjectID = identity
	created, err := s.securityGroups.CreateRule(ctx, rule)
	switch {
	case errors.Is(err, ErrDuplicateRule):
		osauth.WriteError(w, http.StatusConflict, "Conflict", ErrDuplicateRule.Error())
	case err != nil:
		slog.Error("neutron: security group rule creation failed", "error", err)
		osauth.WriteError(w, http.StatusServiceUnavailable, "Service Unavailable", "security group rule creation unavailable")
	default:
		writeJSON(w, http.StatusCreated, map[string]any{"security_group_rule": securityGroupRuleBody(created)})
	}
}

// validateSecurityGroupRule enforces exactly migration 000022's CHECK
// constraints, surfaced here as a clear 4xx instead of a raw
// constraint-violation 503 -- direction/protocol must be one of the
// fixed vocabularies, port ranges are only meaningful for tcp/udp and
// must be well-ordered when both are set, and remote_ip_prefix must
// parse as a CIDR (a bare host address like "203.0.113.5" is normalized
// to "203.0.113.5/32", matching real Neutron's own tolerant input
// handling for this field).
func validateSecurityGroupRule(direction, protocol string, portMin, portMax *int32, remoteIPPrefix string) (SecurityGroupRule, error) {
	if direction != DirectionIngress && direction != DirectionEgress {
		return SecurityGroupRule{}, errors.New(`security_group_rule.direction must be "ingress" or "egress"`)
	}
	if protocol != ProtocolTCP && protocol != ProtocolUDP && protocol != ProtocolICMP && protocol != ProtocolAny {
		return SecurityGroupRule{}, errors.New(`security_group_rule.protocol must be "tcp", "udp", "icmp", or "any"`)
	}
	if protocol != ProtocolTCP && protocol != ProtocolUDP {
		if portMin != nil || portMax != nil {
			return SecurityGroupRule{}, errors.New("security_group_rule.port_range_min/max are only meaningful for tcp/udp")
		}
	} else {
		if portMin == nil || portMax == nil {
			return SecurityGroupRule{}, errors.New("security_group_rule.port_range_min and port_range_max are both required for tcp/udp")
		}
		if *portMin < 0 || *portMin > 65535 || *portMax < 0 || *portMax > 65535 || *portMin > *portMax {
			return SecurityGroupRule{}, errors.New("security_group_rule.port_range_min/max must be a valid, ordered 0-65535 range")
		}
	}
	prefix := strings.TrimSpace(remoteIPPrefix)
	if prefix == "" {
		return SecurityGroupRule{}, errors.New("security_group_rule.remote_ip_prefix is required")
	}
	if !strings.Contains(prefix, "/") {
		if ip := net.ParseIP(prefix); ip != nil && ip.To4() != nil {
			prefix += "/32"
		}
	}
	_, parsed, err := net.ParseCIDR(prefix)
	if err != nil || parsed.IP.To4() == nil {
		return SecurityGroupRule{}, errors.New("security_group_rule.remote_ip_prefix must be a valid IPv4 CIDR or address")
	}
	return SecurityGroupRule{Direction: direction, Protocol: protocol, PortRangeMin: portMin, PortRangeMax: portMax, RemoteIPPrefix: parsed.String()}, nil
}

func (s *Server) listSecurityGroupRules(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	identity, ok := requireProjectID(w, r)
	if !ok {
		return
	}
	groupID := r.URL.Query().Get("security_group_id")
	if groupID == "" {
		osauth.WriteError(w, http.StatusBadRequest, "Bad Request", "security_group_id query parameter is required")
		return
	}
	rules, err := s.securityGroups.ListRules(ctx, groupID, identity)
	if err != nil {
		slog.Error("neutron: security group rule listing failed", "error", err)
		osauth.WriteError(w, http.StatusServiceUnavailable, "Service Unavailable", "security group rule listing unavailable")
		return
	}
	bodies := make([]securityGroupRuleResponseBody, 0, len(rules))
	for _, rule := range rules {
		bodies = append(bodies, securityGroupRuleBody(rule))
	}
	writeJSON(w, http.StatusOK, map[string]any{"security_group_rules": bodies})
}

func (s *Server) showSecurityGroupRule(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	identity, ok := requireProjectID(w, r)
	if !ok {
		return
	}
	rule, err := s.securityGroups.GetRule(ctx, r.PathValue("security_group_rule_id"), identity)
	if errors.Is(err, ErrRuleNotFound) {
		osauth.WriteError(w, http.StatusNotFound, "Not Found", "security group rule not found")
		return
	}
	if err != nil {
		slog.Error("neutron: security group rule lookup failed", "error", err)
		osauth.WriteError(w, http.StatusServiceUnavailable, "Service Unavailable", "security group rule lookup unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"security_group_rule": securityGroupRuleBody(rule)})
}

func (s *Server) deleteSecurityGroupRule(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	identity, ok := requireProjectID(w, r)
	if !ok {
		return
	}
	err := s.securityGroups.DeleteRule(ctx, r.PathValue("security_group_rule_id"), identity)
	switch {
	case errors.Is(err, ErrRuleNotFound):
		osauth.WriteError(w, http.StatusNotFound, "Not Found", "security group rule not found")
	case err != nil:
		slog.Error("neutron: security group rule delete failed", "error", err)
		osauth.WriteError(w, http.StatusServiceUnavailable, "Service Unavailable", "security group rule deletion unavailable")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// PortSecurityResolver is the read surface
// internal/orchestrator.Worker needs (SetSecurityGroupResolver) to
// populate DeployRequest's security context at Deploy dispatch time --
// see agent.proto's PortSecurityContext and worker.go's own call site
// for the rest of this wire path.
type PortSecurityResolver interface {
	// ResolveForWorkload returns hasPort=false for a workload with no
	// bound Neutron port -- ADR-035 §1's backward-compatibility
	// guarantee: "a workload submitted with no port_id... is completely
	// unaffected... no network/subnet involved at all", which this
	// package extends to "no security-group enforcement is installed for
	// it either" (the Agent's own security_group.rs treats a nil/absent
	// security context as "legacy path, install nothing", strictly
	// distinct from an empty-but-present rule list, which fails closed --
	// see agent-executor's own doc comment on this exact distinction).
	// hasPort=true with a zero-length rules slice is the fail-closed case
	// (§3): a bound port with no security group, or an attached group
	// with no rules.
	ResolveForWorkload(ctx context.Context, workloadID string) (rules []SecurityGroupRule, fixedIP string, hasPort bool, err error)
}

// PostgresPortSecurityResolver implements PortSecurityResolver directly
// against the ports/security-group repositories, without requiring a
// full neutron.Server (which also needs bandwidth/usage/zones
// dependencies this resolver has no use for) -- constructed once in
// cmd/controlplane/main.go from the same *pgxpool.Pool-backed
// repositories openstackapi.New wires into the HTTP surface, and passed
// to orchestrator.Worker.SetSecurityGroupResolver.
type PostgresPortSecurityResolver struct {
	ports          PortRepository
	securityGroups SecurityGroupRepository
}

func NewPostgresPortSecurityResolver(ports PortRepository, securityGroups SecurityGroupRepository) *PostgresPortSecurityResolver {
	return &PostgresPortSecurityResolver{ports: ports, securityGroups: securityGroups}
}

func (r *PostgresPortSecurityResolver) ResolveForWorkload(ctx context.Context, workloadID string) ([]SecurityGroupRule, string, bool, error) {
	port, found, err := r.ports.PortForWorkload(ctx, workloadID)
	if err != nil {
		return nil, "", false, err
	}
	if !found {
		return nil, "", false, nil
	}
	rules, err := r.securityGroups.ListForPort(ctx, port.PortID)
	if err != nil {
		return nil, "", false, err
	}
	return rules, port.FixedIP, true, nil
}
