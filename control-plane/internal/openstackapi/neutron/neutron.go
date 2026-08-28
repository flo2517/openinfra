// Package neutron implements issue #25's Neutron-compatible networking
// surface in two slices:
//
//   - The "easy half" (ADR-031 §5/§8): QoS/bandwidth and
//     availability-zone reporting, a genuine compatibility *shim* over
//     already-shipped mechanism (ADR-025's tc-enforced bandwidth
//     reservation, ADR-026's availability-zone placement constraint), not
//     new orchestration state. Every handler in this slice (qos.go,
//     availability_zone.go, usage.go) is read-only -- see those files'
//     own doc comments for why.
//   - The "hard half" (ADR-035, issue #170, now Accepted): networks,
//     subnets, ports, security groups, and security-group rules -- this
//     file, network.go, port.go, securitygroup.go, and
//     postgres_networking.go, backed by migration 000022's schema. This
//     is genuinely new orchestration state (ADR-035 §1: "inventing one is
//     unavoidable, not a shim"), unlike the easy half above.
//
// Routers, floating IPs, and DHCP/metadata policy remain out of scope for
// both slices (ADR-035's own "Out of scope" section) -- nothing in this
// package creates any of those three concepts.
//
// The easy half's handlers stay read-only, because everything they
// surface is a live reflection of state some other, already-accepted
// mechanism owns:
//   - a workload's committed bandwidth reservation
//     (workloads.reserved_ingress_mbps/reserved_egress_mbps, migration
//     000010) -- internal/workloadapi.PostgresRepository.AssignLease is
//     the sole writer, gated by its own real, atomic, Serializable-
//     transaction capacity check against ProviderCapacity;
//   - a provider's self-declared availability zone
//     (ResourceCapability.Zone, ADR-026) -- re-sent every heartbeat,
//     read live via agentmanager.Directory.ListSchedulableProviders,
//     never persisted separately by this package;
//   - a workload's self-reported bandwidth usage counters
//     (workload_bandwidth_usage, migration 000015, ADR-025 §2) --
//     internal/providerjoin.PostgresBandwidthUsageStore is the sole
//     writer, populated from the Agent's signed heartbeat payload.
//
// Adding a write path to this package's QoS surface would mean either
// (a) inventing a second, independent bandwidth model with no wire path
// to the Agent's actual tc enforcement (agent-executor's rate_limit.rs
// only reads its ceiling from DeployRequest at deploy time -- there is
// no RPC to change a running workload's reservation afterward), or
// (b) mutating an already-committed workloads row through a code path
// AssignLease's own capacity check never runs against. Both are exactly
// the "do not invent a new bandwidth model" / "do not write a second,
// parallel oversubscription check that could drift from the real one"
// traps this slice was scoped to avoid. See oversubscription_test.go for
// the tests proving this package can only ever report a bandwidth
// figure internal/workloadapi.AssignLease's real capacity check already
// allowed to commit.
package neutron

import (
	"net/http"

	"github.com/openinfra/network/internal/openstackapi/osauth"
)

// Server composes every handler this package registers -- constructed
// once by internal/openstackapi.New, following keystone.Server's shape.
type Server struct {
	users          osauth.TokenAuthenticator
	bandwidth      BandwidthRepository
	usage          UsageRepository
	zones          ZoneLister
	networks       NetworkRepository
	ports          PortRepository
	securityGroups SecurityGroupRepository
	workloads      WorkloadLookup
}

// New builds a neutron Server. users authenticates every route via
// osauth.RequireToken, matching every other internal/openstackapi/*
// package. networks/ports/securityGroups back ADR-035's hard half
// (network.go/port.go/securitygroup.go) -- internal/openstackapi.New
// passes NewPostgresNetworkRepository/NewPostgresPortRepository/
// NewPostgresSecurityGroupRepository, the same pool every other
// PostgresRepository in this package family shares. workloads is the
// same *workloadapi.PostgresRepository instance
// internal/openstackapi.New already threads into cinder.New as its own
// WorkloadLookup -- updatePort's BindPort path uses it to verify a
// device_id's target workload belongs to the caller's own project (see
// port.go's WorkloadLookup doc comment for why: PR #195 Finding 1).
func New(users osauth.TokenAuthenticator, bandwidth BandwidthRepository, usage UsageRepository, zones ZoneLister, networks NetworkRepository, ports PortRepository, securityGroups SecurityGroupRepository, workloads WorkloadLookup) *Server {
	return &Server{users: users, bandwidth: bandwidth, usage: usage, zones: zones, networks: networks, ports: ports, securityGroups: securityGroups, workloads: workloads}
}

// Register adds this package's routes to mux, matching
// keystone.Server.Register's shape -- called once from
// internal/openstackapi.Server.Handler().
func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /v2.0/qos/policies", osauth.RequireToken(s.users, s.listPolicies))
	mux.HandleFunc("GET /v2.0/qos/policies/{policy_id}", osauth.RequireToken(s.users, s.showPolicy))
	mux.HandleFunc("GET /v2.0/qos/policies/{policy_id}/bandwidth_limit_rules", osauth.RequireToken(s.users, s.listBandwidthLimitRules))
	mux.HandleFunc("GET /v2.0/qos/policies/{policy_id}/bandwidth_limit_rules/{rule_id}", osauth.RequireToken(s.users, s.showBandwidthLimitRule))
	mux.HandleFunc("GET /v2.0/availability_zones", osauth.RequireToken(s.users, s.listAvailabilityZones))
	mux.HandleFunc("GET /v2.0/metering/bandwidth_usage", osauth.RequireToken(s.users, s.listBandwidthUsage))
	mux.HandleFunc("GET /v2.0/metering/bandwidth_usage/{workload_id}", osauth.RequireToken(s.users, s.showBandwidthUsage))

	// ADR-035's hard half: networks, subnets, ports, security groups.
	mux.HandleFunc("POST /v2.0/networks", osauth.RequireToken(s.users, s.createNetwork))
	mux.HandleFunc("GET /v2.0/networks", osauth.RequireToken(s.users, s.listNetworks))
	mux.HandleFunc("GET /v2.0/networks/{network_id}", osauth.RequireToken(s.users, s.showNetwork))
	mux.HandleFunc("DELETE /v2.0/networks/{network_id}", osauth.RequireToken(s.users, s.deleteNetwork))

	mux.HandleFunc("POST /v2.0/subnets", osauth.RequireToken(s.users, s.createSubnet))
	mux.HandleFunc("GET /v2.0/subnets", osauth.RequireToken(s.users, s.listSubnets))
	mux.HandleFunc("GET /v2.0/subnets/{subnet_id}", osauth.RequireToken(s.users, s.showSubnet))
	mux.HandleFunc("DELETE /v2.0/subnets/{subnet_id}", osauth.RequireToken(s.users, s.deleteSubnet))

	mux.HandleFunc("POST /v2.0/ports", osauth.RequireToken(s.users, s.createPort))
	mux.HandleFunc("GET /v2.0/ports", osauth.RequireToken(s.users, s.listPorts))
	mux.HandleFunc("GET /v2.0/ports/{port_id}", osauth.RequireToken(s.users, s.showPort))
	mux.HandleFunc("PUT /v2.0/ports/{port_id}", osauth.RequireToken(s.users, s.updatePort))
	mux.HandleFunc("DELETE /v2.0/ports/{port_id}", osauth.RequireToken(s.users, s.deletePort))

	mux.HandleFunc("POST /v2.0/security-groups", osauth.RequireToken(s.users, s.createSecurityGroup))
	mux.HandleFunc("GET /v2.0/security-groups", osauth.RequireToken(s.users, s.listSecurityGroups))
	mux.HandleFunc("GET /v2.0/security-groups/{security_group_id}", osauth.RequireToken(s.users, s.showSecurityGroup))
	mux.HandleFunc("DELETE /v2.0/security-groups/{security_group_id}", osauth.RequireToken(s.users, s.deleteSecurityGroup))

	mux.HandleFunc("POST /v2.0/security-group-rules", osauth.RequireToken(s.users, s.createSecurityGroupRule))
	mux.HandleFunc("GET /v2.0/security-group-rules", osauth.RequireToken(s.users, s.listSecurityGroupRules))
	mux.HandleFunc("GET /v2.0/security-group-rules/{security_group_rule_id}", osauth.RequireToken(s.users, s.showSecurityGroupRule))
	mux.HandleFunc("DELETE /v2.0/security-group-rules/{security_group_rule_id}", osauth.RequireToken(s.users, s.deleteSecurityGroupRule))
}

// requireProjectID reads the project-scoped identity osauth.RequireToken
// already attached to the request context, failing closed (Keystone-
// shaped 403) for an unscoped token -- every resource this package
// serves other than availability_zones (infrastructure-wide, not
// tenant-owned) is scoped by project_id, the same
// ownership-check-via-the-query pattern ADR-016 established and ADR-031
// §3 reuses: the project_id this returns is passed straight into the
// repository query itself, never compared after an unscoped fetch.
func requireProjectID(w http.ResponseWriter, r *http.Request) (string, bool) {
	identity, ok := osauth.FromContext(r.Context())
	if !ok || identity.ProjectID == nil || *identity.ProjectID == "" {
		osauth.WriteError(w, http.StatusForbidden, "Forbidden", "a project-scoped token is required for this resource")
		return "", false
	}
	return *identity.ProjectID, true
}
