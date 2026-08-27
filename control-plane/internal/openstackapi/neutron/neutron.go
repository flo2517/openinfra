// Package neutron implements the "easy half" of issue #25's
// Neutron-compatible networking surface, as ADR-031 §5/§8 scoped it: the
// QoS/bandwidth and availability-zone pieces are a genuine compatibility
// *shim* over already-shipped mechanism (ADR-025's tc-enforced bandwidth
// reservation, ADR-026's availability-zone placement constraint), not
// new orchestration state -- ADR-031 §8's sequencing table marks this
// slice "Yes, directly," unlike networks/subnets/ports/security-groups.
//
// This package deliberately does NOT implement networks, subnets, ports,
// routers, security groups, floating IPs, IPAM, or DHCP/metadata policy.
// That half of Neutron is docs/adr/035-neutron-networks-subnets-security-
// groups.md, which is still Status: Proposed -- not accepted, not this
// package's to build (tracked separately by issue #170). Nothing here
// creates a network-topology primitive of any kind.
//
// Every handler in this package is read-only. Real Neutron's
// qos-policies and availability_zones extensions both support
// create/update; this build exposes list/show only, because everything
// surfaced here is a live reflection of state some other,
// already-accepted mechanism owns:
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
	users     osauth.TokenAuthenticator
	bandwidth BandwidthRepository
	usage     UsageRepository
	zones     ZoneLister
}

// New builds a neutron Server. users authenticates every route via
// osauth.RequireToken, matching every other internal/openstackapi/*
// package.
func New(users osauth.TokenAuthenticator, bandwidth BandwidthRepository, usage UsageRepository, zones ZoneLister) *Server {
	return &Server{users: users, bandwidth: bandwidth, usage: usage, zones: zones}
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
