package neutron

import (
	"context"
	"net/http"
	"sort"
	"time"

	"github.com/openinfra/network/internal/agentmanager"
	"github.com/openinfra/network/internal/openstackapi/osauth"
)

// ZoneLister is the read surface availability_zone.go needs --
// agentmanager.Directory already satisfies this exactly, so no adapter
// is needed at the call site (internal/openstackapi.New). Deliberately
// the same live-heartbeat source scheduler.Candidate.Zone and
// orchestrator.rankableCandidates already read (ADR-026 §1: zone is
// re-declared every heartbeat, sourced from Redis, never the
// write-once-at-join Postgres copy) -- this handler adds no second,
// independently-maintained notion of "what zones exist."
type ZoneLister interface {
	ListSchedulableProviders(ctx context.Context) ([]agentmanager.SchedulableProvider, error)
}

// listAvailabilityZones is GET /v2.0/availability_zones: real Neutron's
// availability-zone extension, listing the zones its DHCP/L3 agents are
// scheduled into, each tagged with the resource type ("network" or
// "router") it applies to. Nothing in this codebase has DHCP/L3 agents
// (out of scope, ADR-035) -- this maps the extension's wire shape onto
// ADR-026's actual placement-constraint zones instead (the closest real
// concept this system has: "where can a resource be scheduled"), always
// reporting resource: "network" since that is the Neutron AZ extension's
// own default/most common resource type and this system has no router
// concept to report a second one for. Every zone returned is one at
// least one currently ACTIVE, heartbeat-fresh provider has actually
// self-declared (ADR-026 §1) -- never an invented or historical zone
// name.
func (s *Server) listAvailabilityZones(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	providers, err := s.zones.ListSchedulableProviders(ctx)
	if err != nil {
		osauth.WriteError(w, http.StatusServiceUnavailable, "Service Unavailable", "availability zone listing unavailable")
		return
	}
	seen := make(map[string]bool, len(providers))
	var zones []string
	for _, provider := range providers {
		if provider.Capabilities == nil {
			continue
		}
		zone := provider.Capabilities.Zone
		if zone == "" || seen[zone] {
			continue
		}
		seen[zone] = true
		zones = append(zones, zone)
	}
	// Deterministic ordering, matching the exact reasoning
	// orchestrator.noEligibleProviderError's zones-present list already
	// applies: provider-iteration order has no relationship to zone
	// name, so ordering must not depend on it.
	sort.Strings(zones)
	body := availabilityZonesBody{AvailabilityZones: make([]availabilityZoneBody, 0, len(zones))}
	for _, zone := range zones {
		body.AvailabilityZones = append(body.AvailabilityZones, availabilityZoneBody{
			Name:     zone,
			State:    "available",
			Resource: "network",
		})
	}
	writeJSON(w, http.StatusOK, body)
}
