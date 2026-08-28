// ADR-035 §1/§2/§4: networks and subnets, the two new grouping/IPAM
// concepts this ADR invents -- neither maps 1:1 onto anything that
// existed in this codebase before ADR-035 was accepted (see that ADR's
// §1, "A Neutron 'network' does not map 1:1 onto anything that exists
// today"). This file owns their Repository interface, HTTP handlers, and
// request/response validation; postgres_networking.go owns the actual
// Postgres-backed implementation.
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

// maxRequestBodyBytes mirrors internal/openstackapi/cinder's identical
// ceiling -- every request this file handles is a handful of short
// fields, never legitimately larger than a few KB.
const maxNetworkingRequestBodyBytes = 16 << 10

// legacyOverlayRange is ADR-010's existing, permanently-reserved
// `10.254.0.0/16` address space (control-plane/internal/wireguard's own
// `overlayAddress`) -- ADR-035 §2's collision-avoidance check rejects any
// subnet CIDR overlapping it. Migration 000022's own CHECK constraint is
// the actual backstop; this is the same check surfaced as a clear 4xx
// instead of a raw constraint-violation 503.
var legacyOverlayRange = mustParseCIDR("10.254.0.0/16")

func mustParseCIDR(s string) *net.IPNet {
	_, network, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return network
}

// minSubnetPrefixLength/maxSubnetPrefixLength bound every subnet's size:
// no more than a /16 (65536 addresses -- IPAM allocation, port.go's
// CreatePort, scans this range for the lowest free address, so an
// unbounded subnet would make that scan unbounded too) and no smaller
// than a /29 (at least a handful of usable host addresses once the
// network/broadcast/optional-gateway addresses are excluded -- ADR-035
// itself does not set either bound; this is the smallest reasonable
// choice consistent with keeping IPAM allocation a bounded operation,
// flagged in the implementing PR's own description as a judgment call the
// ADR did not make).
const (
	minSubnetPrefixLength = 16
	maxSubnetPrefixLength = 29
)

var (
	ErrNetworkNotFound = errors.New("network not found")
	ErrSubnetNotFound  = errors.New("subnet not found")
	// ErrNetworkHasSubnets is DeleteNetwork's failure when live subnets
	// still reference it -- real Neutron's own "subnets must be deleted
	// first" behavior.
	ErrNetworkHasSubnets = errors.New("network still has subnets")
	// ErrSubnetHasPorts is DeleteSubnet's failure when live ports still
	// reference it.
	ErrSubnetHasPorts = errors.New("subnet still has ports")
	// ErrSubnetOverlapsReservedRange is CreateSubnet's failure when the
	// requested CIDR overlaps ADR-010's legacy 10.254.0.0/16 range.
	ErrSubnetOverlapsReservedRange = errors.New("subnet CIDR overlaps the reserved legacy overlay range 10.254.0.0/16")
	// ErrSubnetCIDRInUse is CreateSubnet's failure when the requested
	// CIDR is already claimed by a live subnet in any project -- ADR-035
	// §2's deliberately conservative "globally unique, not just
	// per-tenant-unique" first-slice constraint.
	ErrSubnetCIDRInUse = errors.New("subnet CIDR is already in use")
	// ErrInvalidCIDR is CreateSubnet's failure for a CIDR outside
	// [minSubnetPrefixLength, maxSubnetPrefixLength] or otherwise
	// unparseable.
	ErrInvalidCIDR = errors.New("invalid subnet CIDR")
)

// Network is one durable neutron_networks row.
type Network struct {
	NetworkID string
	ProjectID string
	Name      string
	Shared    bool
	CreatedAt time.Time
}

// Subnet is one durable neutron_subnets row. GatewayIP is nil when unset.
type Subnet struct {
	SubnetID  string
	NetworkID string
	ProjectID string
	CIDR      string
	GatewayIP *string
	CreatedAt time.Time
}

// NetworkRepository is the persistence surface network.go needs. Every
// project-scoped method filters by projectID as part of the query itself
// (ADR-035 §4's ownership-via-query pattern) -- GetNetwork/ListNetworks
// are the one deliberate exception: a `shared` network (ADR-035 §1) is
// visible to every project, read-only, matching real Neutron's own
// visibility rule.
type NetworkRepository interface {
	CreateNetwork(ctx context.Context, network Network) (Network, error)
	// GetNetwork returns ErrNetworkNotFound unless networkID names a live
	// row that is either owned by projectID or shared.
	GetNetwork(ctx context.Context, networkID, projectID string) (Network, error)
	// ListNetworks returns every live network owned by projectID plus
	// every live shared network from any project.
	ListNetworks(ctx context.Context, projectID string) ([]Network, error)
	// DeleteNetwork returns ErrNetworkNotFound unless networkID names a
	// live row owned by projectID (a shared network may only be deleted
	// by its own project, never by a project it was merely shared with --
	// ADR-035 §4's "read-attach, not co-write"). Returns
	// ErrNetworkHasSubnets if any live subnet still references it.
	DeleteNetwork(ctx context.Context, networkID, projectID string) error

	// CreateSubnet inserts a new subnet. Callers must have already
	// confirmed network ownership (only a network's own project may add a
	// subnet to it, even a shared one -- see createSubnet's own
	// validation) before calling this. Returns
	// ErrSubnetOverlapsReservedRange or ErrSubnetCIDRInUse for the two
	// collision cases ADR-035 §2 names.
	CreateSubnet(ctx context.Context, subnet Subnet) (Subnet, error)
	// GetSubnet returns ErrSubnetNotFound unless subnetID names a live row
	// owned by projectID.
	GetSubnet(ctx context.Context, subnetID, projectID string) (Subnet, error)
	// ListSubnets returns every live subnet on networkID owned by
	// projectID.
	ListSubnets(ctx context.Context, networkID, projectID string) ([]Subnet, error)
	// DeleteSubnet returns ErrSubnetNotFound unless subnetID names a live
	// row owned by projectID, ErrSubnetHasPorts if any live port still
	// references it.
	DeleteSubnet(ctx context.Context, subnetID, projectID string) error
}

func (s *Server) createNetwork(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	identity, ok := requireProjectID(w, r)
	if !ok {
		return
	}
	var body struct {
		Network struct {
			Name   string `json:"name"`
			Shared bool   `json:"shared"`
		} `json:"network"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxNetworkingRequestBodyBytes)).Decode(&body); err != nil {
		osauth.WriteError(w, http.StatusBadRequest, "Bad Request", "invalid request body")
		return
	}
	name := strings.TrimSpace(body.Network.Name)
	if name == "" || len(name) > 255 {
		osauth.WriteError(w, http.StatusBadRequest, "Bad Request", "network.name must be between 1 and 255 characters")
		return
	}
	network, err := s.networks.CreateNetwork(ctx, Network{NetworkID: uuid.NewString(), ProjectID: identity, Name: name, Shared: body.Network.Shared})
	if err != nil {
		slog.Error("neutron: network creation failed", "error", err)
		osauth.WriteError(w, http.StatusServiceUnavailable, "Service Unavailable", "network creation unavailable")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"network": networkBody(network)})
}

func (s *Server) listNetworks(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	identity, ok := requireProjectID(w, r)
	if !ok {
		return
	}
	networks, err := s.networks.ListNetworks(ctx, identity)
	if err != nil {
		slog.Error("neutron: network listing failed", "error", err)
		osauth.WriteError(w, http.StatusServiceUnavailable, "Service Unavailable", "network listing unavailable")
		return
	}
	bodies := make([]networkResponseBody, 0, len(networks))
	for _, network := range networks {
		bodies = append(bodies, networkBody(network))
	}
	writeJSON(w, http.StatusOK, map[string]any{"networks": bodies})
}

func (s *Server) showNetwork(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	identity, ok := requireProjectID(w, r)
	if !ok {
		return
	}
	network, err := s.networks.GetNetwork(ctx, r.PathValue("network_id"), identity)
	if errors.Is(err, ErrNetworkNotFound) {
		osauth.WriteError(w, http.StatusNotFound, "Not Found", "network not found")
		return
	}
	if err != nil {
		slog.Error("neutron: network lookup failed", "error", err)
		osauth.WriteError(w, http.StatusServiceUnavailable, "Service Unavailable", "network lookup unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"network": networkBody(network)})
}

func (s *Server) deleteNetwork(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	identity, ok := requireProjectID(w, r)
	if !ok {
		return
	}
	err := s.networks.DeleteNetwork(ctx, r.PathValue("network_id"), identity)
	switch {
	case errors.Is(err, ErrNetworkNotFound):
		osauth.WriteError(w, http.StatusNotFound, "Not Found", "network not found")
	case errors.Is(err, ErrNetworkHasSubnets):
		osauth.WriteError(w, http.StatusConflict, "Conflict", "network still has subnets; delete them first")
	case err != nil:
		slog.Error("neutron: network delete failed", "error", err)
		osauth.WriteError(w, http.StatusServiceUnavailable, "Service Unavailable", "network deletion unavailable")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) createSubnet(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	identity, ok := requireProjectID(w, r)
	if !ok {
		return
	}
	var body struct {
		Subnet struct {
			NetworkID string  `json:"network_id"`
			CIDR      string  `json:"cidr"`
			GatewayIP *string `json:"gateway_ip"`
		} `json:"subnet"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxNetworkingRequestBodyBytes)).Decode(&body); err != nil {
		osauth.WriteError(w, http.StatusBadRequest, "Bad Request", "invalid request body")
		return
	}
	// ADR-035 §4: only a network's own project may add a subnet to it,
	// even a shared one ("read-attach, not co-write") -- GetNetwork alone
	// (which also permits a shared network read by a foreign project)
	// is not enough here; the extra ProjectID comparison below is what
	// actually enforces the write restriction.
	network, err := s.networks.GetNetwork(ctx, body.Subnet.NetworkID, identity)
	if errors.Is(err, ErrNetworkNotFound) {
		osauth.WriteError(w, http.StatusBadRequest, "Bad Request", "subnet.network_id does not name a network visible to this project")
		return
	}
	if err != nil {
		slog.Error("neutron: network lookup for subnet create failed", "error", err)
		osauth.WriteError(w, http.StatusServiceUnavailable, "Service Unavailable", "subnet creation unavailable")
		return
	}
	if network.ProjectID != identity {
		osauth.WriteError(w, http.StatusForbidden, "Forbidden", "only a network's own project may add a subnet to it")
		return
	}
	cidr, gatewayIP, err := validateSubnetCIDR(body.Subnet.CIDR, body.Subnet.GatewayIP)
	if err != nil {
		osauth.WriteError(w, http.StatusBadRequest, "Bad Request", err.Error())
		return
	}
	subnet, err := s.networks.CreateSubnet(ctx, Subnet{SubnetID: uuid.NewString(), NetworkID: network.NetworkID, ProjectID: identity, CIDR: cidr, GatewayIP: gatewayIP})
	switch {
	case errors.Is(err, ErrSubnetOverlapsReservedRange):
		osauth.WriteError(w, http.StatusBadRequest, "Bad Request", ErrSubnetOverlapsReservedRange.Error())
	case errors.Is(err, ErrSubnetCIDRInUse):
		osauth.WriteError(w, http.StatusConflict, "Conflict", ErrSubnetCIDRInUse.Error())
	case err != nil:
		slog.Error("neutron: subnet creation failed", "error", err)
		osauth.WriteError(w, http.StatusServiceUnavailable, "Service Unavailable", "subnet creation unavailable")
	default:
		writeJSON(w, http.StatusCreated, map[string]any{"subnet": subnetBody(subnet)})
	}
}

// validateSubnetCIDR parses and bounds-checks cidr (§2's collision check
// against the legacy overlay range, plus this file's own
// min/maxSubnetPrefixLength bound) and, if gatewayIP is set, confirms it
// falls inside the parsed network.
func validateSubnetCIDR(cidr string, gatewayIP *string) (normalizedCIDR string, normalizedGateway *string, err error) {
	ip, network, parseErr := net.ParseCIDR(cidr)
	if parseErr != nil || network.IP.String() != ip.String() {
		// The second check rejects a host address masquerading as a
		// network CIDR (e.g. "10.0.0.5/24" instead of "10.0.0.0/24") --
		// real Neutron itself rejects this the same way, and silently
		// normalizing it would surprise a caller who supplied a specific
		// host bit pattern for a reason.
		return "", nil, ErrInvalidCIDR
	}
	if network.IP.To4() == nil {
		return "", nil, errors.New("subnet.cidr must be IPv4 (ADR-035 §Out-of-scope: IPv6 is not supported in this slice)")
	}
	prefixLength, _ := network.Mask.Size()
	if prefixLength < minSubnetPrefixLength || prefixLength > maxSubnetPrefixLength {
		return "", nil, ErrInvalidCIDR
	}
	if network.Contains(legacyOverlayRange.IP) || legacyOverlayRange.Contains(network.IP) {
		return "", nil, ErrSubnetOverlapsReservedRange
	}
	if gatewayIP == nil || *gatewayIP == "" {
		return network.String(), nil, nil
	}
	parsedGateway := net.ParseIP(*gatewayIP)
	if parsedGateway == nil || !network.Contains(parsedGateway) {
		return "", nil, errors.New("subnet.gateway_ip must be a valid address inside subnet.cidr")
	}
	normalized := parsedGateway.String()
	return network.String(), &normalized, nil
}

func (s *Server) listSubnets(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	identity, ok := requireProjectID(w, r)
	if !ok {
		return
	}
	networkID := r.URL.Query().Get("network_id")
	subnets, err := s.networks.ListSubnets(ctx, networkID, identity)
	if err != nil {
		slog.Error("neutron: subnet listing failed", "error", err)
		osauth.WriteError(w, http.StatusServiceUnavailable, "Service Unavailable", "subnet listing unavailable")
		return
	}
	bodies := make([]subnetResponseBody, 0, len(subnets))
	for _, subnet := range subnets {
		bodies = append(bodies, subnetBody(subnet))
	}
	writeJSON(w, http.StatusOK, map[string]any{"subnets": bodies})
}

func (s *Server) showSubnet(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	identity, ok := requireProjectID(w, r)
	if !ok {
		return
	}
	subnet, err := s.networks.GetSubnet(ctx, r.PathValue("subnet_id"), identity)
	if errors.Is(err, ErrSubnetNotFound) {
		osauth.WriteError(w, http.StatusNotFound, "Not Found", "subnet not found")
		return
	}
	if err != nil {
		slog.Error("neutron: subnet lookup failed", "error", err)
		osauth.WriteError(w, http.StatusServiceUnavailable, "Service Unavailable", "subnet lookup unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"subnet": subnetBody(subnet)})
}

func (s *Server) deleteSubnet(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	identity, ok := requireProjectID(w, r)
	if !ok {
		return
	}
	err := s.networks.DeleteSubnet(ctx, r.PathValue("subnet_id"), identity)
	switch {
	case errors.Is(err, ErrSubnetNotFound):
		osauth.WriteError(w, http.StatusNotFound, "Not Found", "subnet not found")
	case errors.Is(err, ErrSubnetHasPorts):
		osauth.WriteError(w, http.StatusConflict, "Conflict", "subnet still has ports; delete them first")
	case err != nil:
		slog.Error("neutron: subnet delete failed", "error", err)
		osauth.WriteError(w, http.StatusServiceUnavailable, "Service Unavailable", "subnet deletion unavailable")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}
