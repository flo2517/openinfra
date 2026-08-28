// ADR-035 §1/§2: ports -- the one piece of this resource model that maps
// closely onto existing mechanism (ADR-010's per-workload WireGuard peer
// allocation), promoted here from implicit to an explicit, precreated
// resource. Creating a port reserves a `fixed_ip` from its subnet's IPAM
// pool and is pure Control-Plane bookkeeping: no WireGuard peer exists
// yet, no privileged backend call is made (ADR-035 §1). A port is bound to
// a workload via PUT (real Neutron's own `device_id` field), matching this
// file's own bindPort/unbindPort helpers -- the actual peer allocation and
// its AllowedIPs/security-group wiring only happen later, when
// internal/orchestrator dispatches that workload's Deploy (see
// PortForWorkload's doc comment for that read path).
package neutron

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/openinfra/network/internal/openstackapi/osauth"
)

var (
	ErrPortNotFound = errors.New("port not found")
	// ErrPortBound is DeletePort's failure when the port is still bound
	// to a workload -- real Neutron's own "detach the device first"
	// behavior.
	ErrPortBound = errors.New("port is still bound to a workload")
	// ErrPortAlreadyBound is BindPort's failure when the port already has
	// a different workload bound (this table's own
	// neutron_ports_workload_idx is the same guard's atomic backstop).
	ErrPortAlreadyBound = errors.New("port is already bound to a workload")
	// ErrWorkloadAlreadyHasPort is BindPort's failure when workloadID is
	// already bound to a different port -- a workload may hold at most
	// one Neutron port at a time (migration 000022's
	// neutron_ports_workload_idx).
	ErrWorkloadAlreadyHasPort = errors.New("workload is already bound to a different port")
	// ErrSubnetPoolExhausted is CreatePort's failure when no address in
	// the subnet's CIDR remains unallocated.
	ErrSubnetPoolExhausted = errors.New("subnet has no available addresses")
)

// Port is one durable neutron_ports row. WorkloadID mirrors real
// Neutron's own `device_id` field (translated at the JSON response
// boundary, see portBody) -- nil until BindPort sets it.
type Port struct {
	PortID     string
	NetworkID  string
	SubnetID   string
	ProjectID  string
	FixedIP    string
	WorkloadID *string
	CreatedAt  time.Time
}

// PortRepository is the persistence surface port.go needs.
type PortRepository interface {
	// CreatePort allocates the lowest available address in subnetID's
	// CIDR (excluding the network/broadcast addresses and, if set, the
	// subnet's gateway_ip) and inserts a new, unbound port row --
	// ADR-035 §2's "sequential, lowest-available-first" policy. Returns
	// ErrSubnetPoolExhausted if no address remains.
	CreatePort(ctx context.Context, port Port) (Port, error)
	// GetPort returns ErrPortNotFound unless portID names a live row
	// owned by projectID.
	GetPort(ctx context.Context, portID, projectID string) (Port, error)
	// ListPorts returns every live port on networkID owned by projectID.
	// networkID may be empty, meaning "every live port owned by
	// projectID regardless of network".
	ListPorts(ctx context.Context, networkID, projectID string) ([]Port, error)
	// DeletePort returns ErrPortNotFound unless portID names a live row
	// owned by projectID, ErrPortBound if it is currently bound to a
	// workload. Releases the port's fixed_ip back to its subnet's pool
	// (structural: the row's own deletion is what frees the address,
	// since IPAM allocation only ever scans currently-live rows).
	DeletePort(ctx context.Context, portID, projectID string) error
	// BindPort atomically sets portID's workload_id, matching real
	// Neutron's own `device_id` port-update field. Returns
	// ErrPortNotFound unless portID names a live row owned by projectID,
	// ErrPortAlreadyBound if it is already bound to a *different*
	// workload (binding to the same workload it is already bound to is
	// idempotent -- returns success unchanged), ErrWorkloadAlreadyHasPort
	// if workloadID already holds a different port.
	BindPort(ctx context.Context, portID, projectID, workloadID string) (Port, error)
	// UnbindPort atomically clears portID's workload_id. Idempotent: an
	// already-unbound port returns success unchanged.
	UnbindPort(ctx context.Context, portID, projectID string) (Port, error)
	// PortForWorkload returns the live port currently bound to
	// workloadID, if any -- called by internal/orchestrator at Deploy
	// dispatch time (no project scoping: the orchestrator is a trusted
	// internal caller operating on a workload_id it already resolved via
	// its own project-scoped workload lookup upstream), never by an HTTP
	// handler in this package directly.
	PortForWorkload(ctx context.Context, workloadID string) (port Port, found bool, err error)
}

func (s *Server) createPort(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	identity, ok := requireProjectID(w, r)
	if !ok {
		return
	}
	var body struct {
		Port struct {
			NetworkID string `json:"network_id"`
			SubnetID  string `json:"subnet_id"`
		} `json:"port"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxNetworkingRequestBodyBytes)).Decode(&body); err != nil {
		osauth.WriteError(w, http.StatusBadRequest, "Bad Request", "invalid request body")
		return
	}
	// A port may be created on a shared network by any project (ADR-035
	// §1/§4) -- GetNetwork's own visibility rule (owned OR shared) is
	// exactly the check needed here, unlike createSubnet's stricter
	// owner-only check.
	network, err := s.networks.GetNetwork(ctx, body.Port.NetworkID, identity)
	if errors.Is(err, ErrNetworkNotFound) {
		osauth.WriteError(w, http.StatusBadRequest, "Bad Request", "port.network_id does not name a network visible to this project")
		return
	}
	if err != nil {
		slog.Error("neutron: network lookup for port create failed", "error", err)
		osauth.WriteError(w, http.StatusServiceUnavailable, "Service Unavailable", "port creation unavailable")
		return
	}
	// The subnet itself is looked up scoped to the *network's own*
	// project (not the caller's) -- a subnet always belongs to whichever
	// project owns the network (createSubnet's own enforcement), so this
	// is the correct scope to resolve it against regardless of who is
	// creating the port.
	subnet, err := s.networks.GetSubnet(ctx, body.Port.SubnetID, network.ProjectID)
	if errors.Is(err, ErrSubnetNotFound) {
		osauth.WriteError(w, http.StatusBadRequest, "Bad Request", "port.subnet_id does not name a subnet of that network")
		return
	}
	if err != nil {
		slog.Error("neutron: subnet lookup for port create failed", "error", err)
		osauth.WriteError(w, http.StatusServiceUnavailable, "Service Unavailable", "port creation unavailable")
		return
	}
	if subnet.NetworkID != network.NetworkID {
		osauth.WriteError(w, http.StatusBadRequest, "Bad Request", "port.subnet_id does not name a subnet of that network")
		return
	}
	port, err := s.ports.CreatePort(ctx, Port{PortID: uuid.NewString(), NetworkID: network.NetworkID, SubnetID: subnet.SubnetID, ProjectID: identity})
	switch {
	case errors.Is(err, ErrSubnetPoolExhausted):
		osauth.WriteError(w, http.StatusConflict, "Conflict", ErrSubnetPoolExhausted.Error())
	case err != nil:
		slog.Error("neutron: port creation failed", "error", err)
		osauth.WriteError(w, http.StatusServiceUnavailable, "Service Unavailable", "port creation unavailable")
	default:
		writeJSON(w, http.StatusCreated, map[string]any{"port": s.portBodyWithGroups(ctx, port)})
	}
}

func (s *Server) listPorts(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	identity, ok := requireProjectID(w, r)
	if !ok {
		return
	}
	networkID := r.URL.Query().Get("network_id")
	ports, err := s.ports.ListPorts(ctx, networkID, identity)
	if err != nil {
		slog.Error("neutron: port listing failed", "error", err)
		osauth.WriteError(w, http.StatusServiceUnavailable, "Service Unavailable", "port listing unavailable")
		return
	}
	bodies := make([]portResponseBody, 0, len(ports))
	for _, port := range ports {
		bodies = append(bodies, s.portBodyWithGroups(ctx, port))
	}
	writeJSON(w, http.StatusOK, map[string]any{"ports": bodies})
}

func (s *Server) showPort(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	identity, ok := requireProjectID(w, r)
	if !ok {
		return
	}
	port, err := s.ports.GetPort(ctx, r.PathValue("port_id"), identity)
	if errors.Is(err, ErrPortNotFound) {
		osauth.WriteError(w, http.StatusNotFound, "Not Found", "port not found")
		return
	}
	if err != nil {
		slog.Error("neutron: port lookup failed", "error", err)
		osauth.WriteError(w, http.StatusServiceUnavailable, "Service Unavailable", "port lookup unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"port": s.portBodyWithGroups(ctx, port)})
}

// updatePort is PUT /v2.0/ports/{port_id}, real Neutron's own
// port-update wire shape: a partial update over two independent fields.
// device_id (a *string so "absent" / "present and empty" / "present and
// set" are distinguishable) binds or unbinds (empty string) the port to a
// workload, matching real Neutron's own unbind-via-empty-device_id
// convention. security_groups (a *[]string for the same absent-vs-empty
// reason) replaces the port's full attached security-group set --
// ADR-035's design has no separate attach/detach sub-resource; a port's
// group membership is simply part of its own updatable state, exactly as
// real Neutron models it.
func (s *Server) updatePort(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	identity, ok := requireProjectID(w, r)
	if !ok {
		return
	}
	portID := r.PathValue("port_id")
	var body struct {
		Port struct {
			DeviceID       *string   `json:"device_id"`
			SecurityGroups *[]string `json:"security_groups"`
		} `json:"port"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, maxNetworkingRequestBodyBytes)).Decode(&body); err != nil {
		osauth.WriteError(w, http.StatusBadRequest, "Bad Request", "invalid request body")
		return
	}
	var port Port
	var err error
	if body.Port.DeviceID != nil {
		if *body.Port.DeviceID == "" {
			port, err = s.ports.UnbindPort(ctx, portID, identity)
		} else {
			if _, parseErr := uuid.Parse(*body.Port.DeviceID); parseErr != nil {
				osauth.WriteError(w, http.StatusBadRequest, "Bad Request", "port.device_id must be a workload UUID")
				return
			}
			port, err = s.ports.BindPort(ctx, portID, identity, *body.Port.DeviceID)
		}
		switch {
		case errors.Is(err, ErrPortNotFound):
			osauth.WriteError(w, http.StatusNotFound, "Not Found", "port not found")
			return
		case errors.Is(err, ErrPortAlreadyBound):
			osauth.WriteError(w, http.StatusConflict, "Conflict", ErrPortAlreadyBound.Error())
			return
		case errors.Is(err, ErrWorkloadAlreadyHasPort):
			osauth.WriteError(w, http.StatusConflict, "Conflict", ErrWorkloadAlreadyHasPort.Error())
			return
		case err != nil:
			slog.Error("neutron: port bind/unbind failed", "error", err)
			osauth.WriteError(w, http.StatusServiceUnavailable, "Service Unavailable", "port update unavailable")
			return
		}
	} else {
		port, err = s.ports.GetPort(ctx, portID, identity)
		if errors.Is(err, ErrPortNotFound) {
			osauth.WriteError(w, http.StatusNotFound, "Not Found", "port not found")
			return
		}
		if err != nil {
			slog.Error("neutron: port lookup for update failed", "error", err)
			osauth.WriteError(w, http.StatusServiceUnavailable, "Service Unavailable", "port update unavailable")
			return
		}
	}
	if body.Port.SecurityGroups != nil {
		// ADR-035 §4/§5: a security group can only be attached to a port
		// within the same project that owns the security group -- both
		// s.ports.GetPort (above) and s.securityGroups.ReplacePortGroups
		// (below) scope by identity, so a cross-project group id in this
		// list resolves to ErrSecurityGroupNotFound (never enumerable,
		// matching this codebase's established no-oracle posture) rather
		// than silently attaching.
		if err := s.securityGroups.ReplacePortGroups(ctx, port.PortID, identity, *body.Port.SecurityGroups); err != nil {
			if errors.Is(err, ErrSecurityGroupNotFound) {
				osauth.WriteError(w, http.StatusBadRequest, "Bad Request", "port.security_groups references a security group not owned by this project")
				return
			}
			slog.Error("neutron: port security-group update failed", "error", err)
			osauth.WriteError(w, http.StatusServiceUnavailable, "Service Unavailable", "port update unavailable")
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"port": s.portBodyWithGroups(ctx, port)})
}

func (s *Server) deletePort(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	identity, ok := requireProjectID(w, r)
	if !ok {
		return
	}
	err := s.ports.DeletePort(ctx, r.PathValue("port_id"), identity)
	switch {
	case errors.Is(err, ErrPortNotFound):
		osauth.WriteError(w, http.StatusNotFound, "Not Found", "port not found")
	case errors.Is(err, ErrPortBound):
		osauth.WriteError(w, http.StatusConflict, "Conflict", "port is still bound to a workload; unbind it first")
	case err != nil:
		slog.Error("neutron: port delete failed", "error", err)
		osauth.WriteError(w, http.StatusServiceUnavailable, "Service Unavailable", "port deletion unavailable")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// allocateFromPool returns the lowest address in network (a parsed
// subnet CIDR) that is not the network address, the broadcast address,
// gatewayIP (if set), or present in taken -- ADR-035 §2's
// "sequential, lowest-available-first" IPAM policy, factored out of
// postgres_networking.go's transactional CreatePort so the scan logic
// itself has no Postgres dependency and can be unit-tested directly
// against plain Go values.
func allocateFromPool(cidr string, gatewayIP *string, taken map[string]struct{}) (string, error) {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", fmt.Errorf("parse subnet cidr: %w", err)
	}
	broadcast := broadcastAddress(network)
	for ip := nextIP(network.IP); network.Contains(ip) && !ip.Equal(broadcast); ip = nextIP(ip) {
		candidate := ip.String()
		if gatewayIP != nil && candidate == *gatewayIP {
			continue
		}
		if _, used := taken[candidate]; used {
			continue
		}
		return candidate, nil
	}
	return "", ErrSubnetPoolExhausted
}

func nextIP(ip net.IP) net.IP {
	next := make(net.IP, len(ip))
	copy(next, ip)
	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] != 0 {
			break
		}
	}
	return next
}

func broadcastAddress(network *net.IPNet) net.IP {
	ip4 := network.IP.To4()
	mask := network.Mask
	broadcast := make(net.IP, len(ip4))
	for i := range ip4 {
		broadcast[i] = ip4[i] | ^mask[i]
	}
	return broadcast
}
