// Package wireguard owns short-lived workload overlay peers.
//
// A peer is created only after the Control Plane has an authoritative active
// lease. Private keys stay in memory and are never included in logs or the
// public Allocation returned to callers.
package wireguard

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
)

var (
	ErrLeaseRequired = errors.New("an active lease is required for overlay allocation")
	ErrLeaseExpired  = errors.New("lease has expired")
	ErrPortExhausted = errors.New("wireguard peer port range is exhausted")
	ErrNotFound      = errors.New("overlay peer not found")
)

// Request is the minimum authoritative context required to attach a peer.
// ExpiresAt must be bounded by the on-chain lease expiry.
type Request struct {
	WorkloadID  string
	LeaseID     string
	ContainerID string
	ExpiresAt   time.Time
	AllowedIPs  []string
}

// Allocation deliberately excludes the private key. The private key is held
// only by the manager/backend for the lifetime of the peer.
type Allocation struct {
	WorkloadID string
	LeaseID    string
	PublicKey  string
	Address    string
	Port       int
	ExpiresAt  time.Time
}

// PeerConfig is passed to a backend. Backends must not log PrivateKey.
type PeerConfig struct {
	Allocation
	PrivateKey  []byte
	AllowedIPs  []string
	ContainerID string
}

// Backend performs privileged WireGuard and namespace operations. Keeping it
// behind an interface makes lifecycle tests deterministic and avoids requiring
// CAP_NET_ADMIN in normal Go unit tests.
type Backend interface {
	Configure(ctx context.Context, peer PeerConfig) error
	AttachNamespace(ctx context.Context, peer PeerConfig) error
	DetachNamespace(ctx context.Context, peer PeerConfig) error
	Revoke(ctx context.Context, peer PeerConfig) error
}

type peerState struct {
	config PeerConfig
}

type Manager struct {
	backend             Backend
	now                 func() time.Time
	mu                  sync.Mutex
	peers               map[string]peerState
	nextPort            int
	firstPort, lastPort int
}

func NewManager(backend Backend, firstPort, lastPort int) (*Manager, error) {
	if backend == nil {
		return nil, errors.New("wireguard backend is required")
	}
	if firstPort < 1 || lastPort > 65535 || firstPort > lastPort {
		return nil, errors.New("invalid wireguard port range")
	}
	return &Manager{backend: backend, now: time.Now, peers: make(map[string]peerState), nextPort: firstPort, firstPort: firstPort, lastPort: lastPort}, nil
}

// Allocate creates and attaches a peer. A failed namespace attach rolls back
// the configured peer, so callers never receive a half-attached allocation.
func (m *Manager) Allocate(ctx context.Context, request Request) (Allocation, error) {
	if request.WorkloadID == "" || request.LeaseID == "" || request.ContainerID == "" || request.ExpiresAt.IsZero() {
		return Allocation{}, ErrLeaseRequired
	}
	if !request.ExpiresAt.After(m.now()) {
		return Allocation{}, ErrLeaseExpired
	}
	m.mu.Lock()
	if existing, ok := m.peers[request.WorkloadID]; ok {
		m.mu.Unlock()
		if existing.config.LeaseID != request.LeaseID {
			return Allocation{}, fmt.Errorf("workload already has a different lease")
		}
		return existing.config.Allocation, nil
	}
	port, err := m.reservePortLocked()
	if err != nil {
		m.mu.Unlock()
		return Allocation{}, err
	}
	privateKey := make([]byte, 32)
	if _, err := rand.Read(privateKey); err != nil {
		m.mu.Unlock()
		return Allocation{}, fmt.Errorf("generate WireGuard key: %w", err)
	}
	publicKeyBytes, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		m.mu.Unlock()
		return Allocation{}, fmt.Errorf("derive WireGuard public key: %w", err)
	}
	allocation := Allocation{WorkloadID: request.WorkloadID, LeaseID: request.LeaseID, PublicKey: base64.RawStdEncoding.EncodeToString(publicKeyBytes), Address: overlayAddress(port), Port: port, ExpiresAt: request.ExpiresAt.UTC()}
	allowedIPs := append([]string(nil), request.AllowedIPs...)
	if len(allowedIPs) == 0 {
		allowedIPs = []string{allocation.Address}
	}
	config := PeerConfig{Allocation: allocation, PrivateKey: privateKey, AllowedIPs: allowedIPs, ContainerID: request.ContainerID}
	// Keep the lock while configuring to prevent two allocations racing on the
	// same deterministic port range. Backend calls are bounded by caller ctx.
	if err := m.backend.Configure(ctx, config); err != nil {
		zero(privateKey)
		m.mu.Unlock()
		return Allocation{}, err
	}
	if err := m.backend.AttachNamespace(ctx, config); err != nil {
		_ = m.backend.Revoke(context.Background(), config)
		zero(privateKey)
		m.mu.Unlock()
		return Allocation{}, fmt.Errorf("attach workload namespace: %w", err)
	}
	m.peers[request.WorkloadID] = peerState{config: config}
	m.mu.Unlock()
	return allocation, nil
}

// Attach adapts Manager to the orchestrator lifecycle. The lease has already
// been finalized by the caller; this method performs the short-lived peer
// allocation and namespace attachment atomically.
func (m *Manager) Attach(ctx context.Context, workloadID, leaseID, containerID string, expiresAt time.Time) error {
	return m.AttachWithAllowedIPs(ctx, workloadID, leaseID, containerID, expiresAt, nil)
}

// AttachWithAllowedIPs is Attach, extended for ADR-035 §1: when
// allowedIPs is non-empty, it is passed straight through to Allocate as
// the peer's WireGuard AllowedIPs, instead of the placeholder-derived
// overlayAddress(0) Attach itself always uses. This is the "small,
// mechanical change to one call site" ADR-035 §1 names -- a Neutron
// port's IPAM-reserved fixed_ip, resolved by
// internal/orchestrator.Worker at Deploy dispatch time
// (internal/openstackapi/neutron.PortSecurityResolver.ResolveForWorkload),
// takes the place of that placeholder for exactly the workloads bound to
// one. A nil/empty allowedIPs preserves today's exact behavior
// (overlayAddress(0)) unchanged -- every workload with no bound Neutron
// port, including every workload that predates ADR-035, is completely
// unaffected, matching that ADR's own backward-compatibility guarantee.
func (m *Manager) AttachWithAllowedIPs(ctx context.Context, workloadID, leaseID, containerID string, expiresAt time.Time, allowedIPs []string) error {
	if len(allowedIPs) == 0 {
		allowedIPs = []string{overlayAddress(0)}
	}
	_, err := m.Allocate(ctx, Request{WorkloadID: workloadID, LeaseID: leaseID, ContainerID: containerID, ExpiresAt: expiresAt, AllowedIPs: allowedIPs})
	return err
}

// Revoke tears down namespace attachment and the WireGuard peer. Repeating a
// revoke is safe; state is removed only after both operations succeed.
func (m *Manager) Revoke(ctx context.Context, workloadID string) error {
	m.mu.Lock()
	state, ok := m.peers[workloadID]
	if !ok {
		m.mu.Unlock()
		return nil
	}
	if err := m.backend.DetachNamespace(ctx, state.config); err != nil {
		m.mu.Unlock()
		return err
	}
	if err := m.backend.Revoke(ctx, state.config); err != nil {
		m.mu.Unlock()
		return err
	}
	zero(state.config.PrivateKey)
	delete(m.peers, workloadID)
	m.mu.Unlock()
	return nil
}

// Rotate revokes the existing peer and allocates a fresh key and port.
func (m *Manager) Rotate(ctx context.Context, request Request) (Allocation, error) {
	if err := m.Revoke(ctx, request.WorkloadID); err != nil {
		return Allocation{}, err
	}
	return m.Allocate(ctx, request)
}

func (m *Manager) reservePortLocked() (int, error) {
	for i := 0; i <= m.lastPort-m.firstPort; i++ {
		port := m.nextPort
		m.nextPort++
		if m.nextPort > m.lastPort {
			m.nextPort = m.firstPort
		}
		used := false
		for _, state := range m.peers {
			if state.config.Port == port {
				used = true
				break
			}
		}
		if !used {
			return port, nil
		}
	}
	return 0, ErrPortExhausted
}

func overlayAddress(port int) string {
	return fmt.Sprintf("10.254.%d.%d/32", (port/250)%250, port%250+1)
}

func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

// CommandBackend is the Linux backend. It intentionally keeps private keys in
// a mode-0600 temporary file instead of command arguments or logs.
type CommandBackend struct {
	Interface string
	Runner    func(context.Context, string, ...string) ([]byte, error)
}

func NewCommandBackend(interfaceName string) *CommandBackend {
	return &CommandBackend{Interface: interfaceName, Runner: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return exec.CommandContext(ctx, name, args...).CombinedOutput()
	}}
}

func (b *CommandBackend) run(ctx context.Context, name string, args ...string) error {
	output, err := b.Runner(ctx, name, args...)
	if err != nil {
		return fmt.Errorf("%s failed: %w", name, err)
	}
	_ = output // command output is deliberately never logged (it may contain sensitive data).
	return nil
}

func (b *CommandBackend) Configure(ctx context.Context, peer PeerConfig) error {
	if b.Interface == "" {
		return errors.New("WireGuard interface is required")
	}
	file, err := os.CreateTemp("", "openinfra-wg-key-")
	if err != nil {
		return err
	}
	path := file.Name()
	defer os.Remove(path)
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(peer.PrivateKey); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return b.run(ctx, "wg", "set", b.Interface, "listen-port", strconv.Itoa(peer.Port), "private-key", path, "peer", peer.PublicKey, "allowed-ips", strings.Join(peer.AllowedIPs, ","))
}

func (b *CommandBackend) AttachNamespace(ctx context.Context, peer PeerConfig) error {
	if peer.ContainerID == "" {
		return errors.New("container ID is required for namespace attachment")
	}
	// The provider-side runtime resolves the container PID and moves/configures
	// the workload interface. This command is intentionally explicit and
	// inspectable; no Docker socket is exposed to workloads.
	return b.run(ctx, "openinfra-wireguard-attach", peer.ContainerID, peer.Address)
}
func (b *CommandBackend) DetachNamespace(ctx context.Context, peer PeerConfig) error {
	return b.run(ctx, "openinfra-wireguard-detach", peer.ContainerID, peer.Address)
}
func (b *CommandBackend) Revoke(ctx context.Context, peer PeerConfig) error {
	return b.run(ctx, "wg", "set", b.Interface, "peer", peer.PublicKey, "remove")
}
