package wireguard

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

type fakeBackend struct {
	configured, attached, detached, revoked []PeerConfig
	failAttach                              bool
}

func (f *fakeBackend) Configure(_ context.Context, p PeerConfig) error {
	f.configured = append(f.configured, p)
	return nil
}
func (f *fakeBackend) AttachNamespace(_ context.Context, p PeerConfig) error {
	if f.failAttach {
		return errors.New("namespace unavailable")
	}
	f.attached = append(f.attached, p)
	return nil
}
func (f *fakeBackend) DetachNamespace(_ context.Context, p PeerConfig) error {
	f.detached = append(f.detached, p)
	return nil
}
func (f *fakeBackend) Revoke(_ context.Context, p PeerConfig) error {
	f.revoked = append(f.revoked, p)
	return nil
}

func manager(t *testing.T, backend *fakeBackend) *Manager {
	t.Helper()
	m, err := NewManager(backend, 51820, 51821)
	if err != nil {
		t.Fatal(err)
	}
	m.now = func() time.Time { return time.Unix(100, 0) }
	return m
}
func request() Request {
	return Request{WorkloadID: "workload-1", LeaseID: "42", ContainerID: "container-1", ExpiresAt: time.Unix(200, 0), AllowedIPs: []string{"10.254.0.1/32"}}
}

func TestAllocateRequiresLiveLeaseAndNeverExposesPrivateKey(t *testing.T) {
	b := &fakeBackend{}
	m := manager(t, b)
	if _, err := m.Allocate(context.Background(), Request{WorkloadID: "w", LeaseID: "l", ContainerID: "c", ExpiresAt: time.Unix(99, 0)}); !errors.Is(err, ErrLeaseExpired) {
		t.Fatalf("expected expired lease, got %v", err)
	}
	a, err := m.Allocate(context.Background(), request())
	if err != nil {
		t.Fatal(err)
	}
	if a.PublicKey == "" || a.Port != 51820 || a.WorkloadID != "workload-1" {
		t.Fatalf("invalid allocation: %+v", a)
	}
	if len(b.configured[0].PrivateKey) != 32 {
		t.Fatal("backend did not receive a key")
	}
	if string(b.configured[0].PrivateKey) == a.PublicKey {
		t.Fatal("private key leaked into public allocation")
	}
}

func TestPortConflictAndIdempotence(t *testing.T) {
	b := &fakeBackend{}
	m := manager(t, b)
	first, err := m.Allocate(context.Background(), request())
	if err != nil {
		t.Fatal(err)
	}
	secondRequest := request()
	secondRequest.WorkloadID = "workload-2"
	secondRequest.LeaseID = "43"
	secondRequest.ContainerID = "container-2"
	second, err := m.Allocate(context.Background(), secondRequest)
	if err != nil {
		t.Fatal(err)
	}
	if first.Port == second.Port {
		t.Fatal("allocated conflicting WireGuard ports")
	}
	thirdRequest := request()
	third, err := m.Allocate(context.Background(), thirdRequest)
	if err != nil {
		t.Fatal(err)
	}
	if third.PublicKey != first.PublicKey || len(b.configured) != 2 {
		t.Fatal("same lease must be idempotent")
	}
	thirdRequest.WorkloadID = "workload-3"
	thirdRequest.LeaseID = "44"
	thirdRequest.ContainerID = "container-3"
	if _, err := m.Allocate(context.Background(), thirdRequest); !errors.Is(err, ErrPortExhausted) {
		t.Fatalf("expected exhausted range, got %v", err)
	}
}

func TestAttachFailureRollsBackAndRotateRevokesOldPeer(t *testing.T) {
	b := &fakeBackend{failAttach: true}
	m := manager(t, b)
	if _, err := m.Allocate(context.Background(), request()); err == nil {
		t.Fatal("expected namespace attach failure")
	}
	if len(b.revoked) != 1 {
		t.Fatalf("failed attach must revoke configured peer, got %d", len(b.revoked))
	}
	b.failAttach = false
	a, err := m.Allocate(context.Background(), request())
	if err != nil {
		t.Fatal(err)
	}
	rotated := request()
	rotated.ExpiresAt = time.Unix(300, 0)
	before := len(b.revoked)
	beforeKey := a.PublicKey
	next, err := m.Rotate(context.Background(), rotated)
	if err != nil {
		t.Fatal(err)
	}
	if next.PublicKey == beforeKey || len(b.revoked) != before+1 {
		t.Fatal("rotation did not revoke and replace peer")
	}
}

func TestRevokeIsIdempotentAndDetachesNamespace(t *testing.T) {
	b := &fakeBackend{}
	m := manager(t, b)
	if _, err := m.Allocate(context.Background(), request()); err != nil {
		t.Fatal(err)
	}
	if err := m.Revoke(context.Background(), "workload-1"); err != nil {
		t.Fatal(err)
	}
	if len(b.detached) != 1 || len(b.revoked) != 1 {
		t.Fatalf("unexpected teardown: detached=%d revoked=%d", len(b.detached), len(b.revoked))
	}
	if err := m.Revoke(context.Background(), "workload-1"); err != nil {
		t.Fatal(err)
	}
	if len(b.detached) != 1 || len(b.revoked) != 1 {
		t.Fatal("revoke must be idempotent")
	}
}

func TestCommandBackendKeepsPrivateKeyOutOfArgumentsAndLogs(t *testing.T) {
	var args []string
	var captured []byte
	b := &CommandBackend{Interface: "wg0", Runner: func(_ context.Context, _ string, commandArgs ...string) ([]byte, error) {
		args = append([]string(nil), commandArgs...)
		for i, value := range commandArgs {
			if value == "private-key" && i+1 < len(commandArgs) {
				data, err := os.ReadFile(commandArgs[i+1])
				if err != nil {
					return nil, err
				}
				captured = data
			}
		}
		return []byte("ignored command output"), nil
	}}
	private := []byte("01234567890123456789012345678901")
	config := PeerConfig{Allocation: Allocation{PublicKey: "public", Port: 51820}, PrivateKey: private, AllowedIPs: []string{"10.254.0.1/32"}}
	if err := b.Configure(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	for _, arg := range args {
		if string(private) == arg {
			t.Fatal("private key passed as command argument")
		}
	}
	if string(captured) != string(private) {
		t.Fatal("backend did not receive the private key through the protected file")
	}
}
