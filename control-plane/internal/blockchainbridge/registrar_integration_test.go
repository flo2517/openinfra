package blockchainbridge

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestRegistrarAgainstLocalNode(t *testing.T) {
	endpoint := os.Getenv("OPENINFRA_TEST_SUBSTRATE_RPC_URL")
	keyFile := os.Getenv("OPENINFRA_TEST_SUBSTRATE_SIGNER_KEY_FILE")
	if endpoint == "" || keyFile == "" {
		t.Skip("local Substrate integration environment is not configured")
	}
	rpc, err := NewRPCClient(endpoint, &http.Client{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("configure RPC: %v", err)
	}
	registrar, err := NewRegistrarFromPKCS8File(rpc, keyFile)
	if err != nil {
		t.Fatalf("configure registrar: %v", err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate provider: %v", err)
	}
	var provider [ed25519.PublicKeySize]byte
	copy(provider[:], publicKey)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, _, _, err = registrar.EnsureActive(ctx, provider)
	if err != nil {
		t.Fatalf("activate provider: %v", err)
	}
	leaseID := uint64(time.Now().UnixNano())
	resourceHash := [32]byte{9, 8, 7}
	lease, err := registrar.EnsureLeaseActive(ctx, leaseID, provider, resourceHash, 100)
	if err != nil {
		t.Fatalf("activate lease: %v", err)
	}
	if lease.State != leaseStateActive || lease.LeaseID != leaseID {
		t.Fatalf("unexpected lease: %+v", lease)
	}
	completed, err := registrar.EnsureLeaseCompleted(ctx, leaseID)
	if err != nil {
		t.Fatalf("complete lease: %v", err)
	}
	if completed.State != leaseStateCompleted || completed.LeaseID != leaseID {
		t.Fatalf("unexpected completed lease: %+v", completed)
	}
	idempotent, err := registrar.EnsureLeaseCompleted(ctx, leaseID)
	if err != nil {
		t.Fatalf("repeat completed lease: %v", err)
	}
	if idempotent.State != leaseStateCompleted || idempotent.LeaseID != leaseID {
		t.Fatalf("unexpected repeated completion result: %+v", idempotent)
	}
}
