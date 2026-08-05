package blockchainbridge

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	sharedv1 "github.com/openinfra/network/protocol/generated/go/shared/v1"
)

type proofClient struct{ submissions int }

func (c *proofClient) GetReputation(context.Context, string) (*sharedv1.ReputationVector, error) {
	return &sharedv1.ReputationVector{}, nil
}
func (c *proofClient) CreateLeaseOnChain(context.Context, *sharedv1.Lease) (string, error) {
	return "1", nil
}
func (c *proofClient) SubmitExecutionProof(context.Context, ExecutionProof) error {
	c.submissions++
	return nil
}

func validProof() ExecutionProof {
	return ExecutionProof{
		LeaseID: "lease-1", NodeID: "node-1", Metrics: MetricSummary{ActualCPUTime: 1, ActualRAMUsage: 2, RuntimeSeconds: 3, AvailabilityRate: 1},
		Availability: &AvailabilityProof{Sequence: 1, ObservedBlock: 4, SuccessfulSamples: 9, TotalSamples: 10, Signature: []byte{1}},
	}
}

func TestSubmitProofIsIdempotent(t *testing.T) {
	client := &proofClient{}
	bridge := NewBridge(client)
	proof := validProof()
	if err := bridge.SubmitProof(context.Background(), proof); err != nil {
		t.Fatal(err)
	}
	if err := bridge.SubmitProof(context.Background(), proof); err != nil {
		t.Fatal(err)
	}
	if client.submissions != 1 {
		t.Fatalf("expected one submission, got %d", client.submissions)
	}
}

func TestSubmitProofRejectsInvalidSummary(t *testing.T) {
	bridge := NewBridge(&proofClient{})
	proof := validProof()
	proof.Availability.TotalSamples = 0
	if err := bridge.SubmitProof(context.Background(), proof); err == nil {
		t.Fatal("expected invalid sample count")
	}
	proof = validProof()
	proof.Metrics.AvailabilityRate = 2
	if err := bridge.SubmitProof(context.Background(), proof); err == nil {
		t.Fatal("expected bounded availability metric")
	}
}

func TestSubmitVerifiedProofChecksProviderSignature(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("openinfra-availability-proof-v1")
	proof := validProof()
	proof.Availability.Signature = ed25519.Sign(privateKey, payload)
	client := &proofClient{}
	bridge := NewBridge(client)
	if err := bridge.SubmitVerifiedProof(context.Background(), proof, publicKey, payload); err != nil {
		t.Fatal(err)
	}
	if err := bridge.SubmitVerifiedProof(context.Background(), proof, publicKey, []byte("tampered")); err == nil {
		t.Fatal("expected signature verification failure")
	}
}
