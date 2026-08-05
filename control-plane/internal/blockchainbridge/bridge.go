package blockchainbridge

import (
	"context"
	"fmt"
	"math"
	"sync"

	sharedv1 "github.com/openinfra/network/protocol/generated/go/shared/v1"
)

// BlockchainClient represents the interface to the Substrate-based layer
type BlockchainClient interface {
	GetReputation(ctx context.Context, nodeID string) (*sharedv1.ReputationVector, error)
	CreateLeaseOnChain(ctx context.Context, lease *sharedv1.Lease) (string, error)
	SubmitExecutionProof(ctx context.Context, proof ExecutionProof) error
}

type ExecutionProof struct {
	LeaseID      string
	NodeID       string
	WorkloadID   string
	Success      bool
	Metrics      MetricSummary
	Signature    string
	Availability *AvailabilityProof
}

// AvailabilityProof is the off-chain, bounded summary relayed by a validator.
// Raw metrics remain off-chain; only its hash and integer counters cross the
// bridge to the deterministic runtime.
type AvailabilityProof struct {
	Sequence          uint64
	ObservedBlock     uint64
	SuccessfulSamples uint32
	TotalSamples      uint32
	PayloadHash       [32]byte
	Signature         []byte
}

func (p AvailabilityProof) Validate() error {
	if p.Sequence == 0 || p.TotalSamples == 0 || p.TotalSamples > 10000 || p.SuccessfulSamples > p.TotalSamples {
		return fmt.Errorf("availability proof counters are invalid")
	}
	if len(p.Signature) == 0 || len(p.Signature) > 96 {
		return fmt.Errorf("availability proof signature length is invalid")
	}
	return nil
}

type MetricSummary struct {
	ActualCPUTime    float32
	ActualRAMUsage   int64
	RuntimeSeconds   int32
	AvailabilityRate float32
}

type Bridge struct {
	mu              sync.RWMutex
	bcClient        BlockchainClient
	repCache        map[string]*sharedv1.ReputationVector
	submittedProofs map[string]struct{}
}

func NewBridge(client BlockchainClient) *Bridge {
	return &Bridge{
		bcClient:        client,
		repCache:        make(map[string]*sharedv1.ReputationVector),
		submittedProofs: make(map[string]struct{}),
	}
}

// GetNodeReputation retrieves the reputation vector, using cache for performance
func (b *Bridge) GetNodeReputation(ctx context.Context, nodeID string) (*sharedv1.ReputationVector, error) {
	b.mu.RLock()
	rep, found := b.repCache[nodeID]
	b.mu.RUnlock()

	if found {
		return rep, nil
	}

	rep, err := b.bcClient.GetReputation(ctx, nodeID)
	if err != nil {
		return nil, fmt.Errorf("blockchain reputation fetch failed: %w", err)
	}

	b.mu.Lock()
	b.repCache[nodeID] = rep
	b.mu.Unlock()

	return rep, nil
}

// CreateLease handles the on-chain commitment of a resource lease
func (b *Bridge) CreateLease(ctx context.Context, lease *sharedv1.Lease) (string, error) {
	leaseID, err := b.bcClient.CreateLeaseOnChain(ctx, lease)
	if err != nil {
		return "", fmt.Errorf("on-chain lease creation failed: %w", err)
	}
	return leaseID, nil
}

// SubmitProof sends the final execution metrics to the blockchain for reputation updating
func (b *Bridge) SubmitProof(ctx context.Context, proof ExecutionProof) error {
	if proof.LeaseID == "" || proof.NodeID == "" {
		return fmt.Errorf("execution proof requires lease and node identifiers")
	}
	if !finiteNonNegative(proof.Metrics.ActualCPUTime) || proof.Metrics.ActualCPUTime > 1e9 ||
		proof.Metrics.ActualRAMUsage < 0 || proof.Metrics.RuntimeSeconds < 0 ||
		!finiteNonNegative(proof.Metrics.AvailabilityRate) || proof.Metrics.AvailabilityRate > 1 {
		return fmt.Errorf("execution metrics are outside bounded ranges")
	}
	if proof.Availability != nil {
		if err := proof.Availability.Validate(); err != nil {
			return err
		}
	}
	key := proof.LeaseID + "\x00" + proof.NodeID
	if proof.Availability != nil {
		key = fmt.Sprintf("%s\x00%d", key, proof.Availability.Sequence)
	}
	b.mu.Lock()
	if _, exists := b.submittedProofs[key]; exists {
		b.mu.Unlock()
		return nil
	}
	b.mu.Unlock()
	err := b.bcClient.SubmitExecutionProof(ctx, proof)
	if err != nil {
		return fmt.Errorf("execution proof submission failed: %w", err)
	}
	b.mu.Lock()
	b.submittedProofs[key] = struct{}{}
	b.mu.Unlock()

	// Invalidate cache for this node as reputation will change
	b.mu.Lock()
	delete(b.repCache, proof.NodeID)
	b.mu.Unlock()

	return nil
}

func finiteNonNegative(value float32) bool {
	return !math.IsNaN(float64(value)) && !math.IsInf(float64(value), 0) && value >= 0
}
