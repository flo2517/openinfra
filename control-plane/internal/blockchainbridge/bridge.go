package blockchainbridge

import (
	"context"
	"fmt"
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
	LeaseID    string
	NodeID     string
	WorkloadID string
	Success    bool
	Metrics    MetricSummary
	Signature  string
}

type MetricSummary struct {
	ActualCPUTime    float32
	ActualRAMUsage   int64
	RuntimeSeconds   int32
	AvailabilityRate float32
}

type Bridge struct {
	mu       sync.RWMutex
	bcClient BlockchainClient
	repCache map[string]*sharedv1.ReputationVector
}

func NewBridge(client BlockchainClient) *Bridge {
	return &Bridge{
		bcClient: client,
		repCache: make(map[string]*sharedv1.ReputationVector),
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
	err := b.bcClient.SubmitExecutionProof(ctx, proof)
	if err != nil {
		return fmt.Errorf("execution proof submission failed: %w", err)
	}

	// Invalidate cache for this node as reputation will change
	b.mu.Lock()
	delete(b.repCache, proof.NodeID)
	b.mu.Unlock()

	return nil
}
