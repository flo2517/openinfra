package orchestrator

import (
	"context"
	"fmt"
	"sync"

	agentv1 "github.com/openinfra/network/protocol/generated/go/agent/v1"
	sharedv1 "github.com/openinfra/network/protocol/generated/go/shared/v1"
)

type WorkloadState string

const (
	StateRequested WorkloadState = "Requested"
	StateScheduled WorkloadState = "Scheduled"
	StateLeased    WorkloadState = "Leased"
	StateDeploying WorkloadState = "Deploying"
	StateRunning   WorkloadState = "Running"
	StateCompleted WorkloadState = "Completed"
	StateFailed    WorkloadState = "Failed"
)

type Orchestrator struct {
	mu             sync.RWMutex
	workloadStatus map[string]WorkloadState
	// Dependencies
	scheduler  SchedulerClient
	blockchain BlockchainClient
	agentMgr   AgentManagerClient
}

type SchedulerClient interface {
	Schedule(ctx context.Context, def *sharedv1.WorkloadDefinition) (string, float32, error)
}

type BlockchainClient interface {
	CreateLease(ctx context.Context, lease *sharedv1.Lease) (string, error)
	SubmitProof(ctx context.Context, nodeID string, metrics interface{}) error
}

type AgentManagerClient interface {
	Deploy(ctx context.Context, nodeID string, req *agentv1.DeployRequest) error
}

func NewOrchestrator(s SchedulerClient, b BlockchainClient, a AgentManagerClient) *Orchestrator {
	return &Orchestrator{
		workloadStatus: make(map[string]WorkloadState),
		scheduler:      s,
		blockchain:     b,
		agentMgr:       a,
	}
}

// ProcessWorkload handles the state machine transition for a new workload

func (o *Orchestrator) ProcessWorkload(ctx context.Context, def *sharedv1.WorkloadDefinition) error {
	o.updateState(def.WorkloadId, StateRequested)

	// 1. Scheduling
	nodeID, _, err := o.scheduler.Schedule(ctx, def)
	if err != nil {
		o.updateState(def.WorkloadId, StateFailed)
		return fmt.Errorf("scheduling failed: %w", err)
	}
	o.updateState(def.WorkloadId, StateScheduled)

	// 2. Lease Creation
	lease := &sharedv1.Lease{
		ProviderId: nodeID,
		WorkloadId: def.WorkloadId,
		State:      sharedv1.LeaseState_LEASE_STATE_PENDING,
	}
	leaseID, err := o.blockchain.CreateLease(ctx, lease)
	if err != nil {
		o.updateState(def.WorkloadId, StateFailed)
		return fmt.Errorf("lease creation failed: %w", err)
	}
	o.updateState(def.WorkloadId, StateLeased)

	// 3. Deployment
	deployReq := &agentv1.DeployRequest{
		WorkloadId: def.WorkloadId,
		LeaseId:    leaseID,
		Limits: &agentv1.ResourceLimits{
			CpuCores: def.Requirements.Cpu,
			MemoryMb: def.Requirements.RamMb,
		},
		Image: "latest", // Placeholder
	}
	err = o.agentMgr.Deploy(ctx, nodeID, deployReq)
	if err != nil {
		o.updateState(def.WorkloadId, StateFailed)
		return fmt.Errorf("deployment failed: %w", err)
	}
	o.updateState(def.WorkloadId, StateDeploying)

	return nil
}

func (o *Orchestrator) updateState(id string, state WorkloadState) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.workloadStatus[id] = state
	fmt.Printf("Workload %s transitioned to %s\n", id, state)
}

func (o *Orchestrator) GetStatus(id string) WorkloadState {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.workloadStatus[id]
}
