package agentmanager

import (
	"context"
	"fmt"
	"sync"
	"time"

	agentv1 "github.com/openinfra/network/protocol/generated/go/agent/v1"
	sharedv1 "github.com/openinfra/network/protocol/generated/go/shared/v1"
)

type NodeConnection struct {
	NodeID       string
	LastSeen     time.Time
	Client       gRPCClient // Mock/Interface for the actual gRPC stream
	Status       sharedv1.NodeStatus
	Capabilities *sharedv1.ResourceCapability
}

type AgentManager struct {
	mu               sync.RWMutex
	connections      map[string]*NodeConnection
	heartbeatTimeout time.Duration
}

type gRPCClient interface {
	SendDeploy(ctx context.Context, req *agentv1.DeployRequest) error
}

type HeartbeatUpdate struct {
	NodeID     string
	Capability *sharedv1.ResourceCapability
	Status     sharedv1.NodeStatus
}

func NewAgentManager() *AgentManager {
	return &AgentManager{
		connections:      make(map[string]*NodeConnection),
		heartbeatTimeout: 30 * time.Second,
	}
}

// RegisterNode establishes the initial tracking of a provider node
func (am *AgentManager) RegisterNode(nodeID string, client gRPCClient) {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.connections[nodeID] = &NodeConnection{
		NodeID: nodeID,
		Client: client,
		Status: sharedv1.NodeStatus_NODE_STATUS_PENDING,
	}
}

// Deploy instructs a specific node to execute a workload
func (am *AgentManager) Deploy(ctx context.Context, nodeID string, req *agentv1.DeployRequest) error {
	am.mu.RLock()
	conn, exists := am.connections[nodeID]
	am.mu.RUnlock()

	if !exists {
		return fmt.Errorf("node %s not connected", nodeID)
	}

	if conn.Status != sharedv1.NodeStatus_NODE_STATUS_ACTIVE || conn.LastSeen.IsZero() || time.Since(conn.LastSeen) > am.heartbeatTimeout {
		return fmt.Errorf("node %s heartbeat timeout", nodeID)
	}

	return conn.Client.SendDeploy(ctx, req)
}

// ApplyHeartbeat updates the in-memory projection after the Control Plane RPC
// handler has authenticated and validated a unary ReportHeartbeat request.
func (am *AgentManager) ApplyHeartbeat(update HeartbeatUpdate) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	conn, exists := am.connections[update.NodeID]
	if !exists {
		return fmt.Errorf("node %s not connected", update.NodeID)
	}
	conn.LastSeen = time.Now()
	conn.Status = update.Status
	conn.Capabilities = update.Capability
	return nil
}

// GetAvailableNodes returns a list of healthy nodes for the scheduler
func (am *AgentManager) GetAvailableNodes() []*sharedv1.NodeIdentity {
	am.mu.RLock()
	defer am.mu.RUnlock()

	var healthyNodes []*sharedv1.NodeIdentity
	for id, conn := range am.connections {
		if time.Since(conn.LastSeen) < am.heartbeatTimeout && conn.Status == sharedv1.NodeStatus_NODE_STATUS_ACTIVE {
			healthyNodes = append(healthyNodes, &sharedv1.NodeIdentity{
				NodeId:       id,
				Capabilities: conn.Capabilities,
				Status:       sharedv1.NodeStatus_NODE_STATUS_ACTIVE,
			})
		}
	}
	return healthyNodes
}
