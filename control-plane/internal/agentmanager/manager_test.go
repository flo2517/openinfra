package agentmanager

import (
	"context"
	"testing"

	agentv1 "github.com/openinfra/network/protocol/generated/go/agent/v1"
)

type clientStub struct{ deployed bool }

func (c *clientStub) SendDeploy(context.Context, *agentv1.DeployRequest) error {
	c.deployed = true
	return nil
}

func TestRegisterDoesNotMakeProviderDeployableBeforeHeartbeat(t *testing.T) {
	manager := NewAgentManager()
	client := &clientStub{}
	manager.RegisterNode("provider", client)

	err := manager.Deploy(context.Background(), "provider", &agentv1.DeployRequest{})
	if err == nil {
		t.Fatal("deploy must fail before an authenticated heartbeat")
	}
	if client.deployed {
		t.Fatal("deploy was sent before heartbeat confirmation")
	}
}
