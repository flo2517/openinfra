package orchestrator

import (
	"testing"

	"github.com/openinfra/network/internal/agentmanager"
	sharedv1 "github.com/openinfra/network/protocol/generated/go/shared/v1"
)

func TestSelectProviderRequiresEndpointAndCapacity(t *testing.T) {
	providers := []agentmanager.SchedulableProvider{
		{RegisteredProvider: agentmanager.RegisteredProvider{ProviderID: "no-endpoint"}, Capabilities: &sharedv1.ResourceCapability{CpuAvailable: 8, RamAvailableMb: 8192}},
		{RegisteredProvider: agentmanager.RegisteredProvider{ProviderID: "small", AgentEndpoint: "https://small:50052"}, Capabilities: &sharedv1.ResourceCapability{CpuAvailable: 1, RamAvailableMb: 128}},
		{RegisteredProvider: agentmanager.RegisteredProvider{ProviderID: "selected", AgentEndpoint: "https://selected:50052"}, Capabilities: &sharedv1.ResourceCapability{CpuAvailable: 4, RamAvailableMb: 4096}},
	}
	selected, err := selectProvider(providers, &sharedv1.ResourceRequirements{Cpu: 2, RamMb: 1024})
	if err != nil {
		t.Fatal(err)
	}
	if selected.ProviderID != "selected" {
		t.Fatalf("selected %q", selected.ProviderID)
	}
}

func TestCanonicalResourceHashIsStable(t *testing.T) {
	first := canonicalResourceHash([]byte{1, 2, 3}, "image@sha256:abc")
	if first != canonicalResourceHash([]byte{1, 2, 3}, "image@sha256:abc") {
		t.Fatal("hash is not stable")
	}
	if first == canonicalResourceHash([]byte{1, 2, 3}, "other@sha256:abc") {
		t.Fatal("image is not covered by hash")
	}
}
