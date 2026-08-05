package agentmanager

import (
	"context"
	"errors"
	"testing"

	controlplanev1 "github.com/openinfra/network/protocol/generated/go/controlplane/v1"
	sharedv1 "github.com/openinfra/network/protocol/generated/go/shared/v1"
	"google.golang.org/protobuf/proto"
)

type registryStub struct {
	providers []RegisteredProvider
	err       error
}

func (s registryStub) ListActive(context.Context) ([]RegisteredProvider, error) {
	return s.providers, s.err
}

type livenessStub struct {
	payloads map[string][]byte
	errors   map[string]error
}

func (s livenessStub) HeartbeatPayload(_ context.Context, providerID string) ([]byte, error) {
	if err := s.errors[providerID]; err != nil {
		return nil, err
	}
	payload, ok := s.payloads[providerID]
	if !ok {
		return nil, ErrHeartbeatNotFresh
	}
	return payload, nil
}

func TestListSchedulableRequiresRegistrationAndFreshHeartbeat(t *testing.T) {
	freshPayload, err := proto.Marshal(&controlplanev1.HeartbeatSigningPayload{
		ProviderId: "fresh",
		Capabilities: &sharedv1.ResourceCapability{
			CpuTotal: 4, CpuAvailable: 3, RamTotalMb: 8192, RamAvailableMb: 4096,
		},
	})
	if err != nil {
		t.Fatalf("marshal heartbeat: %v", err)
	}
	directory := NewDirectory(
		registryStub{providers: []RegisteredProvider{
			{ProviderID: "fresh", ProtocolVersion: "1", AgentVersion: "0.1.0"},
			{ProviderID: "expired", ProtocolVersion: "1", AgentVersion: "0.1.0"},
		}},
		livenessStub{payloads: map[string][]byte{"fresh": freshPayload}, errors: map[string]error{}},
	)

	providers, err := directory.ListSchedulable(context.Background())
	if err != nil {
		t.Fatalf("list schedulable providers: %v", err)
	}
	if len(providers) != 1 || providers[0].NodeId != "fresh" {
		t.Fatalf("providers = %#v, want only fresh", providers)
	}
	if providers[0].Status != sharedv1.NodeStatus_NODE_STATUS_ACTIVE {
		t.Fatalf("status = %s, want ACTIVE", providers[0].Status)
	}
}

func TestListSchedulableRejectsHeartbeatIdentityMismatch(t *testing.T) {
	payload, err := proto.Marshal(&controlplanev1.HeartbeatSigningPayload{
		ProviderId:   "another-provider",
		Capabilities: &sharedv1.ResourceCapability{CpuTotal: 1},
	})
	if err != nil {
		t.Fatalf("marshal heartbeat: %v", err)
	}
	directory := NewDirectory(
		registryStub{providers: []RegisteredProvider{{ProviderID: "registered"}}},
		livenessStub{payloads: map[string][]byte{"registered": payload}, errors: map[string]error{}},
	)

	_, err = directory.ListSchedulable(context.Background())
	if err == nil {
		t.Fatal("identity mismatch must fail")
	}
}

func TestListSchedulablePropagatesCacheFailure(t *testing.T) {
	directory := NewDirectory(
		registryStub{providers: []RegisteredProvider{{ProviderID: "provider"}}},
		livenessStub{payloads: map[string][]byte{}, errors: map[string]error{"provider": errors.New("Redis unavailable")}},
	)

	_, err := directory.ListSchedulable(context.Background())
	if err == nil {
		t.Fatal("cache failure must not look like an empty healthy directory")
	}
}
