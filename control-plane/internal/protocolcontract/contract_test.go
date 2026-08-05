package protocolcontract_test

import (
	"bytes"
	"testing"

	agentv1 "github.com/openinfra/network/protocol/generated/go/agent/v1"
	controlplanev1 "github.com/openinfra/network/protocol/generated/go/controlplane/v1"
	sharedv1 "github.com/openinfra/network/protocol/generated/go/shared/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestJoinAndHeartbeatBelongToControlPlane(t *testing.T) {
	controlPlane := controlplanev1.File_openinfra_controlplane_v1_control_plane_proto.Services().ByName("ControlPlaneService")
	if controlPlane == nil {
		t.Fatal("ControlPlaneService descriptor is missing")
	}
	for _, method := range []protoreflect.Name{"BeginJoin", "CompleteJoin", "ReportHeartbeat", "SubmitWorkload", "GetWorkload"} {
		if controlPlane.Methods().ByName(method) == nil {
			t.Fatalf("ControlPlaneService.%s is missing", method)
		}
	}

	agent := agentv1.File_openinfra_agent_v1_agent_proto.Services().ByName("ProviderAgentService")
	if agent == nil {
		t.Fatal("ProviderAgentService descriptor is missing")
	}
	if agent.Methods().ByName("Join") != nil {
		t.Fatal("ProviderAgentService must not expose Join")
	}
}

func TestHeartbeatPayloadHasDeterministicSigningBytes(t *testing.T) {
	payload := &controlplanev1.HeartbeatSigningPayload{
		RequestId:  "request-1",
		ProviderId: "provider-1",
		Sequence:   42,
		Capabilities: &sharedv1.ResourceCapability{
			CpuTotal:   8,
			RamTotalMb: 16_384,
		},
	}
	options := proto.MarshalOptions{Deterministic: true}
	first, err := options.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal signing payload: %v", err)
	}
	second, err := options.Marshal(proto.Clone(payload))
	if err != nil {
		t.Fatalf("marshal cloned signing payload: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("deterministic heartbeat serialization changed")
	}
}

func TestEnumsReserveZeroForUnspecified(t *testing.T) {
	if sharedv1.NodeStatus_NODE_STATUS_UNSPECIFIED != 0 ||
		sharedv1.WorkloadProfile_WORKLOAD_PROFILE_UNSPECIFIED != 0 ||
		sharedv1.LeaseState_LEASE_STATE_UNSPECIFIED != 0 {
		t.Fatal("shared enum zero values must remain unspecified")
	}
}
