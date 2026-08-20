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
	for _, method := range []protoreflect.Name{"BeginJoin", "CompleteJoin", "ReportHeartbeat", "SubmitWorkload", "GetWorkload", "StopWorkload"} {
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

// TestResourceCapabilityAndWorkloadConstraintsCarryZone is ADR-026's
// contract-conformance case: ResourceCapability.zone (field 9) and
// WorkloadConstraints.required_zone (field 4) round-trip through the wire
// unchanged, and land on the exact field numbers the ADR settled on --
// pinning the wire contract so a future regeneration can't silently
// renumber either field out from under an already-deployed Agent/Control
// Plane pair.
func TestResourceCapabilityAndWorkloadConstraintsCarryZone(t *testing.T) {
	capability := &sharedv1.ResourceCapability{CpuTotal: 4, Zone: "us-east"}
	capabilityBytes, err := proto.Marshal(capability)
	if err != nil {
		t.Fatalf("marshal ResourceCapability: %v", err)
	}
	var decodedCapability sharedv1.ResourceCapability
	if err := proto.Unmarshal(capabilityBytes, &decodedCapability); err != nil {
		t.Fatalf("unmarshal ResourceCapability: %v", err)
	}
	if decodedCapability.Zone != "us-east" {
		t.Fatalf("ResourceCapability.Zone round-trip = %q, want %q", decodedCapability.Zone, "us-east")
	}

	constraints := &sharedv1.WorkloadConstraints{RequiredZone: "us-east"}
	constraintsBytes, err := proto.Marshal(constraints)
	if err != nil {
		t.Fatalf("marshal WorkloadConstraints: %v", err)
	}
	var decodedConstraints sharedv1.WorkloadConstraints
	if err := proto.Unmarshal(constraintsBytes, &decodedConstraints); err != nil {
		t.Fatalf("unmarshal WorkloadConstraints: %v", err)
	}
	if decodedConstraints.RequiredZone != "us-east" {
		t.Fatalf("WorkloadConstraints.RequiredZone round-trip = %q, want %q", decodedConstraints.RequiredZone, "us-east")
	}

	capabilityFields := sharedv1.File_openinfra_shared_v1_shared_proto.Messages().ByName("ResourceCapability").Fields()
	if zone := capabilityFields.ByName("zone"); zone == nil || zone.Number() != 9 {
		t.Fatalf("ResourceCapability.zone must be field 9, got %+v", zone)
	}
	constraintsFields := sharedv1.File_openinfra_shared_v1_shared_proto.Messages().ByName("WorkloadConstraints").Fields()
	if requiredZone := constraintsFields.ByName("required_zone"); requiredZone == nil || requiredZone.Number() != 4 {
		t.Fatalf("WorkloadConstraints.required_zone must be field 4, got %+v", requiredZone)
	}
}

func TestEnumsReserveZeroForUnspecified(t *testing.T) {
	if sharedv1.NodeStatus_NODE_STATUS_UNSPECIFIED != 0 ||
		sharedv1.WorkloadProfile_WORKLOAD_PROFILE_UNSPECIFIED != 0 ||
		sharedv1.LeaseState_LEASE_STATE_UNSPECIFIED != 0 {
		t.Fatal("shared enum zero values must remain unspecified")
	}
}
