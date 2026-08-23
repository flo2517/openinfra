package protocolcontract_test

import (
	"bytes"
	"testing"
	"time"

	agentv1 "github.com/openinfra/network/protocol/generated/go/agent/v1"
	controlplanev1 "github.com/openinfra/network/protocol/generated/go/controlplane/v1"
	sharedv1 "github.com/openinfra/network/protocol/generated/go/shared/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"
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
		sharedv1.LeaseState_LEASE_STATE_UNSPECIFIED != 0 ||
		controlplanev1.AgentWorkloadPhase_AGENT_WORKLOAD_PHASE_UNSPECIFIED != 0 {
		t.Fatal("shared enum zero values must remain unspecified")
	}
}

// TestDeployRequestCarriesLeaseEnd is ADR-028 §3's contract-conformance
// case: DeployRequest.lease_end (field 5) round-trips through the wire
// unchanged and lands on the exact field number the ADR settled on --
// pinning the wire contract the same way TestResourceCapabilityAndWorkload
// ConstraintsCarryZone above pins ADR-026's zone fields.
func TestDeployRequestCarriesLeaseEnd(t *testing.T) {
	leaseEnd := timestamppb.New(time.Unix(1_700_000_000, 0).UTC())
	request := &agentv1.DeployRequest{WorkloadId: "workload-1", LeaseEnd: leaseEnd}
	encoded, err := proto.Marshal(request)
	if err != nil {
		t.Fatalf("marshal DeployRequest: %v", err)
	}
	var decoded agentv1.DeployRequest
	if err := proto.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal DeployRequest: %v", err)
	}
	if !decoded.LeaseEnd.AsTime().Equal(leaseEnd.AsTime()) {
		t.Fatalf("DeployRequest.LeaseEnd round-trip = %s, want %s", decoded.LeaseEnd.AsTime(), leaseEnd.AsTime())
	}
	fields := agentv1.File_openinfra_agent_v1_agent_proto.Messages().ByName("DeployRequest").Fields()
	if field := fields.ByName("lease_end"); field == nil || field.Number() != 5 {
		t.Fatalf("DeployRequest.lease_end must be field 5, got %+v", field)
	}
}

// TestHeartbeatPayloadCarriesWorkloadStatus is ADR-028 §4's
// contract-conformance case: HeartbeatSigningPayload.workload_status
// (field 7) round-trips, and AgentWorkloadPhase is a distinct enum from
// WorkloadState (see WorkloadStatusSummary's proto doc comment for why the
// two vocabularies must never be conflated).
func TestHeartbeatPayloadCarriesWorkloadStatus(t *testing.T) {
	payload := &controlplanev1.HeartbeatSigningPayload{
		RequestId:  "request-1",
		ProviderId: "provider-1",
		Sequence:   1,
		WorkloadStatus: []*controlplanev1.WorkloadStatusSummary{
			{WorkloadId: "workload-1", Phase: controlplanev1.AgentWorkloadPhase_AGENT_WORKLOAD_PHASE_RUNNING, ContainerId: "container-1", SpecHash: []byte{1, 2, 3}},
		},
	}
	encoded, err := proto.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal HeartbeatSigningPayload: %v", err)
	}
	var decoded controlplanev1.HeartbeatSigningPayload
	if err := proto.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal HeartbeatSigningPayload: %v", err)
	}
	if len(decoded.WorkloadStatus) != 1 || decoded.WorkloadStatus[0].Phase != controlplanev1.AgentWorkloadPhase_AGENT_WORKLOAD_PHASE_RUNNING {
		t.Fatalf("workload_status round-trip = %+v", decoded.WorkloadStatus)
	}
	fields := controlplanev1.File_openinfra_controlplane_v1_control_plane_proto.Messages().ByName("HeartbeatSigningPayload").Fields()
	if field := fields.ByName("workload_status"); field == nil || field.Number() != 7 {
		t.Fatalf("HeartbeatSigningPayload.workload_status must be field 7, got %+v", field)
	}
	// AgentWorkloadPhase must remain a distinct enum from WorkloadState --
	// a future change accidentally merging them would silently let an
	// Agent-local phase masquerade as Control-Plane-confirmed state
	// (ADR-028 §2's explicit prohibition).
	agentPhase := controlplanev1.File_openinfra_controlplane_v1_control_plane_proto.Enums().ByName("AgentWorkloadPhase")
	workloadState := controlplanev1.File_openinfra_controlplane_v1_control_plane_proto.Enums().ByName("WorkloadState")
	if agentPhase == nil || workloadState == nil {
		t.Fatal("both AgentWorkloadPhase and WorkloadState enum descriptors must exist")
	}
	if agentPhase.FullName() == workloadState.FullName() {
		t.Fatal("AgentWorkloadPhase must be a distinct enum from WorkloadState")
	}
}
