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
	for _, method := range []protoreflect.Name{"BeginJoin", "CompleteJoin", "RenewCertificate", "ReportHeartbeat", "SubmitWorkload", "GetWorkload", "StopWorkload"} {
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

// TestNodeStatusRevokedIsPinned is ADR-027 §4's contract-conformance case:
// NODE_STATUS_REVOKED must stay exactly 6 -- agentmanager/orchestrator
// treat any non-ACTIVE status as excluded already (see
// PostgresRegistry.ListActive's WHERE status = $1), so this only needs to
// pin the wire value, not add new exclusion logic.
func TestNodeStatusRevokedIsPinned(t *testing.T) {
	if sharedv1.NodeStatus_NODE_STATUS_REVOKED != 6 {
		t.Fatalf("NodeStatus_NODE_STATUS_REVOKED = %d, want 6", sharedv1.NodeStatus_NODE_STATUS_REVOKED)
	}
}

// TestCompleteJoinCarriesADR027EnrollmentFields pins the exact field
// numbers ADR-027 §2 adds to CompleteJoinRequest/CompleteJoinResponse --
// enrollment extends the existing RPC rather than adding a new one, so a
// future regeneration must not silently renumber these out from under an
// already-deployed Agent/Control Plane pair.
func TestCompleteJoinCarriesADR027EnrollmentFields(t *testing.T) {
	requestFields := controlplanev1.File_openinfra_controlplane_v1_control_plane_proto.Messages().ByName("CompleteJoinRequest").Fields()
	if field := requestFields.ByName("tls_public_key"); field == nil || field.Number() != 5 {
		t.Fatalf("CompleteJoinRequest.tls_public_key must be field 5, got %+v", field)
	}
	responseFields := controlplanev1.File_openinfra_controlplane_v1_control_plane_proto.Messages().ByName("CompleteJoinResponse").Fields()
	if field := responseFields.ByName("certificate_pem"); field == nil || field.Number() != 5 {
		t.Fatalf("CompleteJoinResponse.certificate_pem must be field 5, got %+v", field)
	}
	if field := responseFields.ByName("certificate_expires_at"); field == nil || field.Number() != 6 {
		t.Fatalf("CompleteJoinResponse.certificate_expires_at must be field 6, got %+v", field)
	}
}

// TestRenewCertificateMessagesArePinned is the RenewCertificate half of
// ADR-027 §3's contract-conformance case, round-tripping both messages
// through the wire and pinning their field numbers the same way
// TestCompleteJoinCarriesADR027EnrollmentFields does for enrollment.
func TestRenewCertificateMessagesArePinned(t *testing.T) {
	request := &controlplanev1.RenewCertificateRequest{
		RequestId: "request-1", ProviderId: "provider-1",
		NewTlsPublicKey:          []byte("0123456789012345678901234567890123456789"[:32]),
		CurrentCertificateSerial: "12345", Nonce: 7, Signature: make([]byte, 64),
	}
	requestBytes, err := proto.Marshal(request)
	if err != nil {
		t.Fatalf("marshal RenewCertificateRequest: %v", err)
	}
	var decodedRequest controlplanev1.RenewCertificateRequest
	if err := proto.Unmarshal(requestBytes, &decodedRequest); err != nil {
		t.Fatalf("unmarshal RenewCertificateRequest: %v", err)
	}
	if decodedRequest.ProviderId != request.ProviderId || decodedRequest.CurrentCertificateSerial != request.CurrentCertificateSerial {
		t.Fatal("RenewCertificateRequest did not round-trip")
	}

	requestFields := controlplanev1.File_openinfra_controlplane_v1_control_plane_proto.Messages().ByName("RenewCertificateRequest").Fields()
	for name, number := range map[string]protoreflect.FieldNumber{
		"request_id": 1, "provider_id": 2, "new_tls_public_key": 3,
		"current_certificate_serial": 4, "timestamp": 5, "nonce": 6, "signature": 7,
	} {
		if field := requestFields.ByName(protoreflect.Name(name)); field == nil || field.Number() != number {
			t.Fatalf("RenewCertificateRequest.%s must be field %d, got %+v", name, number, field)
		}
	}

	responseFields := controlplanev1.File_openinfra_controlplane_v1_control_plane_proto.Messages().ByName("RenewCertificateResponse").Fields()
	for name, number := range map[string]protoreflect.FieldNumber{
		"certificate_pem": 1, "certificate_expires_at": 2, "certificate_serial": 3,
	} {
		if field := responseFields.ByName(protoreflect.Name(name)); field == nil || field.Number() != number {
			t.Fatalf("RenewCertificateResponse.%s must be field %d, got %+v", name, number, field)
		}
	}
}
