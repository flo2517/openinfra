package providerjoin

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	controlplanev1 "github.com/openinfra/network/protocol/generated/go/controlplane/v1"
	sharedv1 "github.com/openinfra/network/protocol/generated/go/shared/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TestHeartbeatSigningPayloadWireBytesMatchRustFixture is the
// cross-language pin ADR-025 §2 requires: it reproduces, field-for-field,
// the exact HeartbeatSigningPayload built by provider-agent/crates/
// agent-cli/src/main.rs's
// heartbeat_signing_payload_wire_bytes_are_a_pinned_cross_language_fixture
// test, and asserts two things a drift in either side's protobuf runtime
// could silently break:
//
//  1. heartbeatDomain ++ proto.MarshalOptions{Deterministic:
//     true}.Marshal(payload) produces the *exact same bytes* prost's
//     encode did on the Rust side (expectedWireBytesHex below, copied
//     verbatim from that test's own pinned constant).
//  2. The fixed-seed Ed25519 signature the Rust test printed for those
//     bytes verifies against the public key it also printed, confirming
//     both sides are signing/verifying the identical byte string, not
//     two encodings that merely look similar.
//
// WorkloadBandwidthUsage has no signature field of its own (see its
// proto doc comment): it rides inside HeartbeatSigningPayload, so the
// one heartbeat signature this test pins is the *entire* cross-language
// authentication surface for the new field -- there is no second,
// separate signed-bytes layout to pin the way bandwidthSignedBytes pins
// MeasureBandwidth's (internal/networkvalidator/bandwidth.go). A
// mismatch here means Go's deterministic marshal has drifted from
// prost's encode, which would silently break every heartbeat signature
// verification once an Agent starts sending workload_bandwidth.
func TestHeartbeatSigningPayloadWireBytesMatchRustFixture(t *testing.T) {
	const (
		expectedWireBytesHex = "6f70656e696e6672612d6865617274626561742d7631000a2431313131313131312d313131312d313131312d313131312d313131313131313131313131124061616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161180722060880e2cfaa062a110d00000041150000c0401880800120e05d32360a2432323232323232322d323232322d323232322d323232322d32323232323232323232323210c0c40718f1f72722060898dacfaa06"
		publicKeyHex         = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"
		signatureHex         = "66c5ca747555754ce1efbd93e145949ec655e91a49a8fdc02fa5fe78827f968b8c11d3689f73470fb530c5078e17e1c55e37471aee931184783c495face77b0c"
	)

	payload := &controlplanev1.HeartbeatSigningPayload{
		RequestId:  "11111111-1111-1111-1111-111111111111",
		ProviderId: strings.Repeat("a", 64),
		Sequence:   7,
		ObservedAt: &timestamppb.Timestamp{Seconds: 1_700_000_000, Nanos: 0},
		Capabilities: &sharedv1.ResourceCapability{
			CpuTotal:       8.0,
			CpuAvailable:   6.0,
			RamTotalMb:     16_384,
			RamAvailableMb: 12_000,
		},
		WorkloadBandwidth: []*controlplanev1.WorkloadBandwidthUsage{{
			WorkloadId:        "22222222-2222-2222-2222-222222222222",
			IngressBytesTotal: 123_456,
			EgressBytesTotal:  654_321,
			WindowStartedAt:   &timestamppb.Timestamp{Seconds: 1_699_999_000, Nanos: 0},
		}},
	}
	payloadBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	signed := append([]byte(heartbeatDomain), payloadBytes...)

	if got := hex.EncodeToString(signed); got != expectedWireBytesHex {
		t.Fatalf("wire bytes = %s, want %s (Go's deterministic marshal has drifted from prost's encode -- update both fixtures together)", got, expectedWireBytesHex)
	}

	publicKey, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		t.Fatalf("decode public key fixture: %v", err)
	}
	signature, err := hex.DecodeString(signatureHex)
	if err != nil {
		t.Fatalf("decode signature fixture: %v", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), signed, signature) {
		t.Fatal("Rust-produced signature does not verify over Go's re-encoded wire bytes")
	}
}

func TestValidateWorkloadBandwidthRejectsMalformedEntries(t *testing.T) {
	validTimestamp := timestamppb.New(time.Unix(1_700_000_000, 0).UTC())
	tests := map[string]struct {
		entries []*controlplanev1.WorkloadBandwidthUsage
		wantErr bool
	}{
		"nil list is fine": {entries: nil, wantErr: false},
		"well-formed entry": {
			entries: []*controlplanev1.WorkloadBandwidthUsage{{
				WorkloadId: uuid.NewString(), IngressBytesTotal: 1, EgressBytesTotal: 2, WindowStartedAt: validTimestamp,
			}},
			wantErr: false,
		},
		"non-UUID workload_id": {
			entries: []*controlplanev1.WorkloadBandwidthUsage{{
				WorkloadId: "not-a-uuid", WindowStartedAt: validTimestamp,
			}},
			wantErr: true,
		},
		"missing window_started_at": {
			entries: []*controlplanev1.WorkloadBandwidthUsage{{
				WorkloadId: uuid.NewString(),
			}},
			wantErr: true,
		},
		"nil entry": {
			entries: []*controlplanev1.WorkloadBandwidthUsage{nil},
			wantErr: true,
		},
		"too many entries": {
			entries: func() []*controlplanev1.WorkloadBandwidthUsage {
				entries := make([]*controlplanev1.WorkloadBandwidthUsage, maxWorkloadBandwidthEntriesPerHeartbeat+1)
				for i := range entries {
					entries[i] = &controlplanev1.WorkloadBandwidthUsage{WorkloadId: uuid.NewString(), WindowStartedAt: validTimestamp}
				}
				return entries
			}(),
			wantErr: true,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := validateWorkloadBandwidth(tc.entries)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateWorkloadBandwidth() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// memoryBandwidthUsageStore is the Service-level fake -- it records every
// call it receives (or fails, on demand) so tests can assert both the
// happy path (entries reach the store) and the degrade path (a store
// failure never fails ReportHeartbeat).
type memoryBandwidthUsageStore struct {
	err   error
	calls int
	last  []*controlplanev1.WorkloadBandwidthUsage
}

func (s *memoryBandwidthUsageStore) RecordUsage(_ context.Context, _ string, entries []*controlplanev1.WorkloadBandwidthUsage) error {
	s.calls++
	s.last = entries
	return s.err
}

// bandwidthFixtureNow is bandwidthHeartbeatFixture's fixed ObservedAt,
// exposed so callers can build workload_bandwidth entries (which need a
// window_started_at) before calling the fixture, which only returns
// "now" alongside the already-signed request.
var bandwidthFixtureNow = time.Unix(1_700_000_000, 0).UTC()

// bandwidthHeartbeatFixture builds a signed ReportHeartbeatRequest whose
// payload carries the given workload_bandwidth entries -- like
// heartbeatFixture, but with the entries baked into the signed payload
// from the start rather than needing a second signature pass.
func bandwidthHeartbeatFixture(t *testing.T, entries []*controlplanev1.WorkloadBandwidthUsage) (*memoryRepository, *controlplanev1.ReportHeartbeatRequest, time.Time) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	repository := newMemoryRepository()
	providerDigest := sha256.Sum256(publicKey)
	providerID := fmt.Sprintf("%x", providerDigest)
	repository.completion[uuid.NewString()] = Completion{ProviderID: providerID, Challenge: Challenge{PublicKey: publicKey}, Status: sharedv1.NodeStatus_NODE_STATUS_ACTIVE}
	now := bandwidthFixtureNow
	payload := &controlplanev1.HeartbeatSigningPayload{
		RequestId: uuid.NewString(), ProviderId: providerID, Sequence: 1,
		ObservedAt:        timestamppb.New(now),
		Capabilities:      &sharedv1.ResourceCapability{CpuTotal: 8, CpuAvailable: 6, RamTotalMb: 16_384, RamAvailableMb: 12_000},
		WorkloadBandwidth: entries,
	}
	payloadBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	request := &controlplanev1.ReportHeartbeatRequest{Payload: payload, Signature: ed25519.Sign(privateKey, append([]byte(heartbeatDomain), payloadBytes...))}
	return repository, request, now
}

// TestReportHeartbeatPersistsWorkloadBandwidthAfterSignatureVerification
// covers the happy path: a validly signed heartbeat carrying
// workload_bandwidth entries reaches the configured store exactly once,
// with the entries intact.
func TestReportHeartbeatPersistsWorkloadBandwidthAfterSignatureVerification(t *testing.T) {
	workloadID := uuid.NewString()
	repository, request, now := bandwidthHeartbeatFixture(t, []*controlplanev1.WorkloadBandwidthUsage{{
		WorkloadId:        workloadID,
		IngressBytesTotal: 111,
		EgressBytesTotal:  222,
		WindowStartedAt:   timestamppb.New(bandwidthFixtureNow),
	}})

	store := &memoryBandwidthUsageStore{}
	service := NewService(repository, newMemoryHeartbeatStore(), &memoryRegistrar{})
	service.now = func() time.Time { return now }
	service.SetBandwidthUsageStore(store)

	if _, err := service.ReportHeartbeat(context.Background(), request); err != nil {
		t.Fatalf("report heartbeat: %v", err)
	}
	if store.calls != 1 {
		t.Fatalf("RecordUsage calls = %d, want 1", store.calls)
	}
	if len(store.last) != 1 || store.last[0].WorkloadId != workloadID {
		t.Fatalf("RecordUsage entries = %v, want one entry for %s", store.last, workloadID)
	}
}

// TestReportHeartbeatSucceedsWhenBandwidthStoreFails is the degrade-mode
// half: liveness (ReportHeartbeat's core job) must not depend on this
// secondary telemetry path succeeding, matching activeValidators'
// identical posture for its own optional heartbeat-adjacent data.
func TestReportHeartbeatSucceedsWhenBandwidthStoreFails(t *testing.T) {
	repository, request, now := bandwidthHeartbeatFixture(t, []*controlplanev1.WorkloadBandwidthUsage{{
		WorkloadId: uuid.NewString(), WindowStartedAt: timestamppb.New(bandwidthFixtureNow),
	}})

	store := &memoryBandwidthUsageStore{err: errors.New("connection refused")}
	service := NewService(repository, newMemoryHeartbeatStore(), &memoryRegistrar{})
	service.now = func() time.Time { return now }
	service.SetBandwidthUsageStore(store)

	response, err := service.ReportHeartbeat(context.Background(), request)
	if err != nil {
		t.Fatalf("report heartbeat should still succeed when the bandwidth store fails: %v", err)
	}
	if response.Status != sharedv1.NodeStatus_NODE_STATUS_ACTIVE {
		t.Fatalf("status = %s, want ACTIVE", response.Status)
	}
	if store.calls != 1 {
		t.Fatalf("RecordUsage calls = %d, want 1", store.calls)
	}
}

// TestReportHeartbeatWithoutBandwidthStoreConfiguredStillSucceeds covers
// the SetBandwidthUsageStore-never-called path, matching
// TestHeartbeatSucceedsWithoutValidatorSourceConfigured's identical
// contract for ValidatorSource: heartbeats must keep working exactly as
// they did before this ADR-025 §2 slice existed.
func TestReportHeartbeatWithoutBandwidthStoreConfiguredStillSucceeds(t *testing.T) {
	repository, request, now := bandwidthHeartbeatFixture(t, []*controlplanev1.WorkloadBandwidthUsage{{
		WorkloadId: uuid.NewString(), WindowStartedAt: timestamppb.New(bandwidthFixtureNow),
	}})

	service := NewService(repository, newMemoryHeartbeatStore(), &memoryRegistrar{})
	service.now = func() time.Time { return now }

	if _, err := service.ReportHeartbeat(context.Background(), request); err != nil {
		t.Fatalf("report heartbeat: %v", err)
	}
}

// TestReportHeartbeatRejectsMalformedWorkloadBandwidth confirms
// validateWorkloadBandwidth is actually wired into ReportHeartbeat's
// request validation, not just unit-tested in isolation -- the malformed
// workload_id must be caught before any signature/store work happens.
func TestReportHeartbeatRejectsMalformedWorkloadBandwidth(t *testing.T) {
	repository, request, now := bandwidthHeartbeatFixture(t, []*controlplanev1.WorkloadBandwidthUsage{{
		WorkloadId: "not-a-uuid", WindowStartedAt: timestamppb.New(bandwidthFixtureNow),
	}})
	service := NewService(repository, newMemoryHeartbeatStore(), &memoryRegistrar{})
	service.now = func() time.Time { return now }

	_, err := service.ReportHeartbeat(context.Background(), request)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %s, want InvalidArgument", status.Code(err))
	}
}
