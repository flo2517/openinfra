package metering

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	sharedv1 "github.com/openinfra/network/protocol/generated/go/shared/v1"
)

// TestMeteringSignedBytesMatchRustFixture is the cross-language pin for
// ADR-029 §6's canonical byte encoding, the same convention
// TestHeartbeatSigningPayloadWireBytesMatchRustFixture (bandwidth_test.go)
// already established for heartbeat: the fixed summary, the pinned
// canonical-byte hex, and the Ed25519 signature over it with a fixed
// 32-byte seed key are byte-for-byte identical to
// metering_signed_bytes_are_a_pinned_cross_language_fixture in
// provider-agent/crates/agent-api/src/lib.rs. A mismatch here means
// Go's verification has drifted from agent-api's signing.
func TestMeteringSignedBytesMatchRustFixture(t *testing.T) {
	summary := &sharedv1.MeteringSummary{
		WorkloadId:            "22222222-2222-2222-2222-222222222222",
		LeaseId:               "42",
		Sequence:              7,
		PeriodStart:           1_700_000_000,
		PeriodEnd:             1_700_003_600,
		MeteringSchemaVersion: 1,
		CpuCoreSeconds:        3600,
		RamMbSeconds:          16_384_000,
		StorageGbSeconds:      100,
		NetworkEgressMb:       512,
		NetworkIngressMb:      256,
		GpuSeconds:            0,
	}

	const expectedWireBytesHex = "6f70656e696e6672612d6d65746572696e672d7631000000002432323232323232322d323232322d323232322d323232322d3232323232323232323232320000000234320000000000000007000000006553f100000000006553ff10000000010000000000000e100000000000fa00000000000000000064000000000000020000000000000001000000000000000000"

	signed := signedBytes(summary)
	if got := hex.EncodeToString(signed); got != expectedWireBytesHex {
		t.Fatalf("signed bytes changed -- update this fixture and the mirrored Rust one together\n got: %s\nwant: %s", got, expectedWireBytesHex)
	}

	const fixturePublicKeyHex = "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394"
	const fixtureSignatureHex = "58698a07b133dae02aad9eda2d3ce20991cfeae5fcad6b380f7fe0074233826f7181d50929242193ffb3ef0dd8dd0ec717143282e3e6798534f64678342b740e"

	publicKey, err := hex.DecodeString(fixturePublicKeyHex)
	if err != nil {
		t.Fatalf("decode fixture public key: %v", err)
	}
	signature, err := hex.DecodeString(fixtureSignatureHex)
	if err != nil {
		t.Fatalf("decode fixture signature: %v", err)
	}
	if !verifySignature(ed25519.PublicKey(publicKey), summary, signature) {
		t.Fatal("fixture signature must verify against the pinned canonical bytes")
	}

	tampered := append([]byte(nil), signature...)
	tampered[0] ^= 0xFF
	if verifySignature(ed25519.PublicKey(publicKey), summary, tampered) {
		t.Fatal("a tampered signature must not verify")
	}
}

func TestSignedBytesChangeWhenAnyFieldChanges(t *testing.T) {
	// baseSummary returns a fresh struct each call rather than being
	// copied/cloned -- MeteringSummary embeds a protoimpl.MessageState
	// (a sync.Mutex), which go vet correctly flags as unsafe to copy by
	// value.
	baseSummary := func() *sharedv1.MeteringSummary {
		return &sharedv1.MeteringSummary{
			WorkloadId: "workload-1", LeaseId: "1", Sequence: 1,
			PeriodStart: 100, PeriodEnd: 200, MeteringSchemaVersion: 1,
			CpuCoreSeconds: 1, RamMbSeconds: 1, StorageGbSeconds: 1,
			NetworkEgressMb: 1, NetworkIngressMb: 1, GpuSeconds: 1,
		}
	}
	baseline := signedBytes(baseSummary())

	variants := []func(*sharedv1.MeteringSummary){
		func(s *sharedv1.MeteringSummary) { s.WorkloadId = "workload-2" },
		func(s *sharedv1.MeteringSummary) { s.LeaseId = "2" },
		func(s *sharedv1.MeteringSummary) { s.Sequence = 2 },
		func(s *sharedv1.MeteringSummary) { s.PeriodStart = 101 },
		func(s *sharedv1.MeteringSummary) { s.PeriodEnd = 201 },
		func(s *sharedv1.MeteringSummary) { s.MeteringSchemaVersion = 2 },
		func(s *sharedv1.MeteringSummary) { s.CpuCoreSeconds = 2 },
		func(s *sharedv1.MeteringSummary) { s.RamMbSeconds = 2 },
		func(s *sharedv1.MeteringSummary) { s.StorageGbSeconds = 2 },
		func(s *sharedv1.MeteringSummary) { s.NetworkEgressMb = 2 },
		func(s *sharedv1.MeteringSummary) { s.NetworkIngressMb = 2 },
		func(s *sharedv1.MeteringSummary) { s.GpuSeconds = 2 },
	}
	for i, mutate := range variants {
		variant := baseSummary()
		mutate(variant)
		if hex.EncodeToString(signedBytes(variant)) == hex.EncodeToString(baseline) {
			t.Fatalf("variant %d did not change the signed bytes", i)
		}
	}
}
