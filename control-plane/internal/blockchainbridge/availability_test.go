package blockchainbridge

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// palletEncodedSummary rebuilds the exact byte sequence
// pallet-availability produces for the fixture pinned in
// blockchain/pallets/availability/src/tests.rs
// (availability_summary_encoding_is_stable_for_the_control_plane_decoder).
//
// The two tests share no code and no schema -- they are two independent
// statements about the same wire format, in the two languages that have
// to agree on it. If the pallet's struct changes, the Rust pin fails; if
// this decoder drifts from it, this one does.
func palletEncodedSummary() []byte {
	var encoded bytes.Buffer
	_ = binary.Write(&encoded, binary.LittleEndian, uint64(7))   // sequence
	_ = binary.Write(&encoded, binary.LittleEndian, uint32(42))  // observed_at
	_ = binary.Write(&encoded, binary.LittleEndian, uint32(95))  // successful_samples
	_ = binary.Write(&encoded, binary.LittleEndian, uint32(100)) // total_samples
	_ = binary.Write(&encoded, binary.LittleEndian, uint16(9500))
	encoded.Write(bytes.Repeat([]byte{0xAB}, 32)) // payload_hash
	// Compact length prefix for a 64-byte signature: 64<<2|0b01 = 0x0101.
	encoded.Write([]byte{0x01, 0x01})
	encoded.Write(bytes.Repeat([]byte{0xCD}, 64))
	return encoded.Bytes()
}

func TestDecodeAvailabilitySummaryMatchesThePalletEncoding(t *testing.T) {
	encoded := palletEncodedSummary()
	if len(encoded) != 120 {
		t.Fatalf("fixture is %d bytes, want the 120 the pallet test pins", len(encoded))
	}

	summary, err := decodeAvailabilitySummary(encoded)
	if err != nil {
		t.Fatalf("decodeAvailabilitySummary: %v", err)
	}

	// Distinct values per field, so a field-order or width bug fails
	// loudly instead of passing by coincidence.
	if summary.Sequence != 7 {
		t.Errorf("Sequence = %d, want 7", summary.Sequence)
	}
	if summary.ObservedAt != 42 {
		t.Errorf("ObservedAt = %d, want 42", summary.ObservedAt)
	}
	if summary.SuccessfulSamples != 95 {
		t.Errorf("SuccessfulSamples = %d, want 95", summary.SuccessfulSamples)
	}
	if summary.TotalSamples != 100 {
		t.Errorf("TotalSamples = %d, want 100", summary.TotalSamples)
	}
	if summary.AvailabilityBps != 9500 {
		t.Errorf("AvailabilityBps = %d, want 9500", summary.AvailabilityBps)
	}
	if summary.PayloadHash != [32]byte(bytes.Repeat([]byte{0xAB}, 32)) {
		t.Errorf("PayloadHash = %x", summary.PayloadHash)
	}
	if !bytes.Equal(summary.Signature, bytes.Repeat([]byte{0xCD}, 64)) {
		t.Errorf("Signature = %x", summary.Signature)
	}
}

// A truncated or over-long value must be an error, never a partially
// populated summary: this decodes consensus state, and a proof that
// half-decodes is not a proof.
func TestDecodeAvailabilitySummaryRejectsMalformedInput(t *testing.T) {
	valid := palletEncodedSummary()
	cases := map[string][]byte{
		"empty":                   {},
		"fixed fields only":       valid[:54],
		"truncated mid-signature": valid[:len(valid)-1],
		"trailing garbage":        append(append([]byte(nil), valid...), 0x00),
		"shorter than fixed part": valid[:20],
		"missing compact prefix":  valid[:55],
	}
	for name, input := range cases {
		if _, err := decodeAvailabilitySummary(input); err == nil {
			t.Errorf("%s: expected an error decoding %d bytes", name, len(input))
		}
	}
}

// The pallet bounds the signature at 96 bytes (ConstU32<96>). A length
// prefix claiming more than that means this decoder and the pallet
// disagree about the type, which is worth refusing rather than trusting.
func TestDecodeAvailabilitySummaryRejectsAnOversizedSignature(t *testing.T) {
	var encoded bytes.Buffer
	encoded.Write(make([]byte, 54))
	// Compact length 200: 200<<2|0b01 = 801 = 0x0321, two-byte mode.
	encoded.Write([]byte{0x21, 0x03})
	encoded.Write(make([]byte, 200))

	if _, err := decodeAvailabilitySummary(encoded.Bytes()); err == nil {
		t.Fatal("expected an error for a signature longer than the pallet's bound")
	}
}

func TestLatestProofStorageKeyIsAPerProviderMapEntry(t *testing.T) {
	var providerA, providerB [32]byte
	providerA[0] = 1
	providerB[0] = 2

	keyA := latestProofStorageKey(providerA)
	if keyA == latestProofStorageKey(providerB) {
		t.Fatal("expected different providers to hash to different storage keys")
	}
	// "0x" + 16-byte pallet prefix + 16-byte item prefix + 16-byte
	// blake2_128 hash + 32-byte raw key.
	if len(keyA) != 2+2*(16+16+16+32) {
		t.Fatalf("unexpected key length %d: %s", len(keyA), keyA)
	}
}
