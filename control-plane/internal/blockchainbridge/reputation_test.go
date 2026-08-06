package blockchainbridge

import (
	"encoding/binary"
	"testing"
)

func encodeReputationVectorForTest(v ReputationVector) []byte {
	data := make([]byte, 24)
	binary.LittleEndian.PutUint32(data[0:4], v.Compute)
	binary.LittleEndian.PutUint32(data[4:8], v.Storage)
	binary.LittleEndian.PutUint32(data[8:12], v.Network)
	binary.LittleEndian.PutUint32(data[12:16], v.Availability)
	binary.LittleEndian.PutUint32(data[16:20], v.Reliability)
	binary.LittleEndian.PutUint32(data[20:24], v.Global)
	return data
}

func TestDecodeReputationVectorRoundTripsAllFieldsInDeclarationOrder(t *testing.T) {
	// Distinct values per field so a field-order bug (e.g. swapping
	// network and availability) fails loudly instead of passing by
	// coincidence with equal test values.
	want := ReputationVector{Compute: 111, Storage: 222, Network: 333, Availability: 444, Reliability: 555, Global: 666}
	got, err := decodeReputationVector(encodeReputationVectorForTest(want))
	if err != nil {
		t.Fatalf("decodeReputationVector: %v", err)
	}
	if got != want {
		t.Fatalf("decodeReputationVector() = %+v, want %+v", got, want)
	}
}

func TestDecodeReputationVectorRejectsWrongLength(t *testing.T) {
	cases := [][]byte{
		{},
		make([]byte, 23),
		make([]byte, 25),
		make([]byte, 4), // one field's worth, not six
	}
	for _, input := range cases {
		if _, err := decodeReputationVector(input); err == nil {
			t.Fatalf("expected an error decoding %d bytes", len(input))
		}
	}
}

func TestReputationVectorStorageKeyIsAPerProviderMapEntry(t *testing.T) {
	var providerA, providerB [32]byte
	providerA[0] = 1
	providerB[0] = 2

	keyA := reputationVectorStorageKey(providerA)
	keyB := reputationVectorStorageKey(providerB)
	if keyA == keyB {
		t.Fatal("expected different providers to hash to different storage keys")
	}
	// "0x" + 16-byte pallet prefix + 16-byte item prefix + 16-byte
	// blake2_128 hash + 32-byte raw key = 80 bytes = 160 hex chars.
	if len(keyA) != 2+2*(16+16+16+32) {
		t.Fatalf("unexpected key length %d: %s", len(keyA), keyA)
	}
	if keyA != reputationVectorStorageKey(providerA) {
		t.Fatal("expected a deterministic storage key for the same provider")
	}
}
