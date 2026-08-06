package blockchainbridge

import (
	"encoding/binary"
	"testing"
)

func encodeResourceOfferForTest(o ResourceOffer) []byte {
	data := make([]byte, 20)
	binary.LittleEndian.PutUint32(data[0:4], o.CPUMillicores)
	binary.LittleEndian.PutUint64(data[4:12], o.RAMMB)
	binary.LittleEndian.PutUint64(data[12:20], o.StorageGB)
	return append(data, encodeBoundedBytes(o.Capabilities)...)
}

func TestDecodeResourceOfferRoundTripsFixedFieldsAndCapabilities(t *testing.T) {
	cases := []ResourceOffer{
		{CPUMillicores: 2000, RAMMB: 4096, StorageGB: 100, Capabilities: []byte("gpu,fast-nvme")},
		{CPUMillicores: 1, RAMMB: 1, StorageGB: 1, Capabilities: nil},
		{CPUMillicores: 0, RAMMB: 0, StorageGB: 0, Capabilities: []byte{}},
	}
	for _, want := range cases {
		got, err := decodeResourceOffer(encodeResourceOfferForTest(want))
		if err != nil {
			t.Fatalf("decodeResourceOffer(%+v): %v", want, err)
		}
		if got.CPUMillicores != want.CPUMillicores || got.RAMMB != want.RAMMB || got.StorageGB != want.StorageGB {
			t.Fatalf("decodeResourceOffer() = %+v, want %+v", got, want)
		}
		if len(got.Capabilities) != len(want.Capabilities) {
			t.Fatalf("capabilities length = %d, want %d", len(got.Capabilities), len(want.Capabilities))
		}
		for i := range want.Capabilities {
			if got.Capabilities[i] != want.Capabilities[i] {
				t.Fatalf("capabilities mismatch at %d: got %v, want %v", i, got.Capabilities, want.Capabilities)
			}
		}
	}
}

func TestDecodeResourceOfferRejectsTruncatedAndTrailingData(t *testing.T) {
	valid := encodeResourceOfferForTest(ResourceOffer{CPUMillicores: 1, RAMMB: 1, StorageGB: 1, Capabilities: []byte("x")})
	if _, err := decodeResourceOffer(valid[:19]); err == nil {
		t.Fatal("expected an error decoding fewer than the fixed 20 bytes")
	}
	if _, err := decodeResourceOffer(append(valid, 0xFF)); err == nil {
		t.Fatal("expected an error decoding a trailing byte past the declared capabilities length")
	}
	truncatedCapabilities := valid[:len(valid)-1] // claims 1 byte of capabilities but supplies 0
	if _, err := decodeResourceOffer(truncatedCapabilities); err == nil {
		t.Fatal("expected an error when the capabilities length exceeds the remaining data")
	}
}

func TestEncodeBoundedBytesMatchesTheExistingCompactEncoder(t *testing.T) {
	value := []byte("gpu,fast-nvme")
	encoded := encodeBoundedBytes(value)
	length, offset, err := decodeCompactUint(encoded)
	if err != nil {
		t.Fatalf("decodeCompactUint: %v", err)
	}
	if int(length) != len(value) {
		t.Fatalf("encoded length prefix = %d, want %d", length, len(value))
	}
	if string(encoded[offset:]) != string(value) {
		t.Fatalf("encoded payload = %q, want %q", encoded[offset:], value)
	}
}

func TestResourceMarketOfferStorageKeyIsAPerProviderMapEntry(t *testing.T) {
	var providerA, providerB [32]byte
	providerA[0], providerB[0] = 1, 2
	keyA := resourceMarketOfferStorageKey(providerA)
	if keyA == resourceMarketOfferStorageKey(providerB) {
		t.Fatal("expected different providers to hash to different storage keys")
	}
	if keyA != resourceMarketOfferStorageKey(providerA) {
		t.Fatal("expected a deterministic storage key for the same provider")
	}
}
