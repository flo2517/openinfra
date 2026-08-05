package blockchainbridge

import (
	"encoding/hex"
	"testing"
)

func TestCompactUintBoundaries(t *testing.T) {
	tests := map[uint64]string{0: "00", 63: "fc", 64: "0101", 16383: "fdff", 16384: "02000100", 1 << 30: "0300000040"}
	for value, expected := range tests {
		if actual := hex.EncodeToString(compactUint(value)); actual != expected {
			t.Fatalf("compact(%d) = %s, want %s", value, actual, expected)
		}
	}
}

func TestProviderStorageKeyIsStable(t *testing.T) {
	provider := [32]byte{1, 2, 3}
	key := providerStorageKey(provider)
	if len(key) != 2+(16+16+16+32)*2 {
		t.Fatalf("storage key length = %d", len(key))
	}
	if key[len(key)-64:] != hex.EncodeToString(provider[:]) {
		t.Fatal("storage key does not end in provider account")
	}
}
