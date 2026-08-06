package blockchainbridge

import (
	"testing"
)

func TestDecodeCompactUintRoundTripsWithTheExistingEncoder(t *testing.T) {
	cases := []uint64{0, 1, 63, 64, 65, 16_383, 16_384, 1<<30 - 1, 1 << 30, 1 << 40}
	for _, value := range cases {
		encoded := compactUint(value)
		decoded, consumed, err := decodeCompactUint(encoded)
		if err != nil {
			t.Fatalf("decodeCompactUint(%d encoded): %v", value, err)
		}
		if decoded != value {
			t.Fatalf("round trip mismatch: encoded %d, decoded %d", value, decoded)
		}
		if consumed != len(encoded) {
			t.Fatalf("expected to consume all %d encoded bytes, consumed %d", len(encoded), consumed)
		}
	}
}

func TestDecodeCompactUintRejectsTruncatedInput(t *testing.T) {
	cases := [][]byte{
		{},
		{0b01},       // two-byte mode, only one byte present
		{0b10},       // four-byte mode, only one byte present
		{0b10, 0, 0}, // four-byte mode, three bytes present
		{0b11},       // big-integer mode, length byte only
	}
	for _, input := range cases {
		if _, _, err := decodeCompactUint(input); err == nil {
			t.Fatalf("expected an error decoding truncated input %v", input)
		}
	}
}

func TestDecodeAccountIdVecRoundTripsAnArbitraryCount(t *testing.T) {
	var accounts [][32]byte
	for i := 0; i < 5; i++ {
		var account [32]byte
		for b := range account {
			account[b] = byte(i)
		}
		accounts = append(accounts, account)
	}
	encoded := compactUint(uint64(len(accounts)))
	for _, account := range accounts {
		encoded = append(encoded, account[:]...)
	}
	decoded, err := decodeAccountIdVec(encoded)
	if err != nil {
		t.Fatalf("decodeAccountIdVec: %v", err)
	}
	if len(decoded) != len(accounts) {
		t.Fatalf("expected %d accounts, got %d", len(accounts), len(decoded))
	}
	for i := range accounts {
		if decoded[i] != accounts[i] {
			t.Fatalf("account %d mismatch: want %x, got %x", i, accounts[i], decoded[i])
		}
	}
}

func TestDecodeAccountIdVecHandlesAnEmptySet(t *testing.T) {
	decoded, err := decodeAccountIdVec(compactUint(0))
	if err != nil {
		t.Fatalf("decodeAccountIdVec(empty): %v", err)
	}
	if len(decoded) != 0 {
		t.Fatalf("expected zero accounts, got %d", len(decoded))
	}
}

func TestDecodeAccountIdVecRejectsALengthMismatch(t *testing.T) {
	// Prefix claims 2 accounts but only one 32-byte chunk follows.
	encoded := append(compactUint(2), make([]byte, 32)...)
	if _, err := decodeAccountIdVec(encoded); err == nil {
		t.Fatal("expected a length-mismatch error")
	}
}

func TestNetworkValidatorStorageKeyIsAFixedLengthPrefix(t *testing.T) {
	key := networkValidatorStorageKey("ActiveValidatorSet")
	// "0x" + 16 bytes (pallet) + 16 bytes (item) = 2 + 64 hex chars.
	if len(key) != 66 {
		t.Fatalf("expected a 32-byte storage prefix, got key of length %d: %s", len(key), key)
	}
	if key[:2] != "0x" {
		t.Fatalf("expected a 0x-prefixed key, got %s", key)
	}
	// Same pallet/item always yields the same key -- it addresses a fixed
	// StorageValue, not a per-account map entry.
	if key != networkValidatorStorageKey("ActiveValidatorSet") {
		t.Fatal("expected a deterministic storage key")
	}
}
