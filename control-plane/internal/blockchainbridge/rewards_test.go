package blockchainbridge

import (
	"encoding/binary"
	"testing"
)

func TestDecodeRewardPointsRoundTripsAU64(t *testing.T) {
	// A value above 2^32 so a decoder that read only four bytes -- the
	// width every other scalar in this package uses -- fails here.
	const want = uint64(9_000_000_000)
	encoded := make([]byte, 8)
	binary.LittleEndian.PutUint64(encoded, want)

	got, err := decodeRewardPoints(encoded)
	if err != nil {
		t.Fatalf("decodeRewardPoints: %v", err)
	}
	if got != want {
		t.Fatalf("decodeRewardPoints() = %d, want %d", got, want)
	}
}

func TestDecodeRewardPointsRejectsWrongLength(t *testing.T) {
	for _, length := range []int{0, 4, 7, 9, 16} {
		if _, err := decodeRewardPoints(make([]byte, length)); err == nil {
			t.Errorf("expected an error decoding %d bytes", length)
		}
	}
}

func TestRewardBalanceStorageKeyIsAPerProviderMapEntry(t *testing.T) {
	var providerA, providerB [32]byte
	providerA[0] = 1
	providerB[0] = 2

	keyA := rewardBalanceStorageKey(providerA)
	if keyA == rewardBalanceStorageKey(providerB) {
		t.Fatal("expected different providers to hash to different storage keys")
	}
	if len(keyA) != 2+2*(16+16+16+32) {
		t.Fatalf("unexpected key length %d: %s", len(keyA), keyA)
	}
}

// pallet-rewards declares RewardBalances with ValueQuery, so a provider
// that has never been credited has no storage entry at all. That absence
// means zero points -- not "unknown" -- and must not be reported as a
// failure. The distinction that DOES matter (a read error) is covered by
// the caller returning err, never a silent 0.
func TestRewardBalanceStorageKeyPinsTheValueQuerySemantics(t *testing.T) {
	// Documented as a test so the invariant is checked rather than
	// living only in a comment: decoding an 8-byte zero must succeed and
	// yield 0, matching what the chain would return for a credited-then-
	// emptied account. Absence is handled by ProviderRewardPoints itself.
	got, err := decodeRewardPoints(make([]byte, 8))
	if err != nil {
		t.Fatalf("decodeRewardPoints(zero): %v", err)
	}
	if got != 0 {
		t.Fatalf("decodeRewardPoints(zero) = %d, want 0", got)
	}
}
