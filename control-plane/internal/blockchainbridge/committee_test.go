package blockchainbridge

import "testing"

// fill32 builds a 32-byte AccountId32-shaped value the same way the Rust
// golden-vector fixture did: every byte set to b (AccountId32::new([b;
// 32])).
func fill32(b byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = b
	}
	return out
}

// TestCommitteeMatchesRustGoldenVector pins this Go port to the exact
// output of pallet-network-validator::Pallet::committee, captured from a
// real 32-byte-AccountId32 run of the actual pallet (not the mock
// runtime's u64 AccountId used by blockchain/pallets/network-validator/
// src/tests.rs). The golden vector was captured with a temporary
// #[test] added to a scratch module in
// blockchain/pallets/network-validator/src/ (deleted before this PR's
// final commit -- see the PR description for the exact captured
// eprintln! output and how it was reproduced independently in Python
// before being ported here), using:
//
//	TargetCommitteeSize = 5, matching the real runtime's
//	ValidatorTargetCommitteeSize (blockchain/runtime/src/lib.rs).
//
// Scenario 1: provider=0xAA*32, round=42, candidates=[0x01..0x06]*32 (six
// candidates, more than TargetCommitteeSize, exercising the
// draw-without-replacement-capped-at-target branch). Captured Rust
// output:
//
//	committee[0]=0x06*32
//	committee[1]=0x03*32
//	committee[2]=0x02*32
//	committee[3]=0x01*32
//	committee[4]=0x05*32
//
// Scenario 2: provider=0x02*32 (itself present in the candidate list, and
// must be excluded), round=7, candidates=[0x01,0x02,0x03]*32. Captured
// Rust output:
//
//	committee[0]=0x03*32
//	committee[1]=0x01*32
func TestCommitteeMatchesRustGoldenVector(t *testing.T) {
	t.Run("six_candidates_more_than_target", func(t *testing.T) {
		provider := fill32(0xAA)
		candidates := [][32]byte{fill32(1), fill32(2), fill32(3), fill32(4), fill32(5), fill32(6)}
		want := [][32]byte{fill32(6), fill32(3), fill32(2), fill32(1), fill32(5)}

		got := Committee(provider, 42, candidates, 5)
		assertCommitteeEqual(t, got, want)
	})

	t.Run("provider_present_in_candidates_is_excluded", func(t *testing.T) {
		provider := fill32(0x02)
		candidates := [][32]byte{fill32(1), fill32(2), fill32(3)}
		want := [][32]byte{fill32(3), fill32(1)}

		got := Committee(provider, 7, candidates, 5)
		assertCommitteeEqual(t, got, want)

		if IsAssigned(provider, provider, 7, candidates, 5) {
			t.Fatal("provider must never be assigned to score itself")
		}
	})
}

func assertCommitteeEqual(t *testing.T, got, want [][32]byte) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("committee length = %d, want %d (got=%x want=%x)", len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("committee[%d] = %x, want %x (full got=%x want=%x)", i, got[i], want[i], got, want)
		}
	}
}

func TestIsAssignedMatchesCommitteeMembership(t *testing.T) {
	provider := fill32(0xAA)
	candidates := [][32]byte{fill32(1), fill32(2), fill32(3), fill32(4), fill32(5), fill32(6)}
	committee := Committee(provider, 42, candidates, 5)

	for _, candidate := range candidates {
		want := false
		for _, member := range committee {
			if member == candidate {
				want = true
				break
			}
		}
		if got := IsAssigned(candidate, provider, 42, candidates, 5); got != want {
			t.Fatalf("IsAssigned(%x) = %v, want %v", candidate, got, want)
		}
	}
}
