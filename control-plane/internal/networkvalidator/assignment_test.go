package networkvalidator

import (
	"testing"

	"github.com/openinfra/network/internal/blockchainbridge"
)

// fill32 mirrors blockchainbridge's own test helper of the same name
// (unexported there, so duplicated here rather than exported solely for
// tests): a 32-byte value with every byte set to b, matching how the
// captured Rust golden vectors were constructed
// (AccountId32::new([b; 32])).
func fill32(b byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = b
	}
	return out
}

func TestAssignedWorkSelectsEveryDimensionForAnAssignedProvider(t *testing.T) {
	self := fill32(6) // committee[0] in the six-candidate golden vector (round 42)
	provider := fill32(0xAA)
	activeValidators := [][32]byte{fill32(1), fill32(2), fill32(3), fill32(4), fill32(5), fill32(6)}

	work := AssignedWork(self, [][32]byte{provider}, 42, activeValidators, 5, nil)
	if len(work) != len(Dimensions) {
		t.Fatalf("got %d assignments, want %d (one per dimension)", len(work), len(Dimensions))
	}
	seen := make(map[blockchainbridge.ScoreDimension]bool)
	for _, key := range work {
		if key.provider != provider || key.round != 42 {
			t.Fatalf("unexpected key %+v", key)
		}
		seen[key.dimension] = true
	}
	for _, dimension := range Dimensions {
		if !seen[dimension] {
			t.Fatalf("dimension %s missing from assigned work", dimension)
		}
	}
}

func TestAssignedWorkSkipsAnUnassignedProvider(t *testing.T) {
	self := fill32(9) // not in the six-candidate active set at all
	provider := fill32(0xAA)
	activeValidators := [][32]byte{fill32(1), fill32(2), fill32(3), fill32(4), fill32(5), fill32(6)}

	work := AssignedWork(self, [][32]byte{provider}, 42, activeValidators, 5, nil)
	if len(work) != 0 {
		t.Fatalf("got %d assignments, want 0 for an unassigned validator", len(work))
	}
}

func TestAssignedWorkSkipsAlreadyDoneKeys(t *testing.T) {
	self := fill32(6)
	provider := fill32(0xAA)
	activeValidators := [][32]byte{fill32(1), fill32(2), fill32(3), fill32(4), fill32(5), fill32(6)}
	done := map[roundKey]bool{
		{provider: provider, round: 42, dimension: blockchainbridge.DimensionCompute}: true,
	}

	work := AssignedWork(self, [][32]byte{provider}, 42, activeValidators, 5, done)
	if len(work) != len(Dimensions)-1 {
		t.Fatalf("got %d assignments, want %d (all but the already-done one)", len(work), len(Dimensions)-1)
	}
	for _, key := range work {
		if key.dimension == blockchainbridge.DimensionCompute {
			t.Fatal("already-done dimension must not be re-assigned")
		}
	}
}

func TestAssignedWorkNeverAssignsAProviderToItself(t *testing.T) {
	self := fill32(0xAA)
	// self also appears as a "provider" in the input list -- committee()
	// must exclude it from its own candidate pool, and AssignedWork's
	// early continue is a redundant belt-and-braces check on top of that.
	work := AssignedWork(self, [][32]byte{self}, 42, [][32]byte{fill32(1), self, fill32(2)}, 5, nil)
	if len(work) != 0 {
		t.Fatalf("got %d assignments, want 0: a validator must never be assigned to itself", len(work))
	}
}
