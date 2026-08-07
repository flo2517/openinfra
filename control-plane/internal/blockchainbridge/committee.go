package blockchainbridge

import (
	"encoding/binary"

	"golang.org/x/crypto/blake2b"
)

// NetworkValidatorTargetCommitteeSize mirrors the runtime's
// ValidatorTargetCommitteeSize constant (blockchain/runtime/src/lib.rs,
// wired to pallet_network_validator::Config::TargetCommitteeSize). Like
// this package's other runtime-shape constants (supportedSpecVersion,
// the various pallet/call indices in registrar.go and
// networkvalidatorregistrar.go), this is a value this Go code must be
// kept in sync with by hand -- there is no runtime API this off-chain
// client can query it from at the safe RPC surface this project uses
// (state_getMetadata would expose it, but nothing here parses metadata
// today; hard-coding it here matches the existing pattern rather than
// introducing a new one for a single constant).
const NetworkValidatorTargetCommitteeSize uint32 = 5

// Committee replicates pallet-network-validator::Pallet::committee's
// selection bit-for-bit (blockchain/pallets/network-validator/src/lib.rs).
// It is a pure function of public inputs -- ADR-011 §1's explicit design:
// assignment is publicly computable once the active validator set and
// round number are known, not secret -- so this Go port needs no chain
// call beyond having already read activeValidators (e.g. via
// LatestActiveNetworkValidators) at some finalized block.
//
// activeValidators must be in the exact order ActiveValidatorSet's
// on-chain BoundedVec holds them (insertion order, order-preserving
// removals) -- the pallet's own doc comment on leave_active_set explains
// why a swap_remove would have silently reshuffled assignments, which is
// precisely why the runtime doesn't use one; this port must read the set
// with that same ordering guarantee (ActiveNetworkValidators/
// LatestActiveNetworkValidators already provide it, see networkvalidator.go).
//
// Algorithm (verified byte-for-byte against a real 32-byte-AccountId32
// pallet run -- see this PR's description for how the golden vectors
// below were captured):
//
//  1. candidates := activeValidators with provider filtered out.
//  2. wanted := min(targetCommitteeSize, len(candidates)).
//  3. for nth in 0..wanted:
//     seed := blake2_256(provider ++ le_u64(round) ++ le_u32(nth))
//     index := le_u64(seed[0:8]) % len(candidates)
//     committee = append(committee, candidates[index])
//     candidates = candidates with index removed (order-preserving,
//     i.e. Vec::remove semantics -- draw without replacement)
func Committee(provider [32]byte, round uint64, activeValidators [][32]byte, targetCommitteeSize uint32) [][32]byte {
	candidates := make([][32]byte, 0, len(activeValidators))
	for _, candidate := range activeValidators {
		if candidate != provider {
			candidates = append(candidates, candidate)
		}
	}
	wanted := int(targetCommitteeSize)
	if wanted > len(candidates) {
		wanted = len(candidates)
	}
	committee := make([][32]byte, 0, wanted)
	for nth := 0; nth < wanted; nth++ {
		seed := committeeSeed(provider, round, uint32(nth))
		index := binary.LittleEndian.Uint64(seed[:8]) % uint64(len(candidates))
		committee = append(committee, candidates[index])
		// Vec::remove(index): shift everything after index down by one,
		// preserving the relative order of what remains -- not a
		// swap_remove, matching the pallet exactly (see doc comment above).
		candidates = append(candidates[:index], candidates[index+1:]...)
	}
	return committee
}

// IsAssigned reports whether validator holds a committee slot for
// (provider, round) under the same committee() computation, mirroring the
// pallet's own is_assigned helper -- used by the challenge loop to decide
// locally, with no extra chain call, whether this validator process
// should challenge a given provider this round.
func IsAssigned(validator, provider [32]byte, round uint64, activeValidators [][32]byte, targetCommitteeSize uint32) bool {
	for _, member := range Committee(provider, round, activeValidators, targetCommitteeSize) {
		if member == validator {
			return true
		}
	}
	return false
}

// committeeSeed reproduces blake2_256(SCALE_encode((provider: AccountId32,
// round: u64, nth: u32))). SCALE-encoding a tuple is just the
// concatenation of each field's own encoding: AccountId32 is 32 raw
// bytes, u64/u32 are fixed-width little-endian -- no compact encoding,
// no length prefix (this isn't a Vec/BoundedVec). blake2_256 is
// Substrate's name for blake2b with a 32-byte (256-bit) digest.
func committeeSeed(provider [32]byte, round uint64, nth uint32) [32]byte {
	input := make([]byte, 0, 32+8+4)
	input = append(input, provider[:]...)
	input = binary.LittleEndian.AppendUint64(input, round)
	input = binary.LittleEndian.AppendUint32(input, nth)
	return blake2b.Sum256(input)
}
