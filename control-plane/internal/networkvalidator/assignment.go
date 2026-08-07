package networkvalidator

import "github.com/openinfra/network/internal/blockchainbridge"

// Dimensions enumerates every ScoreDimension this validator's challenge
// loop scores, in the pallet's own declaration order (blockchainbridge.
// ScoreDimension's doc comment explains why that order matters for SCALE
// encoding elsewhere; here it only affects iteration/log order, but
// keeping the same order avoids a second, possibly-diverging ordering to
// reason about).
var Dimensions = []blockchainbridge.ScoreDimension{
	blockchainbridge.DimensionCompute,
	blockchainbridge.DimensionStorage,
	blockchainbridge.DimensionNetwork,
	blockchainbridge.DimensionAvailability,
	blockchainbridge.DimensionReliability,
}

// roundKey identifies one (provider, round, dimension) unit of work --
// the same granularity pallet-network-validator's Evidence/Rounds storage
// is keyed by.
type roundKey struct {
	provider  [32]byte
	round     uint64
	dimension blockchainbridge.ScoreDimension
}

// AssignedWork computes, purely from already-fetched public inputs, the
// (provider, dimension) pairs this validator (self) is locally assigned
// to challenge for round, among providers, skipping anything already
// present in done. No chain call happens inside this function -- it is
// the local, ADR-011-§1-endorsed replacement for asking the chain "am I
// assigned," built entirely on blockchainbridge.Committee. Kept separate
// from the I/O-driving loop in run.go so the assignment-selection logic
// itself is directly unit-testable without a mock RPC server.
func AssignedWork(self [32]byte, providers [][32]byte, round uint64, activeValidators [][32]byte, targetCommitteeSize uint32, done map[roundKey]bool) []roundKey {
	var assigned []roundKey
	for _, provider := range providers {
		// A validator is never assigned to score itself -- committee()
		// already excludes the provider account from candidates, so this
		// is redundant with that filter, not a separate rule; kept as an
		// explicit early-continue purely to avoid the wasted per-dimension
		// Committee() calls below when it's already certain to be false.
		if provider == self {
			continue
		}
		committee := blockchainbridge.Committee(provider, round, activeValidators, targetCommitteeSize)
		inCommittee := false
		for _, member := range committee {
			if member == self {
				inCommittee = true
				break
			}
		}
		if !inCommittee {
			continue
		}
		for _, dimension := range Dimensions {
			key := roundKey{provider: provider, round: round, dimension: dimension}
			if done[key] {
				continue
			}
			assigned = append(assigned, key)
		}
	}
	return assigned
}
