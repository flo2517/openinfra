// Package networkvalidator implements ADR-013 slice 4
// (docs/adr/013-network-validator-daemon.md, tracked as issue #78): the
// Network Validator's continuous challenge loop -- discovering assigned
// (provider, dimension) work, calling an Agent's SolveChallenge over
// mTLS, scoring the result, and submitting evidence/closing rounds on
// pallet-network-validator. cmd/networkvalidator's `run` subcommand is a
// thin CLI wrapper around this package; the package itself has no
// dependency on flag parsing or os.Args so it stays testable.
package networkvalidator

// DefaultRoundLengthBlocks is this implementation's default round length:
// 100 finalized blocks. At this runtime's ~3-second block time
// (MinimumPeriod=1500ms, SlotDuration=MinimumPeriodTimesTwo -- see
// blockchain/runtime/src/lib.rs), 100 blocks is ~5 minutes, a reasonable
// default cadence for a challenge round: long enough that a
// committee-sized burst of SolveChallenge calls per round is not
// excessive load on any one Agent, short enough that reputation reacts to
// a provider's behavior within a few rounds rather than hours.
//
// *** This is an off-chain convention this validator implementation
// chooses, not something pallet-network-validator enforces or defines. ***
// `round: u64` in submit_evidence/close_round/committee is a plain
// caller-supplied number -- see the pallet source, it is never derived
// from block height by the runtime itself. Any two validator
// implementations must agree on the same round-derivation function (or
// at least converge on the same round value for the same block) for
// their submissions to land in the same Evidence/Rounds entry and
// contribute to the same quorum; nothing on-chain checks or enforces
// that agreement. A future multi-implementation validator ecosystem
// needs to standardize this in its own ADR -- flagged here, not silently
// assumed to be canonical, per this task's explicit instructions.
const DefaultRoundLengthBlocks = 100

// RoundLength is overridable (CLI flag / env var in cmd/networkvalidator)
// precisely because it is a convention, not a protocol constant: an
// operator running against a chain with a different block time, or who
// wants a different challenge cadence, can change it without any pallet
// change. Every validator that wants to land in the same rounds as this
// one must be configured with the same value, though -- see the
// package-level convention note above.
type RoundLength uint64

// Round derives the current round number from a finalized block number:
// round = finalizedBlockNumber / roundLengthBlocks (integer division).
// Round 0 covers blocks [0, roundLengthBlocks), round 1 covers
// [roundLengthBlocks, 2*roundLengthBlocks), and so on. roundLengthBlocks
// of 0 is treated as DefaultRoundLengthBlocks rather than dividing by
// zero, so a zero-value RoundLength (e.g. an unset config field) fails
// safe into the documented default instead of panicking.
func (length RoundLength) Round(finalizedBlockNumber uint64) uint64 {
	blocks := uint64(length)
	if blocks == 0 {
		blocks = DefaultRoundLengthBlocks
	}
	return finalizedBlockNumber / blocks
}
