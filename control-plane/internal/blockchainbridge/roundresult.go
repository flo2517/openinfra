package blockchainbridge

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"

	"github.com/OneOfOne/xxhash"
	"golang.org/x/crypto/blake2b"
)

// RoundStatus mirrors pallet-network-validator::RoundStatus byte-for-byte
// (declaration order = SCALE variant tag): Final, Disputed,
// DisputeUpheld, DisputeRejected.
type RoundStatus byte

const (
	RoundFinal RoundStatus = iota
	RoundDisputed
	RoundDisputeUpheld
	RoundDisputeRejected
)

func (s RoundStatus) String() string {
	switch s {
	case RoundFinal:
		return "final"
	case RoundDisputed:
		return "disputed"
	case RoundDisputeUpheld:
		return "dispute_upheld"
	case RoundDisputeRejected:
		return "dispute_rejected"
	default:
		return "unknown"
	}
}

// RoundResult mirrors pallet_network_validator::pallet::RoundResult
// exactly (blockchain/pallets/network-validator/src/lib.rs).
type RoundResult struct {
	ScoreBps         uint16
	PreviousScoreBps uint16
	Submissions      uint32
	CommitteeTarget  uint32
	ClosedAt         uint32
	Status           RoundStatus
}

// Confidence is Submissions/CommitteeTarget as a 0..10_000 basis-point
// figure -- a thin display value over RoundResult, not a new decode --
// exposed as its own method so a dashboard can distinguish a
// well-attested score from a thin one without recomputing this everywhere
// (issue #76's "score history... without false success" acceptance
// criterion). 0 CommitteeTarget (should not happen in practice, but a
// decoded value is still just bytes off the chain, never trusted blindly)
// returns 0 rather than dividing by zero.
func (r RoundResult) ConfidenceBps() uint32 {
	if r.CommitteeTarget == 0 {
		return 0
	}
	confidence := uint64(r.Submissions) * 10_000 / uint64(r.CommitteeTarget)
	if confidence > 10_000 {
		confidence = 10_000
	}
	return uint32(confidence)
}

// FinalizedRoundResult reads pallet-network-validator's Rounds NMap for
// (provider, round, dimension) at the current finalized head. found is
// false when the round hasn't closed yet (no close_round call has landed
// for it) -- a normal, common state for a round still in progress or one
// that never reached quorum, distinct from a read failure.
func (c *RPCClient) FinalizedRoundResult(ctx context.Context, provider [32]byte, round uint64, dimension ScoreDimension) (RoundResult, bool, error) {
	head, err := c.FinalizedHead(ctx)
	if err != nil {
		return RoundResult{}, false, err
	}
	value, found, err := c.Storage(ctx, roundResultStorageKey(provider, round, dimension), head)
	if err != nil || !found {
		return RoundResult{}, found, err
	}
	result, err := decodeRoundResult(value)
	if err != nil {
		return RoundResult{}, false, err
	}
	return result, true, nil
}

// roundResultStorageKey addresses pallet-network-validator's Rounds
// StorageNMap, keyed (Blake2_128Concat AccountId, Twox64Concat u64,
// Twox64Concat ScoreDimension) -- unlike mapStorageKey's single hashed
// key, an NMap's storage key is the pallet/item prefix followed by each
// key component's own hasher output concatenated in declaration order,
// each one immediately followed by that component's own raw SCALE
// encoding (the "Concat" half of each hasher's name). Evidence uses the
// identical key shape (same three key types, same hashers) -- if a
// caller ever needs to read Evidence too, this same construction applies
// with "Evidence" in place of "Rounds".
func roundResultStorageKey(provider [32]byte, round uint64, dimension ScoreDimension) string {
	key := append(twox128([]byte("NetworkValidator")), twox128([]byte("Rounds"))...)

	providerDigest, _ := blake2b.New(16, nil)
	_, _ = providerDigest.Write(provider[:])
	key = append(key, providerDigest.Sum(nil)...)
	key = append(key, provider[:]...)

	roundEncoded := make([]byte, 8)
	binary.LittleEndian.PutUint64(roundEncoded, round)
	key = append(key, twox64(roundEncoded)...)
	key = append(key, roundEncoded...)

	dimensionEncoded := []byte{byte(dimension)}
	key = append(key, twox64(dimensionEncoded)...)
	key = append(key, dimensionEncoded...)

	return "0x" + hex.EncodeToString(key)
}

// twox64 is twox128's 8-byte sibling (Twox64Concat's hash component): a
// single xxHash64 pass with seed 0, matching Substrate's twox_64 exactly
// -- twox128 concatenates two differently-seeded 8-byte checksums,
// twox64 is just the first of those on its own.
func twox64(value []byte) []byte {
	result := make([]byte, 8)
	binary.LittleEndian.PutUint64(result, xxhash.Checksum64S(value, 0))
	return result
}

// decodeRoundResult decodes RoundResult's six fixed-width fields in
// declaration order -- no compact encoding, no length prefix, matching
// every other plain-struct decode in this package (e.g.
// decodeReputationVector).
func decodeRoundResult(data []byte) (RoundResult, error) {
	const wantLength = 2 + 2 + 4 + 4 + 4 + 1
	if len(data) != wantLength {
		return RoundResult{}, errors.New("round result has an unexpected encoded length")
	}
	status := RoundStatus(data[16])
	if status > RoundDisputeRejected {
		return RoundResult{}, errors.New("round result has an unknown status variant")
	}
	return RoundResult{
		ScoreBps:         binary.LittleEndian.Uint16(data[0:2]),
		PreviousScoreBps: binary.LittleEndian.Uint16(data[2:4]),
		Submissions:      binary.LittleEndian.Uint32(data[4:8]),
		CommitteeTarget:  binary.LittleEndian.Uint32(data[8:12]),
		ClosedAt:         binary.LittleEndian.Uint32(data[12:16]),
		Status:           status,
	}, nil
}
