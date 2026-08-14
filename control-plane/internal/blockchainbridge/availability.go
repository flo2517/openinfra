package blockchainbridge

import (
	"context"
	"encoding/binary"
	"errors"
)

// AvailabilitySummary mirrors pallet-availability's on-chain
// AvailabilitySummary<BlockNumber>: the most recent availability proof a
// provider submitted. Integer fields only -- AvailabilityBps is basis
// points (0..=10_000), never a float, matching the pallet's own type and
// the no-float rule that applies to everything crossing this boundary.
type AvailabilitySummary struct {
	Sequence          uint64
	ObservedAt        uint32
	SuccessfulSamples uint32
	TotalSamples      uint32
	AvailabilityBps   uint16
	PayloadHash       [32]byte
	// Signature is the provider's signature over the proof. Carried as
	// raw bytes because this bridge does not re-verify it: the pallet
	// already did, at submission, and a second verification here against
	// a different key source would be a second, divergent authority on
	// what a valid proof is.
	Signature []byte
}

// ProviderLatestProof reads pallet-availability's LatestProof map at
// blockHash for provider (its raw 32-byte on-chain account). found is
// false when the provider has never submitted a proof -- a normal state
// for a freshly joined provider, and deliberately distinct from a read
// failure, which returns an error.
func (c *RPCClient) ProviderLatestProof(ctx context.Context, provider [32]byte, blockHash string) (AvailabilitySummary, bool, error) {
	value, found, err := c.Storage(ctx, latestProofStorageKey(provider), blockHash)
	if err != nil {
		return AvailabilitySummary{}, false, err
	}
	if !found {
		return AvailabilitySummary{}, false, nil
	}
	summary, err := decodeAvailabilitySummary(value)
	if err != nil {
		return AvailabilitySummary{}, false, err
	}
	return summary, true, nil
}

// LatestProviderProof resolves the current finalized head and reads
// ProviderLatestProof at it.
func (c *RPCClient) LatestProviderProof(ctx context.Context, provider [32]byte) (AvailabilitySummary, bool, error) {
	head, err := c.FinalizedHead(ctx)
	if err != nil {
		return AvailabilitySummary{}, false, err
	}
	return c.ProviderLatestProof(ctx, provider, head)
}

func latestProofStorageKey(provider [32]byte) string {
	return mapStorageKey("Availability", "LatestProof", provider)
}

// decodeAvailabilitySummary decodes AvailabilitySummary's fields in
// declaration order. Unlike the plain-struct decodes elsewhere in this
// package, this one is not fixed-length: the trailing
// BoundedVec<u8, ConstU32<96>> signature carries a SCALE compact length
// prefix, so the total size varies with the signature's actual length
// (64 bytes for Ed25519 today, but the pallet's bound allows up to 96).
//
// The fixed part is 8 + 4 + 4 + 4 + 2 + 32 = 54 bytes: sequence u64,
// observed_at BlockNumber (u32 in this runtime, same as RoundResult's
// closed_at), successful_samples u32, total_samples u32,
// availability_bps u16, payload_hash [u8; 32].
func decodeAvailabilitySummary(data []byte) (AvailabilitySummary, error) {
	const fixedLength = 8 + 4 + 4 + 4 + 2 + 32
	// The pallet's own bound. Decoding a longer signature than the chain
	// can store would mean this decoder and the pallet disagree about the
	// type, which is worth failing on rather than papering over.
	const maxSignatureLength = 96

	if len(data) < fixedLength {
		return AvailabilitySummary{}, errors.New("availability summary is shorter than its fixed fields")
	}
	summary := AvailabilitySummary{
		Sequence:          binary.LittleEndian.Uint64(data[0:8]),
		ObservedAt:        binary.LittleEndian.Uint32(data[8:12]),
		SuccessfulSamples: binary.LittleEndian.Uint32(data[12:16]),
		TotalSamples:      binary.LittleEndian.Uint32(data[16:20]),
		AvailabilityBps:   binary.LittleEndian.Uint16(data[20:22]),
	}
	copy(summary.PayloadHash[:], data[22:54])

	length, prefixSize, err := decodeCompactUint(data[fixedLength:])
	if err != nil {
		return AvailabilitySummary{}, err
	}
	if length > maxSignatureLength {
		return AvailabilitySummary{}, errors.New("availability summary signature exceeds the pallet's bound")
	}
	start := fixedLength + prefixSize
	if uint64(len(data)) != uint64(start)+length {
		return AvailabilitySummary{}, errors.New("availability summary has an unexpected encoded length")
	}
	summary.Signature = append([]byte(nil), data[start:]...)
	return summary, nil
}
