package blockchainbridge

import (
	"context"
	"encoding/binary"
	"errors"
)

// ReputationVector mirrors pallet-reputation's on-chain
// ReputationVector exactly: six u32 fields, in declaration order, never a
// float. This is a distinct type from sharedv1.ReputationVector (the
// wire/display float32 format) on purpose -- scheduler ranking must never
// let a float re-enter the comparison path this decodes into.
type ReputationVector struct {
	Compute, Storage, Network, Availability, Reliability, Global uint32
}

// ProviderReputationVector reads pallet-reputation's ReputationVectors map
// at blockHash for provider (its raw 32-byte on-chain account, the same
// key EnsureActive registers -- not the sha256-derived provider_id used
// in Postgres/dashboard). found is false when the provider has no
// on-chain reputation record yet, which is a normal state (not yet
// scored), distinct from a read failure.
func (c *RPCClient) ProviderReputationVector(ctx context.Context, provider [32]byte, blockHash string) (ReputationVector, bool, error) {
	value, found, err := c.Storage(ctx, reputationVectorStorageKey(provider), blockHash)
	if err != nil {
		return ReputationVector{}, false, err
	}
	if !found {
		return ReputationVector{}, false, nil
	}
	vector, err := decodeReputationVector(value)
	if err != nil {
		return ReputationVector{}, false, err
	}
	return vector, true, nil
}

// LatestReputationVector resolves the current finalized head and reads
// ProviderReputationVector at it -- the convenience form callers that
// don't otherwise need a specific block hash (e.g. the scheduler) should
// use.
func (c *RPCClient) LatestReputationVector(ctx context.Context, provider [32]byte) (ReputationVector, bool, error) {
	head, err := c.FinalizedHead(ctx)
	if err != nil {
		return ReputationVector{}, false, err
	}
	return c.ProviderReputationVector(ctx, provider, head)
}

func reputationVectorStorageKey(provider [32]byte) string {
	return mapStorageKey("Reputation", "ReputationVectors", provider)
}

// decodeReputationVector decodes six fixed-width u32 fields (24 bytes
// total, no compact prefixes -- plain struct fields, unlike the compact
// length-prefixed Vec decodeAccountIdVec handles), in the same order
// pallet_reputation::pallet::ReputationVector declares them:
// compute, storage, network, availability, reliability, global.
func decodeReputationVector(data []byte) (ReputationVector, error) {
	const fieldCount = 6
	if len(data) != fieldCount*4 {
		return ReputationVector{}, errors.New("reputation vector has an unexpected encoded length")
	}
	return ReputationVector{
		Compute:      binary.LittleEndian.Uint32(data[0:4]),
		Storage:      binary.LittleEndian.Uint32(data[4:8]),
		Network:      binary.LittleEndian.Uint32(data[8:12]),
		Availability: binary.LittleEndian.Uint32(data[12:16]),
		Reliability:  binary.LittleEndian.Uint32(data[16:20]),
		Global:       binary.LittleEndian.Uint32(data[20:24]),
	}, nil
}
