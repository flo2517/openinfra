package blockchainbridge

import (
	"context"
	"encoding/binary"
	"errors"
)

// ProviderRewardPoints reads pallet-rewards' RewardBalances map at
// blockHash for provider (its raw 32-byte on-chain account, the same key
// the registrar registers -- not the sha256-derived provider_id used in
// Postgres and on the dashboard).
//
// RewardBalances is declared ValueQuery, so a provider that has never
// been credited simply has no storage entry: absence means zero points,
// not a missing record. This returns 0 for that case rather than a
// found=false flag, because on-chain "no entry" and "zero points" are the
// same statement here -- unlike ReputationVectors (OptionQuery), where
// "not yet scored" is genuinely distinct from a score of zero and
// ProviderReputationVector reports it as such.
//
// A read *failure* stays an error and is never flattened into 0. An
// operator looking at an earnings figure must be able to tell "this
// provider has earned nothing" from "we could not ask the chain", which
// is the same false-green rule the rest of this bridge follows.
func (c *RPCClient) ProviderRewardPoints(ctx context.Context, provider [32]byte, blockHash string) (uint64, error) {
	value, found, err := c.Storage(ctx, rewardBalanceStorageKey(provider), blockHash)
	if err != nil {
		return 0, err
	}
	if !found {
		return 0, nil
	}
	return decodeRewardPoints(value)
}

// LatestProviderRewardPoints resolves the current finalized head and
// reads ProviderRewardPoints at it, for callers with no reason to pin a
// specific block (the dashboard's provider view).
func (c *RPCClient) LatestProviderRewardPoints(ctx context.Context, provider [32]byte) (uint64, error) {
	head, err := c.FinalizedHead(ctx)
	if err != nil {
		return 0, err
	}
	return c.ProviderRewardPoints(ctx, provider, head)
}

func rewardBalanceStorageKey(provider [32]byte) string {
	return mapStorageKey("Rewards", "RewardBalances", provider)
}

// decodeRewardPoints decodes pallet_rewards::RewardPoints, a plain u64 --
// fixed width, little-endian, no compact prefix, matching every other
// plain-scalar decode in this package.
func decodeRewardPoints(data []byte) (uint64, error) {
	if len(data) != 8 {
		return 0, errors.New("reward points have an unexpected encoded length")
	}
	return binary.LittleEndian.Uint64(data), nil
}
