package blockchainbridge

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
)

// maxProviderKeysPerPage bounds each state_getKeysPaged round trip. The
// active-validator committee loop (ADR-013 slice 4) needs the full
// provider set on every polling tick, so this stays generous rather than
// tuned -- a local dev chain has a handful of providers, and even a large
// deployment's registry is small compared to, say, account storage.
const maxProviderKeysPerPage = 1000

// providerRegistryKeyPrefixLen is the fixed pallet+item prefix
// (twox128("ProviderRegistry") ++ twox128("Providers")) every
// ProviderRegistry::Providers storage key starts with -- 16 bytes per
// segment, matching mapStorageKey's construction below.
const providerRegistryKeyPrefixLen = 32

// mapStorageKeySuffixLen is the Blake2_128Concat(key) ++ key trailer every
// entry's storage key carries after the pallet+item prefix: 16 bytes of
// blake2_128 hash followed by the 32-byte AccountId itself that produced
// it (mapStorageKey builds exactly this for a single known key; this
// enumeration instead has to parse it back out of keys the chain returns,
// since it doesn't already know which accounts exist).
const mapStorageKeySuffixLen = 16 + 32

// FinalizedProviderAccounts enumerates every account currently present as
// a key in pallet-provider-registry's Providers StorageMap, at the
// finalized head. This pallet has no bounded "active set" storage item
// analogous to pallet-network-validator's ActiveValidatorSet -- it has
// never needed one before this method, since every existing caller does a
// single-key lookup (finalizedProvider) rather than enumeration -- so a
// genuine prefix scan is required. Uses state_getKeysPaged, which (unlike
// state_getPairs) is permitted under this project's dev chain's
// --rpc-methods=safe restriction (verified directly against a running
// local node before writing this).
//
// A returned account being present here means only "has a Providers
// entry" -- it says nothing about status (Registered/Verified/Active);
// callers that need to filter by status must still consult
// finalizedProvider-style single-key reads (or FinalizedValidatorRecord's
// sibling for providers, if one is ever added) per account.
func (c *RPCClient) FinalizedProviderAccounts(ctx context.Context) ([][32]byte, error) {
	head, err := c.FinalizedHead(ctx)
	if err != nil {
		return nil, err
	}
	prefix := providerRegistryKeysPrefix()
	var accounts [][32]byte
	startKey := ""
	for {
		keys, err := c.stateGetKeysPaged(ctx, prefix, maxProviderKeysPerPage, startKey, head)
		if err != nil {
			return nil, err
		}
		if len(keys) == 0 {
			break
		}
		for _, key := range keys {
			account, err := decodeProviderAccountFromKey(key)
			if err != nil {
				return nil, err
			}
			accounts = append(accounts, account)
		}
		if len(keys) < maxProviderKeysPerPage {
			break
		}
		// Substrate's paging is exclusive-of-startKey-only-if-equal, i.e.
		// requesting again with the last returned key as startKey resumes
		// immediately after it -- the standard state_getKeysPaged
		// pagination idiom.
		startKey = keys[len(keys)-1]
	}
	return accounts, nil
}

// stateGetKeysPaged calls state_getKeysPaged(prefix, count, startKey, at)
// -- a safelisted RPC method distinct from RPCClient's other read helpers
// in rpc.go because it's the only one this package needs that returns a
// list of storage *keys* rather than a single value, and takes pagination
// parameters none of the existing methods need.
func (c *RPCClient) stateGetKeysPaged(ctx context.Context, prefix string, count int, startKey, blockHash string) ([]string, error) {
	var keys []string
	var startParam any
	if startKey == "" {
		startParam = nil
	} else {
		startParam = startKey
	}
	if err := c.call(ctx, "state_getKeysPaged", []any{prefix, count, startParam, blockHash}, &keys); err != nil {
		return nil, err
	}
	return keys, nil
}

// providerRegistryKeysPrefix returns the fixed 32-byte
// twox128("ProviderRegistry") ++ twox128("Providers") prefix every
// Providers entry's storage key starts with, hex-encoded the same way
// mapStorageKey's callers expect.
func providerRegistryKeysPrefix() string {
	key := append(twox128([]byte("ProviderRegistry")), twox128([]byte("Providers"))...)
	return "0x" + hex.EncodeToString(key)
}

// decodeProviderAccountFromKey extracts the 32-byte AccountId from one
// full storage key returned by a state_getKeysPaged scan under the
// Providers prefix: prefix(32) ++ blake2_128(account)(16) ++ account(32).
// The middle 16 bytes are the Blake2_128Concat hash component and are not
// needed to recover the account -- only the trailing 32 bytes are, which
// is exactly the "key" half of "hash-and-key" that Blake2_128Concat (as
// opposed to plain Blake2_128) preserves for this reason.
func decodeProviderAccountFromKey(key string) ([32]byte, error) {
	var account [32]byte
	decoded, err := decodeHex(key)
	if err != nil {
		return account, fmt.Errorf("decode provider registry key: %w", err)
	}
	if len(decoded) != providerRegistryKeyPrefixLen+mapStorageKeySuffixLen {
		return account, errors.New("provider registry key has an unexpected length")
	}
	copy(account[:], decoded[providerRegistryKeyPrefixLen+16:])
	return account, nil
}
