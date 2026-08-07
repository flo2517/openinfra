package blockchainbridge

import (
	"context"
	"encoding/hex"
	"errors"
)

// ActiveNetworkValidators reads pallet-network-validator's
// ActiveValidatorSet at blockHash (callers pass the finalized head they
// already have, e.g. from FinalizedHead, to avoid a redundant RPC round
// trip) and returns the raw account ids it holds. Read-only,
// dashboard-facing: it never submits anything, and a failure here must
// never be mistaken for "zero validators" by the caller (see dashboard.go,
// which treats an error as "unavailable", not "empty").
func (c *RPCClient) ActiveNetworkValidators(ctx context.Context, blockHash string) ([][32]byte, error) {
	value, found, err := c.Storage(ctx, networkValidatorStorageKey("ActiveValidatorSet"), blockHash)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return decodeAccountIdVec(value)
}

// LatestActiveNetworkValidators resolves the current finalized head and
// reads ActiveNetworkValidators at it -- the convenience form callers that
// don't otherwise need a specific block hash (e.g. the heartbeat path
// pushing the allowlist to Agents, ADR-013 §3) should use, mirroring
// LatestReputationVector's role for reputation.go.
func (c *RPCClient) LatestActiveNetworkValidators(ctx context.Context) ([][32]byte, error) {
	head, err := c.FinalizedHead(ctx)
	if err != nil {
		return nil, err
	}
	return c.ActiveNetworkValidators(ctx, head)
}

// networkValidatorStorageKey addresses a StorageValue item (no map key
// component), unlike mapStorageKey which hashes a lookup key onto the
// prefix. "NetworkValidator" must match the pallet's identifier in
// construct_runtime! exactly, the same convention providerStorageKey
// relies on for "ProviderRegistry".
func networkValidatorStorageKey(item string) string {
	key := append(twox128([]byte("NetworkValidator")), twox128([]byte(item))...)
	return "0x" + hex.EncodeToString(key)
}

// decodeAccountIdVec decodes a SCALE-encoded BoundedVec<AccountId32, _>:
// a compact length prefix followed by that many 32-byte account ids.
func decodeAccountIdVec(data []byte) ([][32]byte, error) {
	count, offset, err := decodeCompactUint(data)
	if err != nil {
		return nil, err
	}
	remaining := uint64(len(data) - offset)
	if remaining != count*32 {
		return nil, errors.New("account id vector length does not match its prefix")
	}
	accounts := make([][32]byte, 0, count)
	for i := uint64(0); i < count; i++ {
		var account [32]byte
		copy(account[:], data[offset+int(i)*32:offset+int(i+1)*32])
		accounts = append(accounts, account)
	}
	return accounts, nil
}

// decodeCompactUint decodes a SCALE compact-encoded unsigned integer from
// the start of data, mirroring compactUint's encoding one mode at a time.
// Returns the value and how many bytes it occupied.
func decodeCompactUint(data []byte) (uint64, int, error) {
	if len(data) == 0 {
		return 0, 0, errors.New("compact integer: empty input")
	}
	switch data[0] & 0b11 {
	case 0:
		return uint64(data[0] >> 2), 1, nil
	case 1:
		if len(data) < 2 {
			return 0, 0, errors.New("compact integer: truncated two-byte mode")
		}
		return uint64(uint16(data[0])|uint16(data[1])<<8) >> 2, 2, nil
	case 2:
		if len(data) < 4 {
			return 0, 0, errors.New("compact integer: truncated four-byte mode")
		}
		value := uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24
		return uint64(value) >> 2, 4, nil
	default: // big-integer mode
		length := int(data[0]>>2) + 4
		if len(data) < 1+length {
			return 0, 0, errors.New("compact integer: truncated big-integer mode")
		}
		var value uint64
		for i := length - 1; i >= 0; i-- {
			value = value<<8 | uint64(data[1+i])
		}
		return value, 1 + length, nil
	}
}
