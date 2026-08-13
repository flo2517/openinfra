package blockchainbridge

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
)

// Submission mirrors pallet_network_validator::pallet::Submission
// (blockchain/pallets/network-validator/src/lib.rs) field for field: one
// Network Validator's attributable observation of one provider, for one
// round and dimension. PayloadHash addresses the full evidence off-chain
// (ADR-011 §3) -- only this bounded integer summary is ever in consensus
// state, so a reader gets the *claim* and its address, never the payload.
type Submission struct {
	Validator   [32]byte
	ScoreBps    uint16
	SampleCount uint32
	PayloadHash [32]byte
}

// submissionEncodedLength is Submission's fixed SCALE width: AccountId
// (32) ++ u16 (2) ++ u32 (4) ++ [u8; 32] (32). No field is compact or
// variable-length, so every element in the vec is exactly this wide and
// the vec's total length is checkable up front rather than discovered by
// running off the end mid-decode.
const submissionEncodedLength = 32 + 2 + 4 + 32

// NetworkValidatorMaxSubmissionsPerRound mirrors the runtime's
// MaxValidatorSubmissionsPerRound constant (blockchain/runtime/src/lib.rs,
// wired to pallet_network_validator::Config::MaxSubmissionsPerRound).
// Like NetworkValidatorTargetCommitteeSize it is duplicated here rather
// than read off the chain: the value is a runtime constant, not storage,
// and reading it live would mean decoding the full metadata blob on every
// call. It is used only as a sanity bound on a decoded length prefix --
// a wrong value here rejects an over-long vec, it never changes what the
// chain accepts.
const NetworkValidatorMaxSubmissionsPerRound uint64 = 32

// FinalizedEvidence reads pallet-network-validator's Evidence NMap for
// (provider, round, dimension) at the current finalized head: the
// submissions received so far for a round that has not closed yet.
//
// Evidence is declared ValueQuery over a BoundedVec, so "no storage entry"
// and "an entry holding an empty vec" are the same state on-chain -- both
// mean nobody has submitted. This returns an empty slice with a nil error
// for that case rather than a found flag, because unlike Rounds (where
// absent means "this round never closed", a genuinely different state
// from a closed one) there is nothing for a caller to distinguish.
//
// A round that has already closed keeps its Evidence entry until
// close_round removes it; callers that want "open rounds only" should
// check FinalizedRoundResult as well rather than inferring openness from
// an empty result here.
func (c *RPCClient) FinalizedEvidence(ctx context.Context, provider [32]byte, round uint64, dimension ScoreDimension) ([]Submission, error) {
	head, err := c.FinalizedHead(ctx)
	if err != nil {
		return nil, err
	}
	value, found, err := c.Storage(ctx, evidenceStorageKey(provider, round, dimension), head)
	if err != nil {
		return nil, err
	}
	if !found {
		return []Submission{}, nil
	}
	return decodeSubmissions(value)
}

// evidenceStorageKey addresses pallet-network-validator's Evidence
// StorageNMap -- same three key components and hashers as Rounds, hence
// the shared construction.
func evidenceStorageKey(provider [32]byte, round uint64, dimension ScoreDimension) string {
	return networkValidatorRoundKey("Evidence", provider, round, dimension)
}

// decodeSubmissions decodes a SCALE Vec<Submission>: a compact length
// prefix followed by that many fixed-width elements. The length is
// checked against both the runtime bound and the actual remaining bytes
// before any element is read, so a corrupt or truncated value is an error
// rather than a partial slice or an allocation sized by untrusted input.
func decodeSubmissions(data []byte) ([]Submission, error) {
	count, prefixLength, err := decodeCompactUint(data)
	if err != nil {
		return nil, fmt.Errorf("evidence vec length: %w", err)
	}
	if count > NetworkValidatorMaxSubmissionsPerRound {
		return nil, errors.New("evidence vec claims more submissions than the runtime bound allows")
	}
	body := data[prefixLength:]
	if len(body) != int(count)*submissionEncodedLength {
		return nil, errors.New("evidence vec has an unexpected encoded length")
	}
	submissions := make([]Submission, 0, count)
	for offset := 0; offset < len(body); offset += submissionEncodedLength {
		element := body[offset : offset+submissionEncodedLength]
		var submission Submission
		copy(submission.Validator[:], element[0:32])
		submission.ScoreBps = binary.LittleEndian.Uint16(element[32:34])
		submission.SampleCount = binary.LittleEndian.Uint32(element[34:38])
		copy(submission.PayloadHash[:], element[38:70])
		submissions = append(submissions, submission)
	}
	return submissions, nil
}
