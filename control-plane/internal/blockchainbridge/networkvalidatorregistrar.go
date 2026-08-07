package blockchainbridge

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
)

// pallet-network-validator lives at construct_runtime! pallet_index 16
// (blockchain/runtime/src/lib.rs); call indices match its
// #[pallet::call_index(N)] declarations in source order.
const (
	networkValidatorPalletIndex = 16
	registerValidatorCallIndex  = 0
	requestExitCallIndex        = 1
	withdrawUnbondedCallIndex   = 2
	submitEvidenceCallIndex     = 5
	closeRoundCallIndex         = 6
)

// ScoreDimension mirrors pallet-network-validator::ScoreDimension
// (blockchain/pallets/network-validator/src/lib.rs) byte-for-byte: a
// C-like enum with no associated data, so its SCALE encoding is a single
// byte equal to its declaration-order variant index. That order --
// Compute, Storage, Network, Availability, Reliability -- must track the
// pallet's `pub enum ScoreDimension { ... }` exactly; it is not
// alphabetical and not the same order agent.proto's
// SolveChallengeRequest.Type declares its variants in.
type ScoreDimension byte

const (
	DimensionCompute ScoreDimension = iota
	DimensionStorage
	DimensionNetwork
	DimensionAvailability
	DimensionReliability
)

func (d ScoreDimension) String() string {
	switch d {
	case DimensionCompute:
		return "compute"
	case DimensionStorage:
		return "storage"
	case DimensionNetwork:
		return "network"
	case DimensionAvailability:
		return "availability"
	case DimensionReliability:
		return "reliability"
	default:
		return "unknown"
	}
}

// Account returns this Registrar's own public key -- the account every
// extrinsic it signs is attributed to. Exported so callers that need to
// look up their own on-chain record (e.g. cmd/networkvalidator's status
// command) don't need a second, separately-loaded copy of the same key.
func (r *Registrar) Account() [ed25519.PublicKeySize]byte {
	return r.account
}

// RegisterValidator submits pallet-network-validator's register_validator
// extrinsic, signed directly by this Registrar's own account and never
// sudo-wrapped -- the ADR-011 trust boundary this whole daemon exists to
// exercise: a Network Validator submits its own signed extrinsics, never
// through the Control Plane's bridge account. stake is in the runtime's
// Balance unit (u64; blockchain/runtime/src/lib.rs's MinValidatorStake is
// also a plain u64, not the usual u128 -- this runtime keeps balances
// integer and narrow deliberately, matching AGENTS.md's no-floats rule).
func (r *Registrar) RegisterValidator(ctx context.Context, stake uint64) error {
	call := []byte{networkValidatorPalletIndex, registerValidatorCallIndex}
	call = binary.LittleEndian.AppendUint64(call, stake)
	return r.SubmitDirect(ctx, call)
}

// RequestExit submits request_exit, starting the unbonding period. Once
// UnbondingPeriod blocks have finalized with no pending assignment,
// WithdrawUnbonded releases the stake.
func (r *Registrar) RequestExit(ctx context.Context) error {
	return r.SubmitDirect(ctx, []byte{networkValidatorPalletIndex, requestExitCallIndex})
}

// WithdrawUnbonded submits withdraw_unbonded, releasing a stake whose
// unbonding period has already elapsed.
func (r *Registrar) WithdrawUnbonded(ctx context.Context) error {
	return r.SubmitDirect(ctx, []byte{networkValidatorPalletIndex, withdrawUnbondedCallIndex})
}

// SubmitEvidence submits pallet-network-validator's submit_evidence
// extrinsic (call_index 5), directly signed by this Registrar's own
// account -- one validator's bounded, integer-only, attributable
// observation for (provider, round, dimension). Field encoding is fixed-
// width throughout (the pallet's submit_evidence signature has no
// #[pallet::compact] annotations on any argument, verified directly
// against blockchain/pallets/network-validator/src/lib.rs): provider is
// 32 raw bytes, round is u64 LE, dimension is a 1-byte SCALE enum tag,
// score_bps is u16 LE, sample_count is u32 LE, payload_hash is 32 raw
// bytes.
func (r *Registrar) SubmitEvidence(ctx context.Context, provider [32]byte, round uint64, dimension ScoreDimension, scoreBps uint16, sampleCount uint32, payloadHash [32]byte) error {
	return r.SubmitDirect(ctx, encodeSubmitEvidenceCall(provider, round, dimension, scoreBps, sampleCount, payloadHash))
}

// encodeSubmitEvidenceCall is split out from SubmitEvidence so its exact
// byte layout can be unit tested without a live/mock RPC round trip
// (SubmitDirect itself needs one, for RuntimeVersion/genesis/nonce).
func encodeSubmitEvidenceCall(provider [32]byte, round uint64, dimension ScoreDimension, scoreBps uint16, sampleCount uint32, payloadHash [32]byte) []byte {
	call := []byte{networkValidatorPalletIndex, submitEvidenceCallIndex}
	call = append(call, provider[:]...)
	call = binary.LittleEndian.AppendUint64(call, round)
	call = append(call, byte(dimension))
	call = binary.LittleEndian.AppendUint16(call, scoreBps)
	call = binary.LittleEndian.AppendUint32(call, sampleCount)
	call = append(call, payloadHash[:]...)
	return call
}

// CloseRound submits close_round (call_index 6) for (provider, round,
// dimension). Callable by any active validator -- closing is a
// deterministic function of already-committed Evidence, gated only by
// quorum, not by caller identity beyond "an active validator" (see the
// pallet's own doc comment on close_round). A call that arrives before
// MinQuorum submissions exist is accepted by the chain (the extrinsic
// dispatches) but fails with QuorumNotReached inside the runtime -- an
// RPC-visible submission success that is nonetheless a no-op, which
// callers of this method (the challenge loop's periodic close-attempt
// pass) must expect and treat as normal, not as an error to retry
// aggressively.
func (r *Registrar) CloseRound(ctx context.Context, provider [32]byte, round uint64, dimension ScoreDimension) error {
	return r.SubmitDirect(ctx, encodeCloseRoundCall(provider, round, dimension))
}

// encodeCloseRoundCall mirrors encodeSubmitEvidenceCall's reasoning: split
// out purely so the byte layout is directly unit testable.
func encodeCloseRoundCall(provider [32]byte, round uint64, dimension ScoreDimension) []byte {
	call := []byte{networkValidatorPalletIndex, closeRoundCallIndex}
	call = append(call, provider[:]...)
	call = binary.LittleEndian.AppendUint64(call, round)
	call = append(call, byte(dimension))
	return call
}

// SubmitDirect signs and submits an arbitrary call with this Registrar's
// own account, never sudo-wrapped -- the shared version/genesis/nonce
// plumbing every directly-signed extrinsic needs (RegisterValidator/
// RequestExit/WithdrawUnbonded build on it; so can tooling/tests that need
// to submit a directly-signed extrinsic this package has no named wrapper
// for yet), factored out so it isn't duplicated per call the way
// EnsureActive/EnsureLeaseActive each inline it for their own multi-step
// sudo-wrapped sequences.
func (r *Registrar) SubmitDirect(ctx context.Context, call []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	version, err := r.rpc.RuntimeVersion(ctx)
	if err != nil {
		return err
	}
	if version.SpecVersion != supportedSpecVersion || version.TransactionVersion != supportedTransactionVersion {
		return fmt.Errorf("unsupported runtime version spec=%d transaction=%d", version.SpecVersion, version.TransactionVersion)
	}
	genesisHex, err := r.rpc.BlockHash(ctx, 0)
	if err != nil {
		return err
	}
	genesis, err := fixedHash(genesisHex)
	if err != nil {
		return err
	}
	nonce, err := r.finalizedAccountNonce(ctx)
	if err != nil {
		return err
	}
	return r.submitSigned(ctx, call, nonce, version, genesis)
}

// ValidatorRecord mirrors pallet_network_validator::pallet::ValidatorRecord.
type ValidatorRecord struct {
	Status ValidatorLifecycleStatus
	// AvailableAt is only meaningful when Status == ValidatorExiting: the
	// block number WithdrawUnbonded becomes callable at.
	AvailableAt  uint32
	Stake        uint64
	RegisteredAt uint32
}

type ValidatorLifecycleStatus byte

const (
	ValidatorActive ValidatorLifecycleStatus = iota
	ValidatorSuspended
	ValidatorExiting
)

func (s ValidatorLifecycleStatus) String() string {
	switch s {
	case ValidatorActive:
		return "ACTIVE"
	case ValidatorSuspended:
		return "SUSPENDED"
	case ValidatorExiting:
		return "EXITING"
	default:
		return "UNKNOWN"
	}
}

// FinalizedValidatorRecord reads pallet-network-validator's Validators map
// for account at the current finalized head. found is false when the
// account has never registered (or has fully exited and been pruned) --
// a normal state for any not-yet-registered key, distinct from a read
// failure.
func (c *RPCClient) FinalizedValidatorRecord(ctx context.Context, account [ed25519.PublicKeySize]byte) (ValidatorRecord, bool, error) {
	head, err := c.FinalizedHead(ctx)
	if err != nil {
		return ValidatorRecord{}, false, err
	}
	value, found, err := c.Storage(ctx, validatorStorageKey(account), head)
	if err != nil || !found {
		return ValidatorRecord{}, found, err
	}
	record, err := decodeValidatorRecord(value)
	if err != nil {
		return ValidatorRecord{}, false, err
	}
	return record, true, nil
}

func validatorStorageKey(account [32]byte) string {
	return mapStorageKey("NetworkValidator", "Validators", account)
}

// decodeValidatorRecord decodes ValidatorStatus<BlockNumber> (a 1-byte
// variant tag, plus 4 more bytes only for the Exiting{available_at}
// variant) followed by fixed-width stake: u64 and registered_at: u32 --
// the same SCALE enum-then-fixed-fields shape this package already
// decodes elsewhere (e.g. decodeReputationVector for the fixed-only case).
func decodeValidatorRecord(data []byte) (ValidatorRecord, error) {
	if len(data) < 1 {
		return ValidatorRecord{}, errors.New("validator record is empty")
	}
	var record ValidatorRecord
	offset := 1
	switch data[0] {
	case 0:
		record.Status = ValidatorActive
	case 1:
		record.Status = ValidatorSuspended
	case 2:
		record.Status = ValidatorExiting
		if len(data) < offset+4 {
			return ValidatorRecord{}, errors.New("validator record truncated in Exiting.available_at")
		}
		record.AvailableAt = binary.LittleEndian.Uint32(data[offset : offset+4])
		offset += 4
	default:
		return ValidatorRecord{}, errors.New("validator record has an unknown status variant")
	}
	if len(data) != offset+8+4 {
		return ValidatorRecord{}, errors.New("validator record has an unexpected encoded length")
	}
	record.Stake = binary.LittleEndian.Uint64(data[offset : offset+8])
	record.RegisteredAt = binary.LittleEndian.Uint32(data[offset+8 : offset+12])
	return record, nil
}
