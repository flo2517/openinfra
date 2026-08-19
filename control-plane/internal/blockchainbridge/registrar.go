package blockchainbridge

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/OneOfOne/xxhash"
	"golang.org/x/crypto/blake2b"
)

const (
	// supportedSpecVersion is 3, not 2: #37 (commit d9d8df6, "add local
	// Aura GRANDPA testnet") bumped runtime/src/lib.rs's spec_version
	// from 2 to 3 for the move off manual sealing but never updated this
	// guard, so every on-chain registrar call (EnsureActive, lease
	// finalization, Network Validator registration) unconditionally
	// failed with "unsupported runtime version spec=3 transaction=1"
	// against any post-#37 node -- caught only by actually running the
	// join -> deploy path end to end (issue #117), not by any unit test:
	// nothing here mocks a real spec_version. The runtime's own
	// bridge_call_indices_remain_stable_in_spec_version_three test
	// (blockchain/runtime/src/lib.rs) confirms the pallet/call indices
	// below did not change across that bump, so this version number is
	// the only thing that needed correcting.
	supportedSpecVersion        = 3
	supportedTransactionVersion = 1
	runtimeExtrinsicVersion     = 4
	sudoPalletIndex             = 2
	sudoCallIndex               = 0
	providerRegistryPalletIndex = 10
	setStatusCallIndex          = 1
	registerForCallIndex        = 2
	leasePalletIndex            = 12
	createLeaseCallIndex        = 0
	updateLeaseStateCallIndex   = 1
	leaseStateCreated           = 0
	leaseStateActive            = 1
	leaseStateCompleted         = 2
	statusRegistered            = 0
	statusVerified              = 1
	statusActive                = 2
)

type Registrar struct {
	rpc          *RPCClient
	privateKey   ed25519.PrivateKey
	account      [ed25519.PublicKeySize]byte
	pollInterval time.Duration
	mu           sync.Mutex
}

type FinalizedLease struct {
	LeaseID              uint64
	Provider             [32]byte
	Consumer             [32]byte
	ResourceHash         [32]byte
	Start, End           uint32
	State                byte
	FinalizedBlockHash   []byte
	FinalizedBlockNumber uint64
}

// EnsureLeaseCompleted returns only after the lease is Completed in finalized
// storage. Repeating the call for an already completed lease is a no-op.
func (r *Registrar) EnsureLeaseCompleted(ctx context.Context, leaseID uint64) (FinalizedLease, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	version, err := r.rpc.RuntimeVersion(ctx)
	if err != nil {
		return FinalizedLease{}, err
	}
	if version.SpecVersion != supportedSpecVersion || version.TransactionVersion != supportedTransactionVersion {
		return FinalizedLease{}, fmt.Errorf("unsupported runtime version spec=%d transaction=%d", version.SpecVersion, version.TransactionVersion)
	}

	lease, found, err := r.finalizedLease(ctx, leaseID)
	if err != nil {
		return FinalizedLease{}, err
	}
	if !found {
		return FinalizedLease{}, fmt.Errorf("lease %d does not exist in finalized storage", leaseID)
	}
	if lease.Consumer != r.account {
		return FinalizedLease{}, fmt.Errorf("lease %d is not owned by the bridge account", leaseID)
	}
	if lease.State == leaseStateCompleted {
		return lease, nil
	}
	if lease.State != leaseStateActive {
		return FinalizedLease{}, fmt.Errorf("lease %d cannot transition from state %d to Completed", leaseID, lease.State)
	}
	expected := lease

	genesisHex, err := r.rpc.BlockHash(ctx, 0)
	if err != nil {
		return FinalizedLease{}, err
	}
	genesis, err := fixedHash(genesisHex)
	if err != nil {
		return FinalizedLease{}, err
	}
	nonce, err := r.finalizedAccountNonce(ctx)
	if err != nil {
		return FinalizedLease{}, err
	}
	inner := []byte{leasePalletIndex, updateLeaseStateCallIndex}
	inner = binary.LittleEndian.AppendUint64(inner, leaseID)
	inner = append(inner, leaseStateCompleted)
	if err := r.submitSigned(ctx, append([]byte{sudoPalletIndex, sudoCallIndex}, inner...), nonce, version, genesis); err != nil {
		return FinalizedLease{}, err
	}

	for {
		lease, found, err = r.finalizedLease(ctx, leaseID)
		if err != nil {
			return FinalizedLease{}, err
		}
		if !found {
			return FinalizedLease{}, fmt.Errorf("lease %d disappeared from finalized storage", leaseID)
		}
		if !sameLeaseIdentity(lease, expected) {
			return FinalizedLease{}, fmt.Errorf("lease %d finalized data changed while completing", leaseID)
		}
		if lease.State == leaseStateCompleted {
			return lease, nil
		}
		if lease.State != leaseStateActive {
			return FinalizedLease{}, fmt.Errorf("lease %d reached unexpected state %d while completing", leaseID, lease.State)
		}
		select {
		case <-ctx.Done():
			return FinalizedLease{}, ctx.Err()
		case <-time.After(r.pollInterval):
		}
	}
}

func sameLeaseIdentity(actual, expected FinalizedLease) bool {
	return actual.LeaseID == expected.LeaseID &&
		actual.Provider == expected.Provider &&
		actual.Consumer == expected.Consumer &&
		actual.ResourceHash == expected.ResourceHash &&
		actual.Start == expected.Start &&
		actual.End == expected.End
}

// EnsureLeaseActive returns only after the exact lease is Active in finalized storage.
func (r *Registrar) EnsureLeaseActive(ctx context.Context, leaseID uint64, provider, resourceHash [32]byte, duration uint32) (FinalizedLease, error) {
	if duration == 0 || duration > 1_000_000 {
		return FinalizedLease{}, errors.New("lease duration must be between 1 and 1000000 blocks")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	version, err := r.rpc.RuntimeVersion(ctx)
	if err != nil {
		return FinalizedLease{}, err
	}
	if version.SpecVersion != supportedSpecVersion || version.TransactionVersion != supportedTransactionVersion {
		return FinalizedLease{}, fmt.Errorf("unsupported runtime version spec=%d transaction=%d", version.SpecVersion, version.TransactionVersion)
	}
	genesisHex, err := r.rpc.BlockHash(ctx, 0)
	if err != nil {
		return FinalizedLease{}, err
	}
	genesis, err := fixedHash(genesisHex)
	if err != nil {
		return FinalizedLease{}, err
	}
	lease, found, err := r.finalizedLease(ctx, leaseID)
	if err != nil {
		return FinalizedLease{}, err
	}
	if found {
		if err := r.validateLease(lease, provider, resourceHash, duration); err != nil {
			return FinalizedLease{}, err
		}
		if lease.State == leaseStateActive {
			return lease, nil
		}
		if lease.State != leaseStateCreated {
			return FinalizedLease{}, fmt.Errorf("lease %d has unsupported state %d", leaseID, lease.State)
		}
	}
	nonce, err := r.finalizedAccountNonce(ctx)
	if err != nil {
		return FinalizedLease{}, err
	}
	if !found {
		call := []byte{leasePalletIndex, createLeaseCallIndex}
		call = binary.LittleEndian.AppendUint64(call, leaseID)
		call = append(call, provider[:]...)
		call = append(call, resourceHash[:]...)
		call = binary.LittleEndian.AppendUint32(call, duration)
		if err := r.submitSigned(ctx, call, nonce, version, genesis); err != nil {
			return FinalizedLease{}, err
		}
		nonce++
	}
	inner := []byte{leasePalletIndex, updateLeaseStateCallIndex}
	inner = binary.LittleEndian.AppendUint64(inner, leaseID)
	inner = append(inner, leaseStateActive)
	if err := r.submitSigned(ctx, append([]byte{sudoPalletIndex, sudoCallIndex}, inner...), nonce, version, genesis); err != nil {
		return FinalizedLease{}, err
	}
	for {
		lease, found, err = r.finalizedLease(ctx, leaseID)
		if err != nil {
			return FinalizedLease{}, err
		}
		if found {
			if err := r.validateLease(lease, provider, resourceHash, duration); err != nil {
				return FinalizedLease{}, err
			}
			if lease.State == leaseStateActive {
				return lease, nil
			}
		}
		select {
		case <-ctx.Done():
			return FinalizedLease{}, ctx.Err()
		case <-time.After(r.pollInterval):
		}
	}
}

func (r *Registrar) validateLease(lease FinalizedLease, provider, resourceHash [32]byte, duration uint32) error {
	if lease.Provider != provider || lease.Consumer != r.account || lease.ResourceHash != resourceHash || lease.End < lease.Start || lease.End-lease.Start != duration {
		return fmt.Errorf("lease %d finalized data does not match request", lease.LeaseID)
	}
	return nil
}

func (r *Registrar) finalizedLease(ctx context.Context, leaseID uint64) (FinalizedLease, bool, error) {
	head, err := r.rpc.FinalizedHead(ctx)
	if err != nil {
		return FinalizedLease{}, false, err
	}
	value, found, err := r.rpc.Storage(ctx, leaseStorageKey(leaseID), head)
	if err != nil || !found {
		return FinalizedLease{}, found, err
	}
	if len(value) != 105 {
		return FinalizedLease{}, false, fmt.Errorf("lease %d storage has invalid length %d", leaseID, len(value))
	}
	var lease FinalizedLease
	lease.LeaseID = leaseID
	copy(lease.Provider[:], value[:32])
	copy(lease.Consumer[:], value[32:64])
	copy(lease.ResourceHash[:], value[64:96])
	lease.Start = binary.LittleEndian.Uint32(value[96:100])
	lease.End = binary.LittleEndian.Uint32(value[100:104])
	lease.State = value[104]
	header, err := r.rpc.HeaderAt(ctx, head)
	if err != nil {
		return FinalizedLease{}, false, err
	}
	lease.FinalizedBlockNumber, err = header.BlockNumber()
	if err != nil {
		return FinalizedLease{}, false, err
	}
	lease.FinalizedBlockHash, err = decodeHex(head)
	return lease, true, err
}

func (r *Registrar) submitSigned(ctx context.Context, call []byte, nonce uint64, version RuntimeVersion, genesis [32]byte) error {
	extrinsic, hash, err := r.signCall(call, nonce, version, genesis)
	if err != nil {
		return err
	}
	submitted, err := r.rpc.SubmitExtrinsic(ctx, "0x"+hex.EncodeToString(extrinsic))
	if err != nil {
		return err
	}
	if submitted != "0x"+hex.EncodeToString(hash[:]) {
		return errors.New("Substrate returned an unexpected extrinsic hash")
	}
	return nil
}

func NewRegistrarFromPKCS8File(rpc *RPCClient, path string) (*Registrar, error) {
	if rpc == nil {
		return nil, errors.New("Substrate RPC client is required")
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read Substrate signer key: %w", err)
	}
	block, _ := pem.Decode(encoded)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("Substrate signer key must be a PKCS#8 PEM private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse Substrate signer key: %w", err)
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("Substrate signer key must use Ed25519")
	}
	registrar := &Registrar{rpc: rpc, privateKey: privateKey, pollInterval: 500 * time.Millisecond}
	copy(registrar.account[:], privateKey.Public().(ed25519.PublicKey))
	return registrar, nil
}

// EnsureActive serializes nonce use for the bridge account and returns only
// after the provider's Active state is visible at a finalized block.
func (r *Registrar) EnsureActive(ctx context.Context, provider [ed25519.PublicKeySize]byte) ([]byte, []byte, uint64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	version, err := r.rpc.RuntimeVersion(ctx)
	if err != nil {
		return nil, nil, 0, err
	}
	if version.SpecVersion != supportedSpecVersion || version.TransactionVersion != supportedTransactionVersion {
		return nil, nil, 0, fmt.Errorf("unsupported runtime version spec=%d transaction=%d", version.SpecVersion, version.TransactionVersion)
	}
	genesisHex, err := r.rpc.BlockHash(ctx, 0)
	if err != nil {
		return nil, nil, 0, err
	}
	genesis, err := fixedHash(genesisHex)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("decode genesis hash: %w", err)
	}

	status, found, headHash, headNumber, err := r.finalizedProvider(ctx, provider)
	if err != nil {
		return nil, nil, 0, err
	}
	if found && status == statusActive {
		return nil, headHash, headNumber, nil
	}
	var lastExtrinsicHash []byte
	steps := make([][]byte, 0, 3)
	if !found {
		inner := []byte{providerRegistryPalletIndex, registerForCallIndex}
		inner = append(inner, provider[:]...)
		inner = append(inner, provider[:]...)
		steps = append(steps, inner)
		status = statusRegistered
	}
	if status == statusRegistered {
		steps = append(steps, statusCall(provider, statusVerified))
		status = statusVerified
	}
	if status == statusVerified {
		steps = append(steps, statusCall(provider, statusActive))
	}
	if len(steps) == 0 {
		return nil, nil, 0, fmt.Errorf("provider has unsupported on-chain status %d", status)
	}

	nonce, err := r.finalizedAccountNonce(ctx)
	if err != nil {
		return nil, nil, 0, err
	}
	for _, inner := range steps {
		extrinsic, hash, err := r.signSudo(inner, nonce, version, genesis)
		if err != nil {
			return nil, nil, 0, err
		}
		submittedHash, err := r.rpc.SubmitExtrinsic(ctx, "0x"+hex.EncodeToString(extrinsic))
		if err != nil {
			return nil, nil, 0, err
		}
		if submittedHash != "0x"+hex.EncodeToString(hash[:]) {
			return nil, nil, 0, errors.New("Substrate returned an unexpected extrinsic hash")
		}
		lastExtrinsicHash = append(lastExtrinsicHash[:0], hash[:]...)
		nonce++
	}
	if err := r.waitForFinalizedStatus(ctx, provider, statusActive); err != nil {
		return nil, nil, 0, err
	}
	_, _, headHash, headNumber, err = r.finalizedProvider(ctx, provider)
	return lastExtrinsicHash, headHash, headNumber, err
}

func (r *Registrar) finalizedAccountNonce(ctx context.Context) (uint64, error) {
	head, err := r.rpc.FinalizedHead(ctx)
	if err != nil {
		return 0, err
	}
	value, found, err := r.rpc.Storage(ctx, accountStorageKey(r.account), head)
	if err != nil {
		return 0, err
	}
	if !found {
		return 0, nil
	}
	if len(value) < 4 {
		return 0, errors.New("system account storage is shorter than its nonce")
	}
	return uint64(binary.LittleEndian.Uint32(value[:4])), nil
}

func statusCall(provider [32]byte, status byte) []byte {
	call := []byte{providerRegistryPalletIndex, setStatusCallIndex}
	call = append(call, provider[:]...)
	return append(call, status)
}

func (r *Registrar) signSudo(inner []byte, nonce uint64, version RuntimeVersion, genesis [32]byte) ([]byte, [32]byte, error) {
	call := []byte{sudoPalletIndex, sudoCallIndex}
	call = append(call, inner...)
	return r.signCall(call, nonce, version, genesis)
}

func (r *Registrar) signCall(call []byte, nonce uint64, version RuntimeVersion, genesis [32]byte) ([]byte, [32]byte, error) {
	extra := append([]byte{0}, compactUint(nonce)...)
	payload := append(append([]byte{}, call...), extra...)
	implicit := make([]byte, 8, 8+64)
	binary.LittleEndian.PutUint32(implicit[0:4], version.SpecVersion)
	binary.LittleEndian.PutUint32(implicit[4:8], version.TransactionVersion)
	implicit = append(implicit, genesis[:]...)
	implicit = append(implicit, genesis[:]...)
	payload = append(payload, implicit...)
	if len(payload) > 256 {
		digest := blake2b.Sum256(payload)
		payload = digest[:]
	}
	signature := ed25519.Sign(r.privateKey, payload)
	body := []byte{0x80 | runtimeExtrinsicVersion, 0}
	body = append(body, r.account[:]...)
	body = append(body, 0)
	body = append(body, signature...)
	body = append(body, extra...)
	body = append(body, call...)
	extrinsic := append(compactUint(uint64(len(body))), body...)
	return extrinsic, blake2b.Sum256(extrinsic), nil
}

func leaseStorageKey(leaseID uint64) string {
	encoded := make([]byte, 8)
	binary.LittleEndian.PutUint64(encoded, leaseID)
	key := append(twox128([]byte("Lease")), twox128([]byte("Leases"))...)
	digest, _ := blake2b.New(16, nil)
	_, _ = digest.Write(encoded)
	key = append(key, digest.Sum(nil)...)
	key = append(key, encoded...)
	return "0x" + hex.EncodeToString(key)
}

func (r *Registrar) waitForFinalizedStatus(ctx context.Context, provider [32]byte, expected byte) error {
	ticker := time.NewTicker(r.pollInterval)
	defer ticker.Stop()
	for {
		status, found, _, _, err := r.finalizedProvider(ctx, provider)
		if err != nil {
			return err
		}
		if found && status == expected {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (r *Registrar) finalizedProvider(ctx context.Context, provider [32]byte) (byte, bool, []byte, uint64, error) {
	head, err := r.rpc.FinalizedHead(ctx)
	if err != nil {
		return 0, false, nil, 0, err
	}
	value, found, err := r.rpc.Storage(ctx, providerStorageKey(provider), head)
	if err != nil {
		return 0, false, nil, 0, err
	}
	header, err := r.rpc.HeaderAt(ctx, head)
	if err != nil {
		return 0, false, nil, 0, err
	}
	number, err := header.BlockNumber()
	if err != nil {
		return 0, false, nil, 0, err
	}
	headBytes, err := decodeHex(head)
	if err != nil {
		return 0, false, nil, 0, err
	}
	if !found {
		return 0, false, headBytes, number, nil
	}
	if len(value) != 65 || !equal32(value[:32], provider[:]) || !equal32(value[32:64], provider[:]) {
		return 0, false, nil, 0, errors.New("provider registry returned an invalid identity record")
	}
	return value[64], true, headBytes, number, nil
}

func providerStorageKey(provider [32]byte) string {
	return mapStorageKey("ProviderRegistry", "Providers", provider)
}

func accountStorageKey(account [32]byte) string {
	return mapStorageKey("System", "Account", account)
}

func mapStorageKey(pallet, item string, keyValue [32]byte) string {
	key := append(twox128([]byte(pallet)), twox128([]byte(item))...)
	// A nil key is always valid; the constructor can only reject invalid key sizes.
	digest, _ := blake2b.New(16, nil)
	_, _ = digest.Write(keyValue[:])
	key = append(key, digest.Sum(nil)...)
	key = append(key, keyValue[:]...)
	return "0x" + hex.EncodeToString(key)
}

func twox128(value []byte) []byte {
	result := make([]byte, 16)
	binary.LittleEndian.PutUint64(result[:8], xxhash.Checksum64S(value, 0))
	binary.LittleEndian.PutUint64(result[8:], xxhash.Checksum64S(value, 1))
	return result
}

func compactUint(value uint64) []byte {
	switch {
	case value < 1<<6:
		return []byte{byte(value << 2)}
	case value < 1<<14:
		encoded := uint16(value<<2) | 1
		return []byte{byte(encoded), byte(encoded >> 8)}
	case value < 1<<30:
		encoded := uint32(value<<2) | 2
		return []byte{byte(encoded), byte(encoded >> 8), byte(encoded >> 16), byte(encoded >> 24)}
	default:
		bytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(bytes, value)
		length := 8
		for length > 4 && bytes[length-1] == 0 {
			length--
		}
		return append([]byte{byte((length-4)<<2) | 3}, bytes[:length]...)
	}
}

func fixedHash(value string) ([32]byte, error) {
	var result [32]byte
	decoded, err := decodeHex(value)
	if err != nil || len(decoded) != len(result) {
		return result, errors.New("expected a 32-byte hexadecimal hash")
	}
	copy(result[:], decoded)
	return result, nil
}

func equal32(left, right []byte) bool {
	if len(left) != 32 || len(right) != 32 {
		return false
	}
	var different byte
	for index := range left {
		different |= left[index] ^ right[index]
	}
	return different == 0
}
