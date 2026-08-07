package providerjoin

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	controlplanev1 "github.com/openinfra/network/protocol/generated/go/controlplane/v1"
	sharedv1 "github.com/openinfra/network/protocol/generated/go/shared/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type memoryRepository struct {
	byBeginID  map[string]Challenge
	byID       map[string]Challenge
	completion map[string]Completion
}

func (r *memoryRepository) ProviderIdentity(_ context.Context, providerID string) (ProviderIdentity, error) {
	for _, completion := range r.completion {
		if completion.ProviderID == providerID {
			return ProviderIdentity{PublicKey: completion.Challenge.PublicKey, Status: completion.Status}, nil
		}
	}
	return ProviderIdentity{}, ErrProviderNotFound
}

func (r *memoryRepository) ActivateProvider(_ context.Context, providerID string, _ ChainFinalization) (Completion, error) {
	for requestID, completion := range r.completion {
		if completion.ProviderID == providerID {
			completion.Status = sharedv1.NodeStatus_NODE_STATUS_ACTIVE
			r.completion[requestID] = completion
			return completion, nil
		}
	}
	return Completion{}, ErrProviderNotFound
}

type memoryRegistrar struct {
	err   error
	calls int
}

func (r *memoryRegistrar) EnsureActive(_ context.Context, _ [ed25519.PublicKeySize]byte) ([]byte, []byte, uint64, error) {
	r.calls++
	return nil, nil, 1, r.err
}

// memoryValidatorSource stubs blockchainbridge's LatestActiveNetworkValidators
// for the heartbeat-allowlist tests: either returns validators, or fails,
// never both, matching the real RPCClient's single-read behavior.
type memoryValidatorSource struct {
	validators [][32]byte
	err        error
	calls      int
}

func (s *memoryValidatorSource) LatestActiveNetworkValidators(context.Context) ([][32]byte, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return s.validators, nil
}

type memoryHeartbeatStore struct {
	requests map[string][32]byte
	sequence map[string]uint64
}

func newMemoryHeartbeatStore() *memoryHeartbeatStore {
	return &memoryHeartbeatStore{requests: make(map[string][32]byte), sequence: make(map[string]uint64)}
}

func (s *memoryHeartbeatStore) Accept(_ context.Context, providerID, requestID string, sequence uint64, hash [sha256.Size]byte, _ []byte, _ time.Duration) error {
	if existing, ok := s.requests[requestID]; ok {
		if existing == hash {
			return nil
		}
		return ErrConflict
	}
	if sequence <= s.sequence[providerID] {
		return ErrHeartbeatReplay
	}
	s.requests[requestID] = hash
	s.sequence[providerID] = sequence
	return nil
}

func newMemoryRepository() *memoryRepository {
	return &memoryRepository{
		byBeginID:  make(map[string]Challenge),
		byID:       make(map[string]Challenge),
		completion: make(map[string]Completion),
	}
}

func (r *memoryRepository) CreateOrGetChallenge(_ context.Context, candidate Challenge) (Challenge, error) {
	if stored, ok := r.byBeginID[candidate.BeginRequestID]; ok {
		if stored.RequestHash != candidate.RequestHash {
			return Challenge{}, ErrConflict
		}
		return stored, nil
	}
	r.byBeginID[candidate.BeginRequestID] = candidate
	r.byID[candidate.ChallengeID] = candidate
	return candidate, nil
}

func (r *memoryRepository) GetChallenge(_ context.Context, id string) (Challenge, error) {
	challenge, ok := r.byID[id]
	if !ok {
		return Challenge{}, ErrChallengeNotFound
	}
	return challenge, nil
}

func (r *memoryRepository) CompleteJoin(_ context.Context, completion Completion) (Completion, error) {
	if stored, ok := r.completion[completion.RequestID]; ok {
		if stored.Challenge.ChallengeID != completion.Challenge.ChallengeID || stored.RequestHash != completion.RequestHash {
			return Completion{}, ErrConflict
		}
		return stored, nil
	}
	if !completion.RegisteredAt.Before(completion.Challenge.ExpiresAt) {
		return Completion{}, ErrChallengeExpired
	}
	r.completion[completion.RequestID] = completion
	return completion, nil
}

func TestJoinCompletesOnlyWithValidSignature(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	repository := newMemoryRepository()
	registrar := &memoryRegistrar{}
	service := NewService(repository, newMemoryHeartbeatStore(), registrar)
	service.now = func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }

	begin, err := service.BeginJoin(context.Background(), &controlplanev1.BeginJoinRequest{
		RequestId:       uuid.NewString(),
		PublicKey:       publicKey,
		ProtocolVersion: "1",
		AgentVersion:    "0.1.0",
	})
	if err != nil {
		t.Fatalf("begin join: %v", err)
	}
	signature := ed25519.Sign(privateKey, append([]byte(joinDomain), begin.ChallengeNonce...))
	completeRequest := &controlplanev1.CompleteJoinRequest{
		RequestId:          uuid.NewString(),
		ChallengeId:        begin.ChallengeId,
		ChallengeSignature: signature,
		Capabilities:       &sharedv1.ResourceCapability{CpuTotal: 8, RamTotalMb: 16_384},
	}
	completed, err := service.CompleteJoin(context.Background(), completeRequest)
	if err != nil {
		t.Fatalf("complete join: %v", err)
	}
	if completed.Status != sharedv1.NodeStatus_NODE_STATUS_ACTIVE {
		t.Fatalf("status = %s, want ACTIVE", completed.Status)
	}
	if completed.ProviderId == "" {
		t.Fatal("provider ID is empty")
	}
	if registrar.calls != 1 {
		t.Fatalf("registrar calls = %d, want 1", registrar.calls)
	}

	retried, err := service.CompleteJoin(context.Background(), completeRequest)
	if err != nil {
		t.Fatalf("retry complete join: %v", err)
	}
	if retried.ProviderId != completed.ProviderId {
		t.Fatal("idempotent retry returned another provider")
	}
	if registrar.calls != 1 {
		t.Fatalf("idempotent retry resubmitted registration: calls = %d", registrar.calls)
	}
}

func TestCompleteJoinRejectsInvalidSignature(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	service := NewService(newMemoryRepository(), newMemoryHeartbeatStore(), &memoryRegistrar{})
	begin, err := service.BeginJoin(context.Background(), &controlplanev1.BeginJoinRequest{
		RequestId:       uuid.NewString(),
		PublicKey:       publicKey,
		ProtocolVersion: "1",
		AgentVersion:    "0.1.0",
	})
	if err != nil {
		t.Fatalf("begin join: %v", err)
	}
	_, err = service.CompleteJoin(context.Background(), &controlplanev1.CompleteJoinRequest{
		RequestId:          uuid.NewString(),
		ChallengeId:        begin.ChallengeId,
		ChallengeSignature: make([]byte, ed25519.SignatureSize),
		Capabilities: &sharedv1.ResourceCapability{
			CpuTotal:       1,
			CpuAvailable:   1,
			RamTotalMb:     1024,
			RamAvailableMb: 1024,
		},
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %s, want Unauthenticated", status.Code(err))
	}
}

func TestBeginJoinValidatesAgentEndpoint(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(newMemoryRepository(), newMemoryHeartbeatStore(), &memoryRegistrar{})
	request := &controlplanev1.BeginJoinRequest{RequestId: uuid.NewString(), PublicKey: publicKey, ProtocolVersion: "1", AgentVersion: "0.1.0", AgentEndpoint: "http://provider-agent:50052"}
	_, err = service.BeginJoin(context.Background(), request)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %s, want InvalidArgument", status.Code(err))
	}
	request.AgentEndpoint = "https://provider-agent:50052"
	if _, err := service.BeginJoin(context.Background(), request); err != nil {
		t.Fatalf("valid endpoint rejected: %v", err)
	}
}

func TestHeartbeatAcceptsValidSignatureAndRejectsReplay(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	repository := newMemoryRepository()
	providerDigest := sha256.Sum256(publicKey)
	providerID := fmt.Sprintf("%x", providerDigest)
	repository.completion[uuid.NewString()] = Completion{ProviderID: providerID, Challenge: Challenge{PublicKey: publicKey}, Status: sharedv1.NodeStatus_NODE_STATUS_ACTIVE}
	service := NewService(repository, newMemoryHeartbeatStore(), &memoryRegistrar{})
	now := time.Unix(1_700_000_000, 0).UTC()
	service.now = func() time.Time { return now }
	payload := &controlplanev1.HeartbeatSigningPayload{
		RequestId: uuid.NewString(), ProviderId: providerID, Sequence: 1,
		ObservedAt:   timestamppb.New(now),
		Capabilities: &sharedv1.ResourceCapability{CpuTotal: 8, CpuAvailable: 6, RamTotalMb: 16_384, RamAvailableMb: 12_000},
	}
	payloadBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	request := &controlplanev1.ReportHeartbeatRequest{Payload: payload, Signature: ed25519.Sign(privateKey, append([]byte(heartbeatDomain), payloadBytes...))}
	response, err := service.ReportHeartbeat(context.Background(), request)
	if err != nil {
		t.Fatalf("report heartbeat: %v", err)
	}
	if response.Status != sharedv1.NodeStatus_NODE_STATUS_ACTIVE {
		t.Fatalf("status = %s, want ACTIVE", response.Status)
	}
	request.Payload.RequestId = uuid.NewString()
	payloadBytes, _ = proto.MarshalOptions{Deterministic: true}.Marshal(request.Payload)
	request.Signature = ed25519.Sign(privateKey, append([]byte(heartbeatDomain), payloadBytes...))
	_, err = service.ReportHeartbeat(context.Background(), request)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("replay code = %s, want FailedPrecondition", status.Code(err))
	}
}

// heartbeatFixture builds a repository, identity, and signed request ready
// to submit via ReportHeartbeat, factored out of
// TestHeartbeatAcceptsValidSignatureAndRejectsReplay so the two
// validator-allowlist tests below don't have to duplicate its signing
// boilerplate.
func heartbeatFixture(t *testing.T) (*memoryRepository, *controlplanev1.ReportHeartbeatRequest, time.Time) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	repository := newMemoryRepository()
	providerDigest := sha256.Sum256(publicKey)
	providerID := fmt.Sprintf("%x", providerDigest)
	repository.completion[uuid.NewString()] = Completion{ProviderID: providerID, Challenge: Challenge{PublicKey: publicKey}, Status: sharedv1.NodeStatus_NODE_STATUS_ACTIVE}
	now := time.Unix(1_700_000_000, 0).UTC()
	payload := &controlplanev1.HeartbeatSigningPayload{
		RequestId: uuid.NewString(), ProviderId: providerID, Sequence: 1,
		ObservedAt:   timestamppb.New(now),
		Capabilities: &sharedv1.ResourceCapability{CpuTotal: 8, CpuAvailable: 6, RamTotalMb: 16_384, RamAvailableMb: 12_000},
	}
	payloadBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	request := &controlplanev1.ReportHeartbeatRequest{Payload: payload, Signature: ed25519.Sign(privateKey, append([]byte(heartbeatDomain), payloadBytes...))}
	return repository, request, now
}

// TestHeartbeatIncludesActiveValidatorSetWhenChainReadSucceeds is ADR-013
// §3's core wire contract: a successful chain read is forwarded verbatim
// as the raw 32-byte Ed25519 keys the Agent will allowlist for mTLS.
func TestHeartbeatIncludesActiveValidatorSetWhenChainReadSucceeds(t *testing.T) {
	repository, request, now := heartbeatFixture(t)
	validatorOne := [32]byte{1, 2, 3}
	validatorTwo := [32]byte{4, 5, 6}
	source := &memoryValidatorSource{validators: [][32]byte{validatorOne, validatorTwo}}
	service := NewService(repository, newMemoryHeartbeatStore(), &memoryRegistrar{})
	service.now = func() time.Time { return now }
	service.SetValidatorSource(source)

	response, err := service.ReportHeartbeat(context.Background(), request)
	if err != nil {
		t.Fatalf("report heartbeat: %v", err)
	}
	if response.Status != sharedv1.NodeStatus_NODE_STATUS_ACTIVE {
		t.Fatalf("status = %s, want ACTIVE", response.Status)
	}
	if len(response.ActiveValidators) != 2 {
		t.Fatalf("active_validators length = %d, want 2", len(response.ActiveValidators))
	}
	if !bytes.Equal(response.ActiveValidators[0], validatorOne[:]) || !bytes.Equal(response.ActiveValidators[1], validatorTwo[:]) {
		t.Fatalf("active_validators = %x, want [%x %x]", response.ActiveValidators, validatorOne, validatorTwo)
	}
	if source.calls != 1 {
		t.Fatalf("chain read calls = %d, want 1", source.calls)
	}
}

// TestHeartbeatSucceedsWithEmptyValidatorsWhenChainReadFails is the
// degraded-mode half of ADR-013 §3's contract: liveness (this RPC's core
// job) must not depend on the chain being reachable, so a chain read
// failure degrades to an empty allowlist rather than failing the whole
// heartbeat -- status/accepted_at/next_heartbeat_seconds are unaffected.
func TestHeartbeatSucceedsWithEmptyValidatorsWhenChainReadFails(t *testing.T) {
	repository, request, now := heartbeatFixture(t)
	source := &memoryValidatorSource{err: errors.New("substrate RPC unavailable")}
	service := NewService(repository, newMemoryHeartbeatStore(), &memoryRegistrar{})
	service.now = func() time.Time { return now }
	service.SetValidatorSource(source)

	response, err := service.ReportHeartbeat(context.Background(), request)
	if err != nil {
		t.Fatalf("report heartbeat: %v", err)
	}
	if response.Status != sharedv1.NodeStatus_NODE_STATUS_ACTIVE {
		t.Fatalf("status = %s, want ACTIVE", response.Status)
	}
	if response.NextHeartbeatSeconds == 0 {
		t.Fatal("next_heartbeat_seconds should still be populated on a degraded chain read")
	}
	if len(response.ActiveValidators) != 0 {
		t.Fatalf("active_validators = %x, want empty", response.ActiveValidators)
	}
	if source.calls != 1 {
		t.Fatalf("chain read calls = %d, want 1", source.calls)
	}
}

// TestHeartbeatSucceedsWithoutValidatorSourceConfigured covers the
// SetValidatorSource-never-called path (e.g. a chain client that failed to
// initialize at startup): heartbeats must keep working exactly as they did
// before this ADR-013 slice existed.
func TestHeartbeatSucceedsWithoutValidatorSourceConfigured(t *testing.T) {
	repository, request, now := heartbeatFixture(t)
	service := NewService(repository, newMemoryHeartbeatStore(), &memoryRegistrar{})
	service.now = func() time.Time { return now }

	response, err := service.ReportHeartbeat(context.Background(), request)
	if err != nil {
		t.Fatalf("report heartbeat: %v", err)
	}
	if response.Status != sharedv1.NodeStatus_NODE_STATUS_ACTIVE {
		t.Fatalf("status = %s, want ACTIVE", response.Status)
	}
	if response.ActiveValidators != nil {
		t.Fatalf("active_validators = %x, want nil", response.ActiveValidators)
	}
}
