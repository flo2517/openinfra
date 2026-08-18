package networkvalidator

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/openinfra/network/internal/blockchainbridge"
	agentv1 "github.com/openinfra/network/protocol/generated/go/agent/v1"
	"golang.org/x/crypto/blake2b"
)

func marshalPKCS8(privateKey ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// fakeChain is a minimal Substrate JSON-RPC server implementing exactly
// the methods Run()'s tick and Registrar.SubmitDirect need, enough to
// drive one real end-to-end pass of the loop: derive round -> read
// ActiveValidatorSet -> enumerate providers -> (for an assigned provider)
// submit_evidence -> (later) close_round. It is intentionally a fake
// server, not a mock of individual Go methods, so this test exercises
// the real RPCClient/Registrar HTTP+SCALE code paths end to end, the
// same spirit as challenge_test.go's fakeAgentServer exercising the real
// wire format rather than stubbing it away.
type fakeChain struct {
	mu             sync.Mutex
	blockNumberHex string
	activeSetSCALE []byte
	providerKeys   []string
	submittedCalls [][]byte // decoded call bytes (pallet_index, call_index, ...) per accepted extrinsic
}

func (f *fakeChain) handler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     uint64          `json:"id"`
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	body, _ := io.ReadAll(r.Body)
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	result, rpcErr := f.dispatch(req.Method, req.Params)
	response := map[string]any{"jsonrpc": "2.0", "id": req.ID}
	if rpcErr != nil {
		response["error"] = map[string]any{"code": -32000, "message": rpcErr.Error()}
	} else {
		response["result"] = result
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

var fixedHashHex = "0x" + hex.EncodeToString(make([]byte, 32))

func (f *fakeChain) dispatch(method string, params json.RawMessage) (any, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch method {
	case "state_getRuntimeVersion":
		return map[string]any{"specVersion": 2, "transactionVersion": 1}, nil
	case "chain_getBlockHash":
		return fixedHashHex, nil
	case "chain_getFinalizedHead":
		return fixedHashHex, nil
	case "chain_getHeader":
		return map[string]any{
			"parentHash": fixedHashHex, "number": f.blockNumberHex,
			"stateRoot": fixedHashHex, "extrinsicsRoot": fixedHashHex,
		}, nil
	case "state_getStorage":
		var args []string
		_ = json.Unmarshal(params, &args)
		key := args[0]
		decoded, err := hex.DecodeString(key[2:])
		if err != nil {
			return nil, err
		}
		switch len(decoded) {
		case 32: // ActiveValidatorSet: twox128(pallet)+twox128(item), no map key
			return "0x" + hex.EncodeToString(f.activeSetSCALE), nil
		case 80: // System::Account map entry: prefix(32)+hash(16)+account(32)
			return "0x00000000", nil // 4-byte nonce = 0
		default:
			return nil, fmt.Errorf("fakeChain: unexpected storage key length %d", len(decoded))
		}
	case "state_getKeysPaged":
		return f.providerKeys, nil
	case "author_submitExtrinsic":
		var args []string
		_ = json.Unmarshal(params, &args)
		extrinsicHex := args[0]
		extrinsic, err := hex.DecodeString(extrinsicHex[2:])
		if err != nil {
			return nil, err
		}
		// Fixed body shape for this test's single-signer, nonce-always-0
		// scenario (documented in the package test file): a 2-byte
		// compact length prefix, then [0x84,0]+account(32)+[0]+sig(64)+
		// extra(2), then the call itself.
		const fixedHeaderLen = 2 + 32 + 1 + 64 + 2
		if len(extrinsic) < 2+fixedHeaderLen {
			return nil, fmt.Errorf("fakeChain: extrinsic too short (%d bytes)", len(extrinsic))
		}
		call := append([]byte{}, extrinsic[2+fixedHeaderLen:]...)
		f.submittedCalls = append(f.submittedCalls, call)
		digest := blake2b.Sum256(extrinsic)
		return "0x" + hex.EncodeToString(digest[:]), nil
	default:
		return nil, fmt.Errorf("fakeChain: unhandled method %q", method)
	}
}

func (f *fakeChain) calls() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]byte{}, f.submittedCalls...)
}

// scaleEncodeAccountIdVec builds a BoundedVec<AccountId32, _> SCALE
// encoding (compact length prefix + raw 32-byte accounts), matching what
// decodeAccountIdVec in blockchainbridge/networkvalidator.go expects.
func scaleEncodeAccountIdVec(accounts [][32]byte) []byte {
	// All test scenarios use well under 64 accounts, so the single-byte
	// compact-length mode (value<<2) always applies.
	out := []byte{byte(len(accounts) << 2)}
	for _, a := range accounts {
		out = append(out, a[:]...)
	}
	return out
}

func buildProviderStorageKeyHex(provider [32]byte) string {
	// decodeProviderAccountFromKey only checks total length (80 bytes)
	// and reads the trailing 32 bytes -- the leading 48 bytes' exact
	// content is irrelevant to this test.
	key := make([]byte, 48)
	key = append(key, provider[:]...)
	return "0x" + hex.EncodeToString(key)
}

// startValidatorLoop wires a full validator loop against a fake chain and
// a real loopback Agent, and starts it. Shared by the end-to-end tests so
// they differ only in the fake Agent they are given -- which is the whole
// variable under test between "the provider declared a capacity" and "it
// did not" -- plus an optional configure callback for tests that need to
// override a LoopConfig field (e.g. UnscoredRetryInterval) beyond the
// fast-but-otherwise-default values set below.
func startValidatorLoop(t *testing.T, fake *fakeAgentServer, configure ...func(*LoopConfig)) (*fakeChain, context.CancelFunc, chan error) {
	t.Helper()
	_, validatorPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate validator key: %v", err)
	}
	var self [32]byte
	copy(self[:], validatorPriv.Public().(ed25519.PublicKey))

	provider := fill32(0xAA)
	// A single-member active set guarantees Committee() selects self
	// regardless of the blake2 seed (see blockchainbridge.Committee):
	// with exactly one candidate, index := seed % 1 == 0 always.
	chain := &fakeChain{
		blockNumberHex: "0x1068", // 4200 decimal -> round 42 at length 100
		activeSetSCALE: scaleEncodeAccountIdVec([][32]byte{self}),
		providerKeys:   []string{buildProviderStorageKeyHex(provider)},
	}
	chainServer := httptest.NewServer(http.HandlerFunc(chain.handler))
	t.Cleanup(chainServer.Close)

	harness := startTestAgentHarness(t, fake)
	t.Cleanup(harness.close)

	rpc, err := blockchainbridge.NewRPCClient(chainServer.URL, &http.Client{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("new RPC client: %v", err)
	}
	registrar := loadRegistrarFromPrivateKey(t, rpc, validatorPriv)

	resolver, err := NewEndpointResolver(harness.dashboard.URL)
	if err != nil {
		t.Fatalf("new resolver: %v", err)
	}
	clientCert, err := registrar.ClientIdentity()
	if err != nil {
		t.Fatalf("client identity: %v", err)
	}
	challenger := NewChallengeClient(ChallengeClientConfig{
		Resolver:          resolver,
		ClientCertificate: clientCert,
		DialTimeout:       2 * time.Second,
		ChallengeTimeout:  2 * time.Second,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cfg := LoopConfig{
		Chain:      rpc,
		Registrar:  registrar,
		Challenger: challenger,

		RoundLength:               RoundLength(100),
		PollInterval:              30 * time.Millisecond,
		CloseAttemptDelay:         60 * time.Millisecond,
		CloseAttemptRetryInterval: 30 * time.Millisecond,
		MaxCloseAttempts:          2,
		// Fast enough that it never blocks TestRunSubmitsNothingForAn-
		// UnscorableNetworkDimension's default assertion (several rounds
		// of probes inside a ~3s budget at a 30ms poll interval); a test
		// that specifically wants to exercise the backoff itself
		// overrides this via configure.
		UnscoredRetryInterval: 10 * time.Millisecond,
		Logger:                slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	for _, apply := range configure {
		apply(&cfg)
	}

	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, cfg)
	}()
	return chain, cancel, done
}

// countEvidenceCalls counts submit_evidence extrinsics (pallet index 16,
// call index 5) seen by the fake chain.
func countEvidenceCalls(chain *fakeChain) int {
	count := 0
	for _, call := range chain.calls() {
		if len(call) >= 2 && call[0] == 16 && call[1] == 5 {
			count++
		}
	}
	return count
}

func TestRunEndToEndSubmitsEvidenceThenAttemptsCloseRound(t *testing.T) {
	_, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}
	// A declared capacity low enough that any real loopback measurement
	// clears the tolerance. It has to be declared at all: an undeclared
	// capacity is now explicitly unscored rather than an automatic pass,
	// so leaving it at 0 would make this end-to-end test submit four
	// dimensions instead of five and stop covering the Network path.
	// TestRunSubmitsNothingForAnUnscorableNetworkDimension covers the
	// undeclared case on purpose.
	fake := &fakeAgentServer{privateKey: agentPriv, declaredIngressMbps: 1, declaredEgressMbps: 1}
	chain, cancel, done := startValidatorLoop(t, fake)
	defer cancel()

	// Wait for at least one submit_evidence (call_index 5) and one
	// close_round (call_index 6) to have been submitted.
	deadline := time.Now().Add(3 * time.Second)
	var sawEvidence, sawClose bool
	for time.Now().Before(deadline) {
		for _, call := range chain.calls() {
			if len(call) < 2 || call[0] != 16 { // networkValidatorPalletIndex
				continue
			}
			switch call[1] {
			case 5:
				sawEvidence = true
			case 6:
				sawClose = true
			}
		}
		if sawEvidence && sawClose {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done

	if !sawEvidence {
		t.Error("expected at least one submit_evidence call")
	}
	if !sawClose {
		t.Error("expected at least one close_round attempt")
	}

	// Exactly one submit_evidence per dimension (5 dimensions), never
	// re-submitted across ticks -- the in-memory `done` map must prevent
	// duplicates within this process's lifetime.
	evidenceCount := countEvidenceCalls(chain)
	if evidenceCount != len(Dimensions) {
		t.Errorf("submit_evidence called %d times, want exactly %d (once per dimension, never re-submitted)", evidenceCount, len(Dimensions))
	}

	// ADR-015: the Network dimension's evidence must come from
	// MeasureBandwidth calls, never a SolveChallenge(TYPE_NETWORK) call --
	// and every other dimension must still go through SolveChallenge
	// exactly once, unchanged. ADR-025 §1 then made the Network dimension
	// multi-probe: one round now issues DefaultBandwidthProbesPerRound
	// MeasureBandwidth calls (scored on their minimum), not one.
	fake.mu.Lock()
	measureBandwidthCalls := fake.measureBandwidthCalls
	solveChallengeTypes := append([]agentv1.SolveChallengeRequest_Type{}, fake.solveChallengeTypes...)
	fake.mu.Unlock()

	if measureBandwidthCalls != DefaultBandwidthProbesPerRound {
		t.Errorf("MeasureBandwidth called %d times, want exactly %d (ADR-025 §1's per-round probe count)", measureBandwidthCalls, DefaultBandwidthProbesPerRound)
	}
	wantSolveChallengeTypes := map[agentv1.SolveChallengeRequest_Type]int{
		agentv1.SolveChallengeRequest_TYPE_COMPUTE:      1,
		agentv1.SolveChallengeRequest_TYPE_STORAGE:      1,
		agentv1.SolveChallengeRequest_TYPE_AVAILABILITY: 1,
		agentv1.SolveChallengeRequest_TYPE_RELIABILITY:  1,
	}
	gotSolveChallengeTypes := map[agentv1.SolveChallengeRequest_Type]int{}
	for _, solveChallengeType := range solveChallengeTypes {
		gotSolveChallengeTypes[solveChallengeType]++
	}
	for solveChallengeType, wantCount := range wantSolveChallengeTypes {
		if gotSolveChallengeTypes[solveChallengeType] != wantCount {
			t.Errorf("SolveChallenge(%s) called %d times, want %d", solveChallengeType, gotSolveChallengeTypes[solveChallengeType], wantCount)
		}
	}
	if count := gotSolveChallengeTypes[agentv1.SolveChallengeRequest_TYPE_NETWORK]; count != 0 {
		t.Errorf("SolveChallenge(TYPE_NETWORK) called %d times, want 0 -- the Network dimension must use MeasureBandwidth instead (ADR-015)", count)
	}
}

// loadRegistrarFromPrivateKey writes privateKey to a temp PKCS8 PEM file
// and loads it through the real production loader, matching
// testValidatorClientCert's reasoning in challenge_test.go.
func loadRegistrarFromPrivateKey(t *testing.T, rpc *blockchainbridge.RPCClient, privateKey ed25519.PrivateKey) *blockchainbridge.Registrar {
	t.Helper()
	pkcs8, err := marshalPKCS8(privateKey)
	if err != nil {
		t.Fatalf("marshal PKCS8: %v", err)
	}
	keyFile := filepath.Join(t.TempDir(), "validator-key.pem")
	if err := os.WriteFile(keyFile, pkcs8, 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	registrar, err := blockchainbridge.NewRegistrarFromPKCS8File(rpc, keyFile)
	if err != nil {
		t.Fatalf("load registrar: %v", err)
	}
	return registrar
}

// The daemon must submit nothing at all for a dimension it could not
// score, and must keep retrying it rather than marking it done.
//
// This is the loop-level half of the hardening: MeasureBandwidth
// returning Unscored is only useful if challengeAndSubmit actually
// declines to submit it. Before this, a provider that never heartbeated
// its ResourceCapability.Bandwidth had a full-marks Network score written
// to chain every round, on the strength of a tolerance check that had
// nothing to compare against.
func TestRunSubmitsNothingForAnUnscorableNetworkDimension(t *testing.T) {
	_, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}
	// No declared capacity: exactly the state a provider is in before its
	// first capability-bearing heartbeat reaches the dashboard.
	fake := &fakeAgentServer{privateKey: agentPriv}
	chain, cancel, done := startValidatorLoop(t, fake)
	defer cancel()

	// Wait until the four scorable dimensions have all been submitted,
	// then keep the loop running long enough that a Network submission
	// would have had several further ticks to appear.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && countEvidenceCalls(chain) < len(Dimensions)-1 {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	cancel()
	<-done

	if got := countEvidenceCalls(chain); got != len(Dimensions)-1 {
		t.Errorf("submit_evidence called %d times, want %d -- every dimension except Network, which could not be scored", got, len(Dimensions)-1)
	}

	fake.mu.Lock()
	measureBandwidthCalls := fake.measureBandwidthCalls
	solveChallengeTypes := append([]agentv1.SolveChallengeRequest_Type{}, fake.solveChallengeTypes...)
	fake.mu.Unlock()

	// The probe still runs -- the measurement is fine, it is the
	// *judgement* that cannot be made -- and, because the dimension is
	// never marked done, it is retried on later ticks rather than
	// abandoned. More than one round's worth of probes proves the retry.
	if measureBandwidthCalls <= DefaultBandwidthProbesPerRound {
		t.Errorf("MeasureBandwidth called %d times, want more than one round's %d: an unscored dimension must be retried, not marked done",
			measureBandwidthCalls, DefaultBandwidthProbesPerRound)
	}
	// The other four dimensions must be untouched by this: they are
	// scored and submitted exactly once each, as always.
	counts := map[agentv1.SolveChallengeRequest_Type]int{}
	for _, solveChallengeType := range solveChallengeTypes {
		counts[solveChallengeType]++
	}
	for _, solveChallengeType := range []agentv1.SolveChallengeRequest_Type{
		agentv1.SolveChallengeRequest_TYPE_COMPUTE,
		agentv1.SolveChallengeRequest_TYPE_STORAGE,
		agentv1.SolveChallengeRequest_TYPE_AVAILABILITY,
		agentv1.SolveChallengeRequest_TYPE_RELIABILITY,
	} {
		if counts[solveChallengeType] != 1 {
			t.Errorf("SolveChallenge(%s) called %d times, want 1", solveChallengeType, counts[solveChallengeType])
		}
	}
}

// An unscored Network dimension must still be retried eventually (proven
// above), but not on every single poll tick: that reruns a full
// multi-probe MeasureBandwidth round (real mTLS traffic, several MiB each
// way) against a signal -- the provider's declared capacity -- that only
// changes with the provider's next heartbeat, far slower than the poll
// cadence. This pins the bound: within one UnscoredRetryInterval window,
// at most one round of probes runs no matter how many poll ticks land
// inside it; once the window elapses, a further round runs.
func TestChallengeAndSubmitBacksOffRetryingAnUnscoredNetworkDimension(t *testing.T) {
	_, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}
	// No declared capacity: exactly TestRunSubmitsNothingForAnUnscorable-
	// NetworkDimension's setup, but with a backoff window wide enough to
	// observe directly instead of the default fast-test value.
	fake := &fakeAgentServer{privateKey: agentPriv}
	const backoff = 300 * time.Millisecond
	_, cancel, done := startValidatorLoop(t, fake, func(cfg *LoopConfig) {
		cfg.UnscoredRetryInterval = backoff
	})
	defer cancel()

	// Several poll ticks (30ms cadence) land inside this window; only the
	// first should have actually run a probe round.
	time.Sleep(backoff - 60*time.Millisecond)
	fake.mu.Lock()
	withinWindow := fake.measureBandwidthCalls
	fake.mu.Unlock()
	if withinWindow > DefaultBandwidthProbesPerRound {
		t.Errorf("measureBandwidthCalls = %d within one UnscoredRetryInterval window, want at most %d (one round)",
			withinWindow, DefaultBandwidthProbesPerRound)
	}

	// Now past the window: a further round must have been attempted.
	time.Sleep(2 * backoff)
	cancel()
	<-done

	fake.mu.Lock()
	afterWindow := fake.measureBandwidthCalls
	fake.mu.Unlock()
	if afterWindow <= withinWindow {
		t.Errorf("measureBandwidthCalls = %d after the backoff window elapsed, want more than %d: a retry should have happened",
			afterWindow, withinWindow)
	}
}
