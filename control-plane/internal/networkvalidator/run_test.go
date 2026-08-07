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

func TestRunEndToEndSubmitsEvidenceThenAttemptsCloseRound(t *testing.T) {
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
	defer chainServer.Close()

	_, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}
	harness := startTestAgentHarness(t, &fakeAgentServer{privateKey: agentPriv})
	defer harness.close()

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
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, LoopConfig{
			Chain:                     rpc,
			Registrar:                 registrar,
			Challenger:                challenger,
			RoundLength:               RoundLength(100),
			PollInterval:              30 * time.Millisecond,
			CloseAttemptDelay:         60 * time.Millisecond,
			CloseAttemptRetryInterval: 30 * time.Millisecond,
			MaxCloseAttempts:          2,
			Logger:                    slog.New(slog.NewTextHandler(io.Discard, nil)),
		})
	}()

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
	evidenceCount := 0
	for _, call := range chain.calls() {
		if len(call) >= 2 && call[0] == 16 && call[1] == 5 {
			evidenceCount++
		}
	}
	if evidenceCount != len(Dimensions) {
		t.Errorf("submit_evidence called %d times, want exactly %d (once per dimension, never re-submitted)", evidenceCount, len(Dimensions))
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
