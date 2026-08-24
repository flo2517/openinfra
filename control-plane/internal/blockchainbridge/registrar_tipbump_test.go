package blockchainbridge

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/crypto/blake2b"
)

// newTipBumpTestRegistrar builds a Registrar with a freshly generated
// Ed25519 key, talking to rpc -- deliberately not going through
// NewRegistrarFromPKCS8File (which requires a PEM file on disk) since
// these tests only exercise submitSigned, a package-internal method that
// needs nothing but a signing key and an RPCClient.
func newTipBumpTestRegistrar(t *testing.T, rpc *RPCClient) *Registrar {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	registrar := &Registrar{rpc: rpc, privateKey: privateKey}
	copy(registrar.account[:], privateKey.Public().(ed25519.PublicKey))
	return registrar
}

// rpcRequest mirrors the subset of the JSON-RPC envelope this test's mock
// server needs to read.
type rpcRequest struct {
	ID     uint64   `json:"id"`
	Method string   `json:"method"`
	Params []string `json:"params"`
}

// decodeExtrinsicTip parses ChargeTip's Compact<u64> back out of a raw,
// hex-decoded extrinsic -- the extra field's shape is
// Era(1) ++ Compact(nonce) ++ Compact(tip) (ADR-032 Sec3), sitting right
// after extrinsic := Compact(len(body)) ++ body, and
// body := version(1) ++ signerType(1) ++ account(32) ++ sigType(1) ++
// signature(64) ++ extra ++ call.
func decodeExtrinsicTip(t *testing.T, raw []byte) uint64 {
	t.Helper()
	_, lenOffset, err := decodeCompactUint(raw)
	if err != nil {
		t.Fatalf("decode extrinsic length prefix: %v", err)
	}
	body := raw[lenOffset:]
	const fixedPrefix = 1 + 1 + 32 + 1 + 64 // version + signerType + account + sigType + signature
	if len(body) < fixedPrefix+1 {
		t.Fatalf("extrinsic body shorter than its fixed-size prefix: %d bytes", len(body))
	}
	extra := body[fixedPrefix:]
	afterEra := extra[1:] // era is always a single hardcoded-Immortal byte
	_, nonceLen, err := decodeCompactUint(afterEra)
	if err != nil {
		t.Fatalf("decode nonce from extra: %v", err)
	}
	tipBytes := afterEra[nonceLen:]
	tip, _, err := decodeCompactUint(tipBytes)
	if err != nil {
		t.Fatalf("decode tip from extra: %v", err)
	}
	return tip
}

// tipBumpMockServer implements just enough of author_submitExtrinsic to
// drive submitSigned's retry loop: the first len(errorCodes) calls fail
// with the given RPC error codes (in order), and every call after that
// succeeds, computing the real extrinsic hash from the submitted bytes
// (mirroring what a real node's hash-matches-what-we-signed check would
// see) so submitSigned's own "Substrate returned an unexpected extrinsic
// hash" guard never trips. Every call's submitted extrinsic bytes are
// recorded, in order, in *calls.
func tipBumpMockServer(t *testing.T, errorCodes []int64, calls *[][]byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}
		var req rpcRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if req.Method != "author_submitExtrinsic" {
			t.Fatalf("unexpected RPC method %q", req.Method)
		}
		if len(req.Params) != 1 {
			t.Fatalf("expected exactly one param, got %d", len(req.Params))
		}
		raw, err := decodeHex(req.Params[0])
		if err != nil {
			t.Fatalf("decode submitted extrinsic hex: %v", err)
		}

		attemptIndex := len(*calls)
		*calls = append(*calls, raw)

		if attemptIndex < len(errorCodes) {
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"error":{"code":%d,"message":"mock rejection"}}`, req.ID, errorCodes[attemptIndex])
			return
		}
		hash := blake2b.Sum256(raw)
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"result":"0x%x"}`, req.ID, hash[:])
	}))
}

func testSubmitSignedArgs() (call []byte, nonce uint64, version RuntimeVersion, genesis [32]byte) {
	call = []byte{sudoPalletIndex, sudoCallIndex, providerRegistryPalletIndex, setStatusCallIndex}
	nonce = 0
	version = RuntimeVersion{SpecVersion: supportedSpecVersion, TransactionVersion: supportedTransactionVersion}
	return call, nonce, version, genesis
}

// TestSubmitSignedBumpsTipOnPriorityTooLowAndResubmits is the core ADR-032
// Sec4 behavior: exactly one 1014 triggers exactly one bounded tip bump
// and a resubmission with a strictly higher tip, which then succeeds.
func TestSubmitSignedBumpsTipOnPriorityTooLowAndResubmits(t *testing.T) {
	var calls [][]byte
	server := tipBumpMockServer(t, []int64{1014}, &calls)
	defer server.Close()
	rpc, err := NewRPCClient(server.URL, server.Client())
	if err != nil {
		t.Fatalf("configure RPC client: %v", err)
	}
	registrar := newTipBumpTestRegistrar(t, rpc)

	call, nonce, version, genesis := testSubmitSignedArgs()
	hash, err := registrar.submitSigned(context.Background(), call, nonce, version, genesis)
	if err != nil {
		t.Fatalf("submitSigned: expected success after one bounded tip bump, got %v", err)
	}
	if hash == ([32]byte{}) {
		t.Fatal("submitSigned returned a zero hash on success")
	}
	if len(calls) != 2 {
		t.Fatalf("expected exactly 2 submission attempts (1 initial + 1 bump), got %d", len(calls))
	}
	firstTip := decodeExtrinsicTip(t, calls[0])
	secondTip := decodeExtrinsicTip(t, calls[1])
	if firstTip != 0 {
		t.Fatalf("first attempt should carry tip 0, got %d", firstTip)
	}
	if secondTip <= firstTip {
		t.Fatalf("resubmission tip (%d) must be strictly higher than the first attempt's tip (%d)", secondTip, firstTip)
	}
	if secondTip != 1 {
		t.Fatalf("resubmission tip = %d, want 1 (nextTip(0))", secondTip)
	}
}

// TestSubmitSignedDoesNotBumpOnANonPriorityTooLowError is the regression
// guard mirroring IsTemporarilyBanned's own testing discipline: a non-1014
// error -- including 1012, which needs the opposite response (#157's
// MaxBackoff jump, not a tip bump, since retrying an identical extrinsic
// cannot help) -- must not trigger any tip bump. submitSigned returns
// immediately after the single attempt, and the returned error is still
// recognizable by IsTemporarilyBanned, proving the caller-level #157
// handoff is reachable unchanged.
func TestSubmitSignedDoesNotBumpOnANonPriorityTooLowError(t *testing.T) {
	cases := map[string]int64{
		"temporarily_banned_1012":  1012,
		"invalid_transaction_1010": 1010,
		"unrelated_rpc_error":      -32601,
	}
	for name, code := range cases {
		t.Run(name, func(t *testing.T) {
			var calls [][]byte
			server := tipBumpMockServer(t, []int64{code, code, code, code, code}, &calls)
			defer server.Close()
			rpc, err := NewRPCClient(server.URL, server.Client())
			if err != nil {
				t.Fatalf("configure RPC client: %v", err)
			}
			registrar := newTipBumpTestRegistrar(t, rpc)

			call, nonce, version, genesis := testSubmitSignedArgs()
			_, err = registrar.submitSigned(context.Background(), call, nonce, version, genesis)
			if err == nil {
				t.Fatal("expected submitSigned to return an error")
			}
			if len(calls) != 1 {
				t.Fatalf("expected exactly 1 submission attempt (no tip bump), got %d", len(calls))
			}
			if code == 1012 && !IsTemporarilyBanned(err) {
				t.Fatalf("expected the untouched 1012 error to still satisfy IsTemporarilyBanned, got %v", err)
			}
			if code == 1014 {
				t.Fatal("test setup bug: 1014 belongs in the bump test, not the no-bump regression guard")
			}
		})
	}
}

// TestSubmitSignedCapsTipBumpAttemptsIndependently: a run of 1014s that
// never resolves must stop bumping after exactly maxTipBumpAttempts
// resubmissions (maxTipBumpAttempts + 1 total attempts, including the
// initial tip-0 submission), returning the last 1014 error to the caller
// rather than retrying forever -- the cap this ADR is explicit about not
// letting become another unbounded-escalation gap.
func TestSubmitSignedCapsTipBumpAttemptsIndependently(t *testing.T) {
	alwaysTooLow := make([]int64, maxTipBumpAttempts+5) // more failures than the cap allows
	for i := range alwaysTooLow {
		alwaysTooLow[i] = 1014
	}
	var calls [][]byte
	server := tipBumpMockServer(t, alwaysTooLow, &calls)
	defer server.Close()
	rpc, err := NewRPCClient(server.URL, server.Client())
	if err != nil {
		t.Fatalf("configure RPC client: %v", err)
	}
	registrar := newTipBumpTestRegistrar(t, rpc)

	call, nonce, version, genesis := testSubmitSignedArgs()
	_, err = registrar.submitSigned(context.Background(), call, nonce, version, genesis)
	if err == nil {
		t.Fatal("expected submitSigned to give up and return an error once bump attempts are exhausted")
	}
	if !IsPriorityTooLow(err) {
		t.Fatalf("expected the exhausted error to still be a 1014, got %v", err)
	}
	wantAttempts := maxTipBumpAttempts + 1 // the initial attempt plus every bump
	if len(calls) != wantAttempts {
		t.Fatalf("expected exactly %d submission attempts (attempt cap), got %d", wantAttempts, len(calls))
	}

	tips := make([]uint64, len(calls))
	for i, raw := range calls {
		tips[i] = decodeExtrinsicTip(t, raw)
	}
	for i := 1; i < len(tips); i++ {
		if tips[i] <= tips[i-1] {
			t.Fatalf("tip sequence %v is not strictly increasing at index %d", tips, i)
		}
	}
	for _, tip := range tips {
		if tip > maxTip {
			t.Fatalf("tip %d exceeds maxTip (%d) -- the tip cap was not respected", tip, maxTip)
		}
	}
}

// TestNextTipDoublesFromOneAndCapsAtMaxTip pins nextTip's exact sequence
// (ADR-032 Sec4: 1, 2, 4, doubling) and proves the cap holds independently
// of how many times it's called -- not just within the 3 calls
// submitSigned's own attempt cap ever actually makes.
func TestNextTipDoublesFromOneAndCapsAtMaxTip(t *testing.T) {
	tip := uint64(0)
	var sequence []uint64
	for i := 0; i < 20; i++ {
		tip = nextTip(tip)
		sequence = append(sequence, tip)
	}
	want := []uint64{1, 2, 4, 8, 16, 32, 64, 100, 100, 100}
	for i, w := range want {
		if sequence[i] != w {
			t.Fatalf("nextTip sequence[%d] = %d, want %d (full sequence so far: %v)", i, sequence[i], w, sequence[:i+1])
		}
	}
	for _, tip := range sequence {
		if tip > maxTip {
			t.Fatalf("nextTip produced %d, exceeding maxTip (%d)", tip, maxTip)
		}
	}
}
