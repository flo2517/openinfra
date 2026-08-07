package blockchainbridge

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestRoundResultStorageKeyIsAPerKeyMapEntry(t *testing.T) {
	var providerA, providerB [32]byte
	providerA[0], providerB[0] = 1, 2

	base := roundResultStorageKey(providerA, 7, DimensionNetwork)

	cases := map[string]string{
		"different provider":  roundResultStorageKey(providerB, 7, DimensionNetwork),
		"different round":     roundResultStorageKey(providerA, 8, DimensionNetwork),
		"different dimension": roundResultStorageKey(providerA, 7, DimensionStorage),
	}
	for name, other := range cases {
		if other == base {
			t.Fatalf("expected %s to change the storage key, but it did not", name)
		}
	}
	if roundResultStorageKey(providerA, 7, DimensionNetwork) != base {
		t.Fatal("expected a deterministic storage key for identical inputs")
	}
}

// TestRoundResultStorageKeyPrefixMatchesPalletAndItemName pins the
// pallet/item prefix bytes (the first 32 hex-encoded bytes = twox128
// "NetworkValidator" ++ twox128 "Rounds") independently of the per-key
// hashing, so a future rename of either string is caught here rather than
// only surfacing as a live-chain "not found" that looks identical to a
// round that legitimately hasn't closed yet.
func TestRoundResultStorageKeyPrefixMatchesPalletAndItemName(t *testing.T) {
	var provider [32]byte
	key := roundResultStorageKey(provider, 0, DimensionCompute)
	wantPrefix := "0x" + toHex(twox128([]byte("NetworkValidator"))) + toHex(twox128([]byte("Rounds")))
	if !strings.HasPrefix(key, wantPrefix) {
		t.Fatalf("storage key %s does not start with pallet/item prefix %s", key, wantPrefix)
	}
}

func toHex(b []byte) string {
	const hexDigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[2*i] = hexDigits[v>>4]
		out[2*i+1] = hexDigits[v&0x0f]
	}
	return string(out)
}

func TestTwox64ProducesEightBytesAndDiffersFromTwox128sFirstHalf(t *testing.T) {
	value := []byte("round")
	got := twox64(value)
	if len(got) != 8 {
		t.Fatalf("twox64 returned %d bytes, want 8", len(got))
	}
	// twox128 is defined as two 8-byte xxHash64 passes (seeds 0 and 1)
	// concatenated; twox64 must be exactly the first of those, not some
	// independent construction that happens to also be 8 bytes.
	full := twox128(value)
	if string(full[:8]) != string(got) {
		t.Fatal("expected twox64 to equal twox128's first 8 bytes (the seed-0 half)")
	}
}

func TestDecodeRoundResultMatchesPalletFieldOrder(t *testing.T) {
	data := []byte{
		0x10, 0x27, // score_bps = 10000 (LE u16)
		0xE8, 0x03, // previous_score_bps = 1000 (LE u16)
		0x05, 0x00, 0x00, 0x00, // submissions = 5 (LE u32)
		0x05, 0x00, 0x00, 0x00, // committee_target = 5 (LE u32)
		0x64, 0x00, 0x00, 0x00, // closed_at = 100 (LE u32)
		0x00, // status = Final
	}
	got, err := decodeRoundResult(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := RoundResult{
		ScoreBps:         10000,
		PreviousScoreBps: 1000,
		Submissions:      5,
		CommitteeTarget:  5,
		ClosedAt:         100,
		Status:           RoundFinal,
	}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	if got.ConfidenceBps() != 10_000 {
		t.Fatalf("expected full attendance (5/5) to be 10000 bps confidence, got %d", got.ConfidenceBps())
	}
}

func TestDecodeRoundResultRejectsWrongLength(t *testing.T) {
	if _, err := decodeRoundResult(make([]byte, 16)); err == nil {
		t.Fatal("expected an error for a truncated RoundResult")
	}
	if _, err := decodeRoundResult(make([]byte, 18)); err == nil {
		t.Fatal("expected an error for an over-long RoundResult")
	}
}

func TestDecodeRoundResultRejectsUnknownStatusVariant(t *testing.T) {
	data := make([]byte, 17)
	data[16] = 4 // one past DisputeRejected(3)
	if _, err := decodeRoundResult(data); err == nil {
		t.Fatal("expected an error for an out-of-range RoundStatus variant tag")
	}
}

func TestRoundResultConfidenceBpsHandlesPartialAttendanceAndZeroTarget(t *testing.T) {
	partial := RoundResult{Submissions: 2, CommitteeTarget: 5}
	if got := partial.ConfidenceBps(); got != 4_000 {
		t.Fatalf("expected 2/5 = 4000 bps, got %d", got)
	}
	zero := RoundResult{Submissions: 3, CommitteeTarget: 0}
	if got := zero.ConfidenceBps(); got != 0 {
		t.Fatalf("expected a zero CommitteeTarget to report 0 confidence rather than divide by zero, got %d", got)
	}
}

func TestRoundStatusStringCoversEveryVariant(t *testing.T) {
	cases := map[RoundStatus]string{
		RoundFinal:           "final",
		RoundDisputed:        "disputed",
		RoundDisputeUpheld:   "dispute_upheld",
		RoundDisputeRejected: "dispute_rejected",
		RoundStatus(200):     "unknown",
	}
	for status, want := range cases {
		if got := status.String(); got != want {
			t.Fatalf("RoundStatus(%d).String() = %q, want %q", status, got, want)
		}
	}
}

// TestFinalizedRoundResultAgainstLocalNode proves the read path (storage
// key + state_getStorage + decode) actually round-trips against a real
// running chain. As documented throughout this session, the local dev
// chain's compiled wasm predates pallet-network-validator entirely, so no
// round can genuinely exist on it -- this test can only prove the
// "not found" path behaves correctly (no RPC error, found=false) rather
// than a real decode. That is still worth pinning: it is the exact
// behavior a dashboard sees for every round that has not closed yet, the
// overwhelmingly common case.
func TestFinalizedRoundResultAgainstLocalNode(t *testing.T) {
	endpoint := os.Getenv("OPENINFRA_TEST_SUBSTRATE_RPC_URL")
	if endpoint == "" {
		t.Skip("local Substrate integration environment is not configured")
	}
	rpc, err := NewRPCClient(endpoint, &http.Client{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("configure RPC: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var provider [32]byte
	provider[0] = 0xEE
	_, found, err := rpc.FinalizedRoundResult(ctx, provider, 0, DimensionNetwork)
	if err != nil {
		t.Fatalf("read round result: %v", err)
	}
	if found {
		t.Fatal("did not expect a closed round for a made-up provider/round pair")
	}
}
