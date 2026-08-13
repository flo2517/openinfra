package blockchainbridge

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// encodeSubmissionForTest mirrors SCALE's encoding of
// pallet_network_validator::Submission by hand, so decodeSubmissions is
// tested against an independently constructed byte sequence rather than
// against its own inverse.
func encodeSubmissionForTest(validator [32]byte, scoreBps uint16, sampleCount uint32, payloadHash [32]byte) []byte {
	encoded := make([]byte, 0, submissionEncodedLength)
	encoded = append(encoded, validator[:]...)
	encoded = binary.LittleEndian.AppendUint16(encoded, scoreBps)
	encoded = binary.LittleEndian.AppendUint32(encoded, sampleCount)
	encoded = append(encoded, payloadHash[:]...)
	return encoded
}

// encodeSubmissionVecForTest prefixes elements with SCALE's compact
// length. Only single-byte mode (n < 64) is produced, which covers every
// length the runtime's MaxSubmissionsPerRound (32) permits.
func encodeSubmissionVecForTest(elements ...[]byte) []byte {
	encoded := []byte{byte(len(elements) << 2)}
	for _, element := range elements {
		encoded = append(encoded, element...)
	}
	return encoded
}

func TestDecodeSubmissionsDecodesEveryFieldInDeclarationOrder(t *testing.T) {
	var validatorA, validatorB, hashA, hashB [32]byte
	validatorA[0], validatorB[0] = 0xAA, 0xBB
	hashA[31], hashB[31] = 0x01, 0x02

	data := encodeSubmissionVecForTest(
		encodeSubmissionForTest(validatorA, 9_000, 12, hashA),
		encodeSubmissionForTest(validatorB, 10_000, 4_000_000_000, hashB),
	)

	got, err := decodeSubmissions(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("decoded %d submissions, want 2", len(got))
	}
	if got[0].Validator != validatorA || got[0].ScoreBps != 9_000 || got[0].SampleCount != 12 || got[0].PayloadHash != hashA {
		t.Fatalf("first submission decoded as %+v", got[0])
	}
	// Second element pins that a u32 above 2^31 survives the decode --
	// a sample count is unsigned on-chain and must not be read as signed.
	if got[1].Validator != validatorB || got[1].ScoreBps != 10_000 || got[1].SampleCount != 4_000_000_000 || got[1].PayloadHash != hashB {
		t.Fatalf("second submission decoded as %+v", got[1])
	}
}

func TestDecodeSubmissionsReturnsEmptyForAnEmptyVec(t *testing.T) {
	got, err := decodeSubmissions(encodeSubmissionVecForTest())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("decoded %d submissions from an empty vec", len(got))
	}
}

func TestDecodeSubmissionsRejectsMalformedInput(t *testing.T) {
	var validator, hash [32]byte
	valid := encodeSubmissionForTest(validator, 1, 1, hash)

	cases := map[string][]byte{
		"empty input":                     {},
		"truncated element":               append([]byte{1 << 2}, valid[:submissionEncodedLength-1]...),
		"length prefix promises too many": append([]byte{2 << 2}, valid...),
		"trailing bytes after the last element": append(
			encodeSubmissionVecForTest(valid), 0xFF),
		// 33 elements' worth of prefix: above the runtime's bound of 32,
		// so it must be rejected on the prefix alone rather than by
		// attempting to size a slice from an untrusted length.
		"more submissions than the runtime bound": {33 << 2},
	}
	for name, data := range cases {
		if _, err := decodeSubmissions(data); err == nil {
			t.Fatalf("expected an error for %s", name)
		}
	}
}

func TestEvidenceStorageKeyIsDistinctFromTheRoundsKeyForTheSameTriple(t *testing.T) {
	var provider [32]byte
	provider[0] = 7
	evidence := evidenceStorageKey(provider, 4, DimensionCompute)
	rounds := roundResultStorageKey(provider, 4, DimensionCompute)
	if evidence == rounds {
		t.Fatal("Evidence and Rounds share a storage key: the item name is not reaching the prefix")
	}
	if len(evidence) != len(rounds) {
		t.Fatalf("Evidence key length %d != Rounds key length %d, but both NMaps have the identical key shape", len(evidence), len(rounds))
	}
}

func TestEvidenceStorageKeyPrefixMatchesPalletAndItemName(t *testing.T) {
	var provider [32]byte
	key := evidenceStorageKey(provider, 0, DimensionCompute)
	wantPrefix := "0x" + toHex(twox128([]byte("NetworkValidator"))) + toHex(twox128([]byte("Evidence")))
	if !strings.HasPrefix(key, wantPrefix) {
		t.Fatalf("storage key %s does not start with pallet/item prefix %s", key, wantPrefix)
	}
}

func TestEvidenceStorageKeyVariesWithEveryKeyComponent(t *testing.T) {
	var providerA, providerB [32]byte
	providerA[0], providerB[0] = 1, 2

	base := evidenceStorageKey(providerA, 7, DimensionNetwork)
	cases := map[string]string{
		"different provider":  evidenceStorageKey(providerB, 7, DimensionNetwork),
		"different round":     evidenceStorageKey(providerA, 8, DimensionNetwork),
		"different dimension": evidenceStorageKey(providerA, 7, DimensionStorage),
	}
	for name, other := range cases {
		if other == base {
			t.Fatalf("expected %s to change the storage key, but it did not", name)
		}
	}
	if evidenceStorageKey(providerA, 7, DimensionNetwork) != base {
		t.Fatal("expected a deterministic storage key for identical inputs")
	}
}

// TestNetworkValidatorRoundKeySharesEverythingButTheItemName pins that the
// two NMaps' keys differ *only* in the item-name segment -- the shared
// construction's whole justification. Bytes 0..16 are the pallet prefix
// (identical), 16..32 the item prefix (different), and everything after
// is the per-key hashing (identical).
func TestNetworkValidatorRoundKeySharesEverythingButTheItemName(t *testing.T) {
	var provider [32]byte
	provider[0] = 9
	evidence := evidenceStorageKey(provider, 3, DimensionAvailability)
	rounds := roundResultStorageKey(provider, 3, DimensionAvailability)

	const hexPrefixLength = 2
	const palletSegment = hexPrefixLength + 32 // "0x" + 16 bytes hex-encoded
	const itemSegment = palletSegment + 32

	if evidence[:palletSegment] != rounds[:palletSegment] {
		t.Fatal("pallet prefix differs between Evidence and Rounds")
	}
	if evidence[palletSegment:itemSegment] == rounds[palletSegment:itemSegment] {
		t.Fatal("item prefix is identical between Evidence and Rounds")
	}
	if evidence[itemSegment:] != rounds[itemSegment:] {
		t.Fatal("per-key hashing differs between Evidence and Rounds, but both are declared with the same key shape")
	}
}

func TestSubmissionEncodedLengthMatchesAHandBuiltElement(t *testing.T) {
	var account, hash [32]byte
	if got := len(encodeSubmissionForTest(account, 0, 0, hash)); got != submissionEncodedLength {
		t.Fatalf("hand-built submission is %d bytes, constant says %d", got, submissionEncodedLength)
	}
	if !bytes.Equal(encodeSubmissionForTest(account, 0, 0, hash)[32:38], []byte{0, 0, 0, 0, 0, 0}) {
		t.Fatal("score_bps/sample_count are not where the decoder expects them")
	}
}
