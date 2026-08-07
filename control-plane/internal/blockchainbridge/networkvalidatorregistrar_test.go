package blockchainbridge

import (
	"encoding/binary"
	"testing"
)

func encodeValidatorRecordForTest(status byte, availableAt uint32, stake uint64, registeredAt uint32) []byte {
	data := []byte{status}
	if status == 2 {
		data = binary.LittleEndian.AppendUint32(data, availableAt)
	}
	data = binary.LittleEndian.AppendUint64(data, stake)
	data = binary.LittleEndian.AppendUint32(data, registeredAt)
	return data
}

func TestDecodeValidatorRecordRoundTripsEveryStatusVariant(t *testing.T) {
	cases := []struct {
		name   string
		status byte
		want   ValidatorRecord
	}{
		{"active", 0, ValidatorRecord{Status: ValidatorActive, Stake: 1000, RegisteredAt: 42}},
		{"suspended", 1, ValidatorRecord{Status: ValidatorSuspended, Stake: 1000, RegisteredAt: 42}},
		{"exiting", 2, ValidatorRecord{Status: ValidatorExiting, AvailableAt: 15400, Stake: 1000, RegisteredAt: 42}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			encoded := encodeValidatorRecordForTest(c.status, c.want.AvailableAt, c.want.Stake, c.want.RegisteredAt)
			got, err := decodeValidatorRecord(encoded)
			if err != nil {
				t.Fatalf("decodeValidatorRecord: %v", err)
			}
			if got != c.want {
				t.Fatalf("decodeValidatorRecord() = %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestDecodeValidatorRecordRejectsMalformedInput(t *testing.T) {
	valid := encodeValidatorRecordForTest(0, 0, 1000, 42)
	cases := map[string][]byte{
		"empty":                 {},
		"unknown status":        {99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		"truncated exiting tag": {2, 0, 0},
		"truncated fixed tail":  valid[:len(valid)-1],
		"trailing byte":         append(append([]byte{}, valid...), 0xFF),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeValidatorRecord(data); err == nil {
				t.Fatalf("expected an error decoding %q, got none", name)
			}
		})
	}
}

func TestValidatorLifecycleStatusString(t *testing.T) {
	cases := map[ValidatorLifecycleStatus]string{
		ValidatorActive:              "ACTIVE",
		ValidatorSuspended:           "SUSPENDED",
		ValidatorExiting:             "EXITING",
		ValidatorLifecycleStatus(99): "UNKNOWN",
	}
	for status, want := range cases {
		if got := status.String(); got != want {
			t.Errorf("ValidatorLifecycleStatus(%d).String() = %q, want %q", status, got, want)
		}
	}
}

func TestEncodeSubmitEvidenceCallMatchesPalletFieldOrder(t *testing.T) {
	var provider [32]byte
	for i := range provider {
		provider[i] = byte(i)
	}
	var payloadHash [32]byte
	for i := range payloadHash {
		payloadHash[i] = byte(0xF0 + i%16)
	}
	round := uint64(123456789)
	dimension := DimensionReliability
	scoreBps := uint16(9500)
	sampleCount := uint32(1)

	got := encodeSubmitEvidenceCall(provider, round, dimension, scoreBps, sampleCount, payloadHash)

	want := []byte{networkValidatorPalletIndex, submitEvidenceCallIndex}
	want = append(want, provider[:]...)
	want = binary.LittleEndian.AppendUint64(want, round)
	want = append(want, byte(dimension)) // ScoreDimension::Reliability == 4
	want = binary.LittleEndian.AppendUint16(want, scoreBps)
	want = binary.LittleEndian.AppendUint32(want, sampleCount)
	want = append(want, payloadHash[:]...)

	if string(got) != string(want) {
		t.Fatalf("encodeSubmitEvidenceCall() = %x, want %x", got, want)
	}
	// Fixed total length sanity check: 2 (pallet+call) + 32 (provider) +
	// 8 (round) + 1 (dimension tag) + 2 (score_bps) + 4 (sample_count) +
	// 32 (payload_hash) = 81 bytes, no compact-encoding variability.
	if len(got) != 81 {
		t.Fatalf("encodeSubmitEvidenceCall() length = %d, want 81", len(got))
	}
	if got[len(got)-32-4-2-1] != byte(DimensionReliability) {
		t.Fatalf("dimension tag byte is misplaced")
	}
}

func TestScoreDimensionEncodesAsDeclarationOrderByte(t *testing.T) {
	cases := []struct {
		dimension ScoreDimension
		want      byte
	}{
		{DimensionCompute, 0},
		{DimensionStorage, 1},
		{DimensionNetwork, 2},
		{DimensionAvailability, 3},
		{DimensionReliability, 4},
	}
	for _, c := range cases {
		if byte(c.dimension) != c.want {
			t.Fatalf("ScoreDimension %s encodes as %d, want %d", c.dimension, byte(c.dimension), c.want)
		}
	}
}

func TestEncodeCloseRoundCallMatchesPalletFieldOrder(t *testing.T) {
	var provider [32]byte
	provider[0] = 0xAB
	round := uint64(42)
	dimension := DimensionNetwork

	got := encodeCloseRoundCall(provider, round, dimension)

	want := []byte{networkValidatorPalletIndex, closeRoundCallIndex}
	want = append(want, provider[:]...)
	want = binary.LittleEndian.AppendUint64(want, round)
	want = append(want, byte(dimension))

	if string(got) != string(want) {
		t.Fatalf("encodeCloseRoundCall() = %x, want %x", got, want)
	}
	if len(got) != 2+32+8+1 {
		t.Fatalf("encodeCloseRoundCall() length = %d, want %d", len(got), 2+32+8+1)
	}
}

func TestValidatorStorageKeyIsAPerAccountMapEntry(t *testing.T) {
	var accountA, accountB [32]byte
	accountA[0], accountB[0] = 1, 2
	keyA := validatorStorageKey(accountA)
	if keyA == validatorStorageKey(accountB) {
		t.Fatal("expected different accounts to hash to different storage keys")
	}
	if keyA != validatorStorageKey(accountA) {
		t.Fatal("expected a deterministic storage key for the same account")
	}
}
