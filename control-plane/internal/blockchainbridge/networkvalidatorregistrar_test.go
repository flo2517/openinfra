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
