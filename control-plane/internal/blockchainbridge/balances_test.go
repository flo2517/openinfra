package blockchainbridge

import "testing"

func TestEncodeTransferAllowDeathCallMatchesPalletFieldOrder(t *testing.T) {
	var dest [32]byte
	dest[0] = 0x42
	dest[31] = 0x99
	amount := uint64(2_010)

	got := encodeTransferAllowDeathCall(dest, amount)

	want := []byte{balancesPalletIndex, transferAllowDeathCallIndex, multiAddressIdTag}
	want = append(want, dest[:]...)
	want = append(want, compactUint(amount)...)

	if string(got) != string(want) {
		t.Fatalf("encodeTransferAllowDeathCall() = %x, want %x", got, want)
	}
	// pallet index (1) + call index (1) + MultiAddress tag (1) + AccountId (32) + compact(2010) (2 bytes, two-byte compact mode).
	if len(got) != 1+1+1+32+2 {
		t.Fatalf("encodeTransferAllowDeathCall() length = %d, want %d", len(got), 1+1+1+32+2)
	}
}

func TestEncodeTransferAllowDeathCallUsesCompactAmountEncoding(t *testing.T) {
	var dest [32]byte
	cases := []struct {
		name       string
		amount     uint64
		compactLen int
	}{
		{"single-byte mode", 63, 1},
		{"two-byte mode", 1_000, 2},
		{"four-byte mode", 100_000, 4},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := encodeTransferAllowDeathCall(dest, c.amount)
			fixedPrefix := 1 + 1 + 1 + 32
			if len(got) != fixedPrefix+c.compactLen {
				t.Fatalf("encodeTransferAllowDeathCall(%d) length = %d, want %d", c.amount, len(got), fixedPrefix+c.compactLen)
			}
			if string(got[fixedPrefix:]) != string(compactUint(c.amount)) {
				t.Fatalf("encodeTransferAllowDeathCall(%d) compact suffix = %x, want %x", c.amount, got[fixedPrefix:], compactUint(c.amount))
			}
		})
	}
}
