package networkvalidator

import "testing"

func TestRoundDerivation(t *testing.T) {
	cases := []struct {
		name   string
		length RoundLength
		block  uint64
		want   uint64
	}{
		{"first block of round zero", 100, 0, 0},
		{"last block of round zero", 100, 99, 0},
		{"first block of round one", 100, 100, 1},
		{"large block number", 100, 12345, 123},
		{"zero length falls back to default", 0, 250, DefaultRoundLengthBlocks / DefaultRoundLengthBlocks * 2}, // 250/100=2
		{"custom short length", 10, 25, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.length.Round(c.block); got != c.want {
				t.Fatalf("Round(%d) with length %d = %d, want %d", c.block, c.length, got, c.want)
			}
		})
	}
}

func TestZeroRoundLengthMatchesExplicitDefault(t *testing.T) {
	var zero RoundLength
	explicit := RoundLength(DefaultRoundLengthBlocks)
	for _, block := range []uint64{0, 1, 99, 100, 999999} {
		if zero.Round(block) != explicit.Round(block) {
			t.Fatalf("Round(%d): zero-value length diverged from explicit default (%d vs %d)", block, zero.Round(block), explicit.Round(block))
		}
	}
}
