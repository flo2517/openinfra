package metering

import "testing"

func TestComputeChargeMatchesTheADRFormula(t *testing.T) {
	schedule := PriceSchedule{Version: 1, CPUCoreSecond: 3, RAMMBSecond: 2, StorageGBSecond: 5, NetworkMB: 7}
	charge, err := ComputeCharge(schedule, 10, 20, 30, 4, 6)
	if err != nil {
		t.Fatalf("ComputeCharge: %v", err)
	}
	if charge.CPUAmount != 30 || charge.RAMAmount != 40 || charge.StorageAmount != 150 {
		t.Fatalf("unexpected per-dimension amounts: %+v", charge)
	}
	// network_mb = egress + ingress = 10, at rate 7 => 70.
	if charge.NetworkAmount != 70 {
		t.Fatalf("network amount = %d, want 70", charge.NetworkAmount)
	}
	wantTotal := uint64(30 + 40 + 150 + 70)
	if charge.TotalAmount != wantTotal {
		t.Fatalf("total amount = %d, want %d", charge.TotalAmount, wantTotal)
	}
}

func TestComputeChargeZeroUsageIsZeroRegardlessOfRate(t *testing.T) {
	schedule := PriceSchedule{Version: 1, CPUCoreSecond: 1_000_000, RAMMBSecond: 1_000_000, StorageGBSecond: 1_000_000, NetworkMB: 1_000_000}
	charge, err := ComputeCharge(schedule, 0, 0, 0, 0, 0)
	if err != nil {
		t.Fatalf("ComputeCharge: %v", err)
	}
	if charge.TotalAmount != 0 {
		t.Fatalf("total amount = %d, want 0", charge.TotalAmount)
	}
}

// TestComputeChargeRejectsMultiplicationOverflow is the "overflow (usage
// counters approaching/exceeding bounds)" acceptance criterion: a usage
// counter and rate whose product does not fit uint64 must error, not
// wrap to a small/incorrect billable amount.
func TestComputeChargeRejectsMultiplicationOverflow(t *testing.T) {
	schedule := PriceSchedule{Version: 1, CPUCoreSecond: 2}
	_, err := ComputeCharge(schedule, ^uint64(0), 0, 0, 0, 0) // math.MaxUint64 * 2
	if err == nil {
		t.Fatal("expected an overflow error, got nil")
	}
}

func TestComputeChargeRejectsAdditionOverflowAcrossDimensions(t *testing.T) {
	// Each individual dimension amount fits uint64 on its own, but their
	// sum does not -- the addition step, not just the multiplications,
	// must be checked.
	schedule := PriceSchedule{Version: 1, CPUCoreSecond: 1, RAMMBSecond: 1}
	half := ^uint64(0) / 2
	_, err := ComputeCharge(schedule, half+1, half+1, 0, 0, 0)
	if err == nil {
		t.Fatal("expected an overflow error from the cpu+ram addition, got nil")
	}
}

func TestComputeChargeRejectsNetworkAdditionOverflow(t *testing.T) {
	schedule := PriceSchedule{Version: 1, NetworkMB: 1}
	_, err := ComputeCharge(schedule, 0, 0, 0, ^uint64(0), 1)
	if err == nil {
		t.Fatal("expected an overflow error from egress+ingress, got nil")
	}
}

func TestLookupPriceScheduleRejectsUnknownVersion(t *testing.T) {
	if _, ok := LookupPriceSchedule(9999); ok {
		t.Fatal("version 9999 must not resolve to a schedule")
	}
	if _, ok := LookupPriceSchedule(CurrentPriceVersion); !ok {
		t.Fatalf("CurrentPriceVersion (%d) must resolve to a schedule", CurrentPriceVersion)
	}
}
