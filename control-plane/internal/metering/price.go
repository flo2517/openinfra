package metering

import "fmt"

// PriceSchedule mirrors ADR-029 §1's on-chain PriceSchedule struct
// (rate per Currency-smallest-unit, per priced dimension). Unlike the
// ADR's on-chain design -- where a PriceSchedule is supplied per-escrow
// at fund_escrow time and committed immutably to that one escrow -- this
// PR scopes pricing down to a small, explicit, versioned constant table
// (issue #20's own "a real pricing engine is out of scope" allowance).
// A real per-escrow/per-lease negotiated price, matching #21's
// fund_escrow argument exactly, is follow-up work once #21 exists to
// coordinate against; naming a price_version on every invoice line now
// (rather than an implicit, unversioned rate) is what makes that
// migration additive later instead of a breaking schema change.
type PriceSchedule struct {
	Version         uint32
	CPUCoreSecond   uint64
	RAMMBSecond     uint64
	StorageGBSecond uint64
	NetworkMB       uint64 // same rate applied to egress and ingress MB, matching ADR-029 §1
}

// priceSchedules is the versioned constant table. Deliberately a Go map
// literal, not a database row: ADR-029 §1 treats a price as a
// per-escrow, off-chain-agreed commitment, not a global on-chain rate
// card, and this PR's scoped-down v1 mirrors that by keeping the table
// out of mutable storage entirely -- a new version is a code change and
// a deploy, not a row update. version 0 is intentionally absent: it is
// used as the "unversioned/invalid" sentinel by validation.
var priceSchedules = map[uint32]PriceSchedule{
	1: {
		Version:         1,
		CPUCoreSecond:   1,
		RAMMBSecond:     1,
		StorageGBSecond: 1,
		NetworkMB:       1,
	},
}

// CurrentPriceVersion is the price_version RecordUsage attaches to every
// new invoice line it computes.
const CurrentPriceVersion uint32 = 1

// LookupPriceSchedule returns the price schedule for `version`, or false
// if it is not a known version -- callers must quarantine rather than
// guess a fallback price, matching #20's "missing/conflicting evidence
// never becomes silent billable success" for the price dimension too.
func LookupPriceSchedule(version uint32) (PriceSchedule, bool) {
	schedule, ok := priceSchedules[version]
	return schedule, ok
}

// Charge is one invoice line's computed amounts, all overflow-checked
// (ADR-029 §1: "erroring... rather than saturating" for anything
// monetary -- deliberately not this codebase's usual saturating_*
// style, matching pallet-reputation's bounded-score reasoning being
// wrong here).
type Charge struct {
	CPUAmount     uint64
	RAMAmount     uint64
	StorageAmount uint64
	NetworkAmount uint64
	TotalAmount   uint64
}

// ErrChargeOverflow is returned by ComputeCharge when any intermediate
// or total amount would not fit in a uint64 -- RecordUsage quarantines
// the submission on this error rather than computing a wrapped or
// truncated charge.
var errChargeOverflow = fmt.Errorf("metering: charge computation overflowed")

// ComputeCharge computes one evidence record's charge under `schedule`,
// matching ADR-029 §4.2's formula exactly (cpu*rate + ram*rate +
// storage*rate + (egress+ingress)*rate), entirely via checked u64
// arithmetic. gpu_seconds is intentionally not priced (ADR-029 §1: GPU
// is "reserved... priced at 0 and not billed in v1") and does not appear
// in this computation at all.
func ComputeCharge(schedule PriceSchedule, cpuCoreSeconds, ramMBSeconds, storageGBSeconds, networkEgressMB, networkIngressMB uint64) (Charge, error) {
	cpuAmount, err := checkedMul(cpuCoreSeconds, schedule.CPUCoreSecond)
	if err != nil {
		return Charge{}, err
	}
	ramAmount, err := checkedMul(ramMBSeconds, schedule.RAMMBSecond)
	if err != nil {
		return Charge{}, err
	}
	storageAmount, err := checkedMul(storageGBSeconds, schedule.StorageGBSecond)
	if err != nil {
		return Charge{}, err
	}
	networkMB, err := checkedAdd(networkEgressMB, networkIngressMB)
	if err != nil {
		return Charge{}, err
	}
	networkAmount, err := checkedMul(networkMB, schedule.NetworkMB)
	if err != nil {
		return Charge{}, err
	}
	total, err := checkedAdd(cpuAmount, ramAmount)
	if err != nil {
		return Charge{}, err
	}
	total, err = checkedAdd(total, storageAmount)
	if err != nil {
		return Charge{}, err
	}
	total, err = checkedAdd(total, networkAmount)
	if err != nil {
		return Charge{}, err
	}
	return Charge{
		CPUAmount:     cpuAmount,
		RAMAmount:     ramAmount,
		StorageAmount: storageAmount,
		NetworkAmount: networkAmount,
		TotalAmount:   total,
	}, nil
}

// checkedMul and checkedAdd are Go's stand-in for Rust's checked_mul/
// checked_add (ADR-029 §1) -- Go has no built-in overflow-checked
// integer arithmetic, so overflow is detected explicitly rather than
// silently wrapping (uint64 arithmetic in Go wraps on overflow like any
// fixed-width integer type).
func checkedMul(a, b uint64) (uint64, error) {
	if a == 0 || b == 0 {
		return 0, nil
	}
	result := a * b
	if result/a != b {
		return 0, errChargeOverflow
	}
	return result, nil
}

func checkedAdd(a, b uint64) (uint64, error) {
	result := a + b
	if result < a {
		return 0, errChargeOverflow
	}
	return result, nil
}
