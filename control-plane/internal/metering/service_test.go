package metering

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	agentv1 "github.com/openinfra/network/protocol/generated/go/agent/v1"
	sharedv1 "github.com/openinfra/network/protocol/generated/go/shared/v1"
)

// testFixture wires a memoryRepository with one registered provider and
// one workload it owns, ready for RecordUsage calls.
type testFixture struct {
	repository *memoryRepository
	service    *Service
	providerID string
	workloadID string
	leaseID    int64
	privateKey ed25519.PrivateKey
	now        time.Time
}

func newTestFixture(t *testing.T) *testFixture {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	repository := newMemoryRepository()
	providerID := "provider-1"
	workloadID := "11111111-1111-1111-1111-111111111111"
	repository.publicKeys[providerID] = publicKey
	repository.workloads[workloadID] = WorkloadRef{ProviderID: providerID, LeaseID: 42}

	service := NewService(repository)
	now := time.Unix(1_700_000_000, 0).UTC()
	service.now = func() time.Time { return now }

	return &testFixture{
		repository: repository, service: service, providerID: providerID,
		workloadID: workloadID, leaseID: 42, privateKey: privateKey, now: now,
	}
}

// signedResponse builds a valid, signed GetUsageSummaryResponse for this
// fixture's provider/workload/lease, with the given sequence and
// period_end (period_start is always period_end-1, a 1-second window).
func (f *testFixture) signedResponse(sequence, periodEnd uint64) *agentv1.GetUsageSummaryResponse {
	summary := &sharedv1.MeteringSummary{
		WorkloadId: f.workloadID, LeaseId: "42", Sequence: sequence,
		PeriodStart: periodEnd - 1, PeriodEnd: periodEnd, MeteringSchemaVersion: 1,
		CpuCoreSeconds: 10, RamMbSeconds: 20, StorageGbSeconds: 30,
		NetworkEgressMb: 5, NetworkIngressMb: 5, GpuSeconds: 0,
	}
	signature := ed25519.Sign(f.privateKey, signedBytes(summary))
	return &agentv1.GetUsageSummaryResponse{Summary: summary, Signature: signature}
}

func TestRecordUsageAcceptsAValidSignedSummary(t *testing.T) {
	f := newTestFixture(t)
	result, err := f.service.RecordUsage(context.Background(), f.providerID, f.signedResponse(1, uint64(f.now.Unix())))
	if err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}
	if result.Outcome != OutcomeAccepted {
		t.Fatalf("outcome = %s, want accepted", result.Outcome)
	}
	if result.EvidenceID == "" || result.InvoiceLineID == "" {
		t.Fatal("accepted result must carry evidence/invoice line ids")
	}
	// price schedule v1's rates are all 1: total = 10+20+30+(5+5) = 70.
	if result.TotalAmount != 70 {
		t.Fatalf("total amount = %d, want 70", result.TotalAmount)
	}
}

func TestRecordUsageRejectsInvalidSignature(t *testing.T) {
	f := newTestFixture(t)
	response := f.signedResponse(1, uint64(f.now.Unix()))
	response.Signature[0] ^= 0xFF
	result, err := f.service.RecordUsage(context.Background(), f.providerID, response)
	if err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}
	if result.Outcome != OutcomeInvalidSignature {
		t.Fatalf("outcome = %s, want invalid_signature", result.Outcome)
	}
	rejection, ok := f.repository.lastRejection()
	if !ok || rejection.Reason != "invalid_signature" {
		t.Fatal("an invalid signature must be recorded as a rejection, not silently dropped")
	}
}

// TestRecordUsageQuarantinesClockSkew is the "clock skew (summary
// timestamp offset from server time within/outside tolerance)"
// acceptance criterion: a period_end far in the future or far in the
// past relative to the server's own clock must be quarantined, and a
// period_end within tolerance must be accepted.
func TestRecordUsageQuarantinesClockSkew(t *testing.T) {
	f := newTestFixture(t)

	future := uint64(f.now.Add(maxMeteringClockSkew + time.Minute).Unix())
	result, err := f.service.RecordUsage(context.Background(), f.providerID, f.signedResponse(1, future))
	if err != nil {
		t.Fatalf("RecordUsage (future): %v", err)
	}
	if result.Outcome != OutcomeClockSkew {
		t.Fatalf("outcome = %s, want clock_skew for a period_end far in the future", result.Outcome)
	}

	past := uint64(f.now.Add(-(maxMeteringClockSkew + time.Minute)).Unix())
	result, err = f.service.RecordUsage(context.Background(), f.providerID, f.signedResponse(1, past))
	if err != nil {
		t.Fatalf("RecordUsage (past): %v", err)
	}
	if result.Outcome != OutcomeClockSkew {
		t.Fatalf("outcome = %s, want clock_skew for a period_end far in the past", result.Outcome)
	}

	withinTolerance := uint64(f.now.Add(maxMeteringClockSkew - time.Minute).Unix())
	result, err = f.service.RecordUsage(context.Background(), f.providerID, f.signedResponse(1, withinTolerance))
	if err != nil {
		t.Fatalf("RecordUsage (within tolerance): %v", err)
	}
	if result.Outcome != OutcomeAccepted {
		t.Fatalf("outcome = %s, want accepted for a period_end within tolerance", result.Outcome)
	}
}

// TestRecordUsageTreatsAnIdenticalRetryAsIdempotentDuplicate is the
// "duplicate reports (same sequence number twice -- must not
// double-bill)" acceptance criterion.
func TestRecordUsageTreatsAnIdenticalRetryAsIdempotentDuplicate(t *testing.T) {
	f := newTestFixture(t)
	response := f.signedResponse(1, uint64(f.now.Unix()))

	first, err := f.service.RecordUsage(context.Background(), f.providerID, response)
	if err != nil || first.Outcome != OutcomeAccepted {
		t.Fatalf("first submission: outcome=%s err=%v", first.Outcome, err)
	}

	second, err := f.service.RecordUsage(context.Background(), f.providerID, response)
	if err != nil {
		t.Fatalf("second (retried) submission: %v", err)
	}
	if second.Outcome != OutcomeDuplicate {
		t.Fatalf("outcome = %s, want duplicate", second.Outcome)
	}
	if second.EvidenceID != first.EvidenceID || second.InvoiceLineID != first.InvoiceLineID {
		t.Fatal("a duplicate retry must return the original evidence/invoice line, not mint a new one")
	}
	if second.TotalAmount != first.TotalAmount {
		t.Fatal("a duplicate retry must not double-bill: the total must match the original")
	}
}

// TestRecordUsageQuarantinesConflictingEvidenceUnderTheSameSequence
// covers ADR-029 §6's "conflicting" evidence case: two different
// signed summaries claiming the same sequence.
func TestRecordUsageQuarantinesConflictingEvidenceUnderTheSameSequence(t *testing.T) {
	f := newTestFixture(t)
	first := f.signedResponse(1, uint64(f.now.Unix()))
	if _, err := f.service.RecordUsage(context.Background(), f.providerID, first); err != nil {
		t.Fatalf("first submission: %v", err)
	}

	conflicting := f.signedResponse(1, uint64(f.now.Unix()))
	conflicting.Summary.CpuCoreSeconds = 999 // different content, same sequence
	conflicting.Signature = ed25519.Sign(f.privateKey, signedBytes(conflicting.Summary))
	result, err := f.service.RecordUsage(context.Background(), f.providerID, conflicting)
	if err != nil {
		t.Fatalf("conflicting submission: %v", err)
	}
	if result.Outcome != OutcomeConflictingEvidence {
		t.Fatalf("outcome = %s, want conflicting_evidence", result.Outcome)
	}
}

// TestRecordUsageQuarantinesARegressedSequenceAfterAnAgentRestart is the
// "restart (Agent restart resets in-memory sequence -- must not be
// silently treated as a valid continuation...)" acceptance criterion,
// exercised at the Control Plane's authoritative boundary: whatever
// caused the regression (a genuinely reset Agent, a replay, anything
// else), a sequence that is not strictly greater than the last accepted
// one is quarantined, never silently billed as a fresh continuation.
func TestRecordUsageQuarantinesARegressedSequenceAfterAnAgentRestart(t *testing.T) {
	f := newTestFixture(t)
	for _, sequence := range []uint64{1, 2, 3, 4, 5} {
		result, err := f.service.RecordUsage(context.Background(), f.providerID, f.signedResponse(sequence, uint64(f.now.Unix())))
		if err != nil || result.Outcome != OutcomeAccepted {
			t.Fatalf("priming sequence %d: outcome=%s err=%v", sequence, result.Outcome, err)
		}
	}

	// Simulates a restarted Agent whose durable sequence state was lost
	// (e.g. its local state directory did not survive the restart): it
	// reports sequence 1 again, as if starting fresh, at a later moment
	// in time -- a genuinely different summary (different period bounds)
	// under an already-used sequence, not a byte-identical retry.
	restarted := f.signedResponse(1, uint64(f.now.Add(10*time.Second).Unix()))
	result, err := f.service.RecordUsage(context.Background(), f.providerID, restarted)
	if err != nil {
		t.Fatalf("RecordUsage after simulated restart: %v", err)
	}
	if result.Outcome == OutcomeAccepted {
		t.Fatal("a regressed post-restart sequence must never be silently accepted as a fresh continuation")
	}
	if result.Outcome != OutcomeConflictingEvidence {
		t.Fatalf("outcome = %s, want conflicting_evidence (different content resubmitted under an already-used sequence)", result.Outcome)
	}
	rejection, ok := f.repository.lastRejection()
	if !ok || rejection.Reason != "conflicting_evidence" {
		t.Fatal("the regressed sequence must be recorded as a rejection, not silently dropped")
	}

	// A correctly-continuing sequence (6, after the primed 1..5) must
	// still be accepted normally -- the restart only refused the
	// regressed value, it did not wedge the cursor.
	result, err = f.service.RecordUsage(context.Background(), f.providerID, f.signedResponse(6, uint64(f.now.Unix())))
	if err != nil || result.Outcome != OutcomeAccepted {
		t.Fatalf("sequence 6 after the regressed attempt: outcome=%s err=%v", result.Outcome, err)
	}
}

// TestRecordUsageQuarantinesAStaleSequenceWithNoStoredEvidenceAtAll
// covers the other out-of-order shape: a sequence that is behind the
// cursor and was never itself individually accepted (a jump ahead
// happened, leaving a gap) rather than a reused one -- neither
// duplicate nor conflicting-evidence applies, since there is no
// existing row at that exact sequence to compare against.
func TestRecordUsageQuarantinesAStaleSequenceWithNoStoredEvidenceAtAll(t *testing.T) {
	f := newTestFixture(t)
	// Jumps straight to sequence 10 -- sequences 1..9 are never
	// individually stored.
	result, err := f.service.RecordUsage(context.Background(), f.providerID, f.signedResponse(10, uint64(f.now.Unix())))
	if err != nil || result.Outcome != OutcomeAccepted {
		t.Fatalf("priming sequence 10: outcome=%s err=%v", result.Outcome, err)
	}

	result, err = f.service.RecordUsage(context.Background(), f.providerID, f.signedResponse(7, uint64(f.now.Unix())))
	if err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}
	if result.Outcome != OutcomeOutOfOrder {
		t.Fatalf("outcome = %s, want out_of_order", result.Outcome)
	}
}

// TestRecordUsageQuarantinesChargeOverflow is the "overflow (usage
// counters approaching/exceeding bounds)" acceptance criterion,
// exercised end-to-end through RecordUsage (price.go's own tests cover
// ComputeCharge in isolation).
func TestRecordUsageQuarantinesChargeOverflow(t *testing.T) {
	f := newTestFixture(t)
	response := f.signedResponse(1, uint64(f.now.Unix()))
	// price schedule v1's rate is 1 per unit, so a near-max cpu counter
	// plus a nonzero ram counter overflows the addition step.
	response.Summary.CpuCoreSeconds = ^uint64(0)
	response.Summary.RamMbSeconds = 1
	response.Signature = ed25519.Sign(f.privateKey, signedBytes(response.Summary))

	result, err := f.service.RecordUsage(context.Background(), f.providerID, response)
	if err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}
	if result.Outcome != OutcomeChargeOverflow {
		t.Fatalf("outcome = %s, want charge_overflow", result.Outcome)
	}
	rejection, ok := f.repository.lastRejection()
	if !ok || rejection.Reason != "charge_overflow" {
		t.Fatal("an overflowing charge must be recorded as a rejection, not silently truncated/billed")
	}
}

func TestRecordUsageRejectsAPeriodLongerThanTheMaximum(t *testing.T) {
	f := newTestFixture(t)
	response := f.signedResponse(1, uint64(f.now.Unix()))
	response.Summary.PeriodStart = response.Summary.PeriodEnd - maxMeteringPeriodSeconds - 1
	response.Signature = ed25519.Sign(f.privateKey, signedBytes(response.Summary))

	result, err := f.service.RecordUsage(context.Background(), f.providerID, response)
	if err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}
	if result.Outcome != OutcomeBoundsViolation {
		t.Fatalf("outcome = %s, want bounds_violation", result.Outcome)
	}
}

func TestRecordUsageRejectsAnUnknownProvider(t *testing.T) {
	f := newTestFixture(t)
	result, err := f.service.RecordUsage(context.Background(), "not-a-registered-provider", f.signedResponse(1, uint64(f.now.Unix())))
	if err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}
	if result.Outcome != OutcomeUnknownProvider {
		t.Fatalf("outcome = %s, want unknown_provider", result.Outcome)
	}
}

func TestRecordUsageRejectsAWorkloadOwnedByAnotherProvider(t *testing.T) {
	f := newTestFixture(t)
	otherPublicKey, otherPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate second identity: %v", err)
	}
	f.repository.publicKeys["provider-2"] = otherPublicKey

	summary := &sharedv1.MeteringSummary{
		WorkloadId: f.workloadID, LeaseId: "42", Sequence: 1,
		PeriodStart: uint64(f.now.Unix()) - 1, PeriodEnd: uint64(f.now.Unix()), MeteringSchemaVersion: 1,
	}
	response := &agentv1.GetUsageSummaryResponse{Summary: summary, Signature: ed25519.Sign(otherPrivateKey, signedBytes(summary))}

	result, err := f.service.RecordUsage(context.Background(), "provider-2", response)
	if err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}
	if result.Outcome != OutcomeWorkloadProviderMismatch {
		t.Fatalf("outcome = %s, want workload_provider_mismatch", result.Outcome)
	}
}

// TestRaiseDisputeIsInspectableNotSilentlyResolved is the "disputes (a
// flagged/conflicting evidence record must be inspectable, not silently
// resolved either way)" acceptance criterion.
func TestRaiseDisputeIsInspectableNotSilentlyResolved(t *testing.T) {
	f := newTestFixture(t)
	accepted, err := f.service.RecordUsage(context.Background(), f.providerID, f.signedResponse(1, uint64(f.now.Unix())))
	if err != nil || accepted.Outcome != OutcomeAccepted {
		t.Fatalf("priming acceptance: outcome=%s err=%v", accepted.Outcome, err)
	}

	dispute, err := f.service.RaiseDispute(context.Background(), accepted.InvoiceLineID, DisputePartyPayer, "reported usage looks too high")
	if err != nil {
		t.Fatalf("RaiseDispute: %v", err)
	}
	if dispute.DisputeID == "" {
		t.Fatal("a raised dispute must have an id")
	}
	// Never auto-resolved either way, per the acceptance criterion's own
	// wording.
	if dispute.Status != DisputeStatusOpen {
		t.Fatalf("status = %s, want open -- RaiseDispute must never resolve a dispute itself", dispute.Status)
	}

	disputes, err := f.service.ListDisputes(context.Background(), accepted.InvoiceLineID)
	if err != nil {
		t.Fatalf("ListDisputes: %v", err)
	}
	if len(disputes) != 1 || disputes[0].DisputeID != dispute.DisputeID {
		t.Fatalf("the raised dispute must be inspectable via ListDisputes, got %+v", disputes)
	}
}

func TestRaiseDisputeRejectsAnUnknownInvoiceLine(t *testing.T) {
	f := newTestFixture(t)
	_, err := f.service.RaiseDispute(context.Background(), "does-not-exist", DisputePartyPayer, "reason")
	if err != ErrInvoiceLineNotFound {
		t.Fatalf("err = %v, want ErrInvoiceLineNotFound", err)
	}
}

func TestRaiseDisputeRejectsAnInvalidParty(t *testing.T) {
	f := newTestFixture(t)
	accepted, err := f.service.RecordUsage(context.Background(), f.providerID, f.signedResponse(1, uint64(f.now.Unix())))
	if err != nil || accepted.Outcome != OutcomeAccepted {
		t.Fatalf("priming acceptance: outcome=%s err=%v", accepted.Outcome, err)
	}
	_, err = f.service.RaiseDispute(context.Background(), accepted.InvoiceLineID, DisputeParty("someone-else"), "reason")
	if err != ErrInvalidDisputeParty {
		t.Fatalf("err = %v, want ErrInvalidDisputeParty", err)
	}
}
