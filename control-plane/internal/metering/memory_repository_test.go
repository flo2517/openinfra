package metering

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// memoryRepository is a from-scratch fake of Repository for fast,
// database-free unit tests -- mirroring PostgresRepository's exact
// accept/duplicate/conflicting/out-of-order semantics (including the
// single-lock-per-workload atomicity AcceptEvidence's own doc comment
// describes) so these tests exercise the real decision logic, not a
// simplified stand-in.
type memoryRepository struct {
	mu sync.Mutex

	publicKeys map[string]ed25519.PublicKey
	workloads  map[string]WorkloadRef

	cursors        map[string]uint64 // key: providerID+"/"+workloadID
	evidenceBySeq  map[string]storedEvidence
	invoiceByEvID  map[string]storedInvoiceLine
	rejections     []Rejection
	disputes       map[string]Dispute
	invoiceLineIDs map[string]bool
}

type storedEvidence struct {
	evidenceID string
	hash       [32]byte
}

type storedInvoiceLine struct {
	invoiceLineID string
	totalAmount   uint64
}

func newMemoryRepository() *memoryRepository {
	return &memoryRepository{
		publicKeys:     make(map[string]ed25519.PublicKey),
		workloads:      make(map[string]WorkloadRef),
		cursors:        make(map[string]uint64),
		evidenceBySeq:  make(map[string]storedEvidence),
		invoiceByEvID:  make(map[string]storedInvoiceLine),
		disputes:       make(map[string]Dispute),
		invoiceLineIDs: make(map[string]bool),
	}
}

func cursorKey(providerID, workloadID string) string { return providerID + "/" + workloadID }
func seqKey(providerID, workloadID string, sequence uint64) string {
	return fmt.Sprintf("%s/%s/%d", providerID, workloadID, sequence)
}

func (r *memoryRepository) ProviderPublicKey(_ context.Context, providerID string) (ed25519.PublicKey, error) {
	key, ok := r.publicKeys[providerID]
	if !ok {
		return nil, ErrProviderNotFound
	}
	return key, nil
}

func (r *memoryRepository) Workload(_ context.Context, workloadID string) (WorkloadRef, error) {
	ref, ok := r.workloads[workloadID]
	if !ok {
		return WorkloadRef{}, ErrWorkloadNotFound
	}
	return ref, nil
}

func (r *memoryRepository) AcceptEvidence(_ context.Context, request AcceptRequest) (Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := cursorKey(request.ProviderID, request.WorkloadID)
	last := r.cursors[key]
	if request.Sequence <= last {
		existing, ok := r.evidenceBySeq[seqKey(request.ProviderID, request.WorkloadID, request.Sequence)]
		if !ok {
			return Result{Outcome: OutcomeOutOfOrder}, nil
		}
		if existing.hash != request.EvidenceHash {
			return Result{Outcome: OutcomeConflictingEvidence, EvidenceID: existing.evidenceID}, nil
		}
		invoice := r.invoiceByEvID[existing.evidenceID]
		return Result{
			Outcome: OutcomeDuplicate, EvidenceID: existing.evidenceID,
			InvoiceLineID: invoice.invoiceLineID, TotalAmount: invoice.totalAmount,
		}, nil
	}

	r.cursors[key] = request.Sequence
	evidenceID := uuid.NewString()
	r.evidenceBySeq[seqKey(request.ProviderID, request.WorkloadID, request.Sequence)] = storedEvidence{
		evidenceID: evidenceID, hash: request.EvidenceHash,
	}
	invoiceLineID := uuid.NewString()
	r.invoiceByEvID[evidenceID] = storedInvoiceLine{invoiceLineID: invoiceLineID, totalAmount: request.Charge.TotalAmount}
	r.invoiceLineIDs[invoiceLineID] = true
	return Result{Outcome: OutcomeAccepted, EvidenceID: evidenceID, InvoiceLineID: invoiceLineID, TotalAmount: request.Charge.TotalAmount}, nil
}

func (r *memoryRepository) RecordRejection(_ context.Context, rejection Rejection) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rejections = append(r.rejections, rejection)
	return nil
}

func (r *memoryRepository) InvoiceLineExists(_ context.Context, invoiceLineID string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.invoiceLineIDs[invoiceLineID], nil
}

func (r *memoryRepository) InsertDispute(_ context.Context, dispute Dispute) (Dispute, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	dispute.DisputeID = uuid.NewString()
	dispute.RaisedAt = time.Now().UTC()
	r.disputes[dispute.DisputeID] = dispute
	return dispute, nil
}

func (r *memoryRepository) GetDispute(_ context.Context, disputeID string) (Dispute, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	dispute, ok := r.disputes[disputeID]
	if !ok {
		return Dispute{}, fmt.Errorf("dispute %s not found", disputeID)
	}
	return dispute, nil
}

func (r *memoryRepository) ListDisputesForInvoiceLine(_ context.Context, invoiceLineID string) ([]Dispute, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var disputes []Dispute
	for _, dispute := range r.disputes {
		if dispute.InvoiceLineID == invoiceLineID {
			disputes = append(disputes, dispute)
		}
	}
	return disputes, nil
}

func (r *memoryRepository) lastRejection() (Rejection, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.rejections) == 0 {
		return Rejection{}, false
	}
	return r.rejections[len(r.rejections)-1], true
}
