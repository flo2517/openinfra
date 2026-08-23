package metering

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strconv"
	"time"

	agentv1 "github.com/openinfra/network/protocol/generated/go/agent/v1"
	sharedv1 "github.com/openinfra/network/protocol/generated/go/shared/v1"
)

// maxMeteringPeriodSeconds bounds one summary's claimed
// period_end-period_start (ADR-029 §6/§7's MaxMeteringPeriodSeconds).
// The Control Plane is the authoritative check -- agent-api's own
// MAX_METERING_PERIOD_SECONDS bounds what a compliant Agent produces,
// but this is the value that actually gates acceptance.
const maxMeteringPeriodSeconds = uint64(3600)

// maxMeteringClockSkew bounds how far period_end may sit from the
// Control Plane's own clock, in either direction -- the same symmetric
// window shape ReportHeartbeat's maxHeartbeatClockSkew already
// established for this codebase's other signed, timestamped evidence.
const maxMeteringClockSkew = 5 * time.Minute

// knownSchemaVersions is the set of metering_schema_version values this
// build understands how to price and store (ADR-029 §1/§7: an unknown
// version must never be silently reinterpreted).
var knownSchemaVersions = map[uint32]bool{1: true}

// Outcome classifies what RecordUsage did with a submission. Every
// non-Accepted/non-Duplicate outcome corresponds to a row written to
// metering_evidence_rejections -- "reject/quarantine, never silently
// drop" (issue #20's own acceptance criterion) applies to all of them.
type Outcome int

const (
	OutcomeAccepted Outcome = iota
	// OutcomeDuplicate: the identical (provider, workload, sequence,
	// evidence_hash) was already accepted. Idempotent no-op -- the
	// existing invoice line is returned, nothing new is billed. Not a
	// rejection: a retried, byte-identical resubmission (e.g. after a
	// dropped response) is expected traffic, not evidence of a problem.
	OutcomeDuplicate
	// OutcomeConflictingEvidence: the same (provider, workload,
	// sequence) was already accepted with a *different* evidence_hash.
	OutcomeConflictingEvidence
	// OutcomeOutOfOrder: sequence is not strictly greater than the last
	// accepted sequence for this (provider, workload) and does not
	// match an existing evidence row either -- a replay, a regressed
	// Agent restart, or an otherwise stale submission.
	OutcomeOutOfOrder
	OutcomeInvalidSignature
	OutcomeClockSkew
	OutcomeBoundsViolation
	OutcomeUnknownSchemaVersion
	OutcomeUnknownPriceVersion
	OutcomeChargeOverflow
	OutcomeUnknownProvider
	OutcomeUnknownWorkload
	OutcomeWorkloadProviderMismatch
	OutcomeLeaseMismatch
)

func (o Outcome) String() string {
	switch o {
	case OutcomeAccepted:
		return "accepted"
	case OutcomeDuplicate:
		return "duplicate"
	case OutcomeConflictingEvidence:
		return "conflicting_evidence"
	case OutcomeOutOfOrder:
		return "out_of_order"
	case OutcomeInvalidSignature:
		return "invalid_signature"
	case OutcomeClockSkew:
		return "clock_skew"
	case OutcomeBoundsViolation:
		return "bounds_violation"
	case OutcomeUnknownSchemaVersion:
		return "unknown_schema_version"
	case OutcomeUnknownPriceVersion:
		return "unknown_price_version"
	case OutcomeChargeOverflow:
		return "charge_overflow"
	case OutcomeUnknownProvider:
		return "unknown_provider"
	case OutcomeUnknownWorkload:
		return "unknown_workload"
	case OutcomeWorkloadProviderMismatch:
		return "workload_provider_mismatch"
	case OutcomeLeaseMismatch:
		return "lease_mismatch"
	default:
		return "unknown"
	}
}

// Result is RecordUsage's return value. EvidenceID/InvoiceLineID are
// only populated for OutcomeAccepted and OutcomeDuplicate.
type Result struct {
	Outcome       Outcome
	EvidenceID    string
	InvoiceLineID string
	TotalAmount   uint64
}

// WorkloadRef is the subset of a workloads row RecordUsage needs to
// cross-check a submission against, independent of what the submission
// itself claims.
type WorkloadRef struct {
	ProviderID string
	LeaseID    int64
	ConsumerID *string
}

var ErrProviderNotFound = errors.New("metering: provider not found")
var ErrWorkloadNotFound = errors.New("metering: workload not found")

// Repository is everything RecordUsage needs from durable storage.
// AcceptEvidence is the single transactional gate: it must atomically
// check-and-advance the per-(provider,workload) sequence cursor and
// insert the evidence/invoice rows (or classify why it could not),
// under a lock that prevents two concurrent submissions for the same
// workload from both observing "not yet seen" (metering_cursors' row
// lock in the Postgres implementation).
type Repository interface {
	ProviderPublicKey(ctx context.Context, providerID string) (ed25519.PublicKey, error)
	Workload(ctx context.Context, workloadID string) (WorkloadRef, error)
	AcceptEvidence(ctx context.Context, request AcceptRequest) (Result, error)
	RecordRejection(ctx context.Context, rejection Rejection) error
	// InsertDispute, GetDispute, ListDisputesForInvoiceLine back
	// Service's RaiseDispute/ListDisputes -- see those methods' doc
	// comments for what this PR does and does not implement.
	InsertDispute(ctx context.Context, dispute Dispute) (Dispute, error)
	GetDispute(ctx context.Context, disputeID string) (Dispute, error)
	ListDisputesForInvoiceLine(ctx context.Context, invoiceLineID string) ([]Dispute, error)
	InvoiceLineExists(ctx context.Context, invoiceLineID string) (bool, error)
}

// AcceptRequest is a fully validated submission, ready for the
// repository's atomic accept-or-classify step.
type AcceptRequest struct {
	ProviderID                                     string
	WorkloadID                                     string
	LeaseID                                        int64
	ConsumerID                                     *string
	Sequence                                       uint64
	PeriodStart                                    time.Time
	PeriodEnd                                      time.Time
	SchemaVersion                                  uint32
	CPUCoreSeconds, RAMMBSeconds, StorageGBSeconds uint64
	NetworkEgressMB, NetworkIngressMB, GPUSeconds  uint64
	Signature                                      []byte
	EvidenceHash                                   [32]byte
	PriceVersion                                   uint32
	Charge                                         Charge
}

// Rejection is one quarantined/refused submission, written to
// metering_evidence_rejections for later inspection -- never silently
// dropped.
type Rejection struct {
	ProviderID   string
	WorkloadID   *string
	Sequence     *uint64
	Reason       string
	Detail       string
	EvidenceHash *[32]byte
}

type Service struct {
	repository Repository
	now        func() time.Time
}

func NewService(repository Repository) *Service {
	return &Service{repository: repository, now: time.Now}
}

// RecordUsage verifies and accepts (or quarantines) one Agent-signed
// MeteringSummary. `providerID` is the caller's already-authenticated
// provider identity (e.g. from the same mTLS/registration trust the
// Agent connection was established under, mirroring how
// ReportHeartbeat trusts request.Payload.ProviderId only after a
// successful signature check against that provider's own known key) --
// RecordUsage still independently verifies the summary's signature
// against that specific provider's registered public key before
// accepting anything, exactly as ReportHeartbeat does.
func (s *Service) RecordUsage(ctx context.Context, providerID string, response *agentv1.GetUsageSummaryResponse) (Result, error) {
	if response == nil || response.Summary == nil {
		return s.reject(ctx, providerID, nil, 0, OutcomeBoundsViolation, "missing summary")
	}
	summary := response.Summary

	if err := validateBounds(summary); err != nil {
		return s.reject(ctx, providerID, summary, summary.Sequence, OutcomeBoundsViolation, err.Error())
	}
	if !knownSchemaVersions[summary.MeteringSchemaVersion] {
		return s.reject(ctx, providerID, summary, summary.Sequence, OutcomeUnknownSchemaVersion,
			fmt.Sprintf("schema version %d is not recognized", summary.MeteringSchemaVersion))
	}

	now := s.now().UTC()
	periodEnd := time.Unix(int64(summary.PeriodEnd), 0).UTC()
	if periodEnd.Before(now.Add(-maxMeteringClockSkew)) || periodEnd.After(now.Add(maxMeteringClockSkew)) {
		return s.reject(ctx, providerID, summary, summary.Sequence, OutcomeClockSkew,
			fmt.Sprintf("period_end %s is outside the allowed clock skew of server time %s", periodEnd, now))
	}

	publicKey, err := s.repository.ProviderPublicKey(ctx, providerID)
	if err != nil {
		if errors.Is(err, ErrProviderNotFound) {
			return s.reject(ctx, providerID, summary, summary.Sequence, OutcomeUnknownProvider, err.Error())
		}
		return Result{}, err
	}
	if !verifySignature(publicKey, summary, response.Signature) {
		return s.reject(ctx, providerID, summary, summary.Sequence, OutcomeInvalidSignature, "signature does not verify against the provider's registered public key")
	}

	workload, err := s.repository.Workload(ctx, summary.WorkloadId)
	if err != nil {
		if errors.Is(err, ErrWorkloadNotFound) {
			return s.reject(ctx, providerID, summary, summary.Sequence, OutcomeUnknownWorkload, err.Error())
		}
		return Result{}, err
	}
	if workload.ProviderID != providerID {
		return s.reject(ctx, providerID, summary, summary.Sequence, OutcomeWorkloadProviderMismatch,
			"workload belongs to a different provider than the one presenting this evidence")
	}
	leaseID, err := strconv.ParseInt(summary.LeaseId, 10, 64)
	if err != nil || leaseID < 0 || leaseID != workload.LeaseID {
		return s.reject(ctx, providerID, summary, summary.Sequence, OutcomeLeaseMismatch,
			fmt.Sprintf("evidence lease_id %q does not match the workload's own recorded lease %d", summary.LeaseId, workload.LeaseID))
	}

	schedule, ok := LookupPriceSchedule(CurrentPriceVersion)
	if !ok {
		// Cannot happen for CurrentPriceVersion in practice (it is
		// always a key of priceSchedules by construction) -- guarded
		// explicitly anyway rather than assuming that invariant holds
		// forever as the table grows.
		return s.reject(ctx, providerID, summary, summary.Sequence, OutcomeUnknownPriceVersion,
			fmt.Sprintf("current price version %d has no schedule", CurrentPriceVersion))
	}
	charge, err := ComputeCharge(schedule, summary.CpuCoreSeconds, summary.RamMbSeconds, summary.StorageGbSeconds, summary.NetworkEgressMb, summary.NetworkIngressMb)
	if err != nil {
		return s.reject(ctx, providerID, summary, summary.Sequence, OutcomeChargeOverflow, err.Error())
	}

	hash := evidenceHash(signedBytes(summary))
	result, err := s.repository.AcceptEvidence(ctx, AcceptRequest{
		ProviderID:       providerID,
		WorkloadID:       summary.WorkloadId,
		LeaseID:          leaseID,
		ConsumerID:       workload.ConsumerID,
		Sequence:         summary.Sequence,
		PeriodStart:      time.Unix(int64(summary.PeriodStart), 0).UTC(),
		PeriodEnd:        periodEnd,
		SchemaVersion:    summary.MeteringSchemaVersion,
		CPUCoreSeconds:   summary.CpuCoreSeconds,
		RAMMBSeconds:     summary.RamMbSeconds,
		StorageGBSeconds: summary.StorageGbSeconds,
		NetworkEgressMB:  summary.NetworkEgressMb,
		NetworkIngressMB: summary.NetworkIngressMb,
		GPUSeconds:       summary.GpuSeconds,
		Signature:        response.Signature,
		EvidenceHash:     hash,
		PriceVersion:     CurrentPriceVersion,
		Charge:           charge,
	})
	if err != nil {
		return Result{}, err
	}
	if result.Outcome != OutcomeAccepted && result.Outcome != OutcomeDuplicate {
		detail := fmt.Sprintf("sequence=%d", summary.Sequence)
		_ = s.repository.RecordRejection(ctx, Rejection{
			ProviderID: providerID, WorkloadID: &summary.WorkloadId, Sequence: &summary.Sequence,
			Reason: result.Outcome.String(), Detail: detail, EvidenceHash: &hash,
		})
	}
	return result, nil
}

func validateBounds(summary *sharedv1.MeteringSummary) error {
	if summary.WorkloadId == "" {
		return errors.New("workload_id is required")
	}
	if summary.LeaseId == "" {
		return errors.New("lease_id is required")
	}
	if summary.Sequence == 0 {
		return errors.New("sequence must be positive")
	}
	if summary.PeriodEnd < summary.PeriodStart {
		return errors.New("period_end must not precede period_start")
	}
	if summary.PeriodEnd-summary.PeriodStart > maxMeteringPeriodSeconds {
		return fmt.Errorf("period length %ds exceeds the maximum of %ds", summary.PeriodEnd-summary.PeriodStart, maxMeteringPeriodSeconds)
	}
	return nil
}

// reject writes an audit row (when enough is known to key one) and
// returns the corresponding Result -- the single place every rejection
// path in RecordUsage funnels through, so "never silently drop" cannot
// be forgotten on any one branch.
func (s *Service) reject(ctx context.Context, providerID string, summary *sharedv1.MeteringSummary, sequence uint64, outcome Outcome, detail string) (Result, error) {
	rejection := Rejection{ProviderID: providerID, Reason: outcome.String(), Detail: detail}
	if summary != nil {
		workloadID := summary.WorkloadId
		rejection.WorkloadID = &workloadID
		if sequence != 0 {
			rejection.Sequence = &sequence
		}
		hash := evidenceHash(signedBytes(summary))
		rejection.EvidenceHash = &hash
	}
	if err := s.repository.RecordRejection(ctx, rejection); err != nil {
		return Result{}, err
	}
	return Result{Outcome: outcome}, nil
}

// Dispute is issue #20's own acceptance criterion made concrete: "a
// flagged/conflicting evidence record must be inspectable, not silently
// resolved either way." A Dispute always starts (and, in this PR,
// stays) DisputeStatusOpen -- resolving one (paying the provider in
// full, refunding the payer, or anything in between) is ADR-029 §4.5's
// on-chain resolve_dispute, #21's job once pallet-escrow exists, not
// re-implemented here. This PR's scope is raising a dispute against an
// already-computed invoice line and making every raised dispute
// listable/inspectable -- explicitly not automatic resolution either
// way, matching the acceptance criterion's own wording.
type DisputeStatus string

const (
	DisputeStatusOpen                DisputeStatus = "open"
	DisputeStatusResolvedPayProvider DisputeStatus = "resolved_pay_provider"
	DisputeStatusResolvedRefundPayer DisputeStatus = "resolved_refund_payer"
)

type DisputeParty string

const (
	DisputePartyPayer    DisputeParty = "payer"
	DisputePartyProvider DisputeParty = "provider"
	DisputePartyOperator DisputeParty = "operator"
)

type Dispute struct {
	DisputeID     string
	InvoiceLineID string
	RaisedBy      DisputeParty
	Reason        string
	Status        DisputeStatus
	RaisedAt      time.Time
}

var ErrInvoiceLineNotFound = errors.New("metering: invoice line not found")
var ErrInvalidDisputeParty = errors.New("metering: raised_by must be payer, provider, or operator")
var ErrEmptyDisputeReason = errors.New("metering: dispute reason is required")

// RaiseDispute records a new, always-open dispute against
// `invoiceLineID`. It never resolves an existing dispute and never
// changes the invoice line itself -- see Dispute's doc comment for what
// is and is not implemented.
func (s *Service) RaiseDispute(ctx context.Context, invoiceLineID string, raisedBy DisputeParty, reason string) (Dispute, error) {
	if raisedBy != DisputePartyPayer && raisedBy != DisputePartyProvider && raisedBy != DisputePartyOperator {
		return Dispute{}, ErrInvalidDisputeParty
	}
	if reason == "" {
		return Dispute{}, ErrEmptyDisputeReason
	}
	exists, err := s.repository.InvoiceLineExists(ctx, invoiceLineID)
	if err != nil {
		return Dispute{}, err
	}
	if !exists {
		return Dispute{}, ErrInvoiceLineNotFound
	}
	return s.repository.InsertDispute(ctx, Dispute{
		InvoiceLineID: invoiceLineID,
		RaisedBy:      raisedBy,
		Reason:        reason,
		Status:        DisputeStatusOpen,
	})
}

// ListDisputes returns every dispute ever raised against
// `invoiceLineID`, in the order the repository returns them -- the
// "inspectable" half of #20's acceptance criterion. Always includes
// disputes regardless of status (this PR never sets a non-open status,
// but a future resolution mechanism's disputes must remain listable
// here too).
func (s *Service) ListDisputes(ctx context.Context, invoiceLineID string) ([]Dispute, error) {
	return s.repository.ListDisputesForInvoiceLine(ctx, invoiceLineID)
}
