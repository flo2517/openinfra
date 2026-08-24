package metering

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"math"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresRepository implements Repository against migration 000016's
// metering_cursors/metering_evidence/invoice_lines/
// metering_evidence_rejections tables.
type PostgresRepository struct{ pool *pgxpool.Pool }

func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

func (r *PostgresRepository) ProviderPublicKey(ctx context.Context, providerID string) (ed25519.PublicKey, error) {
	var publicKey []byte
	err := r.pool.QueryRow(ctx, `SELECT public_key FROM providers WHERE provider_id = $1`, providerID).Scan(&publicKey)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrProviderNotFound
	}
	if err != nil {
		return nil, err
	}
	return ed25519.PublicKey(publicKey), nil
}

func (r *PostgresRepository) Workload(ctx context.Context, workloadID string) (WorkloadRef, error) {
	var providerID *string
	var leaseID *int64
	var consumerID *string
	err := r.pool.QueryRow(ctx, `SELECT provider_id, lease_id, owner_id::text FROM workloads WHERE workload_id = $1`, workloadID).
		Scan(&providerID, &leaseID, &consumerID)
	if errors.Is(err, pgx.ErrNoRows) {
		return WorkloadRef{}, ErrWorkloadNotFound
	}
	if err != nil {
		return WorkloadRef{}, err
	}
	ref := WorkloadRef{ConsumerID: consumerID}
	if providerID != nil {
		ref.ProviderID = *providerID
	}
	if leaseID != nil {
		ref.LeaseID = *leaseID
	}
	return ref, nil
}

// AcceptEvidence is the single atomic gate described on Repository's own
// doc comment: it locks this (provider, workload) pair's cursor row,
// decides accept/duplicate/conflicting/out-of-order under that lock,
// and -- only for a fresh, strictly increasing sequence -- advances the
// cursor and inserts the evidence + invoice-line rows, all inside one
// transaction. Two concurrent calls for the same workload cannot both
// observe "not yet seen": the second blocks on `FOR UPDATE` until the
// first commits, then re-reads the now-advanced cursor.
func (r *PostgresRepository) AcceptEvidence(ctx context.Context, request AcceptRequest) (Result, error) {
	if err := checkBigintRange(request); err != nil {
		return Result{}, err
	}

	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Result{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()

	if _, err := tx.Exec(ctx, `
		INSERT INTO metering_cursors (provider_id, workload_id, last_sequence)
		VALUES ($1, $2, 0)
		ON CONFLICT (provider_id, workload_id) DO NOTHING`,
		request.ProviderID, request.WorkloadID,
	); err != nil {
		return Result{}, err
	}
	var lastSequence int64
	if err := tx.QueryRow(ctx, `
		SELECT last_sequence FROM metering_cursors
		WHERE provider_id = $1 AND workload_id = $2 FOR UPDATE`,
		request.ProviderID, request.WorkloadID,
	).Scan(&lastSequence); err != nil {
		return Result{}, err
	}

	if int64(request.Sequence) <= lastSequence {
		result, err := r.classifyStaleSequence(ctx, tx, request)
		if err != nil {
			return Result{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return Result{}, err
		}
		committed = true
		return result, nil
	}

	if _, err := tx.Exec(ctx, `
		UPDATE metering_cursors SET last_sequence = $3, updated_at = now()
		WHERE provider_id = $1 AND workload_id = $2`,
		request.ProviderID, request.WorkloadID, int64(request.Sequence),
	); err != nil {
		return Result{}, err
	}

	evidenceID := uuid.NewString()
	_, err = tx.Exec(ctx, `
		INSERT INTO metering_evidence (
			evidence_id, provider_id, workload_id, lease_id, sequence, period_start, period_end,
			metering_schema_version, cpu_core_seconds, ram_mb_seconds, storage_gb_seconds,
			network_egress_mb, network_ingress_mb, gpu_seconds, signature, evidence_hash
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
		evidenceID, request.ProviderID, request.WorkloadID, request.LeaseID, int64(request.Sequence),
		request.PeriodStart, request.PeriodEnd, int32(request.SchemaVersion),
		int64(request.CPUCoreSeconds), int64(request.RAMMBSeconds), int64(request.StorageGBSeconds),
		int64(request.NetworkEgressMB), int64(request.NetworkIngressMB), int64(request.GPUSeconds),
		request.Signature, request.EvidenceHash[:],
	)
	if err != nil {
		return Result{}, err
	}

	var consumerID any
	if request.ConsumerID != nil {
		consumerID = *request.ConsumerID
	}
	invoiceLineID := uuid.NewString()
	_, err = tx.Exec(ctx, `
		INSERT INTO invoice_lines (
			invoice_line_id, evidence_id, provider_id, consumer_id, workload_id, lease_id, price_version,
			cpu_amount, ram_amount, storage_amount, network_amount, total_amount, evidence_hash
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		invoiceLineID, evidenceID, request.ProviderID, consumerID, request.WorkloadID, request.LeaseID, int32(request.PriceVersion),
		int64(request.Charge.CPUAmount), int64(request.Charge.RAMAmount), int64(request.Charge.StorageAmount),
		int64(request.Charge.NetworkAmount), int64(request.Charge.TotalAmount), request.EvidenceHash[:],
	)
	if err != nil {
		return Result{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return Result{}, err
	}
	committed = true
	return Result{
		Outcome: OutcomeAccepted, EvidenceID: evidenceID, InvoiceLineID: invoiceLineID,
		TotalAmount: request.Charge.TotalAmount,
	}, nil
}

// classifyStaleSequence runs once AcceptEvidence's lock has confirmed
// `request.Sequence` is not a fresh advance: it distinguishes an exact,
// idempotent duplicate retry from conflicting evidence under the same
// sequence, from a plain out-of-order/replayed/regressed submission
// that never has a matching row at all.
func (r *PostgresRepository) classifyStaleSequence(ctx context.Context, tx pgx.Tx, request AcceptRequest) (Result, error) {
	var existingID string
	var existingHash []byte
	err := tx.QueryRow(ctx, `
		SELECT evidence_id, evidence_hash FROM metering_evidence
		WHERE provider_id = $1 AND workload_id = $2 AND sequence = $3`,
		request.ProviderID, request.WorkloadID, int64(request.Sequence),
	).Scan(&existingID, &existingHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return Result{Outcome: OutcomeOutOfOrder}, nil
	}
	if err != nil {
		return Result{}, err
	}
	if !bytes.Equal(existingHash, request.EvidenceHash[:]) {
		return Result{Outcome: OutcomeConflictingEvidence, EvidenceID: existingID}, nil
	}
	var invoiceLineID string
	var totalAmount int64
	err = tx.QueryRow(ctx, `
		SELECT invoice_line_id, total_amount FROM invoice_lines
		WHERE evidence_id = $1 AND supersedes_invoice_line_id IS NULL`,
		existingID,
	).Scan(&invoiceLineID, &totalAmount)
	if err != nil {
		return Result{}, err
	}
	return Result{
		Outcome: OutcomeDuplicate, EvidenceID: existingID, InvoiceLineID: invoiceLineID,
		TotalAmount: uint64(totalAmount),
	}, nil
}

func (r *PostgresRepository) RecordRejection(ctx context.Context, rejection Rejection) error {
	var workloadID any
	if rejection.WorkloadID != nil {
		workloadID = *rejection.WorkloadID
	}
	var sequence any
	if rejection.Sequence != nil {
		sequence = int64(*rejection.Sequence)
	}
	var hash any
	if rejection.EvidenceHash != nil {
		hash = rejection.EvidenceHash[:]
	}
	_, err := r.pool.Exec(ctx, `
		INSERT INTO metering_evidence_rejections (rejection_id, provider_id, workload_id, sequence, reason, detail, evidence_hash)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		uuid.NewString(), rejection.ProviderID, workloadID, sequence, rejection.Reason, rejection.Detail, hash,
	)
	return err
}

func (r *PostgresRepository) InvoiceLineExists(ctx context.Context, invoiceLineID string) (bool, error) {
	var exists bool
	err := r.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM invoice_lines WHERE invoice_line_id = $1)`, invoiceLineID).Scan(&exists)
	return exists, err
}

func (r *PostgresRepository) InsertDispute(ctx context.Context, dispute Dispute) (Dispute, error) {
	dispute.DisputeID = uuid.NewString()
	err := r.pool.QueryRow(ctx, `
		INSERT INTO metering_disputes (dispute_id, invoice_line_id, raised_by, reason, status)
		VALUES ($1,$2,$3,$4,$5)
		RETURNING raised_at`,
		dispute.DisputeID, dispute.InvoiceLineID, string(dispute.RaisedBy), dispute.Reason, string(dispute.Status),
	).Scan(&dispute.RaisedAt)
	if err != nil {
		return Dispute{}, err
	}
	return dispute, nil
}

func (r *PostgresRepository) GetDispute(ctx context.Context, disputeID string) (Dispute, error) {
	var dispute Dispute
	var raisedBy, status string
	err := r.pool.QueryRow(ctx, `
		SELECT dispute_id, invoice_line_id, raised_by, reason, status, raised_at
		FROM metering_disputes WHERE dispute_id = $1`,
		disputeID,
	).Scan(&dispute.DisputeID, &dispute.InvoiceLineID, &raisedBy, &dispute.Reason, &status, &dispute.RaisedAt)
	if err != nil {
		return Dispute{}, err
	}
	dispute.RaisedBy = DisputeParty(raisedBy)
	dispute.Status = DisputeStatus(status)
	return dispute, nil
}

func (r *PostgresRepository) ListDisputesForInvoiceLine(ctx context.Context, invoiceLineID string) ([]Dispute, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT dispute_id, invoice_line_id, raised_by, reason, status, raised_at
		FROM metering_disputes WHERE invoice_line_id = $1 ORDER BY raised_at`,
		invoiceLineID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var disputes []Dispute
	for rows.Next() {
		var dispute Dispute
		var raisedBy, status string
		if err := rows.Scan(&dispute.DisputeID, &dispute.InvoiceLineID, &raisedBy, &dispute.Reason, &status, &dispute.RaisedAt); err != nil {
			return nil, err
		}
		dispute.RaisedBy = DisputeParty(raisedBy)
		dispute.Status = DisputeStatus(status)
		disputes = append(disputes, dispute)
	}
	return disputes, rows.Err()
}

// checkBigintRange keeps a wire uint64 that does not fit Postgres'
// signed bigint columns from ever reaching an INSERT -- the same
// discipline workload_bandwidth_usage's RecordUsage already applies at
// its own uint64-on-the-wire/bigint-in-Postgres boundary, applied here
// before AcceptEvidence opens a transaction at all.
func checkBigintRange(request AcceptRequest) error {
	values := []uint64{
		request.Sequence, request.CPUCoreSeconds, request.RAMMBSeconds, request.StorageGBSeconds,
		request.NetworkEgressMB, request.NetworkIngressMB, request.GPUSeconds,
		request.Charge.CPUAmount, request.Charge.RAMAmount, request.Charge.StorageAmount,
		request.Charge.NetworkAmount, request.Charge.TotalAmount,
	}
	for _, value := range values {
		if value > math.MaxInt64 {
			return fmt.Errorf("metering: value %d exceeds bigint range", value)
		}
	}
	return nil
}
