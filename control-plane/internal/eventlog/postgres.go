package eventlog

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrConflict is returned when an append loses a race for the next
// sequence value -- migration 000024's UNIQUE(subject_type, subject_id,
// sequence) constraint firing (23505), the defense-in-depth backstop
// behind the "the guarded workloads UPDATE this append follows inside the
// same transaction already established single-writer-per-subject" design
// (see PostgresRepository.AppendControlPlaneSigned's doc comment).
var ErrConflict = errors.New("eventlog: append lost a race for the next sequence")

// ErrRejected wraps the reason AppendProviderSigned quarantined an entry
// into event_log_rejections instead of accepting it.
type ErrRejected struct{ Reason error }

func (e *ErrRejected) Error() string { return "eventlog: rejected: " + e.Reason.Error() }
func (e *ErrRejected) Unwrap() error { return e.Reason }

// PostgresRepository implements this package's storage against migration
// 000024's event_log/event_log_rejections/event_log_witness_acks tables --
// the identical operational shape internal/metering.PostgresRepository
// already has against metering_evidence.
type PostgresRepository struct{ pool *pgxpool.Pool }

func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

// head returns the current sequence/event_id for (subjectType,
// subjectID) within tx -- (0, ZeroHash) for a subject with no events yet,
// which is exactly the state AppendControlPlaneSigned needs to build
// sequence=1's entry (prev_event_hash all-zero, per ADR-039 §2).
//
// Deliberately not FOR UPDATE: this method must only ever be called from
// within a transaction that has *already* executed the caller's own
// guarded state-transition write (e.g. workloadapi's `UPDATE workloads
// SET state=... WHERE ... AND version=$n AND worker_id=$m AND
// worker_lease_until>now()`, RowsAffected checked == 1) for the identical
// subject -- ADR-039 §1's load-bearing fact that every write this system
// does is already single-writer-per-subject by construction. A second,
// concurrent transaction attempting the same subject's guarded update
// will have already failed its own RowsAffected check and rolled back
// before it ever reaches this method, so there is nothing else that could
// be racing head() by the time it runs. The UNIQUE constraint (surfaced
// as ErrConflict below) is defense in depth for exactly the case where
// that invariant is ever violated by a future caller, not the primary
// mechanism.
func (r *PostgresRepository) head(ctx context.Context, tx pgx.Tx, subjectType SubjectType, subjectID []byte) (uint64, [32]byte, error) {
	var sequence int64
	var eventID []byte
	err := tx.QueryRow(ctx, `SELECT sequence, event_id FROM event_log WHERE subject_type=$1 AND subject_id=$2 ORDER BY sequence DESC LIMIT 1`, string(subjectType), subjectID).Scan(&sequence, &eventID)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ZeroHash, nil
	}
	if err != nil {
		return 0, ZeroHash, err
	}
	var prev [32]byte
	copy(prev[:], eventID)
	return uint64(sequence), prev, nil
}

// AppendControlPlaneSigned computes the next (sequence, prev_event_hash)
// for (subjectType, subjectID) from within tx, builds and signs the
// resulting Entry with signer, and inserts it -- all in the caller's own
// transaction, per ADR-039 §11's "in the same Postgres transaction" dual-
// write requirement. Callers (workloadapi.PostgresRepository's Mark*
// methods) must call this only *after* their own guarded workloads UPDATE
// has already succeeded (RowsAffected == 1) inside the same tx -- see
// head's doc comment for why that ordering, not a lock taken here, is
// what makes this race-free.
func (r *PostgresRepository) AppendControlPlaneSigned(ctx context.Context, tx pgx.Tx, signer Signer, subjectType SubjectType, subjectID []byte, eventType string, payload []byte, anchor *ChainAnchor) (Entry, error) {
	sequence, prevHash, err := r.head(ctx, tx, subjectType, subjectID)
	if err != nil {
		return Entry{}, fmt.Errorf("eventlog: read head: %w", err)
	}
	entry := Sign(signer, subjectType, subjectID, sequence+1, prevHash, eventType, payload, anchor)
	if err := insert(ctx, tx, entry); err != nil {
		if isUniqueViolation(err) {
			return Entry{}, ErrConflict
		}
		return Entry{}, err
	}
	return entry, nil
}

// AppendProviderSigned inserts entry, which must already be fully signed
// by its own claimed signer (e.g. a Provider Agent's agent-core identity
// key, per ADR-039 §3) -- this method never signs anything itself. Before
// insert it independently verifies: the entry's own self-consistency
// (VerifyEntry: event_id matches its recomputed hash, signature verifies
// against signer_public_key), that signerPublicKey matches the caller's
// independently-known expected signer (e.g. the on-chain
// pallet-provider-registry public key for the provider that claims to own
// this subject -- checked by the caller, passed in here as
// expectedSigner, never trusted from the entry alone), and hash-chain
// continuity against the current head. Any failure is quarantined into
// event_log_rejections (never silently dropped, ADR-039 §6) and returned
// as *ErrRejected.
func (r *PostgresRepository) AppendProviderSigned(ctx context.Context, tx pgx.Tx, entry Entry, expectedSigner [32]byte) error {
	// Recorded via r.pool, deliberately NOT via tx: a caller returning an
	// *ErrRejected from this method is expected to roll tx back (nothing
	// else in it should commit either), and a rejection recorded inside a
	// transaction that then gets rolled back would vanish along with it
	// -- silently defeating ADR-039 §6's "quarantine, never silently
	// drop" guarantee for exactly the cases that guarantee exists for.
	// The audit trail must survive independently of what the caller does
	// with its own transaction.
	reject := func(reason error, detail string) error {
		_ = r.RecordRejection(ctx, Rejection{SubjectType: entry.SubjectType, SubjectID: entry.SubjectID, Sequence: &entry.Sequence, EventID: &entry.EventID, Reason: reason.Error(), Detail: detail})
		return &ErrRejected{Reason: reason}
	}
	if entry.SignerPublicKey != expectedSigner {
		return reject(errors.New("signer_public_key does not match the expected signer for this subject"), "")
	}
	if err := VerifyEntry(entry); err != nil {
		return reject(err, "")
	}
	sequence, prevHash, err := r.head(ctx, tx, entry.SubjectType, entry.SubjectID)
	if err != nil {
		return fmt.Errorf("eventlog: read head: %w", err)
	}
	if entry.Sequence != sequence+1 {
		return reject(errors.New("sequence is not the next expected value for this subject"), fmt.Sprintf("expected %d, got %d", sequence+1, entry.Sequence))
	}
	if entry.PrevEventHash != prevHash {
		return reject(ErrHashChainBreak, "")
	}
	if err := insert(ctx, tx, entry); err != nil {
		if isUniqueViolation(err) {
			return reject(ErrConflict, "")
		}
		return err
	}
	return nil
}

func insert(ctx context.Context, tx pgx.Tx, entry Entry) error {
	var anchorLeaseID any
	var anchorBlockHash any
	if entry.ChainAnchor != nil {
		anchorLeaseID = int64(entry.ChainAnchor.LeaseID)
		anchorBlockHash = entry.ChainAnchor.BlockHash[:]
	}
	// event_log.payload is NOT NULL (migration 000024): an event with no
	// meaningful payload (e.g. "SCHEDULING") still has a real, empty
	// payload, not an absent one -- pgx otherwise binds a nil []byte as
	// SQL NULL, which the column rejects. sha256(nil) == sha256([]byte{})
	// in Go, so this never changes payload_hash/event_id/signature,
	// computed by Sign/VerifyEntry before this function is ever reached.
	payload := entry.Payload
	if payload == nil {
		payload = []byte{}
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO event_log (
			event_id, subject_type, subject_id, sequence, prev_event_hash, event_type,
			payload, payload_hash, chain_anchor_lease_id, chain_anchor_block_hash,
			signer_public_key, signature
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		entry.EventID[:], string(entry.SubjectType), entry.SubjectID, int64(entry.Sequence), entry.PrevEventHash[:], entry.EventType,
		payload, entry.PayloadHash[:], anchorLeaseID, anchorBlockHash,
		entry.SignerPublicKey[:], entry.Signature[:],
	)
	return err
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// Rejection mirrors internal/metering.Rejection's shape for
// event_log_rejections -- see RecordRejection.
type Rejection struct {
	SubjectType SubjectType
	SubjectID   []byte
	Sequence    *uint64
	EventID     *[32]byte
	Reason      string
	Detail      string
}

// RecordRejection records rejection via r.pool directly (autocommit, its
// own implicit transaction) -- never via a caller-supplied tx, so a
// rejection this method records always survives independent of whatever
// the caller's own transaction (e.g. a doomed AppendProviderSigned
// attempt) ends up doing. Used both by AppendProviderSigned's internal
// `reject` closure and by any external caller reporting a rejection
// discovered outside this package entirely (e.g. a witness's own
// VerifyChain failure being reported back).
func (r *PostgresRepository) RecordRejection(ctx context.Context, rejection Rejection) error {
	return recordRejection(ctx, r.pool, rejection)
}

type execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

func recordRejection(ctx context.Context, exec execer, rejection Rejection) error {
	var sequence any
	if rejection.Sequence != nil {
		sequence = int64(*rejection.Sequence)
	}
	var eventID any
	if rejection.EventID != nil {
		eventID = rejection.EventID[:]
	}
	var subjectID any
	if rejection.SubjectID != nil {
		subjectID = rejection.SubjectID
	}
	_, err := exec.Exec(ctx, `
		INSERT INTO event_log_rejections (rejection_id, subject_type, subject_id, sequence, event_id, reason, detail)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		uuid.NewString(), string(rejection.SubjectType), subjectID, sequence, eventID, rejection.Reason, nullIfEmpty(rejection.Detail),
	)
	return err
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// ExportSubject returns subjectID's full event history for subjectType,
// strictly ordered by sequence, starting after sinceSequence (0 for a
// brand-new witness starting from genesis) -- the read side of ADR-039
// §10's SubscribeEvents(subject_type, since_sequence). limit bounds a
// single call's page size; callers needing a subject's whole history page
// through by passing the last-seen sequence back in as sinceSequence.
func (r *PostgresRepository) ExportSubject(ctx context.Context, subjectType SubjectType, subjectID []byte, sinceSequence uint64, limit int) ([]Entry, error) {
	if limit <= 0 || limit > 10000 {
		limit = 10000
	}
	rows, err := r.pool.Query(ctx, `
		SELECT event_id, subject_id, sequence, prev_event_hash, event_type, payload, payload_hash,
		       chain_anchor_lease_id, chain_anchor_block_hash, signer_public_key, signature, recorded_at
		FROM event_log
		WHERE subject_type=$1 AND subject_id=$2 AND sequence > $3
		ORDER BY sequence ASC
		LIMIT $4`,
		string(subjectType), subjectID, int64(sinceSequence), limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []Entry
	for rows.Next() {
		entry, err := scanEntry(rows, subjectType)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}

// ExportSince pages through every subject_id of subjectType whose
// sequence=1 event was recorded after sinceRecordedAt, for a witness
// discovering subjects it has not seen before -- ExportSubject alone
// requires already knowing which subject_id to ask for.
func (r *PostgresRepository) ExportSince(ctx context.Context, subjectType SubjectType, sinceRecordedAt time.Time, limit int) ([]Entry, error) {
	if limit <= 0 || limit > 10000 {
		limit = 10000
	}
	rows, err := r.pool.Query(ctx, `
		SELECT event_id, subject_id, sequence, prev_event_hash, event_type, payload, payload_hash,
		       chain_anchor_lease_id, chain_anchor_block_hash, signer_public_key, signature, recorded_at
		FROM event_log
		WHERE subject_type=$1 AND recorded_at > $2
		ORDER BY recorded_at ASC
		LIMIT $3`,
		string(subjectType), sinceRecordedAt, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []Entry
	for rows.Next() {
		entry, err := scanEntry(rows, subjectType)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanEntry(row rowScanner, subjectType SubjectType) (Entry, error) {
	var eventID, subjectID, prevHash, payload, payloadHash, signerPublicKey, signature []byte
	var sequence int64
	var eventType string
	var anchorLeaseID *int64
	var anchorBlockHash []byte
	var recordedAt time.Time
	if err := row.Scan(&eventID, &subjectID, &sequence, &prevHash, &eventType, &payload, &payloadHash, &anchorLeaseID, &anchorBlockHash, &signerPublicKey, &signature, &recordedAt); err != nil {
		return Entry{}, err
	}
	entry := Entry{
		SubjectType: subjectType,
		SubjectID:   subjectID,
		Sequence:    uint64(sequence),
		EventType:   eventType,
		Payload:     payload,
		RecordedAt:  recordedAt,
	}
	copy(entry.EventID[:], eventID)
	copy(entry.PrevEventHash[:], prevHash)
	copy(entry.PayloadHash[:], payloadHash)
	copy(entry.SignerPublicKey[:], signerPublicKey)
	copy(entry.Signature[:], signature)
	if anchorLeaseID != nil {
		anchor := &ChainAnchor{LeaseID: uint64(*anchorLeaseID)}
		copy(anchor.BlockHash[:], anchorBlockHash)
		entry.ChainAnchor = anchor
	}
	return entry, nil
}

// RecordWitnessAck records that witnessPublicKey claims to have
// independently verified eventID -- see migration 000024's
// event_log_witness_acks doc comment for what this claim is (and is not)
// evidence of. Idempotent: acking the same (event, witness) pair twice is
// a no-op, not an error.
func (r *PostgresRepository) RecordWitnessAck(ctx context.Context, eventID [32]byte, witnessPublicKey [32]byte) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO event_log_witness_acks (event_id, witness_public_key)
		VALUES ($1,$2)
		ON CONFLICT (event_id, witness_public_key) DO NOTHING`,
		eventID[:], witnessPublicKey[:],
	)
	return err
}

// Prune implements ADR-039 §8: deletes raw event_log rows for
// (subjectType, subjectID) that are (a) strictly older than the most
// recent SNAPSHOT event for that subject, (b) that SNAPSHOT is older than
// retentionWindow, and (c) that SNAPSHOT has at least one row in
// event_log_witness_acks -- closing off "prune, then claim the pruned
// history said whatever is convenient" per §8's explicit requirement.
// event_log_rejections is never touched by this method (§8: "never pruned
// on the same schedule -- it is the audit trail of disagreement").
// Returns 0 rows deleted (not an error) whenever no eligible witnessed
// snapshot exists yet.
func (r *PostgresRepository) Prune(ctx context.Context, subjectType SubjectType, subjectID []byte, retentionWindow time.Duration) (int64, error) {
	var snapshotSequence int64
	var snapshotEventID []byte
	err := r.pool.QueryRow(ctx, `
		SELECT event_log.sequence, event_log.event_id
		FROM event_log
		WHERE event_log.subject_type=$1 AND event_log.subject_id=$2 AND event_log.event_type='SNAPSHOT'
		  AND event_log.recorded_at <= now() - $3::interval
		  AND EXISTS (SELECT 1 FROM event_log_witness_acks WHERE event_log_witness_acks.event_id = event_log.event_id)
		ORDER BY event_log.sequence DESC
		LIMIT 1`,
		string(subjectType), subjectID, retentionWindow.String(),
	).Scan(&snapshotSequence, &snapshotEventID)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	command, err := r.pool.Exec(ctx, `
		DELETE FROM event_log
		WHERE subject_type=$1 AND subject_id=$2 AND sequence < $3`,
		string(subjectType), subjectID, snapshotSequence,
	)
	if err != nil {
		return 0, err
	}
	return command.RowsAffected(), nil
}
