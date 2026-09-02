package eventlog_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/openinfra/network/internal/eventlog"
	"github.com/openinfra/network/internal/testsupport"
	"github.com/openinfra/network/migrations"
)

// newEventLogTestPool isolates each test run into its own schema against
// OPENINFRA_TEST_DATABASE_URL -- the same convention every other
// Postgres-backed package's tests use (workloadapi, metering, ...).
func newEventLogTestPool(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	databaseURL := testsupport.RequireDatabaseURL(t)
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "eventlog_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, fmt.Sprintf(`CREATE SCHEMA %q`, schema)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(ctx, fmt.Sprintf(`DROP SCHEMA %q CASCADE`, schema)) })

	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := migrations.Apply(ctx, pool); err != nil {
		t.Fatal(err)
	}
	return ctx, pool
}

type testSigner struct {
	public  ed25519.PublicKey
	private ed25519.PrivateKey
}

func newTestSigner(t *testing.T) testSigner {
	t.Helper()
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return testSigner{public: public, private: private}
}

func (s testSigner) PublicKey() [32]byte {
	var key [32]byte
	copy(key[:], s.public)
	return key
}

func (s testSigner) Sign(payload []byte) [64]byte {
	var signature [64]byte
	copy(signature[:], ed25519.Sign(s.private, payload))
	return signature
}

// TestAppendControlPlaneSignedSequencesAndChains is the happy path: three
// successive control-plane-signed appends for the same subject land at
// sequence 1, 2, 3, each linked to the previous by prev_event_hash, and
// each independently verifiable.
func TestAppendControlPlaneSignedSequencesAndChains(t *testing.T) {
	ctx, pool := newEventLogTestPool(t)
	repository := eventlog.NewPostgresRepository(pool)
	signer := newTestSigner(t)
	subjectID := []byte(uuid.NewString())

	appendOne := func(eventType string, payload []byte, anchor *eventlog.ChainAnchor) eventlog.Entry {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		entry, err := repository.AppendControlPlaneSigned(ctx, tx, signer, eventlog.SubjectWorkloadLifecycle, subjectID, eventType, payload, anchor)
		if err != nil {
			t.Fatalf("append %s: %v", eventType, err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		return entry
	}

	e1 := appendOne("SCHEDULING", nil, nil)
	e2 := appendOne("LEASE_PENDING", []byte("provider-1"), nil)
	e3 := appendOne("LEASED", nil, &eventlog.ChainAnchor{LeaseID: 7, BlockHash: [32]byte{7, 7, 7}})

	if e1.Sequence != 1 || e2.Sequence != 2 || e3.Sequence != 3 {
		t.Fatalf("expected sequence 1,2,3, got %d,%d,%d", e1.Sequence, e2.Sequence, e3.Sequence)
	}
	if e2.PrevEventHash != e1.EventID || e3.PrevEventHash != e2.EventID {
		t.Fatal("expected each entry's prev_event_hash to chain to the previous entry's event_id")
	}

	entries, err := repository.ExportSubject(ctx, eventlog.SubjectWorkloadLifecycle, subjectID, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := eventlog.VerifyChain(entries); err != nil {
		t.Fatalf("expected a witness reading back this subject's exported history to verify, got %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 exported entries, got %d", len(entries))
	}
	if entries[2].ChainAnchor == nil || entries[2].ChainAnchor.LeaseID != 7 {
		t.Fatal("expected the exported LEASED entry to carry its chain_anchor")
	}

	checker := recordingAnchorChecker{leaseID: 7, blockHash: [32]byte{7, 7, 7}}
	if err := eventlog.VerifyChainAnchors(entries, checker); err != nil {
		t.Fatalf("expected the anchored entry to verify against real chain state, got %v", err)
	}
}

type recordingAnchorChecker struct {
	leaseID   uint64
	blockHash [32]byte
}

func (c recordingAnchorChecker) LeaseExistsAtBlock(leaseID uint64, blockHash [32]byte) (bool, error) {
	return leaseID == c.leaseID && blockHash == c.blockHash, nil
}

// TestAppendProviderSignedIdempotentReplay is ADR-039 §4's idempotence
// criterion end to end: appending the exact same already-accepted event a
// second time is rejected outright (never silently merged, never
// double-inserted) and the subject's authoritative history is left with
// exactly one row for that sequence either way.
func TestAppendProviderSignedIdempotentReplay(t *testing.T) {
	ctx, pool := newEventLogTestPool(t)
	repository := eventlog.NewPostgresRepository(pool)
	signer := newTestSigner(t)
	subjectID := []byte(uuid.NewString())
	entry := eventlog.Sign(signer, eventlog.SubjectWorkloadLifecycle, subjectID, 1, eventlog.ZeroHash, "RUNNING", []byte("container-abc"), nil)

	appendOnce := func() error {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if err := repository.AppendProviderSigned(ctx, tx, entry, signer.PublicKey()); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}

	if err := appendOnce(); err != nil {
		t.Fatalf("expected the first append to succeed, got %v", err)
	}
	err := appendOnce()
	if err == nil {
		t.Fatal("expected replaying the identical event to be rejected, not silently re-accepted")
	}
	var rejected *eventlog.ErrRejected
	if !errors.As(err, &rejected) {
		t.Fatalf("expected *eventlog.ErrRejected, got %T: %v", err, err)
	}

	entries, err := repository.ExportSubject(ctx, eventlog.SubjectWorkloadLifecycle, subjectID, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected exactly one authoritative row after a replay, got %d", len(entries))
	}
}

// TestAppendProviderSignedRejectsHashChainBreak: an event that claims to
// follow the current head but whose prev_event_hash points somewhere else
// (a dropped, reordered, or forged predecessor) is quarantined, not
// accepted.
func TestAppendProviderSignedRejectsHashChainBreak(t *testing.T) {
	ctx, pool := newEventLogTestPool(t)
	repository := eventlog.NewPostgresRepository(pool)
	signer := newTestSigner(t)
	subjectID := []byte(uuid.NewString())

	first := eventlog.Sign(signer, eventlog.SubjectWorkloadLifecycle, subjectID, 1, eventlog.ZeroHash, "SCHEDULING", nil, nil)
	mustAppendProviderSigned(t, ctx, pool, repository, signer, first)

	wrongPrev := eventlog.Sign(signer, eventlog.SubjectWorkloadLifecycle, subjectID, 2, [32]byte{9, 9, 9}, "LEASE_PENDING", nil, nil)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	err = repository.AppendProviderSigned(ctx, tx, wrongPrev, signer.PublicKey())
	if err == nil {
		t.Fatal("expected a hash-chain break to be rejected")
	}
	if !errors.Is(err, eventlog.ErrHashChainBreak) {
		t.Fatalf("expected ErrHashChainBreak, got %v", err)
	}

	var rejectionCount int
	if scanErr := pool.QueryRow(ctx, `SELECT count(*) FROM event_log_rejections WHERE reason = $1`, eventlog.ErrHashChainBreak.Error()).Scan(&rejectionCount); scanErr != nil {
		t.Fatal(scanErr)
	}
	if rejectionCount != 1 {
		t.Fatalf("expected the hash-chain break to be recorded in event_log_rejections, got %d rows", rejectionCount)
	}
}

// TestAppendProviderSignedRejectsTamperedSignature is this task's
// explicit "a tampered event detected and rejected" requirement: an event
// whose payload was modified after signing (so its signature no longer
// verifies) is quarantined, never accepted into the authoritative log.
func TestAppendProviderSignedRejectsTamperedSignature(t *testing.T) {
	ctx, pool := newEventLogTestPool(t)
	repository := eventlog.NewPostgresRepository(pool)
	signer := newTestSigner(t)
	subjectID := []byte(uuid.NewString())

	entry := eventlog.Sign(signer, eventlog.SubjectWorkloadLifecycle, subjectID, 1, eventlog.ZeroHash, "RUNNING", []byte("container-abc"), nil)
	entry.Payload = []byte("container-evil") // tampered after signing; payload_hash/event_id/signature are now stale

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	err = repository.AppendProviderSigned(ctx, tx, entry, signer.PublicKey())
	if err == nil {
		t.Fatal("expected a tampered event to be rejected")
	}
	if !errors.Is(err, eventlog.ErrInvalidEventID) {
		t.Fatalf("expected ErrInvalidEventID, got %v", err)
	}

	entries, err := repository.ExportSubject(ctx, eventlog.SubjectWorkloadLifecycle, subjectID, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("expected the tampered event to never reach the authoritative log")
	}
}

// TestAppendProviderSignedRejectsUnexpectedSigner: an event whose
// signer_public_key does not match the caller's independently-known
// expected signer for this subject is rejected, even if its own
// signature is internally self-consistent (i.e. it really was signed by
// *some* key -- just not the one this subject is supposed to belong to).
func TestAppendProviderSignedRejectsUnexpectedSigner(t *testing.T) {
	ctx, pool := newEventLogTestPool(t)
	repository := eventlog.NewPostgresRepository(pool)
	actualSigner := newTestSigner(t)
	expectedSigner := newTestSigner(t)
	subjectID := []byte(uuid.NewString())

	entry := eventlog.Sign(actualSigner, eventlog.SubjectWorkloadLifecycle, subjectID, 1, eventlog.ZeroHash, "RUNNING", nil, nil)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	err = repository.AppendProviderSigned(ctx, tx, entry, expectedSigner.PublicKey())
	if err == nil {
		t.Fatal("expected an event signed by an unexpected key to be rejected")
	}
}

// TestPruneRequiresWitnessAcknowledgement is ADR-039 §8's structural
// guard: raw events superseded by a SNAPSHOT are never pruned until at
// least one independent witness has acknowledged verifying that snapshot.
func TestPruneRequiresWitnessAcknowledgement(t *testing.T) {
	ctx, pool := newEventLogTestPool(t)
	repository := eventlog.NewPostgresRepository(pool)
	signer := newTestSigner(t)
	subjectID := []byte(uuid.NewString())

	appendOne := func(eventType string) eventlog.Entry {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		entry, err := repository.AppendControlPlaneSigned(ctx, tx, signer, eventlog.SubjectWorkloadLifecycle, subjectID, eventType, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		return entry
	}

	appendOne("SCHEDULING")
	appendOne("LEASE_PENDING")
	snapshot := appendOne("SNAPSHOT")
	appendOne("RUNNING")

	// No witness has acknowledged the snapshot yet: Prune must delete
	// nothing, even though the snapshot is already past the (zero)
	// retention window.
	deleted, err := repository.Prune(ctx, eventlog.SubjectWorkloadLifecycle, subjectID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 0 {
		t.Fatalf("expected no rows pruned before any witness ack, got %d", deleted)
	}

	witnessKey := newTestSigner(t).PublicKey()
	if err := repository.RecordWitnessAck(ctx, snapshot.EventID, witnessKey); err != nil {
		t.Fatal(err)
	}
	// Idempotent: acking twice must not error.
	if err := repository.RecordWitnessAck(ctx, snapshot.EventID, witnessKey); err != nil {
		t.Fatal(err)
	}

	deleted, err = repository.Prune(ctx, eventlog.SubjectWorkloadLifecycle, subjectID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 2 {
		t.Fatalf("expected the 2 rows before the witnessed snapshot to be pruned, got %d", deleted)
	}

	remaining, err := repository.ExportSubject(ctx, eventlog.SubjectWorkloadLifecycle, subjectID, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 2 {
		t.Fatalf("expected the snapshot and everything after it to survive, got %d rows", len(remaining))
	}
	if remaining[0].EventType != "SNAPSHOT" {
		t.Fatalf("expected the surviving history to start at the snapshot, got %q", remaining[0].EventType)
	}
}

// TestExportSubjectSinceSequenceSupportsCatchUp: a witness resuming after
// a disconnect (or joining fresh with since_sequence=0) sees exactly the
// events after the sequence it already has -- no gap, no duplicate.
func TestExportSubjectSinceSequenceSupportsCatchUp(t *testing.T) {
	ctx, pool := newEventLogTestPool(t)
	repository := eventlog.NewPostgresRepository(pool)
	signer := newTestSigner(t)
	subjectID := []byte(uuid.NewString())

	for _, eventType := range []string{"SCHEDULING", "LEASE_PENDING", "LEASED", "DEPLOYING", "RUNNING"} {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := repository.AppendControlPlaneSigned(ctx, tx, signer, eventlog.SubjectWorkloadLifecycle, subjectID, eventType, nil, nil); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}

	page, err := repository.ExportSubject(ctx, eventlog.SubjectWorkloadLifecycle, subjectID, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 3 {
		t.Fatalf("expected 3 events after sequence 2, got %d", len(page))
	}
	if page[0].Sequence != 3 || page[0].EventType != "LEASED" {
		t.Fatalf("expected catch-up to resume exactly at sequence 3, got sequence %d (%s)", page[0].Sequence, page[0].EventType)
	}
}

func mustAppendProviderSigned(t *testing.T, ctx context.Context, pool *pgxpool.Pool, repository *eventlog.PostgresRepository, signer testSigner, entry eventlog.Entry) {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := repository.AppendProviderSigned(ctx, tx, entry, signer.PublicKey()); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}
