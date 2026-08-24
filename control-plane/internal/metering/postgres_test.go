package metering

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	agentv1 "github.com/openinfra/network/protocol/generated/go/agent/v1"
	sharedv1 "github.com/openinfra/network/protocol/generated/go/shared/v1"

	"github.com/openinfra/network/internal/testsupport"
	"github.com/openinfra/network/migrations"
)

// newMeteringTestPool isolates each test run into its own schema
// against OPENINFRA_TEST_DATABASE_URL, the same convention every other
// Postgres-backed package's tests use (see testsupport.RequireDatabaseURL's
// own doc comment for why this fails in CI rather than skipping).
func newMeteringTestPool(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	databaseURL := testsupport.RequireDatabaseURL(t)
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "metering_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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

type postgresFixture struct {
	pool       *pgxpool.Pool
	service    *Service
	providerID string
	workloadID string
	ownerID    string
	privateKey ed25519.PrivateKey
	now        time.Time
}

func newPostgresFixture(t *testing.T) (context.Context, *postgresFixture) {
	t.Helper()
	ctx, pool := newMeteringTestPool(t)

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	providerID := uuid.NewString()
	if _, err := pool.Exec(ctx, `
		INSERT INTO providers (provider_id, public_key, protocol_version, agent_version, agent_endpoint, capabilities, status, registered_at)
		VALUES ($1,$2,'1','0.1.0','',$3,0,now())`,
		providerID, []byte(publicKey), []byte("{}"),
	); err != nil {
		t.Fatalf("seed provider: %v", err)
	}

	ownerID := uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO users (user_id, display_name) VALUES ($1, 'metering-test-owner')`, ownerID); err != nil {
		t.Fatalf("seed owner: %v", err)
	}

	workloadID := uuid.NewString()
	if _, err := pool.Exec(ctx, `
		INSERT INTO workloads (workload_id, request_id, owner_id, request_hash, definition, image, state,
		                        provider_id, lease_id, container_id)
		VALUES ($1,$2,$3,$4,$5,'test-image','RUNNING',$6,42,'container-1')`,
		workloadID, uuid.NewString(), ownerID, make([]byte, 32), []byte("definition"), providerID,
	); err != nil {
		t.Fatalf("seed workload: %v", err)
	}

	repository := NewPostgresRepository(pool)
	service := NewService(repository)
	fixedNow := time.Unix(1_700_000_000, 0).UTC()
	service.now = func() time.Time { return fixedNow }

	return ctx, &postgresFixture{
		pool: pool, service: service, providerID: providerID, workloadID: workloadID,
		ownerID: ownerID, privateKey: privateKey, now: fixedNow,
	}
}

// signedResponse builds a valid, signed GetUsageSummaryResponse for
// this fixture's provider/workload/lease (lease_id 42, matching the
// seeded workloads row), mirroring testFixture.signedResponse in
// service_test.go.
func (f *postgresFixture) signedResponse(sequence, periodEnd uint64) *agentv1.GetUsageSummaryResponse {
	summary := &sharedv1.MeteringSummary{
		WorkloadId: f.workloadID, LeaseId: "42", Sequence: sequence,
		PeriodStart: periodEnd - 1, PeriodEnd: periodEnd, MeteringSchemaVersion: 1,
		CpuCoreSeconds: 10, RamMbSeconds: 20, StorageGbSeconds: 30,
		NetworkEgressMb: 5, NetworkIngressMb: 5, GpuSeconds: 0,
	}
	signature := ed25519.Sign(f.privateKey, signedBytes(summary))
	return &agentv1.GetUsageSummaryResponse{Summary: summary, Signature: signature}
}

func TestPostgresRecordUsageAcceptsAndPersistsAnInvoiceLine(t *testing.T) {
	ctx, f := newPostgresFixture(t)
	response := f.signedResponse(1, uint64(f.now.Unix()))

	result, err := f.service.RecordUsage(ctx, f.providerID, response)
	if err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}
	if result.Outcome != OutcomeAccepted {
		t.Fatalf("outcome = %s, want accepted", result.Outcome)
	}

	var storedTotal int64
	var consumerID string
	err = f.pool.QueryRow(ctx, `SELECT total_amount, consumer_id::text FROM invoice_lines WHERE invoice_line_id = $1`, result.InvoiceLineID).
		Scan(&storedTotal, &consumerID)
	if err != nil {
		t.Fatalf("read invoice line: %v", err)
	}
	if uint64(storedTotal) != result.TotalAmount {
		t.Fatalf("stored total_amount = %d, want %d", storedTotal, result.TotalAmount)
	}
	if consumerID != f.ownerID {
		t.Fatalf("consumer_id = %s, want the workload's owner %s", consumerID, f.ownerID)
	}

	var evidenceCount int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM metering_evidence WHERE evidence_id = $1`, result.EvidenceID).Scan(&evidenceCount); err != nil {
		t.Fatal(err)
	}
	if evidenceCount != 1 {
		t.Fatalf("metering_evidence rows for this evidence_id = %d, want 1", evidenceCount)
	}
}

// TestPostgresRecordUsageDuplicateDoesNotInsertASecondRow is the
// database-level half of the "duplicate reports... must not double-bill"
// acceptance criterion: an identical resubmission must not create a
// second metering_evidence or invoice_lines row.
func TestPostgresRecordUsageDuplicateDoesNotInsertASecondRow(t *testing.T) {
	ctx, f := newPostgresFixture(t)
	response := f.signedResponse(1, uint64(f.now.Unix()))

	first, err := f.service.RecordUsage(ctx, f.providerID, response)
	if err != nil || first.Outcome != OutcomeAccepted {
		t.Fatalf("first submission: outcome=%s err=%v", first.Outcome, err)
	}
	second, err := f.service.RecordUsage(ctx, f.providerID, response)
	if err != nil {
		t.Fatalf("second submission: %v", err)
	}
	if second.Outcome != OutcomeDuplicate {
		t.Fatalf("outcome = %s, want duplicate", second.Outcome)
	}

	var evidenceCount, invoiceCount int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM metering_evidence WHERE provider_id = $1 AND workload_id = $2`, f.providerID, f.workloadID).Scan(&evidenceCount); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM invoice_lines WHERE provider_id = $1 AND workload_id = $2`, f.providerID, f.workloadID).Scan(&invoiceCount); err != nil {
		t.Fatal(err)
	}
	if evidenceCount != 1 || invoiceCount != 1 {
		t.Fatalf("evidence rows=%d invoice rows=%d, want 1/1 -- a duplicate retry must not double-bill", evidenceCount, invoiceCount)
	}
}

// TestPostgresRejectionsAreAppendOnlyAndInspectable exercises the
// "missing/late/conflicting evidence never becomes silent billable
// success" criterion at the database boundary: a rejected submission is
// persisted to metering_evidence_rejections, not just logged and
// forgotten.
func TestPostgresRejectionsAreAppendOnlyAndInspectable(t *testing.T) {
	ctx, f := newPostgresFixture(t)
	response := f.signedResponse(1, uint64(f.now.Unix()))
	response.Signature[0] ^= 0xFF // corrupt the signature

	result, err := f.service.RecordUsage(ctx, f.providerID, response)
	if err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}
	if result.Outcome != OutcomeInvalidSignature {
		t.Fatalf("outcome = %s, want invalid_signature", result.Outcome)
	}

	var reason string
	err = f.pool.QueryRow(ctx, `
		SELECT reason FROM metering_evidence_rejections
		WHERE provider_id = $1 ORDER BY received_at DESC LIMIT 1`, f.providerID,
	).Scan(&reason)
	if err != nil {
		t.Fatalf("read rejection: %v", err)
	}
	if reason != "invalid_signature" {
		t.Fatalf("reason = %s, want invalid_signature", reason)
	}
}

// TestPostgresConcurrentSubmissionsForTheSameWorkloadDoNotDoubleAccept
// is the concurrency-safety property AcceptEvidence's own doc comment
// describes: two callers racing to submit the same fresh sequence for
// the same workload must not both succeed.
func TestPostgresConcurrentSubmissionsForTheSameWorkloadDoNotDoubleAccept(t *testing.T) {
	ctx, f := newPostgresFixture(t)
	response := f.signedResponse(1, uint64(f.now.Unix()))

	results := make(chan Result, 2)
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			result, err := f.service.RecordUsage(ctx, f.providerID, response)
			results <- result
			errs <- err
		}()
	}
	var outcomes []Outcome
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent RecordUsage: %v", err)
		}
		outcomes = append(outcomes, (<-results).Outcome)
	}
	accepted := 0
	for _, outcome := range outcomes {
		if outcome == OutcomeAccepted {
			accepted++
		}
	}
	// Exactly one call observes a fresh accept; the other, racing for
	// the same lock, sees the now-advanced cursor and classifies as a
	// duplicate (identical content) once it re-reads under the lock.
	if accepted != 1 {
		t.Fatalf("accepted count = %d, want exactly 1 (outcomes: %v)", accepted, outcomes)
	}

	var evidenceCount int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM metering_evidence WHERE provider_id = $1 AND workload_id = $2`, f.providerID, f.workloadID).Scan(&evidenceCount); err != nil {
		t.Fatal(err)
	}
	if evidenceCount != 1 {
		t.Fatalf("evidence rows = %d, want exactly 1", evidenceCount)
	}
}

func TestPostgresDisputeLifecycleIsInspectable(t *testing.T) {
	ctx, f := newPostgresFixture(t)
	response := f.signedResponse(1, uint64(f.now.Unix()))
	accepted, err := f.service.RecordUsage(ctx, f.providerID, response)
	if err != nil || accepted.Outcome != OutcomeAccepted {
		t.Fatalf("priming acceptance: outcome=%s err=%v", accepted.Outcome, err)
	}

	dispute, err := f.service.RaiseDispute(ctx, accepted.InvoiceLineID, DisputePartyProvider, "usage understated")
	if err != nil {
		t.Fatalf("RaiseDispute: %v", err)
	}
	if dispute.Status != DisputeStatusOpen {
		t.Fatalf("status = %s, want open", dispute.Status)
	}

	disputes, err := f.service.ListDisputes(ctx, accepted.InvoiceLineID)
	if err != nil {
		t.Fatalf("ListDisputes: %v", err)
	}
	if len(disputes) != 1 || disputes[0].DisputeID != dispute.DisputeID {
		t.Fatalf("ListDisputes = %+v, want exactly the raised dispute", disputes)
	}
}
