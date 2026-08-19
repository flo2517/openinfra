package providerjoin_test

import (
	"context"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	controlplanev1 "github.com/openinfra/network/protocol/generated/go/controlplane/v1"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/openinfra/network/internal/providerjoin"
	"github.com/openinfra/network/internal/testsupport"
	"github.com/openinfra/network/migrations"
)

// newTestPool isolates each test run into its own schema against
// OPENINFRA_TEST_DATABASE_URL, the same convention walletlogin/userauth/
// workloadapi's own Postgres integration tests use.
func newTestPool(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	databaseURL := testsupport.RequireDatabaseURL(t)
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "providerjoin_bandwidth_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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

// seedProvider inserts the minimum providers row workload_bandwidth_usage's
// foreign key requires.
func seedProvider(t *testing.T, ctx context.Context, pool *pgxpool.Pool, providerID string) {
	t.Helper()
	_, err := pool.Exec(ctx, `
		INSERT INTO providers (provider_id, public_key, protocol_version, agent_version, agent_endpoint, capabilities, status, registered_at)
		VALUES ($1, $2, '1', '0.1.0', '', '{}', 0, now())`,
		providerID, []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("seed provider: %v", err)
	}
}

// seedWorkload inserts the minimum workloads row RecordUsage's own query
// requires to accept a workload_id at all: it INNER JOINs against
// workloads (see RecordUsage's doc comment for why a JOIN, not a foreign
// key, does the filtering), so a workload_id with no matching row here is
// silently excluded, not persisted -- exactly the property under test
// elsewhere, but every *other* test in this file needs a real row for its
// workload_id to survive that filter at all.
func seedWorkload(t *testing.T, ctx context.Context, pool *pgxpool.Pool, workloadID string) {
	t.Helper()
	_, err := pool.Exec(ctx, `
		INSERT INTO workloads (workload_id, request_id, request_hash, definition, image, state)
		VALUES ($1, $2, $3, 'definition', 'test-image', 'REQUESTED')`,
		workloadID, uuid.NewString(), []byte("01234567890123456789012345678901"))
	if err != nil {
		t.Fatalf("seed workload: %v", err)
	}
}

func readUsage(t *testing.T, ctx context.Context, pool *pgxpool.Pool, providerID, workloadID string) (ingress, egress uint64, windowStartedAt time.Time) {
	t.Helper()
	err := pool.QueryRow(ctx, `
		SELECT ingress_bytes_total, egress_bytes_total, window_started_at
		FROM workload_bandwidth_usage
		WHERE provider_id = $1 AND workload_id = $2`, providerID, workloadID,
	).Scan(&ingress, &egress, &windowStartedAt)
	if err != nil {
		t.Fatalf("read usage: %v", err)
	}
	return ingress, egress, windowStartedAt
}

// TestRecordUsageUpsertsLatestCumulativeCounters is the straightforward
// happy path: a fresh workload's first report is stored, and a later
// report with larger counters (the normal, monotonically increasing
// case) overwrites it.
func TestRecordUsageUpsertsLatestCumulativeCounters(t *testing.T) {
	ctx, pool := newTestPool(t)
	store := providerjoin.NewPostgresBandwidthUsageStore(pool)
	providerID := uuid.NewString()
	seedProvider(t, ctx, pool, providerID)
	workloadID := uuid.NewString()
	seedWorkload(t, ctx, pool, workloadID)
	windowStartedAt := timestamppb.New(time.Unix(1_700_000_000, 0).UTC())

	if err := store.RecordUsage(ctx, providerID, []*controlplanev1.WorkloadBandwidthUsage{{
		WorkloadId: workloadID, IngressBytesTotal: 100, EgressBytesTotal: 200, WindowStartedAt: windowStartedAt,
	}}); err != nil {
		t.Fatalf("first RecordUsage: %v", err)
	}
	ingress, egress, _ := readUsage(t, ctx, pool, providerID, workloadID)
	if ingress != 100 || egress != 200 {
		t.Fatalf("after first report: ingress=%d egress=%d, want 100/200", ingress, egress)
	}

	if err := store.RecordUsage(ctx, providerID, []*controlplanev1.WorkloadBandwidthUsage{{
		WorkloadId: workloadID, IngressBytesTotal: 150, EgressBytesTotal: 250, WindowStartedAt: windowStartedAt,
	}}); err != nil {
		t.Fatalf("second RecordUsage: %v", err)
	}
	ingress, egress, _ = readUsage(t, ctx, pool, providerID, workloadID)
	if ingress != 150 || egress != 250 {
		t.Fatalf("after second (larger) report: ingress=%d egress=%d, want 150/250", ingress, egress)
	}
}

// TestRecordUsageDiscardsADecreasedCounterWithinTheSameWindow is ADR-025
// §2's core defensive property: "a counter decrease as a signal to
// discard that workload's data point rather than trust it." A report
// whose window_started_at is unchanged (no restart happened) but whose
// counters are lower than what's already stored must leave the stored
// row untouched.
func TestRecordUsageDiscardsADecreasedCounterWithinTheSameWindow(t *testing.T) {
	ctx, pool := newTestPool(t)
	store := providerjoin.NewPostgresBandwidthUsageStore(pool)
	providerID := uuid.NewString()
	seedProvider(t, ctx, pool, providerID)
	workloadID := uuid.NewString()
	seedWorkload(t, ctx, pool, workloadID)
	windowStartedAt := timestamppb.New(time.Unix(1_700_000_000, 0).UTC())

	if err := store.RecordUsage(ctx, providerID, []*controlplanev1.WorkloadBandwidthUsage{{
		WorkloadId: workloadID, IngressBytesTotal: 1000, EgressBytesTotal: 2000, WindowStartedAt: windowStartedAt,
	}}); err != nil {
		t.Fatalf("first RecordUsage: %v", err)
	}

	// A decreased ingress counter, same window: this must be discarded
	// even though egress increased -- ADR-025 §2 treats the whole data
	// point as suspect, not just the direction that decreased.
	if err := store.RecordUsage(ctx, providerID, []*controlplanev1.WorkloadBandwidthUsage{{
		WorkloadId: workloadID, IngressBytesTotal: 500, EgressBytesTotal: 2500, WindowStartedAt: windowStartedAt,
	}}); err != nil {
		t.Fatalf("decreased RecordUsage should not error, only discard: %v", err)
	}

	ingress, egress, _ := readUsage(t, ctx, pool, providerID, workloadID)
	if ingress != 1000 || egress != 2000 {
		t.Fatalf("after a decreased report: ingress=%d egress=%d, want the untouched 1000/2000", ingress, egress)
	}
}

// TestRecordUsageTreatsAChangedWindowAsANewSeriesEvenIfLower is the other
// half: a window_started_at change (container restart) means the
// counters reset, so a lower value is expected and must be accepted, not
// discarded as a suspicious decrease.
func TestRecordUsageTreatsAChangedWindowAsANewSeriesEvenIfLower(t *testing.T) {
	ctx, pool := newTestPool(t)
	store := providerjoin.NewPostgresBandwidthUsageStore(pool)
	providerID := uuid.NewString()
	seedProvider(t, ctx, pool, providerID)
	workloadID := uuid.NewString()
	seedWorkload(t, ctx, pool, workloadID)
	firstWindow := timestamppb.New(time.Unix(1_700_000_000, 0).UTC())
	restartedWindow := timestamppb.New(time.Unix(1_700_001_000, 0).UTC())

	if err := store.RecordUsage(ctx, providerID, []*controlplanev1.WorkloadBandwidthUsage{{
		WorkloadId: workloadID, IngressBytesTotal: 9000, EgressBytesTotal: 9000, WindowStartedAt: firstWindow,
	}}); err != nil {
		t.Fatalf("first RecordUsage: %v", err)
	}

	if err := store.RecordUsage(ctx, providerID, []*controlplanev1.WorkloadBandwidthUsage{{
		WorkloadId: workloadID, IngressBytesTotal: 10, EgressBytesTotal: 20, WindowStartedAt: restartedWindow,
	}}); err != nil {
		t.Fatalf("post-restart RecordUsage: %v", err)
	}

	ingress, egress, windowStartedAt := readUsage(t, ctx, pool, providerID, workloadID)
	if ingress != 10 || egress != 20 {
		t.Fatalf("after a window restart: ingress=%d egress=%d, want the new series' 10/20", ingress, egress)
	}
	if !windowStartedAt.Equal(restartedWindow.AsTime()) {
		t.Fatalf("window_started_at = %v, want %v", windowStartedAt, restartedWindow.AsTime())
	}
}

// TestRecordUsageIsolatesOneBadEntryFromTheRestOfTheSameHeartbeat mirrors
// the producer side's identical per-workload tolerance
// (collect_workload_bandwidth in agent-executor): within one
// RecordUsage call (i.e. one heartbeat), one workload's problem must not
// prevent the others from being recorded. The failure engineered here is
// a real boundary, not a contrived one: ingress_bytes_total is uint64 on
// the wire but the column is bigint (int8, max 2^63-1) -- a value above
// that range is rejected by Postgres, and that must stay a per-entry
// failure, not one that silently drops the rest of the heartbeat's
// otherwise-valid entries.
func TestRecordUsageIsolatesOneBadEntryFromTheRestOfTheSameHeartbeat(t *testing.T) {
	ctx, pool := newTestPool(t)
	store := providerjoin.NewPostgresBandwidthUsageStore(pool)
	providerID := uuid.NewString()
	seedProvider(t, ctx, pool, providerID)
	goodWorkloadID := uuid.NewString()
	seedWorkload(t, ctx, pool, goodWorkloadID)
	overflowingWorkloadID := uuid.NewString()
	// Seeded too, deliberately: this test's isolation property is about
	// the range overflow specifically, not incidentally about the JOIN's
	// separate existence filter (see TestRecordUsageSkipsAnEntryForAn-
	// UnknownWorkload for that one) -- both entries are otherwise
	// well-formed rows.
	seedWorkload(t, ctx, pool, overflowingWorkloadID)
	windowStartedAt := timestamppb.New(time.Unix(1_700_000_000, 0).UTC())

	err := store.RecordUsage(ctx, providerID, []*controlplanev1.WorkloadBandwidthUsage{
		{WorkloadId: overflowingWorkloadID, IngressBytesTotal: math.MaxUint64, EgressBytesTotal: 1, WindowStartedAt: windowStartedAt},
		{WorkloadId: goodWorkloadID, IngressBytesTotal: 42, EgressBytesTotal: 43, WindowStartedAt: windowStartedAt},
	})
	if err == nil {
		t.Fatal("expected an error from the out-of-range entry")
	}

	ingress, egress, _ := readUsage(t, ctx, pool, providerID, goodWorkloadID)
	if ingress != 42 || egress != 43 {
		t.Fatalf("the well-formed entry in the same heartbeat: ingress=%d egress=%d, want 42/43", ingress, egress)
	}

	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM workload_bandwidth_usage WHERE workload_id = $1`, overflowingWorkloadID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("the out-of-range entry must not have been persisted, found %d rows", count)
	}
}

// TestRecordUsageSkipsAnEntryForAnUnknownWorkload is the other class of
// per-entry problem RecordUsage must isolate, distinct from the overflow
// case above: workload_bandwidth rides inside the already-authenticated
// heartbeat, so a validly-signed but buggy/compromised Agent could
// otherwise report usage for a syntactically-valid but nonexistent
// workload forever. RecordUsage's INNER JOIN against workloads excludes
// it from the row set entirely (see RecordUsage's own doc comment for why
// a JOIN, not letting the workload_id foreign key reject it, is what
// keeps this from also taking down the rest of the same heartbeat's
// otherwise-valid entries).
func TestRecordUsageSkipsAnEntryForAnUnknownWorkload(t *testing.T) {
	ctx, pool := newTestPool(t)
	store := providerjoin.NewPostgresBandwidthUsageStore(pool)
	providerID := uuid.NewString()
	seedProvider(t, ctx, pool, providerID)
	knownWorkloadID := uuid.NewString()
	seedWorkload(t, ctx, pool, knownWorkloadID)
	unknownWorkloadID := uuid.NewString() // deliberately never seeded into workloads
	windowStartedAt := timestamppb.New(time.Unix(1_700_000_000, 0).UTC())

	if err := store.RecordUsage(ctx, providerID, []*controlplanev1.WorkloadBandwidthUsage{
		{WorkloadId: unknownWorkloadID, IngressBytesTotal: 1, EgressBytesTotal: 1, WindowStartedAt: windowStartedAt},
		{WorkloadId: knownWorkloadID, IngressBytesTotal: 42, EgressBytesTotal: 43, WindowStartedAt: windowStartedAt},
	}); err != nil {
		// Unlike the overflow case, an unknown workload_id is not
		// reported as an error at all -- it is exactly as unremarkable
		// to RecordUsage as a workload that simply isn't running on this
		// provider yet, which is not an error condition.
		t.Fatalf("an unknown workload_id must not itself cause an error: %v", err)
	}

	ingress, egress, _ := readUsage(t, ctx, pool, providerID, knownWorkloadID)
	if ingress != 42 || egress != 43 {
		t.Fatalf("the well-formed entry in the same heartbeat: ingress=%d egress=%d, want 42/43", ingress, egress)
	}

	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM workload_bandwidth_usage WHERE workload_id = $1`, unknownWorkloadID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("the unknown workload_id must not have been persisted, found %d rows", count)
	}
}
