package providerjoin

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	controlplanev1 "github.com/openinfra/network/protocol/generated/go/controlplane/v1"
)

// PostgresBandwidthUsageStore implements BandwidthUsageStore against the
// workload_bandwidth_usage table (migration 000015). One row per
// (provider_id, workload_id): the latest known cumulative counters and
// when they were last seen -- no history, no persisted deltas (ADR-025
// §2's "What this is not": not billing-grade telemetry).
type PostgresBandwidthUsageStore struct {
	pool *pgxpool.Pool
}

func NewPostgresBandwidthUsageStore(pool *pgxpool.Pool) *PostgresBandwidthUsageStore {
	return &PostgresBandwidthUsageStore{pool: pool}
}

// RecordUsage writes all of this heartbeat's entries in a single
// statement/round trip, not N sequential Execs: this is best-effort
// telemetry riding inside ReportHeartbeat's own response path (the
// caller, Service.recordBandwidthUsage, only logs the result), so N
// round trips per heartbeat was pure added latency on the
// liveness-critical heartbeat RPC for no durability benefit.
//
// A naive multi-row batch is not safe here, and was tried and measured
// against a real database before landing on this instead: pgx sends a
// pgx.Batch's queued statements before a single protocol Sync, which
// PostgreSQL treats as one implicit transaction regardless of an
// explicit BEGIN -- one bad entry (e.g. a workload_id that fails the FK
// below) aborts and rolls back every other entry already queued in the
// same batch, not just the bad one. A single multi-row INSERT has the
// identical problem: one row failing a constraint aborts the whole
// statement. Confirmed by writing both variants against a real
// Postgres with one deliberately-bad row mixed among good ones: the
// pgx.Batch variant returned zero surviving rows.
//
// What actually preserves the pre-existing "one bad or stale entry must
// not block the others" property (mirroring the producer side's
// identical per-workload tolerance in collect_workload_bandwidth,
// agent-executor) while still being one round trip: unnest() turns the
// parallel Go slices into a row set, INNER JOIN against workloads
// silently *excludes* any workload_id that doesn't exist there (a JOIN
// omitting a row is not a constraint violation, so it cannot abort
// anything), and only the surviving rows are ever handed to INSERT.
// workload_id's foreign key below is then defense in depth, not the
// mechanism doing the filtering -- by construction, nothing that
// reaches the INSERT can violate it during normal operation.
//
// The same "one bad entry must not block the others" property also has
// to hold for a value-range problem a JOIN cannot filter: *BytesTotal is
// uint64 on the wire but the column is bigint (signed int64) like every
// other byte/count column in this schema, and a single multi-row INSERT
// aborts entirely if any one row fails a CHECK constraint, the same way
// it would for a foreign key. That case is filtered in Go before the
// query runs, for the identical reason the JOIN filters workload_id --
// keeping it out of the row set entirely, rather than letting Postgres
// reject it, is what makes it not abort the batch.
//
// The counter-decrease guard (ADR-025 §2: "the Control Plane computes
// deltas across successive reports itself and treats a counter decrease
// as a signal to discard that workload's data point rather than trust
// it") is enforced inside the UPSERT's own WHERE clause rather than by a
// separate read-then-write in Go: this makes the decision atomic against
// concurrent heartbeats for the same workload (there is exactly one
// Agent per provider, but nothing stops two ReportHeartbeat calls from
// racing in flight) and avoids a TOCTOU window a read-then-compare in
// application code would have. A row is only overwritten when either the
// window restarted (window_started_at changed -- the counters were reset
// by a container restart, so this is a new series, not a decrease to
// distrust) or both directions are greater than or equal to what is
// already stored.
func (s *PostgresBandwidthUsageStore) RecordUsage(ctx context.Context, providerID string, entries []*controlplanev1.WorkloadBandwidthUsage) error {
	if len(entries) == 0 {
		return nil
	}
	workloadIDs := make([]string, 0, len(entries))
	ingress := make([]int64, 0, len(entries))
	egress := make([]int64, 0, len(entries))
	windowStarted := make([]time.Time, 0, len(entries))
	var skipped []error
	for _, entry := range entries {
		// entry.*BytesTotal are proto uint64; the column is bigint
		// (signed int64, matching every other byte/count column in this
		// schema). A value that does not fit is excluded from this
		// heartbeat's row set -- not sent at all -- rather than truncated
		// or handed to Postgres to reject, so it cannot abort the
		// multi-row INSERT below and take the rest of the heartbeat's
		// otherwise-valid entries down with it.
		if entry.IngressBytesTotal > math.MaxInt64 || entry.EgressBytesTotal > math.MaxInt64 {
			skipped = append(skipped, fmt.Errorf("workload_bandwidth[workload_id=%s]: ingress/egress_bytes_total exceeds bigint range", entry.WorkloadId))
			continue
		}
		workloadIDs = append(workloadIDs, entry.WorkloadId)
		ingress = append(ingress, int64(entry.IngressBytesTotal))
		egress = append(egress, int64(entry.EgressBytesTotal))
		windowStarted = append(windowStarted, entry.WindowStartedAt.AsTime())
	}
	if len(workloadIDs) == 0 {
		return errors.Join(skipped...)
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO workload_bandwidth_usage (
			provider_id, workload_id, ingress_bytes_total, egress_bytes_total,
			window_started_at, last_reported_at
		)
		SELECT $1, e.workload_id, e.ingress_bytes_total, e.egress_bytes_total, e.window_started_at, now()
		FROM unnest($2::uuid[], $3::bigint[], $4::bigint[], $5::timestamptz[])
			AS e(workload_id, ingress_bytes_total, egress_bytes_total, window_started_at)
		JOIN workloads w ON w.workload_id = e.workload_id
		ON CONFLICT (provider_id, workload_id) DO UPDATE SET
			ingress_bytes_total = EXCLUDED.ingress_bytes_total,
			egress_bytes_total = EXCLUDED.egress_bytes_total,
			window_started_at = EXCLUDED.window_started_at,
			last_reported_at = EXCLUDED.last_reported_at
		WHERE EXCLUDED.window_started_at <> workload_bandwidth_usage.window_started_at
		   OR (EXCLUDED.ingress_bytes_total >= workload_bandwidth_usage.ingress_bytes_total
		       AND EXCLUDED.egress_bytes_total >= workload_bandwidth_usage.egress_bytes_total)`,
		providerID, workloadIDs, ingress, egress, windowStarted,
	)
	if err != nil {
		skipped = append(skipped, err)
	}
	return errors.Join(skipped...)
}
