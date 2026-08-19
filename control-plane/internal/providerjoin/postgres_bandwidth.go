package providerjoin

import (
	"context"
	"errors"

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

// RecordUsage upserts each entry independently: one bad or stale entry
// must not block the others in the same heartbeat, mirroring the
// producer side's identical per-workload tolerance
// (collect_workload_bandwidth in agent-executor). Errors from individual
// entries are joined and returned together; the caller
// (Service.recordBandwidthUsage) only logs the result, so a partial
// failure here does not fail the heartbeat.
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
	var errs []error
	for _, entry := range entries {
		if _, err := s.pool.Exec(ctx, `
			INSERT INTO workload_bandwidth_usage (
				provider_id, workload_id, ingress_bytes_total, egress_bytes_total,
				window_started_at, last_reported_at
			) VALUES ($1, $2, $3, $4, $5, now())
			ON CONFLICT (provider_id, workload_id) DO UPDATE SET
				ingress_bytes_total = EXCLUDED.ingress_bytes_total,
				egress_bytes_total = EXCLUDED.egress_bytes_total,
				window_started_at = EXCLUDED.window_started_at,
				last_reported_at = EXCLUDED.last_reported_at
			WHERE EXCLUDED.window_started_at <> workload_bandwidth_usage.window_started_at
			   OR (EXCLUDED.ingress_bytes_total >= workload_bandwidth_usage.ingress_bytes_total
			       AND EXCLUDED.egress_bytes_total >= workload_bandwidth_usage.egress_bytes_total)`,
			providerID, entry.WorkloadId, entry.IngressBytesTotal, entry.EgressBytesTotal,
			entry.WindowStartedAt.AsTime(),
		); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
