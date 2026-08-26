package neutron

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/openinfra/network/internal/openstackapi/osauth"
)

// BandwidthUsage is one workload's latest self-reported cumulative
// bandwidth counters, read verbatim from workload_bandwidth_usage
// (migration 000015, ADR-025 §2) -- internal/providerjoin's
// PostgresBandwidthUsageStore.RecordUsage is the sole writer, populated
// only from a signature-verified Agent heartbeat. Not billing-grade
// telemetry (ADR-025 §2's own "What this is not"), and this package does
// not treat it as such -- see internal/metering for the separate,
// signed-evidence-based invoicing pipeline (issue #19/#21/ADR-029) this
// endpoint does not duplicate or replace.
type BandwidthUsage struct {
	WorkloadID                          string
	ProviderID                          string
	IngressBytesTotal, EgressBytesTotal int64
	WindowStartedAt, LastReportedAt     time.Time
}

// UsageRepository is the read surface usage.go needs, scoped by
// projectID via a JOIN against workloads (workload_bandwidth_usage
// itself carries no project_id column) -- the same
// ownership-check-via-the-query pattern every other project-scoped
// lookup in this package uses.
type UsageRepository interface {
	// ListBandwidthUsage returns one row per workload in projectID that
	// has ever reported bandwidth usage. A workload with no row (never
	// reported, or every heartbeat since creation has been missed) is
	// simply absent from this list -- ADR-025 §5's explicit requirement
	// that a missing report render as "no data," never as "zero usage,"
	// so this package must never synthesize a zero-valued record for a
	// workload that has not actually reported one.
	ListBandwidthUsage(ctx context.Context, projectID string) ([]BandwidthUsage, error)
	// GetBandwidthUsage returns ok=false for a workload_id that does not
	// exist, belongs to a different project, or has never reported
	// usage -- deliberately not distinguished, the same non-enumeration
	// posture BandwidthRepository.GetBandwidthReservation already
	// applies.
	GetBandwidthUsage(ctx context.Context, projectID, workloadID string) (usage BandwidthUsage, ok bool, err error)
}

type PostgresUsageRepository struct{ pool *pgxpool.Pool }

func NewPostgresUsageRepository(pool *pgxpool.Pool) *PostgresUsageRepository {
	return &PostgresUsageRepository{pool: pool}
}

func (r *PostgresUsageRepository) ListBandwidthUsage(ctx context.Context, projectID string) ([]BandwidthUsage, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT u.workload_id, u.provider_id, u.ingress_bytes_total, u.egress_bytes_total, u.window_started_at, u.last_reported_at
		FROM workload_bandwidth_usage u
		JOIN workloads w ON w.workload_id = u.workload_id
		WHERE w.project_id = $1
		ORDER BY u.workload_id`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var usages []BandwidthUsage
	for rows.Next() {
		var usage BandwidthUsage
		if err := rows.Scan(&usage.WorkloadID, &usage.ProviderID, &usage.IngressBytesTotal, &usage.EgressBytesTotal, &usage.WindowStartedAt, &usage.LastReportedAt); err != nil {
			return nil, err
		}
		usages = append(usages, usage)
	}
	return usages, rows.Err()
}

func (r *PostgresUsageRepository) GetBandwidthUsage(ctx context.Context, projectID, workloadID string) (BandwidthUsage, bool, error) {
	var usage BandwidthUsage
	err := r.pool.QueryRow(ctx, `
		SELECT u.workload_id, u.provider_id, u.ingress_bytes_total, u.egress_bytes_total, u.window_started_at, u.last_reported_at
		FROM workload_bandwidth_usage u
		JOIN workloads w ON w.workload_id = u.workload_id
		WHERE w.project_id = $1 AND u.workload_id = $2`,
		projectID, workloadID,
	).Scan(&usage.WorkloadID, &usage.ProviderID, &usage.IngressBytesTotal, &usage.EgressBytesTotal, &usage.WindowStartedAt, &usage.LastReportedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return BandwidthUsage{}, false, nil
	}
	if err != nil {
		return BandwidthUsage{}, false, err
	}
	return usage, true, nil
}

// listBandwidthUsage is GET /v2.0/metering/bandwidth_usage: an
// OpenInfra-specific extension resource under Neutron's real
// "metering" URL namespace (real Neutron's own metering extension --
// metering_labels/metering_label_rules -- has no per-port byte-counter
// read API; per-resource traffic accounting is Ceilometer/Telemetry's
// job in a real OpenStack deployment, which this system does not have).
// Named and placed here, rather than invented as literal Neutron core
// API, so a client can tell the two apart -- consistent with ADR-031
// §1's "an unsupported operation must fail exactly the way a real
// OpenStack deployment fails" discipline applied in the other direction:
// a *supported* but non-standard extension must not masquerade as core
// API either.
func (s *Server) listBandwidthUsage(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	projectID, ok := requireProjectID(w, r)
	if !ok {
		return
	}
	usages, err := s.usage.ListBandwidthUsage(ctx, projectID)
	if err != nil {
		osauth.WriteError(w, http.StatusServiceUnavailable, "Service Unavailable", "bandwidth usage listing unavailable")
		return
	}
	body := bandwidthUsageRecordsBody{BandwidthUsageRecords: make([]bandwidthUsageRecordBody, 0, len(usages))}
	for _, usage := range usages {
		body.BandwidthUsageRecords = append(body.BandwidthUsageRecords, bandwidthUsageRecordBodyFrom(usage))
	}
	writeJSON(w, http.StatusOK, body)
}

func (s *Server) showBandwidthUsage(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	projectID, ok := requireProjectID(w, r)
	if !ok {
		return
	}
	usage, found, err := s.usage.GetBandwidthUsage(ctx, projectID, r.PathValue("workload_id"))
	if err != nil {
		osauth.WriteError(w, http.StatusServiceUnavailable, "Service Unavailable", "bandwidth usage lookup unavailable")
		return
	}
	if !found {
		// ADR-025 §5: absence must render as "no data," never as "zero
		// usage" -- a 404 is exactly that; a 200 with zeroed counters
		// would not be.
		osauth.WriteError(w, http.StatusNotFound, "Not Found", "no bandwidth usage has been reported for this workload")
		return
	}
	writeJSON(w, http.StatusOK, bandwidthUsageRecordEnvelopeBody{BandwidthUsageRecord: bandwidthUsageRecordBodyFrom(usage)})
}
