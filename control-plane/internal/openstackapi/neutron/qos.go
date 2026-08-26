package neutron

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/openinfra/network/internal/openstackapi/osauth"
)

// tcBurstKbps mirrors agent-executor's rate_limit.rs TBF_BURST_BYTES
// (32*1024 bytes = 262144 bits, floor-divided to kbit) -- the exact
// token-bucket burst tc programs against a workload's veth for egress
// enforcement (ADR-025 §3). A literal constant, computed the same way,
// not read from the Rust crate this Go binary cannot import; keep the
// two in sync by hand if TBF_BURST_BYTES ever changes.
const tcBurstKbps = 32 * 1024 * 8 / 1000

// bandwidthRuleNamespace is a fixed, arbitrary namespace UUID used only
// to derive a stable, RFC-4122-shaped bandwidth_limit_rule id from
// (workload_id, direction). Nothing about a rule is stored anywhere
// (this package owns no table -- see the package doc comment), so its id
// must be deterministic across repeated GETs for the same workload
// rather than freshly minted per request.
var bandwidthRuleNamespace = uuid.MustParse("2f9d6f0e-3b3a-4c2a-9c8e-2f2f9d6f0e3b")

func bandwidthRuleID(workloadID, direction string) string {
	return uuid.NewSHA1(bandwidthRuleNamespace, []byte(workloadID+":"+direction)).String()
}

// openWorkloadStates mirrors internal/projects.CommittedUsage's own list
// (and internal/workloadapi.AssignLease's identical inline SQL literal)
// -- a workload outside this set no longer holds a real, committed
// reservation against its provider's capacity, the same "committed
// usage" notion every other consumer of this ledger already uses. A
// candidate that never reached AssignLease (still SCHEDULING) or that
// AssignLease rejected (stays SCHEDULING, per its own doc comment: "a
// rejected AssignLease must not mutate the row") never appears here --
// this is the mechanism behind this package's oversubscription-safety
// property; see oversubscription_test.go.
var openWorkloadStates = []string{"LEASE_PENDING", "LEASED", "DEPLOYING", "RUNNING"}

// BandwidthReservation is one workload's committed bandwidth claim,
// exactly as internal/workloadapi.AssignLease's real capacity check last
// verified it -- fields sourced directly from
// workloads.reserved_ingress_mbps/reserved_egress_mbps (migration
// 000010), never recomputed, rounded, or re-derived independently.
type BandwidthReservation struct {
	WorkloadID                              string
	ProjectID                               string
	ProviderID                              string
	ReservedIngressMbps, ReservedEgressMbps int64
}

// BandwidthRepository is the read surface qos.go needs. Both methods
// scope by projectID as part of the query itself (never a
// fetch-then-compare in Go) -- the same ownership-check-via-the-query
// pattern ADR-016 established and ADR-031 §3 reuses for its own
// project-scoped queries.
type BandwidthRepository interface {
	// ListBandwidthReservations returns every open workload in
	// projectID that holds a nonzero bandwidth reservation -- a
	// workload with 0/0 has nothing for a QoS policy to describe,
	// matching scheduler.fitBps's own "a zero requirement is always
	// satisfied" convention (there is no meaningful policy to report).
	ListBandwidthReservations(ctx context.Context, projectID string) ([]BandwidthReservation, error)
	// GetBandwidthReservation returns ok=false for a workload_id that
	// does not exist, belongs to a different project, is not in an
	// open state, or holds no nonzero bandwidth reservation --
	// deliberately not distinguished, the same non-enumeration posture
	// internal/projects.ErrNotAMember's doc comment already establishes
	// for this codebase's other project-scoped lookups.
	GetBandwidthReservation(ctx context.Context, projectID, workloadID string) (reservation BandwidthReservation, ok bool, err error)
}

type PostgresBandwidthRepository struct{ pool *pgxpool.Pool }

func NewPostgresBandwidthRepository(pool *pgxpool.Pool) *PostgresBandwidthRepository {
	return &PostgresBandwidthRepository{pool: pool}
}

func (r *PostgresBandwidthRepository) ListBandwidthReservations(ctx context.Context, projectID string) ([]BandwidthReservation, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT workload_id, project_id, COALESCE(provider_id, ''), reserved_ingress_mbps, reserved_egress_mbps
		FROM workloads
		WHERE project_id = $1 AND state = ANY($2) AND (reserved_ingress_mbps > 0 OR reserved_egress_mbps > 0)
		ORDER BY workload_id`, projectID, openWorkloadStates)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var reservations []BandwidthReservation
	for rows.Next() {
		var reservation BandwidthReservation
		if err := rows.Scan(&reservation.WorkloadID, &reservation.ProjectID, &reservation.ProviderID, &reservation.ReservedIngressMbps, &reservation.ReservedEgressMbps); err != nil {
			return nil, err
		}
		reservations = append(reservations, reservation)
	}
	return reservations, rows.Err()
}

func (r *PostgresBandwidthRepository) GetBandwidthReservation(ctx context.Context, projectID, workloadID string) (BandwidthReservation, bool, error) {
	var reservation BandwidthReservation
	err := r.pool.QueryRow(ctx, `
		SELECT workload_id, project_id, COALESCE(provider_id, ''), reserved_ingress_mbps, reserved_egress_mbps
		FROM workloads
		WHERE project_id = $1 AND workload_id = $2 AND state = ANY($3) AND (reserved_ingress_mbps > 0 OR reserved_egress_mbps > 0)`,
		projectID, workloadID, openWorkloadStates,
	).Scan(&reservation.WorkloadID, &reservation.ProjectID, &reservation.ProviderID, &reservation.ReservedIngressMbps, &reservation.ReservedEgressMbps)
	if errors.Is(err, pgx.ErrNoRows) {
		return BandwidthReservation{}, false, nil
	}
	if err != nil {
		return BandwidthReservation{}, false, err
	}
	return reservation, true, nil
}

func (s *Server) listPolicies(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	projectID, ok := requireProjectID(w, r)
	if !ok {
		return
	}
	reservations, err := s.bandwidth.ListBandwidthReservations(ctx, projectID)
	if err != nil {
		osauth.WriteError(w, http.StatusServiceUnavailable, "Service Unavailable", "qos policy listing unavailable")
		return
	}
	body := qosPoliciesBody{Policies: make([]qosPolicyBody, 0, len(reservations))}
	for _, reservation := range reservations {
		body.Policies = append(body.Policies, qosPolicyBodyFrom(reservation))
	}
	writeJSON(w, http.StatusOK, body)
}

func (s *Server) showPolicy(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	projectID, ok := requireProjectID(w, r)
	if !ok {
		return
	}
	reservation, found, err := s.bandwidth.GetBandwidthReservation(ctx, projectID, r.PathValue("policy_id"))
	if err != nil {
		osauth.WriteError(w, http.StatusServiceUnavailable, "Service Unavailable", "qos policy lookup unavailable")
		return
	}
	if !found {
		osauth.WriteError(w, http.StatusNotFound, "Not Found", "qos policy not found")
		return
	}
	writeJSON(w, http.StatusOK, qosPolicyEnvelopeBody{Policy: qosPolicyBodyFrom(reservation)})
}

func (s *Server) listBandwidthLimitRules(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	projectID, ok := requireProjectID(w, r)
	if !ok {
		return
	}
	reservation, found, err := s.bandwidth.GetBandwidthReservation(ctx, projectID, r.PathValue("policy_id"))
	if err != nil {
		osauth.WriteError(w, http.StatusServiceUnavailable, "Service Unavailable", "qos policy lookup unavailable")
		return
	}
	if !found {
		osauth.WriteError(w, http.StatusNotFound, "Not Found", "qos policy not found")
		return
	}
	writeJSON(w, http.StatusOK, bandwidthLimitRulesBody{BandwidthLimitRules: bandwidthLimitRuleBodiesFrom(reservation)})
}

func (s *Server) showBandwidthLimitRule(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	projectID, ok := requireProjectID(w, r)
	if !ok {
		return
	}
	reservation, found, err := s.bandwidth.GetBandwidthReservation(ctx, projectID, r.PathValue("policy_id"))
	if err != nil {
		osauth.WriteError(w, http.StatusServiceUnavailable, "Service Unavailable", "qos policy lookup unavailable")
		return
	}
	if !found {
		osauth.WriteError(w, http.StatusNotFound, "Not Found", "qos policy not found")
		return
	}
	ruleID := r.PathValue("rule_id")
	for _, rule := range bandwidthLimitRuleBodiesFrom(reservation) {
		if rule.ID == ruleID {
			writeJSON(w, http.StatusOK, bandwidthLimitRuleEnvelopeBody{BandwidthLimitRule: rule})
			return
		}
	}
	osauth.WriteError(w, http.StatusNotFound, "Not Found", "bandwidth_limit_rule not found")
}
