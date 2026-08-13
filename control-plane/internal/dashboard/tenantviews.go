package dashboard

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/openinfra/network/internal/workloadapi"
	sharedv1 "github.com/openinfra/network/protocol/generated/go/shared/v1"
	"google.golang.org/protobuf/proto"
)

// tenantWorkloadsLimit bounds GET /api/v1/my/workloads' page size, the
// same bounded-cardinality discipline parseOverviewPagination already
// applies to the public overview (#76's "pagination and bounded
// cardinality" item).
const (
	defaultTenantWorkloadsLimit = 50
	maxTenantWorkloadsLimit     = 200
)

// TenantWorkloadRequirements is a workload's decoded resource ask.
//
// ADR-016 §6 asserted that `workload.definition` "includes env vars per
// WorkloadDefinition in shared.proto" and §7 question 1 asked how to
// redact them. That premise is wrong: `WorkloadDefinition`
// (protocol/proto/openinfra/shared/v1/shared.proto) carries only
// workload_id, profile, requirements, constraints, and duration_seconds
// -- there is no env map anywhere in it, nor in `DeployRequest`, and
// there never has been (checked back to the repo's initial commit). So
// there is no tenant secret in this column to withhold.
//
// The conservative half of that decision is still honored: the raw
// `definition` bytes are never returned. Only these named, decoded,
// non-secret fields are, so a field added to `WorkloadDefinition` later
// cannot start leaking through this endpoint by accident -- it would
// have to be added here deliberately.
type TenantWorkloadRequirements struct {
	CPUCores        float32 `json:"cpu_cores"`
	RAMMB           int64   `json:"ram_mb"`
	StorageGB       int64   `json:"storage_gb"`
	IngressMbps     int32   `json:"ingress_mbps,omitempty"`
	EgressMbps      int32   `json:"egress_mbps,omitempty"`
	DurationSeconds int32   `json:"duration_seconds"`
	Profile         string  `json:"profile"`
}

// TenantWorkload is one workload as its owner sees it.
type TenantWorkload struct {
	WorkloadID   string     `json:"workload_id"`
	State        string     `json:"state"`
	Image        string     `json:"image"`
	ProviderID   string     `json:"provider_id,omitempty"`
	LeaseID      string     `json:"lease_id,omitempty"`
	ContainerID  string     `json:"container_id,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	AttemptCount int        `json:"attempt_count"`
	NextRetryAt  *time.Time `json:"next_retry_at,omitempty"`
	// ErrorCode/LastError are ADR-016 §7 question 2's resolution: shown
	// here, on the Tenant tier, because this endpoint is
	// ownership-scoped by its own query -- a tenant needs to know why
	// their own workload failed. They are deliberately absent from the
	// operator-tier cross-tenant queue view (internal/dashboard/
	// operatorviews.go), where an application error message embedding a
	// credential would cross a tenant boundary.
	ErrorCode string `json:"error_code,omitempty"`
	LastError string `json:"last_error,omitempty"`
	// Requirements is nil when the stored definition could not be
	// decoded -- reported as an explicit null rather than a zeroed
	// struct, so a decode failure never renders as "this workload asked
	// for 0 CPU" (#76/#29's no-false-success discipline).
	Requirements *TenantWorkloadRequirements `json:"requirements"`
}

// TenantWorkloads is GET /api/v1/my/workloads' response body.
type TenantWorkloads struct {
	GeneratedAt string           `json:"generated_at"`
	Total       int              `json:"total"`
	Limit       int              `json:"limit"`
	Offset      int              `json:"offset"`
	Workloads   []TenantWorkload `json:"workloads"`
}

// tenantWorkloadColumns is the exact column set both tenant endpoints
// select. `definition` is included (it is decoded into Requirements
// below, never returned raw); no other column is added here without
// deciding what it means for a tenant to see it.
const tenantWorkloadColumns = `workload_id::text, state, image, COALESCE(provider_id,''),
	COALESCE(lease_id::text,''), COALESCE(container_id,''), created_at, updated_at,
	attempt_count, next_attempt_at, COALESCE(error_code,''), COALESCE(last_error,''), definition`

// myWorkloads lists the authenticated tenant's own workloads. Every
// query in this file filters by owner_id in SQL rather than fetching and
// comparing in Go -- the same discipline internal/workloadapi already
// applies (see its RequestStop doc comment on why a fetch-then-compare
// still touches rows the caller has no right to).
func (s *Server) myWorkloads(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	user, ok := s.authenticatedUser(ctx, r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}

	query := r.URL.Query()
	limit := boundedQueryInt(query, "limit", defaultTenantWorkloadsLimit, 1, maxTenantWorkloadsLimit)
	offset := boundedQueryInt(query, "offset", 0, 0, 1_000_000)

	result := TenantWorkloads{
		GeneratedAt: s.now().UTC().Format(time.RFC3339),
		Limit:       limit,
		Offset:      offset,
		Workloads:   []TenantWorkload{},
	}

	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM workloads WHERE owner_id=$1`, user.UserID).Scan(&result.Total); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "workload lookup unavailable"})
		return
	}

	rows, err := s.pool.Query(ctx, `SELECT `+tenantWorkloadColumns+`
		FROM workloads WHERE owner_id=$1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3`, user.UserID, limit, offset)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "workload lookup unavailable"})
		return
	}
	defer rows.Close()
	for rows.Next() {
		workload, err := scanTenantWorkload(rows)
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "workload lookup unavailable"})
			return
		}
		result.Workloads = append(result.Workloads, workload)
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "workload lookup unavailable"})
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// myWorkload returns one of the caller's own workloads. A workload that
// exists but belongs to someone else returns 404, not 403 -- ADR-016 §2
// requires this: a 403 would confirm the workload_id exists, turning
// this endpoint into an existence oracle for other tenants' IDs.
func (s *Server) myWorkload(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	user, ok := s.authenticatedUser(ctx, r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}
	workloadID := r.PathValue("workload_id")
	if _, err := uuid.Parse(workloadID); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "workload_id must be a UUID"})
		return
	}

	row := s.pool.QueryRow(ctx, `SELECT `+tenantWorkloadColumns+`
		FROM workloads WHERE workload_id=$1 AND owner_id=$2`, workloadID, user.UserID)
	workload, err := scanTenantWorkload(row)
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "workload not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "workload lookup unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, workload)
}

// rowScanner is satisfied by both pgx.Row and pgx.Rows, so the list and
// detail endpoints share one scan/decode path rather than drifting.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanTenantWorkload(row rowScanner) (TenantWorkload, error) {
	var workload TenantWorkload
	var definition []byte
	err := row.Scan(
		&workload.WorkloadID, &workload.State, &workload.Image, &workload.ProviderID,
		&workload.LeaseID, &workload.ContainerID, &workload.CreatedAt, &workload.UpdatedAt,
		&workload.AttemptCount, &workload.NextRetryAt, &workload.ErrorCode, &workload.LastError,
		&definition,
	)
	if err != nil {
		return TenantWorkload{}, err
	}
	workload.Requirements = decodeRequirements(definition)
	return workload, nil
}

// decodeRequirements unmarshals the stored WorkloadDefinition and lifts
// only its non-secret, display-relevant fields. Returns nil on a decode
// failure so the caller can render "unavailable" rather than a
// zero-valued ask that looks like a real one.
func decodeRequirements(definition []byte) *TenantWorkloadRequirements {
	if len(definition) == 0 {
		return nil
	}
	var decoded sharedv1.WorkloadDefinition
	if err := proto.Unmarshal(definition, &decoded); err != nil {
		return nil
	}
	requirements := TenantWorkloadRequirements{
		DurationSeconds: decoded.DurationSeconds,
		Profile:         strings.TrimPrefix(decoded.Profile.String(), "WORKLOAD_PROFILE_"),
	}
	if decoded.Requirements != nil {
		requirements.CPUCores = decoded.Requirements.Cpu
		requirements.RAMMB = decoded.Requirements.RamMb
		requirements.StorageGB = decoded.Requirements.StorageGb
		if bandwidth := decoded.Requirements.Bandwidth; bandwidth != nil {
			requirements.IngressMbps = bandwidth.IngressMbps
			requirements.EgressMbps = bandwidth.EgressMbps
		}
	}
	return &requirements
}

// stopMyWorkload is ADR-016 §2's tenant-tier stop action: a thin HTTP
// wrapper over the exact RequestStop path internal/workloadapi already
// exposes over gRPC. No new business logic lives here -- in particular
// the ownership check is RequestStop's own `WHERE workload_id=$1 AND
// owner_id=$2 FOR UPDATE`, not a second check in this package that could
// drift from it.
//
// This is the first authenticated *write* on the dashboard's HTTP
// surface, which is what makes ADR-016 slice 5's audit log meaningful
// rather than an empty table; both success and refusal are recorded.
func (s *Server) stopMyWorkload(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	user, ok := s.authenticatedUser(ctx, r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}
	workloadID := r.PathValue("workload_id")
	if _, err := uuid.Parse(workloadID); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "workload_id must be a UUID"})
		return
	}

	// The stop request's idempotency key is generated server-side rather
	// than taken from the caller: a browser has no way to keep a stable
	// one across a page reload, and RequestStop already treats a second
	// stop on an already-stopping workload as a conflict, so retry
	// safety comes from that check rather than from the caller's key.
	repository := workloadapi.NewPostgresRepository(s.pool)
	stored, err := repository.RequestStop(ctx, workloadID, uuid.NewString(), user.UserID, s.now().UTC())
	switch {
	case errors.Is(err, workloadapi.ErrNotFound), errors.Is(err, pgx.ErrNoRows):
		// 404 for someone else's workload too, same existence-oracle
		// reasoning as myWorkload above.
		s.recordAudit(ctx, user, auditActionWorkloadStop, auditTargetWorkload, workloadID, auditOutcomeDenied)
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "workload not found"})
		return
	case errors.Is(err, workloadapi.ErrConflict):
		s.recordAudit(ctx, user, auditActionWorkloadStop, auditTargetWorkload, workloadID, auditOutcomeDenied)
		writeJSON(w, http.StatusConflict, map[string]string{"error": "workload already has a stop request"})
		return
	case err != nil:
		s.recordAudit(ctx, user, auditActionWorkloadStop, auditTargetWorkload, workloadID, auditOutcomeError)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "stop request unavailable"})
		return
	}

	s.recordAudit(ctx, user, auditActionWorkloadStop, auditTargetWorkload, workloadID, auditOutcomeSuccess)
	writeJSON(w, http.StatusAccepted, map[string]string{
		"workload_id": stored.WorkloadID,
		"state":       stored.State,
	})
}
