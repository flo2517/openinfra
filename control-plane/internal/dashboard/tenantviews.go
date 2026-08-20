package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/openinfra/network/internal/userauth"
	"github.com/openinfra/network/internal/workloadapi"
	controlplanev1 "github.com/openinfra/network/protocol/generated/go/controlplane/v1"
	sharedv1 "github.com/openinfra/network/protocol/generated/go/shared/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

	// The identity requireRole already resolved for this request (see
	// userFromContext's doc comment) -- not a second call to
	// s.authenticatedUser, which would re-run Authenticate's Postgres
	// write (last_used_at) a second time for no reason.
	user, ok := userFromContext(ctx)
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

	// The identity requireRole already resolved for this request (see
	// userFromContext's doc comment) -- not a second call to
	// s.authenticatedUser, which would re-run Authenticate's Postgres
	// write (last_used_at) a second time for no reason.
	user, ok := userFromContext(ctx)
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

	// The identity requireRole already resolved for this request (see
	// userFromContext's doc comment) -- not a second call to
	// s.authenticatedUser, which would re-run Authenticate's Postgres
	// write (last_used_at) a second time for no reason.
	user, ok := userFromContext(ctx)
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

// maxWorkloadSubmitBodyBytes bounds POST /api/v1/my/workloads' JSON body.
// An OCI image reference pinned by a sha256 digest plus four small
// numbers never legitimately needs more than this -- the same
// generous-but-bounded ceiling maxAuthBodyBytes (auth.go) applies to the
// unauthenticated auth endpoints.
const maxWorkloadSubmitBodyBytes = 4096

// submitWorkloadRequestBody is POST /api/v1/my/workloads' request body:
// the same five values `workloadctl submit` takes positionally on the
// command line (cmd/workloadctl/main.go's usage string), as JSON instead.
// There is deliberately no profile field yet -- see submitMyWorkload's
// doc comment on the placeholder it uses instead.
type submitWorkloadRequestBody struct {
	Image           string  `json:"image"`
	CPUCores        float32 `json:"cpu_cores"`
	RAMMB           int64   `json:"ram_mb"`
	StorageGB       int64   `json:"storage_gb"`
	DurationSeconds int32   `json:"duration_seconds"`
}

// submitMyWorkload is ADR-016 §2's tenant-tier submit action, the mirror
// image of stopMyWorkload above: a thin HTTP wrapper over the exact
// SubmitWorkload path internal/workloadapi already exposes over gRPC
// (ControlPlaneService/SubmitWorkload) -- reached here through
// s.workloads, the very *workloadapi.Service instance
// cmd/controlplane/main.go also wires into the gRPC server. No
// validation, request-hashing, or persistence logic is duplicated in
// this package: validateSubmission's checks, the idempotency/ownership
// handling in CreateOrGet, and the capacity/state machine all run
// unmodified, exactly as they would for a `workloadctl submit` call or
// any other direct gRPC caller.
//
// workload_id and request_id are minted server-side rather than taken
// from the caller, for the same reason stopMyWorkload's stop-request
// idempotency key is: a browser has no way to keep a stable value across
// a page reload, and (unlike a stop, which must not be repeated) a
// duplicate POST here should simply mint a second, independent workload
// rather than needing an idempotency key from the caller at all.
//
// The authenticated user_id is attached to ctx with userauth.WithUserID
// -- the exact context key/value shape the gRPC unary interceptor
// (internal/userauth/interceptor.go) sets for an authenticated
// mTLS+API-key caller -- so workloadapi.Service.SubmitWorkload's own
// requireOwner check runs completely unmodified; this handler never
// passes ownership as an explicit parameter that could drift from it.
func (s *Server) submitMyWorkload(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	// The identity requireRole already resolved for this request (see
	// userFromContext's doc comment) -- not a second call to
	// s.authenticatedUser, which would re-run Authenticate's Postgres
	// write (last_used_at) a second time for no reason.
	user, ok := userFromContext(ctx)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}

	var body submitWorkloadRequestBody
	if err := json.NewDecoder(io.LimitReader(r.Body, maxWorkloadSubmitBodyBytes)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	request := &controlplanev1.SubmitWorkloadRequest{
		RequestId: uuid.NewString(),
		Image:     body.Image,
		Definition: &sharedv1.WorkloadDefinition{
			WorkloadId: uuid.NewString(),
			// COMPUTE_INTENSIVE: the same arbitrary-but-valid placeholder
			// cmd/workloadctl/main.go's submit already uses -- this form
			// doesn't ask the tenant to choose a profile yet, and
			// WORKLOAD_PROFILE_UNSPECIFIED is rejected by
			// validateSubmission.
			Profile: sharedv1.WorkloadProfile_WORKLOAD_PROFILE_COMPUTE_INTENSIVE,
			Requirements: &sharedv1.ResourceRequirements{
				Cpu:       body.CPUCores,
				RamMb:     body.RAMMB,
				StorageGb: body.StorageGB,
			},
			DurationSeconds: body.DurationSeconds,
		},
	}

	response, err := s.workloads.SubmitWorkload(userauth.WithUserID(ctx, user.UserID), request)
	if err != nil {
		httpStatus, message := submitWorkloadError(err)
		outcome := auditOutcomeDenied
		if httpStatus == http.StatusServiceUnavailable {
			outcome = auditOutcomeError
		}
		s.recordAudit(ctx, user, auditActionWorkloadSubmit, auditTargetWorkload, request.Definition.WorkloadId, outcome)
		writeJSON(w, httpStatus, map[string]string{"error": message})
		return
	}

	s.recordAudit(ctx, user, auditActionWorkloadSubmit, auditTargetWorkload, response.WorkloadId, auditOutcomeSuccess)
	writeJSON(w, http.StatusAccepted, map[string]string{
		"workload_id": response.WorkloadId,
		"state":       strings.TrimPrefix(response.State.String(), "WORKLOAD_STATE_"),
	})
}

// submitWorkloadError translates a workloadapi.Service.SubmitWorkload gRPC
// status error into the (HTTP status, message) pair this HTTP wrapper
// returns -- InvalidArgument is the caller's own validation failure (400,
// message passed through: validateSubmission's messages name exactly
// which field is wrong and contain nothing tenant-secret), AlreadyExists
// is CreateOrGet's idempotency-conflict case surfaced with a fixed,
// generic message (a colliding request_id can only happen here from a
// UUID collision, not a legitimate retry, since this handler always
// mints a fresh one), and everything else -- including a bare non-status
// error -- is treated as unavailable rather than guessed at.
func submitWorkloadError(err error) (int, string) {
	s, ok := status.FromError(err)
	if !ok {
		return http.StatusServiceUnavailable, "workload submission unavailable"
	}
	switch s.Code() {
	case codes.InvalidArgument:
		return http.StatusBadRequest, s.Message()
	case codes.AlreadyExists:
		return http.StatusConflict, "workload submission conflict"
	default:
		return http.StatusServiceUnavailable, "workload submission unavailable"
	}
}
