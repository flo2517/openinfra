package nova

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/openinfra/network/internal/projects"
	"github.com/openinfra/network/internal/userauth"
	"github.com/openinfra/network/internal/workloadapi"
	controlplanev1 "github.com/openinfra/network/protocol/generated/go/controlplane/v1"
	sharedv1 "github.com/openinfra/network/protocol/generated/go/shared/v1"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

// maxServerBodyBytes bounds POST /servers' JSON body -- a name, two
// OpenStack-ID-shaped references, and a small metadata map never
// legitimately needs more than this, the same generous-but-bounded
// ceiling internal/openstackapi/keystone's maxRequestBodyBytes applies to
// its own small JSON bodies.
const maxServerBodyBytes = 16 << 10

// maxWorkloadDurationSeconds is the value this package always submits as
// WorkloadDefinition.DurationSeconds when creating a server: a Nova
// server has no lease-expiry concept from its caller's perspective (it
// runs until explicitly deleted, like every other Nova instance), but
// internal/workloadapi's validateSubmission requires a positive,
// bounded duration on every submission. This is the maximum
// validateSubmission accepts (30 days, matching its own bound exactly) --
// the workload is stopped only by an explicit DELETE
// (deleteServer below), never by this duration elapsing in practice
// under normal operation, so from a Nova client's point of view a
// server's lifetime is caller-controlled, matching real Nova semantics
// as closely as this system's underlying lease model allows.
const maxWorkloadDurationSeconds = 30 * 24 * 60 * 60

type createServerRequest struct {
	Server struct {
		Name      string            `json:"name"`
		ImageRef  string            `json:"imageRef"`
		FlavorRef string            `json:"flavorRef"`
		Metadata  map[string]string `json:"metadata"`
	} `json:"server"`
}

type serverSummaryBody struct {
	ID    string     `json:"id"`
	Name  string     `json:"name"`
	Links []linkBody `json:"links"`
}

type serverFaultBody struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type serverDetailBody struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Status   string            `json:"status"`
	Created  string            `json:"created"`
	Updated  string            `json:"updated"`
	Flavor   map[string]string `json:"flavor"`
	Image    map[string]string `json:"image"`
	Metadata map[string]string `json:"metadata"`
	Links    []linkBody        `json:"links"`
	Fault    *serverFaultBody  `json:"fault,omitempty"`
}

// serverMeta is one nova_server_metadata row (migration 000018).
type serverMeta struct {
	Name     string
	FlavorID string
	Metadata map[string]string
}

// metaFor reads a workload's Nova-specific bookkeeping (name, flavor,
// metadata) -- found is false for a workload that has no
// nova_server_metadata row, which callers treat as "fall back to
// zero-valued display fields" rather than an error (see createServer's
// own doc comment on why that row's insert is best-effort, not
// transactional with the workload's own creation).
func (s *Server) metaFor(ctx context.Context, workloadID string) (serverMeta, bool) {
	var meta serverMeta
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT name, flavor_id, metadata FROM nova_server_metadata WHERE workload_id=$1`, workloadID).
		Scan(&meta.Name, &meta.FlavorID, &raw)
	if err != nil {
		return serverMeta{}, false
	}
	_ = json.Unmarshal(raw, &meta.Metadata)
	if meta.Metadata == nil {
		meta.Metadata = map[string]string{}
	}
	return meta, true
}

func (s *Server) detailBody(ctx context.Context, workload workloadapi.Workload, projectID string) serverDetailBody {
	name, flavorID, metadata := workload.WorkloadID, "", map[string]string{}
	if meta, found := s.metaFor(ctx, workload.WorkloadID); found {
		name, flavorID, metadata = meta.Name, meta.FlavorID, meta.Metadata
	}
	body := serverDetailBody{
		ID:       workload.WorkloadID,
		Name:     name,
		Status:   novaStatus(workload.State),
		Created:  workload.CreatedAt.UTC().Format(time.RFC3339),
		Updated:  workload.UpdatedAt.UTC().Format(time.RFC3339),
		Flavor:   map[string]string{"id": flavorID},
		Image:    map[string]string{"id": workload.Image},
		Metadata: metadata,
		Links:    selfLinks("servers", workload.WorkloadID, projectID),
	}
	if workload.State == "FAILED" && workload.ErrorCode != "" {
		// A minimal, Nova-shaped fault -- code 500 is a placeholder in the
		// sense that this system does not classify failures the way a real
		// hypervisor fault would; the message (ErrorCode) is the real,
		// specific signal, the same one internal/dashboard's tenant-tier
		// view already surfaces for a failed workload.
		body.Fault = &serverFaultBody{Code: 500, Message: workload.ErrorCode}
	}
	return body
}

// createServer is POST /v2.1/{project_id}/servers: maps directly onto
// workloadapi.Service.SubmitWorkload (ADR-031 §4's "a Nova 'server' IS an
// existing workload"), after resolving the requested flavor and checking
// the project's quota (internal/projects.CheckQuota) -- the same
// commit-time ceiling internal/workloadapi's own per-provider capacity
// check already runs, just a second, independent one, per ADR-031 §3.
//
// name/flavor_id/metadata are recorded in a second statement, after
// SubmitWorkload has already committed the workload row -- not in the
// same transaction, since SubmitWorkload's own transaction boundary
// belongs entirely to internal/workloadapi and this package must not
// reach into it. A failure of that second insert is logged and does not
// fail the request: the workload itself was created successfully, and a
// client that lists/gets it back simply sees its name/flavor/metadata
// fall back to their zero values (detailBody above) rather than a
// phantom creation failure -- the same "a failed audit write must not
// retroactively un-perform the action it was describing" posture
// internal/openstackapi's own audit recorder documents for an identical
// best-effort-second-write shape.
func (s *Server) createServer(w http.ResponseWriter, r *http.Request) {
	identity, projectID, ok := requireProjectScope(w, r)
	if !ok {
		return
	}

	var body createServerRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxServerBodyBytes)).Decode(&body); err != nil {
		writeNovaError(w, http.StatusBadRequest, "badRequest", "invalid request body")
		return
	}
	name := strings.TrimSpace(body.Server.Name)
	if name == "" {
		writeNovaError(w, http.StatusBadRequest, "badRequest", "server name is required")
		return
	}
	if strings.TrimSpace(body.Server.ImageRef) == "" {
		writeNovaError(w, http.StatusBadRequest, "badRequest", "imageRef is required")
		return
	}
	flavor, found := s.flavorByID(body.Server.FlavorRef)
	if !found {
		writeNovaError(w, http.StatusBadRequest, "badRequest", "Flavor "+body.Server.FlavorRef+" could not be found.")
		return
	}

	usage := projects.Usage{
		CPUMillicores: workloadapi.CPUCoresToMillicores(float32(flavor.VCPUs)),
		RAMMB:         flavor.RAMMB,
		StorageGB:     flavor.DiskGB,
		Workloads:     1,
	}
	if err := projects.CheckQuota(r.Context(), s.projects, projectID, usage); err != nil {
		if errors.Is(err, projects.ErrQuotaExceeded) {
			dimension, requested, limit, _ := projects.QuotaErrorDetail(err)
			writeNovaError(w, http.StatusForbidden, "forbidden", quotaExceededMessage(dimension, requested, limit))
			return
		}
		slog.Error("nova: quota check failed", "project_id", projectID, "error", err)
		writeNovaError(w, http.StatusServiceUnavailable, "computeFault", "quota check unavailable")
		return
	}

	request := &controlplanev1.SubmitWorkloadRequest{
		RequestId: uuid.NewString(),
		Image:     body.Server.ImageRef,
		Definition: &sharedv1.WorkloadDefinition{
			WorkloadId: uuid.NewString(),
			// COMPUTE_INTENSIVE: the same arbitrary-but-valid placeholder
			// internal/dashboard's submitMyWorkload already uses -- Nova's
			// wire protocol has no workload-profile concept for this
			// package to translate from.
			Profile: sharedv1.WorkloadProfile_WORKLOAD_PROFILE_COMPUTE_INTENSIVE,
			Requirements: &sharedv1.ResourceRequirements{
				Cpu:       float32(flavor.VCPUs),
				RamMb:     flavor.RAMMB,
				StorageGb: flavor.DiskGB,
			},
			DurationSeconds: maxWorkloadDurationSeconds,
		},
	}

	ctx := userauth.WithUserID(r.Context(), identity.UserID)
	ctx = workloadapi.WithProjectID(ctx, projectID)
	response, err := s.submitter.SubmitWorkload(ctx, request)
	if err != nil {
		httpStatus, faultName, message := submitWorkloadError(err)
		writeNovaError(w, httpStatus, faultName, message)
		return
	}

	metadata := body.Server.Metadata
	if metadata == nil {
		metadata = map[string]string{}
	}
	metadataJSON, marshalErr := json.Marshal(metadata)
	if marshalErr != nil {
		metadataJSON = []byte(`{}`)
	}
	if _, insertErr := s.pool.Exec(r.Context(), `
		INSERT INTO nova_server_metadata (workload_id, name, flavor_id, metadata)
		VALUES ($1,$2,$3,$4) ON CONFLICT (workload_id) DO NOTHING`,
		response.WorkloadId, name, flavor.ID, metadataJSON); insertErr != nil {
		slog.Error("nova: server metadata could not be recorded", "workload_id", response.WorkloadId, "error", insertErr)
	}

	writeJSON(w, http.StatusAccepted, map[string]any{"server": map[string]any{
		"id":     response.WorkloadId,
		"name":   name,
		"status": novaStatus(strings.TrimPrefix(response.State.String(), "WORKLOAD_STATE_")),
		"links":  selfLinks("servers", response.WorkloadId, projectID),
	}})
}

// quotaExceededMessage matches real Nova's own "Quota exceeded" wording
// closely enough for a client to recognize the failure class, while
// naming the specific dimension and numbers internal/projects.CheckQuota
// already computed -- more specific than real Nova's own message, which
// this system's honest-signal philosophy (see scheduler.Candidate's doc
// comment) prefers over a vaguer but more literally identical string.
func quotaExceededMessage(dimension string, requested, limit int64) string {
	return "Quota exceeded for " + dimension + ": requested would total more than the configured limit of " +
		strconv.FormatInt(limit, 10) + " (requested total " + strconv.FormatInt(requested, 10) + ")."
}

// submitWorkloadError translates a workloadapi.Service.SubmitWorkload
// gRPC status error into the (HTTP status, Nova fault name, message)
// triple this handler returns -- the Nova-shaped mirror of
// internal/dashboard's own submitWorkloadError.
func submitWorkloadError(err error) (httpStatus int, faultName, message string) {
	grpcErr, ok := grpcstatus.FromError(err)
	if !ok {
		return http.StatusServiceUnavailable, "computeFault", "workload submission unavailable"
	}
	switch grpcErr.Code() {
	case codes.InvalidArgument:
		return http.StatusBadRequest, "badRequest", grpcErr.Message()
	case codes.AlreadyExists:
		return http.StatusConflict, "conflictingRequest", "server creation conflict"
	default:
		return http.StatusServiceUnavailable, "computeFault", "workload submission unavailable"
	}
}

// listServers is GET /v2.1/{project_id}/servers: real Nova's "brief"
// listing (id, name, links -- see listServersDetail for the full
// representation).
func (s *Server) listServers(w http.ResponseWriter, r *http.Request) {
	_, projectID, ok := requireProjectScope(w, r)
	if !ok {
		return
	}
	workloads, err := s.store.ListByProject(r.Context(), projectID)
	if err != nil {
		writeNovaError(w, http.StatusServiceUnavailable, "computeFault", "server list unavailable")
		return
	}
	summaries := make([]serverSummaryBody, 0, len(workloads))
	for _, workload := range workloads {
		name := workload.WorkloadID
		if meta, found := s.metaFor(r.Context(), workload.WorkloadID); found {
			name = meta.Name
		}
		summaries = append(summaries, serverSummaryBody{ID: workload.WorkloadID, Name: name, Links: selfLinks("servers", workload.WorkloadID, projectID)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"servers": summaries})
}

func (s *Server) listServersDetail(w http.ResponseWriter, r *http.Request) {
	_, projectID, ok := requireProjectScope(w, r)
	if !ok {
		return
	}
	workloads, err := s.store.ListByProject(r.Context(), projectID)
	if err != nil {
		writeNovaError(w, http.StatusServiceUnavailable, "computeFault", "server list unavailable")
		return
	}
	details := make([]serverDetailBody, 0, len(workloads))
	for _, workload := range workloads {
		details = append(details, s.detailBody(r.Context(), workload, projectID))
	}
	writeJSON(w, http.StatusOK, map[string]any{"servers": details})
}

// showServer is GET /v2.1/{project_id}/servers/{server_id}: a workload
// outside the caller's own (already-verified) project, or that never
// existed, is reported identically as 404 itemNotFound -- GetByProject's
// project_id scoping is what makes that so; see its doc comment.
func (s *Server) showServer(w http.ResponseWriter, r *http.Request) {
	_, projectID, ok := requireProjectScope(w, r)
	if !ok {
		return
	}
	workload, err := s.store.GetByProject(r.Context(), r.PathValue("server_id"), projectID)
	if errors.Is(err, workloadapi.ErrNotFound) {
		writeNovaError(w, http.StatusNotFound, "itemNotFound", "Instance could not be found.")
		return
	}
	if err != nil {
		writeNovaError(w, http.StatusServiceUnavailable, "computeFault", "server lookup unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"server": s.detailBody(r.Context(), workload, projectID)})
}

// deleteServer is DELETE /v2.1/{project_id}/servers/{server_id}: maps
// directly onto RequestStopByProject, the exact stop/state-machine path
// internal/dashboard's own stopMyWorkload already exercises for the
// owner-scoped case -- no business logic duplicated here.
func (s *Server) deleteServer(w http.ResponseWriter, r *http.Request) {
	_, projectID, ok := requireProjectScope(w, r)
	if !ok {
		return
	}
	_, err := s.store.RequestStopByProject(r.Context(), r.PathValue("server_id"), uuid.NewString(), projectID, s.now().UTC())
	switch {
	case errors.Is(err, workloadapi.ErrNotFound):
		writeNovaError(w, http.StatusNotFound, "itemNotFound", "Instance could not be found.")
		return
	case errors.Is(err, workloadapi.ErrConflict):
		writeNovaError(w, http.StatusConflict, "conflictingRequest", "Instance already has a pending delete.")
		return
	case err != nil:
		writeNovaError(w, http.StatusServiceUnavailable, "computeFault", "server delete unavailable")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// serverMetadata is GET /v2.1/{project_id}/servers/{server_id}/metadata:
// the task's own "server metadata" acceptance criterion. Existence is
// re-verified via GetByProject even though metaFor alone could answer
// "is there a metadata row" -- a workload that exists but was never
// created through this package's createServer (so has no
// nova_server_metadata row at all) must still 404 like any other
// nonexistent-to-this-caller resource, not silently report empty
// metadata for a server the caller cannot otherwise see via showServer.
func (s *Server) serverMetadata(w http.ResponseWriter, r *http.Request) {
	_, projectID, ok := requireProjectScope(w, r)
	if !ok {
		return
	}
	workloadID := r.PathValue("server_id")
	if _, err := s.store.GetByProject(r.Context(), workloadID, projectID); err != nil {
		writeNovaError(w, http.StatusNotFound, "itemNotFound", "Instance could not be found.")
		return
	}
	metadata := map[string]string{}
	if meta, found := s.metaFor(r.Context(), workloadID); found {
		metadata = meta.Metadata
	}
	writeJSON(w, http.StatusOK, map[string]any{"metadata": metadata})
}
