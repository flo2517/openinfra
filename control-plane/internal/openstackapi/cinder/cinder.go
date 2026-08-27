// Package cinder implements ADR-034's Cinder-compatible block-volume
// subset (issue #171, the Cinder half of issue #26): create/list/get/
// delete/attach/detach lifecycle for a project-scoped, host-local Docker
// named volume, backed by the migration-000021 cinder_volumes table.
//
// Structure matches internal/openstackapi/glance/nova, this subpackage
// family's established shape: a Server built by New, routes registered
// into a *http.ServeMux via Register, and internal/openstackapi/osauth's
// RequireToken middleware guarding every route -- a volume is always
// project-owned, so, like glance, every route here requires a
// project-scoped token.
//
// Deliberately out of scope here, matching ADR-034 §8 exactly:
// cross-provider volume replication/migration, snapshots, resize-in-
// place, encryption at rest, attaching a volume to a VM workload, volume
// types/QoS tiers, and cross-project volume sharing (a volume belongs to
// exactly one project -- there is no glance-style "public" visibility
// concept here at all).
package cinder

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
	"github.com/openinfra/network/internal/openstackapi/osauth"
	"github.com/openinfra/network/internal/projects"
	"github.com/openinfra/network/internal/workloadapi"
)

// maxRequestBodyBytes bounds every handler's request body -- a volume
// create/attach/detach request is a handful of short fields, never
// legitimately larger than a few KB, matching
// internal/openstackapi/glance.maxRequestBodyBytes's identical ceiling.
const maxRequestBodyBytes = 16 << 10

// Volume state machine (ADR-034 §2). available -> in-use (attach) ->
// available (detach) -> deleting (delete, only from available) -> the
// row's deleted_at is set once secure deletion (§6) has completed.
const (
	StateAvailable = "available"
	StateInUse     = "in-use"
	StateDeleting  = "deleting"
	StateError     = "error"
)

// ErrNotFound collapses "genuinely unknown volume_id" and "exists but a
// different project owns it" into one outcome -- the same
// no-enumeration-oracle posture internal/openstackapi/glance.ErrNotFound
// documents, applied here without glance's public/private wrinkle: a
// Cinder volume in this slice has no shared-visibility concept at all
// (ADR-034 §8), so "not this caller's project" and "does not exist" are
// always indistinguishable, not just for one particular visibility case.
var ErrNotFound = errors.New("volume not found")

// ErrNotAvailable is AttachVolume/BeginDelete's failure when the target
// row exists (and is owned by the caller) but is not currently
// 'available' -- covers both "already in-use" (issue #26's own
// double-attachment acceptance criterion) and "already deleting".
var ErrNotAvailable = errors.New("volume is not in the available state")

// ErrProviderMismatch is AttachVolume's failure when the volume is
// already permanently bound (ADR-034 §1/§2: first attach binds a
// volume's provider_id for its whole life) to a provider other than the
// one the target workload is scheduled on.
var ErrProviderMismatch = errors.New("volume is bound to a different provider")

// ErrNotAttached is DetachVolume's failure when the volume is not
// currently attached to the given workload (already detached, or was
// never attached to it in the first place).
var ErrNotAttached = errors.New("volume is not attached to this workload")

// Volume is one durable cinder_volumes row.
type Volume struct {
	VolumeID           string
	ProjectID          string
	Name               string
	SizeGB             int64
	State              string
	ProviderID         *string
	AttachedWorkloadID *string
	MountPath          *string
	ReadOnly           bool
	Encrypted          bool
	CreatedAt          time.Time
}

// Repository is the persistence surface this package needs. Every
// state-changing method performs its precondition check and its write
// in the same statement (ADR-034 §2's "the query itself is the check"
// discipline, ADR-016's own established pattern) -- never a separate
// read-then-write, which is exactly the race issue #26's own
// double-attachment acceptance criterion calls out.
type Repository interface {
	// CreateVolume inserts a new 'available' row, minting VolumeID
	// server-side (a caller-supplied id is never trusted, the same
	// internal/openstackapi/glance.CreateImage precedent).
	CreateVolume(ctx context.Context, volume Volume) (Volume, error)
	// GetVolume returns ErrNotFound unless volumeID names a live row
	// owned by projectID.
	GetVolume(ctx context.Context, volumeID, projectID string) (Volume, error)
	// ListVolumes returns every live volume projectID owns.
	ListVolumes(ctx context.Context, projectID string) ([]Volume, error)
	// AttachVolume atomically transitions volumeID from 'available' to
	// 'in-use', binding it to (providerID, workloadID, mountPath,
	// readOnly). If the volume already has a provider_id (a prior
	// attach/detach cycle), providerID must match it exactly or
	// ErrProviderMismatch is returned -- ADR-034 §1's permanent
	// provider binding. Returns ErrNotFound if volumeID does not name a
	// live row owned by projectID, ErrNotAvailable if it does but is not
	// 'available'.
	AttachVolume(ctx context.Context, volumeID, projectID, providerID, workloadID, mountPath string, readOnly bool) (Volume, error)
	// DetachVolume atomically transitions volumeID from 'in-use' back to
	// 'available', clearing attached_workload_id/mount_path but
	// preserving provider_id (ADR-034 §2: the Docker-level volume is not
	// deleted on detach, and stays pinned to its provider). Returns
	// ErrNotAttached unless volumeID is currently 'in-use' and attached
	// to exactly workloadID.
	DetachVolume(ctx context.Context, volumeID, projectID, workloadID string) (Volume, error)
	// BeginDelete atomically transitions volumeID from 'available' to
	// 'deleting'. Returns ErrNotFound unless volumeID names a live row
	// owned by projectID, ErrNotAvailable if it does but is not
	// 'available' (Cinder's own real behavior: an in-use volume must be
	// detached first).
	BeginDelete(ctx context.Context, volumeID, projectID string) (Volume, error)
	// FinishDelete sets deleted_at on a 'deleting' row, completing the
	// delete lifecycle after secure deletion (§6) has succeeded (or was
	// never needed -- a volume with no provider_id was never created on
	// any provider host, so there is no Docker-level state to delete).
	FinishDelete(ctx context.Context, volumeID string) error
	// AbortDelete rolls a 'deleting' row back to 'available' -- called
	// when the owning provider could not be reached to run secure
	// deletion (VolumeDispatcher failure/timeout), so a transient
	// provider outage does not strand the volume in 'deleting' forever
	// (which would also block a retried delete, since BeginDelete only
	// starts from 'available').
	AbortDelete(ctx context.Context, volumeID string) error
}

// AuditRecorder mirrors internal/openstackapi/glance.AuditRecorder's
// shape exactly (structurally interchangeable, deliberately not the same
// named type, to avoid an import cycle as more internal/openstackapi/*
// subpackages land).
type AuditRecorder func(ctx context.Context, actorUserID, action, targetType, targetID, outcome string)

// Users is the exact subset of userauth.Repository this package needs.
type Users interface {
	osauth.TokenAuthenticator
}

// WorkloadLookup is the subset of *workloadapi.PostgresRepository this
// package needs to resolve an attach target's provider binding --
// mirrors internal/openstackapi/nova.WorkloadStore's identical
// project-scoped GetByProject, so attach can confirm both that the
// target workload belongs to the caller's own project and which
// provider it is actually scheduled on (ADR-034 §2: attach is the
// moment a volume gets pinned to a host, and that host is whichever one
// the target workload already runs on -- never a caller-supplied
// provider_id, which would let a caller attach a volume to a host no
// workload of theirs is even on).
type WorkloadLookup interface {
	GetByProject(ctx context.Context, workloadID, projectID string) (workloadapi.Workload, error)
}

// VolumeDispatcher reaches the specific provider a volume is bound to
// and asks its Agent to securely delete the underlying Docker volume
// (ADR-034 §6). May be nil: deleteVolume's own handling of that case
// (see its doc comment) fails a bound volume's delete closed rather than
// silently skipping secure deletion -- only an unbound volume (never
// attached to any provider) can be deleted with no dispatcher at all,
// since there is genuinely no Docker-level state to delete for one.
type VolumeDispatcher interface {
	DeleteVolume(ctx context.Context, providerID, volumeID string) error
}

// Server holds cinder's handler dependencies. Constructed once by
// internal/openstackapi.New and registered via Register.
type Server struct {
	users      Users
	repository Repository
	workloads  WorkloadLookup
	dispatcher VolumeDispatcher
	projects   projects.Repository
	audit      AuditRecorder
}

// New builds a cinder Server. dispatcher and audit may both be nil (see
// their own doc comments for what nil means for each).
func New(users Users, repository Repository, workloads WorkloadLookup, dispatcher VolumeDispatcher, projectsRepo projects.Repository, audit AuditRecorder) *Server {
	if audit == nil {
		audit = func(context.Context, string, string, string, string, string) {}
	}
	return &Server{users: users, repository: repository, workloads: workloads, dispatcher: dispatcher, projects: projectsRepo, audit: audit}
}

// Register adds this package's routes to mux. Every route carries a real
// Cinder v3 {project_id} path segment and requires a project-scoped
// token whose project matches it (requireProjectScope) -- the same
// wire-authentic cross-project 403 internal/openstackapi/nova's own
// requireProjectScope documents.
func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /v3/{project_id}/volumes", osauth.RequireToken(s.users, s.createVolume))
	mux.HandleFunc("GET /v3/{project_id}/volumes", osauth.RequireToken(s.users, s.listVolumes))
	mux.HandleFunc("GET /v3/{project_id}/volumes/{volume_id}", osauth.RequireToken(s.users, s.getVolume))
	mux.HandleFunc("DELETE /v3/{project_id}/volumes/{volume_id}", osauth.RequireToken(s.users, s.deleteVolume))
	mux.HandleFunc("POST /v3/{project_id}/volumes/{volume_id}/action", osauth.RequireToken(s.users, s.volumeAction))
}

// requireProjectScope is internal/openstackapi/nova.requireProjectScope's
// identical logic, reproduced here rather than exported from nova (this
// package must not import nova, to avoid a future import cycle as more
// internal/openstackapi/* subpackages land -- the same reasoning
// glance's own doc comment gives for not sharing its AuditRecorder type).
func requireProjectScope(w http.ResponseWriter, r *http.Request) (identity osauth.Identity, projectID string, ok bool) {
	identity, found := osauth.FromContext(r.Context())
	if !found {
		writeCinderError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return osauth.Identity{}, "", false
	}
	pathProjectID := r.PathValue("project_id")
	if identity.ProjectID == nil {
		writeCinderError(w, http.StatusForbidden, "forbidden", "A project-scoped token is required to perform this operation.")
		return osauth.Identity{}, "", false
	}
	if *identity.ProjectID != pathProjectID {
		writeCinderError(w, http.StatusForbidden, "forbidden", "You are not authorized to perform the requested action on this project.")
		return osauth.Identity{}, "", false
	}
	return identity, pathProjectID, true
}

type createVolumeRequest struct {
	Volume struct {
		Name string `json:"name"`
		Size int64  `json:"size"`
	} `json:"volume"`
}

// createVolume is POST /v3/{project_id}/volumes: validates the request,
// checks the project's storage_gb quota (internal/projects.CheckQuota,
// ADR-034 §4), and inserts a new 'available' row. Nothing is created on
// any provider host yet (ADR-034 §2) -- a volume with no attachment
// costs no provider disk space, matching real Cinder's own
// create-then-attach-later flow.
func (s *Server) createVolume(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	identity, projectID, ok := requireProjectScope(w, r)
	if !ok {
		return
	}

	var body createVolumeRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxRequestBodyBytes)).Decode(&body); err != nil {
		writeCinderError(w, http.StatusBadRequest, "badRequest", "invalid request body")
		return
	}
	name := strings.TrimSpace(body.Volume.Name)
	if name == "" || len(name) > 255 {
		writeCinderError(w, http.StatusBadRequest, "badRequest", "volume.name must be between 1 and 255 characters")
		return
	}
	if body.Volume.Size <= 0 || body.Volume.Size > 1_000_000 {
		writeCinderError(w, http.StatusBadRequest, "badRequest", "volume.size must be a positive number of GB")
		return
	}

	if err := projects.CheckQuota(ctx, s.projects, projectID, projects.Usage{StorageGB: body.Volume.Size}); err != nil {
		if errors.Is(err, projects.ErrQuotaExceeded) {
			dimension, requested, limit, _ := projects.QuotaErrorDetail(err)
			s.audit(ctx, identity.UserID, "openstack.volume.create", "volume", "", "denied")
			writeCinderError(w, http.StatusForbidden, "forbidden", quotaExceededMessage(dimension, requested, limit))
			return
		}
		slog.Error("cinder: quota check failed", "project_id", projectID, "error", err)
		writeCinderError(w, http.StatusServiceUnavailable, "volumeFault", "quota check unavailable")
		return
	}

	volume, err := s.repository.CreateVolume(ctx, Volume{
		ProjectID: projectID,
		Name:      name,
		SizeGB:    body.Volume.Size,
		State:     StateAvailable,
	})
	if err != nil {
		slog.Error("cinder: volume creation failed", "error", err)
		s.audit(ctx, identity.UserID, "openstack.volume.create", "volume", "", "error")
		writeCinderError(w, http.StatusServiceUnavailable, "volumeFault", "volume creation unavailable")
		return
	}
	s.audit(ctx, identity.UserID, "openstack.volume.create", "volume", volume.VolumeID, "success")
	writeJSON(w, http.StatusAccepted, map[string]any{"volume": volumeBody(volume)})
}

func (s *Server) listVolumes(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	_, projectID, ok := requireProjectScope(w, r)
	if !ok {
		return
	}

	volumes, err := s.repository.ListVolumes(ctx, projectID)
	if err != nil {
		slog.Error("cinder: volume listing failed", "error", err)
		writeCinderError(w, http.StatusServiceUnavailable, "volumeFault", "volume listing unavailable")
		return
	}
	bodies := make([]volumeResponseBody, 0, len(volumes))
	for _, volume := range volumes {
		bodies = append(bodies, volumeBody(volume))
	}
	writeJSON(w, http.StatusOK, map[string]any{"volumes": bodies})
}

func (s *Server) getVolume(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	_, projectID, ok := requireProjectScope(w, r)
	if !ok {
		return
	}

	volumeID := r.PathValue("volume_id")
	if _, err := uuid.Parse(volumeID); err != nil {
		writeCinderError(w, http.StatusNotFound, "itemNotFound", "Volume "+volumeID+" could not be found.")
		return
	}
	volume, err := s.repository.GetVolume(ctx, volumeID, projectID)
	if errors.Is(err, ErrNotFound) {
		writeCinderError(w, http.StatusNotFound, "itemNotFound", "Volume "+volumeID+" could not be found.")
		return
	}
	if err != nil {
		slog.Error("cinder: volume lookup failed", "error", err)
		writeCinderError(w, http.StatusServiceUnavailable, "volumeFault", "volume lookup unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"volume": volumeBody(volume)})
}

// deleteVolume is DELETE /v3/{project_id}/volumes/{volume_id}. Only
// permitted from 'available' (ErrNotAvailable otherwise -- Cinder's own
// real "detach first" behavior, ADR-034 §2). A volume that was never
// attached (provider_id nil) has no Docker-level state at all, so its
// row is finished immediately. A volume that was attached at least once
// requires reaching its bound provider to run secure deletion (ADR-034
// §6) before the row is finished -- if that provider cannot be reached
// (no dispatcher configured, or the dispatch itself fails/times out),
// the row is rolled back to 'available' (AbortDelete) and the request
// fails with 503: never marked deleted without confirmation (AGENTS.md's
// "never report success before authoritative confirmation", extended
// here from deployment confirmation to deletion confirmation), and never
// left stuck in 'deleting' forever either -- a caller can simply retry.
func (s *Server) deleteVolume(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	identity, projectID, ok := requireProjectScope(w, r)
	if !ok {
		return
	}
	volumeID := r.PathValue("volume_id")
	if _, err := uuid.Parse(volumeID); err != nil {
		writeCinderError(w, http.StatusNotFound, "itemNotFound", "Volume "+volumeID+" could not be found.")
		return
	}

	volume, err := s.repository.BeginDelete(ctx, volumeID, projectID)
	if errors.Is(err, ErrNotFound) {
		writeCinderError(w, http.StatusNotFound, "itemNotFound", "Volume "+volumeID+" could not be found.")
		return
	}
	if errors.Is(err, ErrNotAvailable) {
		s.audit(ctx, identity.UserID, "openstack.volume.delete", "volume", volumeID, "denied")
		writeCinderError(w, http.StatusBadRequest, "badRequest", "Volume "+volumeID+" must be detached before it can be deleted.")
		return
	}
	if err != nil {
		slog.Error("cinder: volume delete transition failed", "error", err)
		writeCinderError(w, http.StatusServiceUnavailable, "volumeFault", "volume deletion unavailable")
		return
	}

	if volume.ProviderID != nil {
		if s.dispatcher == nil {
			slog.Error("cinder: volume has provider-bound state but no VolumeDispatcher is configured; secure deletion cannot run", "volume_id", volumeID, "provider_id", *volume.ProviderID)
			s.abortDelete(ctx, volumeID)
			s.audit(ctx, identity.UserID, "openstack.volume.delete", "volume", volumeID, "error")
			writeCinderError(w, http.StatusServiceUnavailable, "volumeFault", "volume deletion unavailable: cannot reach the owning provider right now")
			return
		}
		deleteCtx, deleteCancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := s.dispatcher.DeleteVolume(deleteCtx, *volume.ProviderID, volumeID)
		deleteCancel()
		if err != nil {
			slog.Error("cinder: Agent-side secure deletion failed", "volume_id", volumeID, "provider_id", *volume.ProviderID, "error", err)
			s.abortDelete(ctx, volumeID)
			s.audit(ctx, identity.UserID, "openstack.volume.delete", "volume", volumeID, "error")
			writeCinderError(w, http.StatusServiceUnavailable, "volumeFault", "volume deletion unavailable: the owning provider could not securely delete it")
			return
		}
	}

	if err := s.repository.FinishDelete(ctx, volumeID); err != nil {
		slog.Error("cinder: volume delete finalization failed", "error", err)
		s.audit(ctx, identity.UserID, "openstack.volume.delete", "volume", volumeID, "error")
		writeCinderError(w, http.StatusServiceUnavailable, "volumeFault", "volume deletion unavailable")
		return
	}
	s.audit(ctx, identity.UserID, "openstack.volume.delete", "volume", volumeID, "success")
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) abortDelete(ctx context.Context, volumeID string) {
	if err := s.repository.AbortDelete(ctx, volumeID); err != nil {
		slog.Error("cinder: could not roll a failed delete back to available; volume is stuck in 'deleting'", "volume_id", volumeID, "error", err)
	}
}

type volumeActionRequest struct {
	OSAttach *struct {
		InstanceUUID string `json:"instance_uuid"`
		Mountpoint   string `json:"mountpoint"`
		Mode         string `json:"mode"`
	} `json:"os-attach"`
	OSDetach *struct {
		AttachmentID string `json:"attachment_id"`
	} `json:"os-detach"`
}

// volumeAction is POST /v3/{project_id}/volumes/{volume_id}/action, real
// Cinder's own action-dispatch convention: the body's top-level key names
// which action to run. Only os-attach/os-detach are implemented; any
// other (or absent) action key is rejected the same "no placeholder
// success path" way internal/openstackapi/nova's own unimplemented
// actions are (see nova's package doc comment).
func (s *Server) volumeAction(w http.ResponseWriter, r *http.Request) {
	identity, projectID, ok := requireProjectScope(w, r)
	if !ok {
		return
	}
	volumeID := r.PathValue("volume_id")
	if _, err := uuid.Parse(volumeID); err != nil {
		writeCinderError(w, http.StatusNotFound, "itemNotFound", "Volume "+volumeID+" could not be found.")
		return
	}

	var body volumeActionRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxRequestBodyBytes)).Decode(&body); err != nil {
		writeCinderError(w, http.StatusBadRequest, "badRequest", "invalid request body")
		return
	}

	switch {
	case body.OSAttach != nil:
		s.attachVolume(w, r, identity, projectID, volumeID, *body.OSAttach)
	case body.OSDetach != nil:
		s.detachVolume(w, r, identity, projectID, volumeID)
	default:
		writeCinderError(w, http.StatusBadRequest, "badRequest", "unsupported or missing volume action")
	}
}

func (s *Server) attachVolume(w http.ResponseWriter, r *http.Request, identity osauth.Identity, projectID, volumeID string, attach struct {
	InstanceUUID string `json:"instance_uuid"`
	Mountpoint   string `json:"mountpoint"`
	Mode         string `json:"mode"`
}) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	instanceUUID := strings.TrimSpace(attach.InstanceUUID)
	if _, err := uuid.Parse(instanceUUID); err != nil {
		writeCinderError(w, http.StatusBadRequest, "badRequest", "os-attach.instance_uuid must be a workload UUID")
		return
	}
	mountPath := strings.TrimSpace(attach.Mountpoint)
	if mountPath == "" || len(mountPath) > 255 {
		writeCinderError(w, http.StatusBadRequest, "badRequest", "os-attach.mountpoint must be between 1 and 255 characters")
		return
	}
	readOnly := attach.Mode == "ro"

	workload, err := s.workloads.GetByProject(ctx, instanceUUID, projectID)
	if errors.Is(err, workloadapi.ErrNotFound) {
		writeCinderError(w, http.StatusBadRequest, "badRequest", "instance "+instanceUUID+" could not be found in this project")
		return
	}
	if err != nil {
		slog.Error("cinder: workload lookup for attach failed", "error", err)
		writeCinderError(w, http.StatusServiceUnavailable, "volumeFault", "volume attach unavailable")
		return
	}
	if workload.ProviderID == "" {
		writeCinderError(w, http.StatusBadRequest, "badRequest", "instance "+instanceUUID+" is not yet scheduled to a provider")
		return
	}

	volume, err := s.repository.AttachVolume(ctx, volumeID, projectID, workload.ProviderID, instanceUUID, mountPath, readOnly)
	switch {
	case errors.Is(err, ErrNotFound):
		writeCinderError(w, http.StatusNotFound, "itemNotFound", "Volume "+volumeID+" could not be found.")
	case errors.Is(err, ErrNotAvailable):
		s.audit(ctx, identity.UserID, "openstack.volume.attach", "volume", volumeID, "denied")
		writeCinderError(w, http.StatusBadRequest, "badRequest", "Volume "+volumeID+" is already attached to another instance.")
	case errors.Is(err, ErrProviderMismatch):
		s.audit(ctx, identity.UserID, "openstack.volume.attach", "volume", volumeID, "denied")
		writeCinderError(w, http.StatusBadRequest, "badRequest", "Volume "+volumeID+" is bound to a different provider than instance "+instanceUUID+".")
	case err != nil:
		slog.Error("cinder: volume attach failed", "error", err)
		s.audit(ctx, identity.UserID, "openstack.volume.attach", "volume", volumeID, "error")
		writeCinderError(w, http.StatusServiceUnavailable, "volumeFault", "volume attach unavailable")
	default:
		s.audit(ctx, identity.UserID, "openstack.volume.attach", "volume", volumeID, "success")
		writeJSON(w, http.StatusOK, map[string]any{"volume": volumeBody(volume)})
	}
}

func (s *Server) detachVolume(w http.ResponseWriter, r *http.Request, identity osauth.Identity, projectID, volumeID string) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	existing, err := s.repository.GetVolume(ctx, volumeID, projectID)
	if errors.Is(err, ErrNotFound) {
		writeCinderError(w, http.StatusNotFound, "itemNotFound", "Volume "+volumeID+" could not be found.")
		return
	}
	if err != nil {
		slog.Error("cinder: volume lookup for detach failed", "error", err)
		writeCinderError(w, http.StatusServiceUnavailable, "volumeFault", "volume detach unavailable")
		return
	}
	if existing.AttachedWorkloadID == nil {
		s.audit(ctx, identity.UserID, "openstack.volume.detach", "volume", volumeID, "denied")
		writeCinderError(w, http.StatusBadRequest, "badRequest", "Volume "+volumeID+" is not attached to any instance.")
		return
	}

	volume, err := s.repository.DetachVolume(ctx, volumeID, projectID, *existing.AttachedWorkloadID)
	switch {
	case errors.Is(err, ErrNotFound):
		writeCinderError(w, http.StatusNotFound, "itemNotFound", "Volume "+volumeID+" could not be found.")
	case errors.Is(err, ErrNotAttached):
		s.audit(ctx, identity.UserID, "openstack.volume.detach", "volume", volumeID, "denied")
		writeCinderError(w, http.StatusBadRequest, "badRequest", "Volume "+volumeID+" is not attached to any instance.")
	case err != nil:
		slog.Error("cinder: volume detach failed", "error", err)
		s.audit(ctx, identity.UserID, "openstack.volume.detach", "volume", volumeID, "error")
		writeCinderError(w, http.StatusServiceUnavailable, "volumeFault", "volume detach unavailable")
	default:
		s.audit(ctx, identity.UserID, "openstack.volume.detach", "volume", volumeID, "success")
		writeJSON(w, http.StatusOK, map[string]any{"volume": volumeBody(volume)})
	}
}

// quotaExceededMessage matches internal/openstackapi/nova's identical
// helper -- reproduced here (not exported from nova) for the same
// no-import-cycle reason requireProjectScope is.
func quotaExceededMessage(dimension string, requested, limit int64) string {
	return "Quota exceeded for " + dimension + ": requested would total more than the configured limit of " +
		strconv.FormatInt(limit, 10) + " (requested total " + strconv.FormatInt(requested, 10) + ")."
}
