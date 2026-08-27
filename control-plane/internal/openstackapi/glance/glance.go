// Package glance implements ADR-031 §2's Glance-shaped image-registry
// subset (issue #26's "easy half" -- Cinder's block-volume lifecycle is
// issue #171, gated behind ADR-034's acceptance and deliberately not
// touched by this package): register/list/get/delete a project-scoped
// image *reference* -- a name, a source location, and the digest a
// caller already pins it to. This is a metadata/catalog surface only;
// it never fetches, caches, or stores image bytes itself. The bytes
// continue to be fetched by the provider-agent's own existing,
// separately-audited paths -- Docker pull for container images (see
// internal/workloadapi's digestImage-validated Image field), and
// ADR-033 §4's fetch_and_verify_image for VM qcow2 images
// (provider-agent/crates/agent-executor/src/vm/image.rs) -- so unlike
// those two paths, this package deliberately does not implement a
// second fetch-and-cache pipeline.
//
// Structure matches internal/openstackapi/keystone, this subpackage
// family's established shape: a Server built by New, routes registered
// into a *http.ServeMux via Register, and internal/openstackapi/osauth's
// RequireToken middleware guarding every route (a Glance image is always
// project-scoped, so every route here requires a project-scoped token --
// stricter than keystone's own routes, which tolerate an unscoped
// token where scoping is optional).
package glance

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/openinfra/network/internal/openstackapi/osauth"
)

// maxRequestBodyBytes bounds every handler's request body -- an image
// registration is a handful of short strings, never legitimately larger
// than a few KB; matches the generous-ceiling-against-abuse precedent
// internal/openstackapi/keystone.maxRequestBodyBytes already sets.
const maxRequestBodyBytes = 16 << 10

const (
	VisibilityPrivate = "private"
	VisibilityPublic  = "public"
)

// ErrNotFound is returned by GetImage/DeleteImage both for a genuinely
// unknown image_id and for an image_id that exists but the caller may
// not reach (a private image owned by a different project) -- collapsed
// into one error deliberately, the same "no enumeration oracle" reasoning
// internal/projects.ErrNotAMember's doc comment and
// internal/openstackapi/keystone's cross-project scope check already
// apply: whether the image doesn't exist or simply isn't this caller's
// to see must look identical from the outside.
var ErrNotFound = errors.New("image not found")

// digestHexPattern mirrors ADR-033's
// provider-agent/crates/agent-executor/src/vm/image.rs::validate_sha256_hex
// exactly (64 lowercase hex characters, no uppercase tolerated) --
// applied here to the Go-side handler as the same discipline, and backed
// by an identical CHECK constraint at the database layer (migration
// 000018) as a second, independent backstop.
var digestHexPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// ValidateDigestSHA256 reports whether digest is exactly 64 lowercase
// hex characters -- exported so a future caller (or a test) can reuse
// the same check the handler applies.
func ValidateDigestSHA256(digest string) bool {
	return digestHexPattern.MatchString(digest)
}

// Image is one registered image reference.
type Image struct {
	ImageID      string
	ProjectID    string
	Name         string
	SourceRef    string
	DigestSHA256 string
	SizeBytes    *int64
	Visibility   string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// Repository is the persistence surface this package needs.
type Repository interface {
	// CreateImage inserts a new image row, minting ImageID server-side
	// (a caller-supplied ID is never trusted, the same
	// internal/projects.CreateProject precedent) and returning the
	// row's assigned CreatedAt/UpdatedAt.
	CreateImage(ctx context.Context, image Image) (Image, error)
	// GetImage returns ErrNotFound unless imageID names a row this
	// projectID may see: its own (any visibility) or another project's
	// public one.
	GetImage(ctx context.Context, imageID, projectID string) (Image, error)
	// ListImages returns every image projectID may see: its own (any
	// visibility) plus every other project's public images.
	ListImages(ctx context.Context, projectID string) ([]Image, error)
	// DeleteImage returns ErrNotFound unless imageID names a row owned
	// by projectID -- deliberately stricter than GetImage: visibility
	// controls who may *see* an image, never who may delete someone
	// else's.
	DeleteImage(ctx context.Context, imageID, projectID string) error
}

// AuditRecorder is called for every create/delete attempt, success or
// denial. Same shape as internal/openstackapi/keystone.AuditRecorder --
// intentionally not the same named type (this package must not import
// keystone, and keystone must not import this one, to avoid a future
// import cycle as more internal/openstackapi/* subpackages land) but
// structurally interchangeable, so internal/openstackapi.New can wire
// both from one function value via an explicit conversion.
type AuditRecorder func(ctx context.Context, actorUserID, action, targetType, targetID, outcome string)

// Users is the exact subset of userauth.Repository this package needs --
// the same narrow-interface-at-the-call-site precedent
// internal/openstackapi/keystone.Users already establishes.
type Users interface {
	osauth.TokenAuthenticator
}

// Server holds glance's handler dependencies. Constructed once by
// internal/openstackapi.New and registered via Register.
type Server struct {
	users      Users
	repository Repository
	audit      AuditRecorder
}

// New builds a glance Server. audit may be nil (a no-op is used),
// matching internal/openstackapi/keystone.New's identical tolerance.
func New(users Users, repository Repository, audit AuditRecorder) *Server {
	if audit == nil {
		audit = func(context.Context, string, string, string, string, string) {}
	}
	return &Server{users: users, repository: repository, audit: audit}
}

// Register adds this package's routes to mux. Every route requires a
// project-scoped token (checked inside each handler, since
// internal/openstackapi/osauth.RequireToken itself has no way to know
// which of its callers need scoping and which don't) -- an image is
// always project-owned, so there is no meaningful unscoped operation
// here, unlike keystone's own routes.
func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /v2/images", osauth.RequireToken(s.users, s.createImage))
	mux.HandleFunc("GET /v2/images", osauth.RequireToken(s.users, s.listImages))
	mux.HandleFunc("GET /v2/images/{image_id}", osauth.RequireToken(s.users, s.getImage))
	mux.HandleFunc("DELETE /v2/images/{image_id}", osauth.RequireToken(s.users, s.deleteImage))
}

// requireScopedIdentity reads the osauth.Identity RequireToken attached,
// and additionally requires it to carry a project scope -- every route
// in this package needs one, since an image is always project-owned.
// Writes a Keystone-shaped 401 and returns ok=false if either check
// fails, so every handler can just `if !ok { return }`.
func requireScopedIdentity(w http.ResponseWriter, r *http.Request) (osauth.Identity, bool) {
	identity, ok := osauth.FromContext(r.Context())
	if !ok {
		// Programming error (a route reachable without RequireToken),
		// not an expected runtime case -- fail closed exactly like an
		// actually-missing token, matching osauth.FromContext's own doc
		// comment on why this branch exists at all.
		osauth.WriteError(w, http.StatusUnauthorized, "Unauthorized", "The request you have made requires authentication.")
		return osauth.Identity{}, false
	}
	if identity.ProjectID == nil {
		osauth.WriteError(w, http.StatusUnauthorized, "Unauthorized", "A project-scoped token is required for this operation.")
		return osauth.Identity{}, false
	}
	return identity, true
}

type createImageRequest struct {
	Name string `json:"name"`
	// DirectURL is real Glance's own field name for "where the image
	// bytes actually live" (populated when a backend exposes a
	// dereferenceable location) -- reused here as the *input* field,
	// since this registry never runs Glance's real two-step
	// create-then-PUT-.../file upload flow (there is no upload; the
	// bytes are never touched by the Control Plane at all).
	DirectURL string `json:"direct_url"`
	// OSHashValue is real Glance's modern secure-hash field name
	// (paired with OSHashAlgo, always "sha256" here -- this registry
	// does not support Glance's legacy MD5 "checksum" field).
	OSHashValue string `json:"os_hash_value"`
	Visibility  string `json:"visibility"`
	Size        *int64 `json:"size"`
}

func (s *Server) createImage(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	identity, ok := requireScopedIdentity(w, r)
	if !ok {
		return
	}

	var request createImageRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxRequestBodyBytes)).Decode(&request); err != nil {
		osauth.WriteError(w, http.StatusBadRequest, "Bad Request", "invalid request body")
		return
	}

	name := strings.TrimSpace(request.Name)
	if name == "" || len(name) > 255 {
		osauth.WriteError(w, http.StatusBadRequest, "Bad Request", "name must be between 1 and 255 characters")
		return
	}
	sourceRef := strings.TrimSpace(request.DirectURL)
	if sourceRef == "" || len(sourceRef) > 2000 {
		osauth.WriteError(w, http.StatusBadRequest, "Bad Request", "direct_url must be between 1 and 2000 characters")
		return
	}
	if !ValidateDigestSHA256(request.OSHashValue) {
		osauth.WriteError(w, http.StatusBadRequest, "Bad Request", "os_hash_value must be exactly 64 lowercase hexadecimal characters (a sha256 digest)")
		return
	}
	visibility := request.Visibility
	if visibility == "" {
		visibility = VisibilityPrivate
	}
	if visibility != VisibilityPrivate && visibility != VisibilityPublic {
		osauth.WriteError(w, http.StatusBadRequest, "Bad Request", `visibility must be "private" or "public"`)
		return
	}
	if request.Size != nil && *request.Size <= 0 {
		osauth.WriteError(w, http.StatusBadRequest, "Bad Request", "size must be positive when present")
		return
	}

	image, err := s.repository.CreateImage(ctx, Image{
		ProjectID:    *identity.ProjectID,
		Name:         name,
		SourceRef:    sourceRef,
		DigestSHA256: request.OSHashValue,
		SizeBytes:    request.Size,
		Visibility:   visibility,
	})
	if err != nil {
		slog.Error("glance: image creation failed", "error", err)
		s.audit(ctx, identity.UserID, "openstack.image.create", "image", "", "error")
		osauth.WriteError(w, http.StatusServiceUnavailable, "Service Unavailable", "image creation unavailable")
		return
	}
	s.audit(ctx, identity.UserID, "openstack.image.create", "image", image.ImageID, "success")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(imageBody(image))
}

func (s *Server) listImages(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	identity, ok := requireScopedIdentity(w, r)
	if !ok {
		return
	}

	images, err := s.repository.ListImages(ctx, *identity.ProjectID)
	if err != nil {
		slog.Error("glance: image listing failed", "error", err)
		osauth.WriteError(w, http.StatusServiceUnavailable, "Service Unavailable", "image listing unavailable")
		return
	}
	bodies := make([]imageResponseBody, 0, len(images))
	for _, image := range images {
		bodies = append(bodies, imageBody(image))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(imagesListBody{Images: bodies, Schema: "/v2/schemas/images", First: "/v2/images"})
}

func (s *Server) getImage(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	identity, ok := requireScopedIdentity(w, r)
	if !ok {
		return
	}

	imageID := r.PathValue("image_id")
	if _, err := uuid.Parse(imageID); err != nil {
		osauth.WriteError(w, http.StatusNotFound, "Not Found", "No image found with ID "+imageID)
		return
	}

	image, err := s.repository.GetImage(ctx, imageID, *identity.ProjectID)
	if errors.Is(err, ErrNotFound) {
		osauth.WriteError(w, http.StatusNotFound, "Not Found", "No image found with ID "+imageID)
		return
	}
	if err != nil {
		slog.Error("glance: image lookup failed", "error", err)
		osauth.WriteError(w, http.StatusServiceUnavailable, "Service Unavailable", "image lookup unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(imageBody(image))
}

func (s *Server) deleteImage(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	identity, ok := requireScopedIdentity(w, r)
	if !ok {
		return
	}

	imageID := r.PathValue("image_id")
	if _, err := uuid.Parse(imageID); err != nil {
		osauth.WriteError(w, http.StatusNotFound, "Not Found", "No image found with ID "+imageID)
		return
	}

	err := s.repository.DeleteImage(ctx, imageID, *identity.ProjectID)
	if errors.Is(err, ErrNotFound) {
		s.audit(ctx, identity.UserID, "openstack.image.delete", "image", imageID, "denied")
		osauth.WriteError(w, http.StatusNotFound, "Not Found", "No image found with ID "+imageID)
		return
	}
	if err != nil {
		slog.Error("glance: image deletion failed", "error", err)
		s.audit(ctx, identity.UserID, "openstack.image.delete", "image", imageID, "error")
		osauth.WriteError(w, http.StatusServiceUnavailable, "Service Unavailable", "image deletion unavailable")
		return
	}
	s.audit(ctx, identity.UserID, "openstack.image.delete", "image", imageID, "success")
	w.WriteHeader(http.StatusNoContent)
}
