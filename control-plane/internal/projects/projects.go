// Package projects implements ADR-031 §3's Keystone-compatible project
// model: projects, project<->user memberships with a project-scoped role,
// and a per-project resource quota checked as a second, independent
// ceiling alongside internal/workloadapi's existing per-provider
// ProviderCapacity ceiling.
//
// This is deliberately a separate package from internal/openstackapi: the
// HTTP surface (openstackapi) is a translation layer, this package is the
// domain/persistence layer other HTTP surfaces (the gRPC ControlPlaneService,
// a future internal/openstackapi/nova or /cinder package, #24/#25/#26) can
// call directly without depending on openstackapi's HTTP concerns -- the
// same separation userauth (identity/credentials) already keeps from
// dashboard and openstackapi/keystone (HTTP surfaces built on top of it).
package projects

import (
	"context"
	"errors"
	"time"
)

// ErrProjectNotFound is returned by GetProject/GetProjectByName for an
// unknown project, and by any lookup that needs a project to exist first
// (e.g. AddMembership, SetQuota) -- collapsed into one error rather than
// a generic "not found" so callers can distinguish "no such project" from
// "no such user" (ErrUserNotFound-equivalent concerns belong to
// userauth, not here).
var ErrProjectNotFound = errors.New("project not found")

// ErrProjectNameTaken is CreateProject's failure when name collides with
// an existing project -- projects_name_idx is the actual enforcement
// (migration 000017); this is the typed error a caller gets back instead
// of a raw Postgres unique-violation.
var ErrProjectNameTaken = errors.New("project name already in use")

// ErrNotAMember is GetMembership's failure for a (project, user) pair
// with no project_memberships row. Deliberately distinct from
// ErrProjectNotFound: internal/openstackapi/keystone's cross-project
// scope check must fail exactly the same way whether the project doesn't
// exist or the caller simply isn't a member of it (see RequireMembership),
// so a token-scoping attempt can't be used to enumerate which project IDs
// exist.
var ErrNotAMember = errors.New("user is not a member of this project")

// ErrQuotaExceeded is CheckQuota's failure when a requested allocation
// would push a project's committed usage over one of its configured
// quota dimensions. Wrapped with the specific dimension and numbers in
// its message (via fmt.Errorf's %w) so a caller/log line can say exactly
// what was exceeded, not just that something was.
var ErrQuotaExceeded = errors.New("project quota exceeded")

// RoleMember and RoleAdmin are the only two project-scoped roles
// project_memberships.role's CHECK constraint (migration 000017) allows
// -- ADR-031 §3's deliberately small subset of Keystone's role model.
// Distinct from userauth.RoleTenant/RoleOperatorReadOnly/RoleOperatorAdmin,
// which answer a different question (system-wide dashboard visibility,
// ADR-016) than "what may this user do inside this specific project".
const (
	RoleMember = "project_member"
	RoleAdmin  = "project_admin"
)

// ValidRole reports whether role is one of the roles project_memberships
// recognizes -- the Go-level mirror of the CHECK constraint, checked
// before a write so a caller gets a clear error instead of a raw
// constraint violation, the same split userauth.ValidRole/SetRole already
// use for users.role.
func ValidRole(role string) bool {
	return role == RoleMember || role == RoleAdmin
}

// Project is a Keystone-compatible tenant container: many users may
// belong to it (via Membership), many workloads may be scoped to it.
type Project struct {
	ProjectID   string
	Name        string
	Description string
	Enabled     bool
	CreatedAt   time.Time
}

// Membership is one user's role within one project.
type Membership struct {
	ProjectID string
	UserID    string
	Role      string
	CreatedAt time.Time
}

// Quota is a project's configured resource ceiling. Every field is
// required and positive once a Quota exists at all (migration 000017's
// CHECK constraints are the actual enforcement) -- there is deliberately
// no "unlimited" sentinel value; the *absence* of a quota row (see
// GetQuota's ok return) is the only unbounded state this package
// recognizes, per ADR-031 §3.
type Quota struct {
	ProjectID        string
	MaxCPUMillicores int64
	MaxRAMMB         int64
	MaxStorageGB     int64
	MaxWorkloads     int32
}

// Usage is a requested (or currently committed) resource allocation,
// in the same units Quota and internal/workloadapi's reservation ledger
// already use (CPU in millicores, RAM/storage in MB/GB, a plain workload
// count).
type Usage struct {
	CPUMillicores int64
	RAMMB         int64
	StorageGB     int64
	Workloads     int32
}

// Repository is the persistence surface this package needs.
type Repository interface {
	// CreateProject mints a new project. Returns ErrProjectNameTaken if
	// name is already in use.
	CreateProject(ctx context.Context, name, description string) (Project, error)
	// GetProject returns ErrProjectNotFound for an unknown project_id.
	GetProject(ctx context.Context, projectID string) (Project, error)
	// GetProjectByName returns ErrProjectNotFound for an unknown name --
	// used by internal/openstackapi/keystone to resolve a Keystone
	// scope.project.name request the same way scope.project.id is
	// resolved by GetProject.
	GetProjectByName(ctx context.Context, name string) (Project, error)

	// AddMembership grants userID role within projectID, upserting if a
	// membership row already exists (a re-grant changes the role rather
	// than erroring -- the same "grant path is also the revoke/change
	// path" precedent userauth.SetRole already establishes). Returns
	// ErrProjectNotFound if projectID does not exist.
	AddMembership(ctx context.Context, projectID, userID, role string) error
	// GetMembership returns ErrNotAMember if userID has no
	// project_memberships row for projectID -- including when projectID
	// itself does not exist, deliberately not distinguished (see
	// ErrNotAMember's doc comment).
	GetMembership(ctx context.Context, projectID, userID string) (Membership, error)

	// SetQuota upserts projectID's quota row. Returns ErrProjectNotFound
	// if projectID does not exist; the CHECK constraints on
	// project_quotas (migration 000017) are the backstop against a
	// zero/negative/absurd value, the same split SetRole/ValidRole use.
	SetQuota(ctx context.Context, quota Quota) error
	// GetQuota returns ok=false (not an error) when projectID has no
	// quota row -- the unbounded state ADR-031 §3 deliberately defines,
	// not a failure.
	GetQuota(ctx context.Context, projectID string) (quota Quota, ok bool, err error)
	// CommittedUsage sums the reservation this project's currently-open
	// workloads already hold, mirroring internal/workloadapi's own
	// "open, provider-assigned" state list so a quota check reflects the
	// exact same notion of "in flight" as the provider-capacity ceiling
	// does.
	CommittedUsage(ctx context.Context, projectID string) (Usage, error)
}

// CheckQuota reports whether committing an additional allocation to
// projectID would stay within its configured quota. A project with no
// quota row (GetQuota's ok=false) is unbounded -- CheckQuota returns nil
// immediately without even reading committed usage, since there is
// nothing to check against. This is the "quota storage and check
// primitive" issue #23 asks for; #24/#25/#26 call it at their own
// commit-time (workload/volume/port creation) the same way
// internal/workloadapi already calls its provider-capacity check.
func CheckQuota(ctx context.Context, repository Repository, projectID string, additional Usage) error {
	quota, ok, err := repository.GetQuota(ctx, projectID)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	committed, err := repository.CommittedUsage(ctx, projectID)
	if err != nil {
		return err
	}
	if projected := committed.CPUMillicores + additional.CPUMillicores; projected > quota.MaxCPUMillicores {
		return quotaExceededf("cpu_millicores", projected, quota.MaxCPUMillicores)
	}
	if projected := committed.RAMMB + additional.RAMMB; projected > quota.MaxRAMMB {
		return quotaExceededf("ram_mb", projected, quota.MaxRAMMB)
	}
	if projected := committed.StorageGB + additional.StorageGB; projected > quota.MaxStorageGB {
		return quotaExceededf("storage_gb", projected, quota.MaxStorageGB)
	}
	if projected := int64(committed.Workloads) + int64(additional.Workloads); projected > int64(quota.MaxWorkloads) {
		return quotaExceededf("workloads", projected, int64(quota.MaxWorkloads))
	}
	return nil
}

func quotaExceededf(dimension string, requested, limit int64) error {
	return &quotaError{dimension: dimension, requested: requested, limit: limit}
}

// quotaError carries the specific dimension/numbers a CheckQuota failure
// names, while still satisfying errors.Is(err, ErrQuotaExceeded) for
// callers that only care that quota was exceeded, not which dimension.
type quotaError struct {
	dimension        string
	requested, limit int64
}

func (e *quotaError) Error() string {
	return ErrQuotaExceeded.Error() + ": " + e.dimension
}
func (e *quotaError) Unwrap() error { return ErrQuotaExceeded }

// QuotaErrorDetail extracts the dimension/requested/limit a CheckQuota
// failure carries, for a caller (e.g. an HTTP handler) that wants to
// report specifics rather than just the generic ErrQuotaExceeded message.
// ok is false for any error that isn't one CheckQuota produced.
func QuotaErrorDetail(err error) (dimension string, requested, limit int64, ok bool) {
	var qe *quotaError
	if !errors.As(err, &qe) {
		return "", 0, 0, false
	}
	return qe.dimension, qe.requested, qe.limit, true
}

// NewQuotaExceededError builds the identical *quotaError CheckQuota
// itself returns (same errors.Is(err, ErrQuotaExceeded) and
// QuotaErrorDetail behavior), for a caller that must reproduce
// CheckQuota's per-dimension check atomically with its own write instead
// of calling CheckQuota as a separate, unlocked step beforehand --
// exactly the fix internal/openstackapi/cinder.PostgresRepository.
// CreateVolume makes (issue #26 security review: an unlocked
// CheckQuota-then-insert let 20 concurrent 5GB volume creates against a
// 10GB quota commit 55-60GB). Exported so that fix (and any future one
// needing the same shape) doesn't have to hand-roll a second error type
// that could drift from CheckQuota's own.
func NewQuotaExceededError(dimension string, requested, limit int64) error {
	return quotaExceededf(dimension, requested, limit)
}
