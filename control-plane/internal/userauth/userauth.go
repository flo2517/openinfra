// Package userauth authenticates the user-facing half of ControlPlaneService
// (SubmitWorkload/GetWorkload/StopWorkload) with a bearer API key layered on
// top of the existing mTLS transport, and carries the resulting user
// identity through context for tenancy checks downstream in workloadapi.
//
// This deliberately does not touch the mTLS PKI itself (client CA, cert
// issuance/rotation/revocation): that redesign is separate, still-open work
// tracked by issue #13. Provider Agent RPCs (BeginJoin/CompleteJoin/
// ReportHeartbeat) keep their own Ed25519 challenge-signature auth and are
// untouched by this package.
package userauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"
)

// ErrInvalidKey covers every reason a presented API key is unusable --
// unknown, revoked, or expired -- collapsed into one error so callers can't
// build an oracle that distinguishes "wrong key" from "right key, expired"
// by timing or response shape. Repository implementations that want to log
// the specific reason do so themselves, keyed by key_id/prefix, never by
// the raw key.
var ErrInvalidKey = errors.New("invalid or expired API key")

// ErrUserNotFound is SetRole's failure for a user_id that does not exist
// -- deliberately a distinct error from ErrInvalidKey, since granting a
// role is an operator (cmd/controlplane-admin) action against a known
// user_id, not a credential check with the same "don't leak which part
// was wrong" concern ErrInvalidKey exists for.
var ErrUserNotFound = errors.New("user not found")

// keyPrefix marks OpenInfra user API keys recognizably in logs/tooling
// output, the same spirit as GitHub's "ghp_" or Stripe's "sk_" prefixes.
const keyPrefix = "oiu_"

// rawKeyBytes is the random secret portion's length; 32 bytes gives 256
// bits of entropy, comfortably beyond brute-force range even hashed with a
// fast, non-memory-hard hash (fine here: the input space is the attacker's
// bottleneck, not the hash's cost, unlike a low-entropy user password).
const rawKeyBytes = 32

// User is a tenant identity. Nothing else in the MVP hangs off it yet
// (no profile, no email) -- it exists to give workloads a stable owner.
type User struct {
	UserID      string
	DisplayName string
	CreatedAt   time.Time
	// Role is ADR-016's dashboard-authorization tier: RoleTenant (the
	// default for every user, existing or new), RoleOperatorReadOnly, or
	// RoleOperatorAdmin (both only reachable via an explicit
	// controlplane-admin grant-role). Distinct from anything about
	// API-key scoping -- this field governs what a browser dashboard
	// session may see, not what the gRPC user-facing API already scopes
	// by owner_id.
	Role string
}

// RoleTenant, RoleOperatorReadOnly, and RoleOperatorAdmin are the only
// three values users.role's CHECK constraint
// (migrations/000013_operator_role_levels.sql) allows. ADR-016 §1
// originally assumed a single operator tier was enough for the MVP;
// §7 question 3 resolved that a read-only/admin split was needed instead
// (grant-any-visibility vs. grant-destructive-action, e.g. stop-any-
// workload or revoke-any-key, are different trust levels worth granting
// separately) before slice 4's operator views ship.
const (
	RoleTenant           = "tenant"
	RoleOperatorReadOnly = "operator_readonly"
	RoleOperatorAdmin    = "operator_admin"
)

// ValidRole reports whether role is one of the roles this system
// recognizes -- used by both SetRole implementations and
// cmd/controlplane-admin's grant-role argument parsing, so "reject an
// unknown role" is defined exactly once.
func ValidRole(role string) bool {
	return role == RoleTenant || role == RoleOperatorReadOnly || role == RoleOperatorAdmin
}

// roleRank orders roles for internal/dashboard's requireRole check:
// higher ranks satisfy lower-or-equal requirements (an operator-admin may
// reach a tenant- or operator-readonly-tier endpoint; an operator-
// readonly may reach a tenant-tier endpoint but never an operator-admin
// one; a tenant may never reach either operator tier). Unexported here
// deliberately -- RoleSatisfies below is the only intended way to
// compare roles, so the ranking itself can be restructured later (e.g. a
// fourth tier) without every caller needing to know it's backed by
// integers.
var roleRank = map[string]int{RoleTenant: 1, RoleOperatorReadOnly: 2, RoleOperatorAdmin: 3}

// RoleSatisfies reports whether actual is at least as privileged as
// required. An unrecognized actual role (should not happen once
// ValidRole is enforced at every write path, but this must still fail
// closed rather than panic or vacuously succeed on a corrupt/future
// value) never satisfies anything -- explicitly checked via ValidRole
// rather than relying on roleRank's zero-value-for-a-missing-key
// behavior, which would otherwise let two equally-unrecognized values
// compare as satisfying each other.
func RoleSatisfies(actual, required string) bool {
	if !ValidRole(actual) {
		return false
	}
	return roleRank[actual] >= roleRank[required]
}

// APIKey is a credential a User authenticates with. Raw is populated only
// at creation time, returned once, and never persisted or logged again.
type APIKey struct {
	KeyID     string
	UserID    string
	Prefix    string
	Raw       string
	CreatedAt time.Time
	ExpiresAt *time.Time
	// ProjectID is set only for a key minted by CreateAPIKeyForProject
	// (ADR-031 §3's Keystone-token bridge) -- nil for every key created
	// through the pre-existing CreateAPIKey/CreateAPIKeyWithExpiry paths,
	// which describe an unscoped credential exactly as before this field
	// was added.
	ProjectID *string
}

// GenerateAPIKey mints a new random credential and its storable hash.
// Callers persist Hash, never Raw.
func GenerateAPIKey() (raw string, hash [32]byte, prefix string, err error) {
	secret := make([]byte, rawKeyBytes)
	if _, err := rand.Read(secret); err != nil {
		return "", [32]byte{}, "", err
	}
	raw = keyPrefix + hex.EncodeToString(secret)
	hash = HashAPIKey(raw)
	prefix = raw[:8]
	return raw, hash, prefix, nil
}

// HashAPIKey deterministically maps a raw key to its storable form. Never
// log or persist the raw key itself, only this hash (and, for
// human-readable identification, the short prefix returned alongside it at
// creation).
func HashAPIKey(raw string) [32]byte {
	return sha256.Sum256([]byte(raw))
}

// Repository is the persistence surface userauth needs. CreateUser and
// CreateAPIKey are admin operations (see cmd/controlplane-admin) for a
// user who reaches the system without a wallet; a user who logs in via a
// wallet (ADR-014, package walletlogin) is instead auto-provisioned on
// first successful login -- that self-service path lives in walletlogin,
// not here, to keep this package's own scope at "authenticate a bearer
// key," not "every way a user identity can come to exist."
type Repository interface {
	CreateUser(ctx context.Context, displayName string) (User, error)
	CreateAPIKey(ctx context.Context, userID string) (APIKey, error)
	// CreateAPIKeyWithExpiry is CreateAPIKey with an explicit expiry (nil
	// means no expiry, identical to CreateAPIKey). Used by wallet login
	// (ADR-014) to mint short-lived session keys without needing a
	// separate revocation mechanism -- an expired session key simply
	// stops authenticating, the same check every key already goes
	// through in Authenticate.
	CreateAPIKeyWithExpiry(ctx context.Context, userID string, expiresAt *time.Time) (APIKey, error)
	// CreateAPIKeyForProject is CreateAPIKeyWithExpiry plus a recorded
	// project scope (migration 000017's api_keys.project_id) -- ADR-031
	// §3's Keystone-token bridge: a scoped Keystone token *is*, one more
	// api_keys row, distinguished from an unscoped one only by this
	// column. Callers (internal/openstackapi/keystone) are responsible
	// for having already verified the user holds a project_memberships
	// row for projectID before calling this -- it does not itself check
	// membership, the same way CreateAPIKeyWithExpiry does not itself
	// check that userID exists.
	CreateAPIKeyForProject(ctx context.Context, userID, projectID string, expiresAt *time.Time) (APIKey, error)
	// Authenticate resolves a raw key's hash to its owning user, or
	// ErrInvalidKey if the key is unknown, revoked, or expired. On
	// success it best-effort records last_used_at; a failure to do so
	// must not fail authentication itself. Equivalent to AuthenticateScoped
	// with the project scope discarded -- every existing caller (the gRPC
	// interceptor, internal/dashboard) wants exactly this, unscoped,
	// contract and is unaffected by AuthenticateScoped's addition.
	Authenticate(ctx context.Context, hash [32]byte) (User, error)
	// AuthenticateScoped is Authenticate plus the presented key's project
	// scope (nil for an unscoped key) -- internal/openstackapi's
	// token-validation middleware (ADR-031 §3) needs the scope to resolve
	// which project a Keystone-bridged token grants access to; every
	// other caller uses Authenticate instead and never sees this.
	AuthenticateScoped(ctx context.Context, hash [32]byte) (User, *string, error)
	RevokeAPIKey(ctx context.Context, keyID string) error
	// RevokeAPIKeyByHash revokes a key identified by its hash rather than
	// its key_id -- internal/openstackapi/keystone's DELETE
	// /v3/auth/tokens (token revocation) only ever has the raw
	// X-Subject-Token a client presents, never the internal key_id
	// RevokeAPIKey expects.
	RevokeAPIKeyByHash(ctx context.Context, hash [32]byte) error
	// SetRole is ADR-016's grant path (cmd/controlplane-admin's
	// grant-role): an operator-only, offline, break-glass action, the
	// same trust boundary create-user/issue-key already require -- there
	// is deliberately no self-service way for a user to grant themselves
	// (or anyone else) the operator role. Returns ErrUserNotFound for an
	// unknown userID; callers are expected to have already validated
	// role via ValidRole before calling.
	SetRole(ctx context.Context, userID string, role string) error
}

type contextKey int

const userIDKey contextKey = 0

// WithUserID attaches an authenticated caller's user ID to ctx.
func WithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, userIDKey, userID)
}

// UserIDFromContext returns the authenticated caller's user ID, if the
// interceptor ran and accepted a key for this call.
func UserIDFromContext(ctx context.Context) (string, bool) {
	userID, ok := ctx.Value(userIDKey).(string)
	return userID, ok && userID != ""
}
