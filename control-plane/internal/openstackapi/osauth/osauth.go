// Package osauth is the reusable half of internal/openstackapi's identity
// bridge (ADR-031 §3, issue #23): a Keystone-shaped JSON error writer and
// a token-validation middleware, both designed to be imported by every
// future service package under internal/openstackapi (#24 Nova, #25
// Neutron, #26 Glance/Cinder) the same way this package's own
// internal/openstackapi/keystone already does -- so "how do I check the
// caller's token and get their identity" is answered exactly once for
// the whole OpenStack-compatible surface.
//
// This is a leaf package deliberately: internal/openstackapi (the
// top-level Server/Handler) imports internal/openstackapi/keystone, and
// both import this package -- osauth must never import either of them,
// or that becomes an import cycle.
package osauth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/openinfra/network/internal/userauth"
)

// Identity is what RequireToken resolves a valid token to, and attaches
// to the request context for the wrapped handler to read via
// FromContext.
type Identity struct {
	UserID string
	// ProjectID is nil for an unscoped token -- a caller reaching a
	// route that requires project scope must check this itself
	// (ScopeRequired below exists for exactly that), since osauth has no
	// way to know which routes need scoping and which don't.
	ProjectID *string
	Role      string
}

type identityContextKey struct{}

// FromContext returns the Identity RequireToken resolved for this
// request. ok is false only if called from a handler that was not
// wrapped in RequireToken -- a programming error in a future route
// registration, not an expected runtime case, mirroring
// internal/dashboard/rbac.go's userFromContext.
func FromContext(ctx context.Context) (Identity, bool) {
	identity, ok := ctx.Value(identityContextKey{}).(Identity)
	return identity, ok
}

// TokenAuthenticator is the exact subset of userauth.Repository this
// package needs -- accepting userauth.Repository directly (Go interfaces
// are structural) rather than requiring a caller to adapt it.
type TokenAuthenticator interface {
	AuthenticateScoped(ctx context.Context, hash [32]byte) (userauth.User, *string, error)
}

// authTokenHeader is where every OpenStack service (other than the
// token-issuing/validating Keystone endpoints themselves, which use
// X-Subject-Token -- see internal/openstackapi/keystone) expects the
// caller's bearer token, per the real Keystone wire protocol.
const authTokenHeader = "X-Auth-Token"

// RequireToken wraps next so it only runs for a request carrying a
// valid, unexpired, unrevoked token in X-Auth-Token -- fails closed
// (401, Keystone-shaped error body) on anything else: missing header,
// unknown/expired/revoked token, or a repository error. A repository
// error must never be treated as "let the request through" -- the same
// fail-closed posture internal/userauth's gRPC interceptor already
// applies to a repository failure.
func RequireToken(users TokenAuthenticator, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw := r.Header.Get(authTokenHeader)
		if raw == "" {
			WriteError(w, http.StatusUnauthorized, "Unauthorized", "X-Auth-Token is required")
			return
		}
		user, projectID, err := users.AuthenticateScoped(r.Context(), userauth.HashAPIKey(raw))
		if err != nil {
			// Every failure reason (unknown, revoked, expired, repository
			// unavailable) is surfaced identically -- the same
			// don't-build-an-oracle reasoning userauth.authenticate and
			// internal/dashboard.authenticatedUser already apply to the
			// existing API-key bearer path this token *is*, underneath.
			WriteError(w, http.StatusUnauthorized, "Unauthorized", "The request you have made requires authentication.")
			return
		}
		identity := Identity{UserID: user.UserID, ProjectID: projectID, Role: user.Role}
		next(w, r.WithContext(context.WithValue(r.Context(), identityContextKey{}, identity)))
	}
}

// keystoneError is the real Keystone v3 error body shape
// (`{"error": {"code": ..., "title": ..., "message": ...}}`) -- ADR-031
// §1 requires every unsupported/failing operation to fail exactly the
// way a real OpenStack deployment fails, not a differently-shaped
// OpenInfra error, so a client program can tell "this cloud doesn't have
// that feature" apart from "this isn't really OpenStack."
type keystoneError struct {
	Error keystoneErrorBody `json:"error"`
}
type keystoneErrorBody struct {
	Code    int    `json:"code"`
	Title   string `json:"title"`
	Message string `json:"message"`
}

// WriteError writes a Keystone-shaped JSON error body with status code.
// title is Keystone's short reason phrase ("Unauthorized", "Bad
// Request", "Not Found", ...); message is the longer, still-generic
// explanation -- never include the raw token, credential, or any
// tenant-private data in either field, matching AGENTS.md's "never log
// secrets" rule extended to error responses.
func WriteError(w http.ResponseWriter, status int, title, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(keystoneError{Error: keystoneErrorBody{Code: status, Title: title, Message: message}})
}

// BearerFromHeader extracts a raw token from an "X-Auth-Token" style
// header value with no scheme prefix (Keystone tokens are presented
// bare, unlike the ControlPlaneService's "Authorization: Bearer ..."
// convention) -- exported so keystone's own X-Subject-Token handling can
// share the same "empty means absent" trimming rule.
func BearerFromHeader(value string) (string, bool) {
	trimmed := strings.TrimSpace(value)
	return trimmed, trimmed != ""
}
