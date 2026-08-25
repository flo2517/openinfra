// Package keystone implements ADR-031 §3's Keystone v3 token bridge
// (issue #23): POST/GET/DELETE /v3/auth/tokens, backed entirely by
// internal/userauth's existing API-key mechanism and
// internal/projects' project/membership model -- no Fernet, no PKI
// token bytes, no separate credential-issuance system, per the ADR's
// explicit decision.
package keystone

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/openinfra/network/internal/openstackapi/osauth"
	"github.com/openinfra/network/internal/projects"
	"github.com/openinfra/network/internal/userauth"
)

// maxRequestBodyBytes bounds every handler's request body -- an
// auth-tokens request is a handful of UUIDs/strings, never legitimately
// larger than a few hundred bytes; this is a generous ceiling against an
// oversized-body abuse attempt, the same maxAuthBodyBytes precedent
// internal/dashboard/auth.go already sets for its own auth endpoints.
const maxRequestBodyBytes = 16 << 10

// tokenTTL is how long a Keystone-bridged token lasts -- matches real
// Keystone's own default (Fernet tokens expire after one hour), and is
// deliberately much shorter than the no-expiry, long-lived keys
// controlplane-admin issue-key/internal/dashboard's authIssueAPIKey mint
// for direct API use: a Keystone client expects a token, a credential
// that expires and must be refreshed, not a permanent secret.
const tokenTTL = time.Hour

// Users is the subset of userauth.Repository this package needs.
// Accepting userauth.Repository directly at construction time (New,
// below) satisfies this interface structurally -- declared narrowly here
// so a future test fake only has to implement what this package actually
// calls.
type Users interface {
	osauth.TokenAuthenticator
	CreateAPIKeyWithExpiry(ctx context.Context, userID string, expiresAt *time.Time) (userauth.APIKey, error)
	CreateAPIKeyForProject(ctx context.Context, userID, projectID string, expiresAt *time.Time) (userauth.APIKey, error)
	RevokeAPIKeyByHash(ctx context.Context, hash [32]byte) error
}

// Projects is the subset of projects.Repository this package needs.
type Projects interface {
	GetProject(ctx context.Context, projectID string) (projects.Project, error)
	GetProjectByName(ctx context.Context, name string) (projects.Project, error)
	GetMembership(ctx context.Context, projectID, userID string) (projects.Membership, error)
}

// AuditRecorder is called for every token issue/revoke attempt, success
// or denial -- issue #23's "strict tenant isolation and audit events"
// acceptance criterion. Deliberately a narrow function type rather than
// depending on internal/dashboard's own recordAudit (unexported, and
// dashboard is an HTTP-surface package this one must not import) -- the
// caller (internal/openstackapi's Server) wires this to a shared
// audit_events writer (migration 000014) so both HTTP surfaces append to
// the same table.
type AuditRecorder func(ctx context.Context, actorUserID, action, targetType, targetID, outcome string)

// Server holds keystone's handler dependencies. Constructed once by
// internal/openstackapi.New and registered via Register.
type Server struct {
	users    Users
	projects Projects
	audit    AuditRecorder
	now      func() time.Time
	baseURL  string
}

// New builds a keystone Server. audit may be nil (a no-op is used),
// matching how internal/dashboard.Server tolerates a nil RateLimiter.
func New(users Users, projectsRepo Projects, baseURL string, audit AuditRecorder) *Server {
	if audit == nil {
		audit = func(context.Context, string, string, string, string, string) {}
	}
	return &Server{users: users, projects: projectsRepo, audit: audit, now: time.Now, baseURL: baseURL}
}

// Register adds this package's routes to mux -- the pattern every future
// internal/openstackapi/{nova,neutron,glance,cinder} package (#24-#26)
// follows, called once from internal/openstackapi.Server.Handler().
func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /v3/auth/tokens", s.issueToken)
	mux.HandleFunc("GET /v3/auth/tokens", s.validateToken)
	mux.HandleFunc("DELETE /v3/auth/tokens", s.revokeToken)
}

// authTokensRequest is the real Keystone v3 POST /v3/auth/tokens request
// body shape -- only the fields this bridge actually reads are
// unmarshaled; every other field a real client sends (e.g. a second
// identity method) is silently ignored, not rejected, matching how a
// real Keystone deployment tolerates fields it doesn't need.
type authTokensRequest struct {
	Auth struct {
		Identity struct {
			Methods  []string `json:"methods"`
			Password *struct {
				User struct {
					ID       string `json:"id"`
					Name     string `json:"name"`
					Password string `json:"password"`
				} `json:"user"`
			} `json:"password"`
			Token *struct {
				ID string `json:"id"`
			} `json:"token"`
		} `json:"identity"`
		Scope *struct {
			Project *struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"project"`
		} `json:"scope"`
	} `json:"auth"`
}

// issueToken is POST /v3/auth/tokens: bridges either a "password" method
// (the password field carries the raw oiu_-prefixed API key -- ADR-031
// §3 does not implement real username/password auth, only the wire
// shape) or a "token" method (re-scope an existing token) onto
// userauth.Repository.AuthenticateScoped, then mints a fresh,
// tokenTTL-bounded API key -- project-scoped via
// CreateAPIKeyForProject if the request carries a scope the caller is
// actually a member of, unscoped otherwise.
func (s *Server) issueToken(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var request authTokensRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxRequestBodyBytes)).Decode(&request); err != nil {
		osauth.WriteError(w, http.StatusBadRequest, "Bad Request", "invalid request body")
		return
	}

	raw, method, ok := credentialFromRequest(request)
	if !ok {
		osauth.WriteError(w, http.StatusBadRequest, "Bad Request", "identity.methods must be exactly one of \"password\" or \"token\", with a matching identity.password or identity.token body")
		return
	}

	user, _, err := s.users.AuthenticateScoped(ctx, userauth.HashAPIKey(raw))
	if err != nil {
		s.audit(ctx, "", "openstack.token.issue", "user", "", "denied")
		osauth.WriteError(w, http.StatusUnauthorized, "Unauthorized", "The request you have made requires authentication.")
		return
	}

	var scopedProject *projects.Project
	if request.Auth.Scope != nil && request.Auth.Scope.Project != nil {
		project, membership, resolveErr := s.resolveScope(ctx, user.UserID, *request.Auth.Scope.Project)
		if resolveErr != nil {
			s.audit(ctx, user.UserID, "openstack.token.issue", "project", scopeIdentifier(*request.Auth.Scope.Project), "denied")
			// Fail closed and generic: whether the project doesn't exist
			// or the caller simply isn't a member of it must look
			// identical, so a scoping attempt can't be used to enumerate
			// which project IDs/names exist (ADR-031's threat model
			// section, and the same reasoning ErrNotAMember's doc comment
			// states).
			osauth.WriteError(w, http.StatusUnauthorized, "Unauthorized", "You are not authorized to perform the requested action: scope.project.")
			return
		}
		scopedProject = &project
		_ = membership
	}

	expiresAt := s.now().Add(tokenTTL).UTC()
	var key userauth.APIKey
	if scopedProject != nil {
		key, err = s.users.CreateAPIKeyForProject(ctx, user.UserID, scopedProject.ProjectID, &expiresAt)
	} else {
		key, err = s.users.CreateAPIKeyWithExpiry(ctx, user.UserID, &expiresAt)
	}
	if err != nil {
		slog.Error("keystone: token issuance failed", "error", err)
		s.audit(ctx, user.UserID, "openstack.token.issue", "project", projectIDOrEmpty(scopedProject), "error")
		osauth.WriteError(w, http.StatusServiceUnavailable, "Service Unavailable", "token issuance unavailable")
		return
	}

	role := ""
	if scopedProject != nil {
		membership, membershipErr := s.projects.GetMembership(ctx, scopedProject.ProjectID, user.UserID)
		if membershipErr == nil {
			role = membership.Role
		}
	}

	s.audit(ctx, user.UserID, "openstack.token.issue", "project", projectIDOrEmpty(scopedProject), "success")

	body := tokenResponseBody(s.baseURL, user, method, s.now(), expiresAt, scopedProject, role)
	w.Header().Set("X-Subject-Token", key.Raw)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(body)
}

// validateToken is GET /v3/auth/tokens: resolves the token in
// X-Subject-Token and returns the same token-shaped body issueToken
// would have returned, without minting a new credential -- real
// Keystone's "validate a token" operation.
func (s *Server) validateToken(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	raw, ok := osauth.BearerFromHeader(r.Header.Get("X-Subject-Token"))
	if !ok {
		osauth.WriteError(w, http.StatusBadRequest, "Bad Request", "X-Subject-Token is required")
		return
	}
	user, projectID, err := s.users.AuthenticateScoped(ctx, userauth.HashAPIKey(raw))
	if err != nil {
		osauth.WriteError(w, http.StatusUnauthorized, "Unauthorized", "Could not find token.")
		return
	}

	var scopedProject *projects.Project
	role := ""
	if projectID != nil {
		project, getErr := s.projects.GetProject(ctx, *projectID)
		if getErr == nil {
			scopedProject = &project
			if membership, membershipErr := s.projects.GetMembership(ctx, *projectID, user.UserID); membershipErr == nil {
				role = membership.Role
			}
		}
	}

	body := tokenResponseBody(s.baseURL, user, "token", s.now(), s.now().Add(tokenTTL), scopedProject, role)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(body)
}

// revokeToken is DELETE /v3/auth/tokens: revokes the token named by
// X-Subject-Token. Idempotent-failure, not idempotent-success: revoking
// an already-revoked (or never-issued) token reports 404, the same
// "don't silently succeed twice" posture
// TestRevokeAPIKeyByHashRevokesAndIsNotReplayable pins at the storage
// layer.
func (s *Server) revokeToken(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	raw, ok := osauth.BearerFromHeader(r.Header.Get("X-Subject-Token"))
	if !ok {
		osauth.WriteError(w, http.StatusBadRequest, "Bad Request", "X-Subject-Token is required")
		return
	}
	hash := userauth.HashAPIKey(raw)
	// Resolve the owning user first, purely so the audit row names who
	// revoked it -- RevokeAPIKeyByHash below is the actual enforcement
	// and does not depend on this lookup succeeding.
	user, _, _ := s.users.AuthenticateScoped(ctx, hash)

	if err := s.users.RevokeAPIKeyByHash(ctx, hash); err != nil {
		if errors.Is(err, userauth.ErrInvalidKey) {
			s.audit(ctx, user.UserID, "openstack.token.revoke", "user", user.UserID, "denied")
			osauth.WriteError(w, http.StatusNotFound, "Not Found", "Could not find token.")
			return
		}
		slog.Error("keystone: token revocation failed", "error", err)
		s.audit(ctx, user.UserID, "openstack.token.revoke", "user", user.UserID, "error")
		osauth.WriteError(w, http.StatusServiceUnavailable, "Service Unavailable", "token revocation unavailable")
		return
	}
	s.audit(ctx, user.UserID, "openstack.token.revoke", "user", user.UserID, "success")
	w.WriteHeader(http.StatusNoContent)
}

// resolveScope resolves a Keystone scope.project request (by ID or name)
// to a Project the caller actually holds a project_memberships row for
// -- ErrNotAMember and ErrProjectNotFound (projects package) are the two
// possible failures, deliberately not distinguished by the caller (see
// issueToken's comment on why).
func (s *Server) resolveScope(ctx context.Context, userID string, scope struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}) (projects.Project, projects.Membership, error) {
	var project projects.Project
	var err error
	if scope.ID != "" {
		project, err = s.projects.GetProject(ctx, scope.ID)
	} else if scope.Name != "" {
		project, err = s.projects.GetProjectByName(ctx, scope.Name)
	} else {
		return projects.Project{}, projects.Membership{}, errors.New("scope.project requires id or name")
	}
	if err != nil {
		return projects.Project{}, projects.Membership{}, err
	}
	membership, err := s.projects.GetMembership(ctx, project.ProjectID, userID)
	if err != nil {
		return projects.Project{}, projects.Membership{}, err
	}
	return project, membership, nil
}

// credentialFromRequest extracts the raw credential (bridged onto an
// oiu_-prefixed API key) and the identity method name from a decoded
// request -- ok is false for any shape this bridge doesn't recognize
// (issue #23 supports exactly "password" and "token", not Keystone's
// other methods like "totp" or "application_credential").
func credentialFromRequest(request authTokensRequest) (raw, method string, ok bool) {
	for _, candidate := range request.Auth.Identity.Methods {
		switch candidate {
		case "password":
			if request.Auth.Identity.Password == nil || request.Auth.Identity.Password.User.Password == "" {
				continue
			}
			return request.Auth.Identity.Password.User.Password, "password", true
		case "token":
			if request.Auth.Identity.Token == nil || request.Auth.Identity.Token.ID == "" {
				continue
			}
			return request.Auth.Identity.Token.ID, "token", true
		}
	}
	return "", "", false
}

func scopeIdentifier(scope struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}) string {
	if scope.ID != "" {
		return scope.ID
	}
	return scope.Name
}

func projectIDOrEmpty(project *projects.Project) string {
	if project == nil {
		return ""
	}
	return project.ProjectID
}
