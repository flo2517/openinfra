package dashboard

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/openinfra/network/internal/userauth"
	"github.com/openinfra/network/internal/walletlogin"
)

// maxAuthBodyBytes bounds every auth endpoint's request body -- none of
// these payloads legitimately exceeds a few hundred bytes (a UUID, a
// 32-byte account, a 64-byte signature, all hex-encoded), so this is a
// generous ceiling against an oversized-body abuse attempt, not a tight
// fit to the expected shape.
const maxAuthBodyBytes = 4096

// authChallenge issues a fresh login challenge (ADR-014 §1). No auth
// required by definition -- this is where a login begins -- so it is
// rate-limited by caller IP instead.
func (s *Server) authChallenge(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if !s.allowRate(ctx, w, r, "auth-challenge") {
		return
	}
	challenge, err := s.wallet.NewChallenge(ctx)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "challenge issuance unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"challenge_id": challenge.ChallengeID,
		"nonce":        hex.EncodeToString(challenge.Nonce[:]),
		"expires_at":   challenge.ExpiresAt.Format(time.RFC3339),
	})
}

type loginRequest struct {
	ChallengeID string `json:"challenge_id"`
	Account     string `json:"account"`
	Scheme      int    `json:"scheme"`
	Signature   string `json:"signature"`
}

// authLogin verifies a signed challenge and, on success, returns a
// short-lived session key (ADR-014 §5). Every failure reason -- bad
// input, unknown challenge, wrong signature, unsupported scheme --
// returns the same 401 with the same generic message: a login endpoint
// must not give a caller a way to distinguish "this account doesn't
// exist" from "wrong signature" from "challenge expired," the same
// oracle concern userauth.authenticate already applies to API keys.
func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if !s.allowRate(ctx, w, r, "auth-login") {
		return
	}
	var request loginRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxAuthBodyBytes)).Decode(&request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if _, err := uuid.Parse(request.ChallengeID); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "challenge_id must be a UUID"})
		return
	}
	accountBytes, err := hex.DecodeString(request.Account)
	if err != nil || len(accountBytes) != ed25519.PublicKeySize {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "account must be 32 bytes, hex-encoded"})
		return
	}
	signature, err := hex.DecodeString(request.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "signature must be a 64-byte Ed25519 signature, hex-encoded"})
		return
	}
	var account [32]byte
	copy(account[:], accountBytes)

	session, err := s.wallet.Login(ctx, request.ChallengeID, account, walletlogin.Scheme(request.Scheme), signature)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]any{
			"session_key": session.APIKey,
			"expires_at":  session.ExpiresAt.Format(time.RFC3339),
		})
	case errors.Is(err, walletlogin.ErrChallengeNotFound),
		errors.Is(err, walletlogin.ErrInvalidSignature),
		errors.Is(err, walletlogin.ErrSchemeNotSupported):
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login failed"})
	default:
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "login unavailable"})
	}
}

// authIssueAPIKey mints a long-lived (no-expiry) API key for the caller's
// own account (ADR-014 §6) -- self-service, replacing
// cmd/controlplane-admin's issue-key as the primary path for a user who
// reaches the system through a wallet login first. Requires an
// Authorization: Bearer header carrying a still-valid key (a session key
// from authLogin, or an existing long-lived one) -- reuses
// userauth.Repository.Authenticate directly rather than a new
// verification path.
func (s *Server) authIssueAPIKey(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	userID, ok := s.authenticatedUserID(ctx, r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}
	key, err := s.users.CreateAPIKey(ctx, userID)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "key issuance unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"api_key": key.Raw, "key_id": key.KeyID})
}

// SessionIdentity is GET /api/v1/me's response body: who the presented
// credential belongs to, and which ADR-016 tier it holds.
type SessionIdentity struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
}

// authMe answers "who am I, and what am I allowed to see" for the
// credential on this request. The dashboard client needs it to decide
// whether to render the operator panel at all: without it the client's
// only way to discover its own tier is to fire a request at an
// operator-gated endpoint and read the status code, which cannot tell
// "you are a tenant" (403) apart from "Postgres is down" (503).
//
// This is a rendering hint, never an authorization decision. Every
// operator route stays gated server-side by requireRole; a client that
// lies to itself about its role gets 403s from the endpoints, not data.
//
// Deliberately NOT wrapped in requireRole(RoleTenant), even though every
// valid role satisfies it: RoleSatisfies fails closed on a role it does
// not recognize, so a user whose role somehow fell outside the known set
// would get a 403 here and the client could not distinguish that from
// "not logged in". Answering with the role we actually hold lets the UI
// say "your account has no operator access" instead of breaking.
//
// The role is read fresh per request rather than baked into the login
// response, so an operator grant (or revocation) through
// cmd/controlplane-admin takes effect on the next page load instead of
// waiting for the user's session to expire.
func (s *Server) authMe(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	user, ok := s.authenticatedUser(ctx, r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}
	writeJSON(w, http.StatusOK, SessionIdentity{UserID: user.UserID, Role: user.Role})
}

func (s *Server) authenticatedUserID(ctx context.Context, r *http.Request) (string, bool) {
	user, ok := s.authenticatedUser(ctx, r)
	if !ok {
		return "", false
	}
	return user.UserID, true
}

// authenticatedUser is authenticatedUserID's superset: the full
// userauth.User (including Role, ADR-016), for callers that need more
// than just the ID -- currently only requireRole (rbac.go), which needs
// Role. Kept as the one bearer-token-parsing implementation rather than
// duplicating it, with authenticatedUserID as a thin wrapper so its
// existing callers/behavior are unchanged.
func (s *Server) authenticatedUser(ctx context.Context, r *http.Request) (userauth.User, bool) {
	const prefix = "Bearer "
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, prefix) {
		return userauth.User{}, false
	}
	raw := strings.TrimPrefix(header, prefix)
	if raw == "" {
		return userauth.User{}, false
	}
	user, err := s.users.Authenticate(ctx, userauth.HashAPIKey(raw))
	if err != nil {
		return userauth.User{}, false
	}
	return user, true
}

// allowRate applies the per-endpoint abuse rate limit, keyed by caller
// IP -- these three endpoints are the only unauthenticated ones on this
// listener that do real work (a Postgres write, or a signature
// verification) per request, unlike /api/v1/overview's read-only cost.
// Fails closed: a limiter error denies the request rather than silently
// permitting unbounded load, matching userauth's interceptor.
func (s *Server) allowRate(ctx context.Context, w http.ResponseWriter, r *http.Request, action string) bool {
	if s.limiter == nil {
		return true
	}
	allowed, err := s.limiter.Allow(ctx, action+":"+clientIP(r))
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "rate limiter unavailable"})
		return false
	}
	if !allowed {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded"})
		return false
	}
	return true
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
