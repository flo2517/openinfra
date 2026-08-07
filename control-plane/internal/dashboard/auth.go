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

func (s *Server) authenticatedUserID(ctx context.Context, r *http.Request) (string, bool) {
	const prefix = "Bearer "
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, prefix) {
		return "", false
	}
	raw := strings.TrimPrefix(header, prefix)
	if raw == "" {
		return "", false
	}
	user, err := s.users.Authenticate(ctx, userauth.HashAPIKey(raw))
	if err != nil {
		return "", false
	}
	return user.UserID, true
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
