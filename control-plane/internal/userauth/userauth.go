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
// CreateAPIKey are admin operations (see cmd/controlplane-admin), not
// exposed over gRPC in the MVP -- there is no self-service registration
// RPC, matching the "no PKI redesign" scope boundary above.
type Repository interface {
	CreateUser(ctx context.Context, displayName string) (User, error)
	CreateAPIKey(ctx context.Context, userID string) (APIKey, error)
	// Authenticate resolves a raw key's hash to its owning user, or
	// ErrInvalidKey if the key is unknown, revoked, or expired. On
	// success it best-effort records last_used_at; a failure to do so
	// must not fail authentication itself.
	Authenticate(ctx context.Context, hash [32]byte) (User, error)
	RevokeAPIKey(ctx context.Context, keyID string) error
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
