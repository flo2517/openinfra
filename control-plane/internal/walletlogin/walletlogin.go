// Package walletlogin implements ADR-014: a user proves control of a key
// by signing a server-issued nonce, mirroring internal/providerjoin's
// BeginJoin/CompleteJoin challenge-signature pattern for a second caller
// type (a human, in a browser, rather than a Provider Agent). A
// successful login does not invent a new session mechanism -- it mints a
// short-lived internal/userauth API key (a "session key"), so
// userauth's Authenticate/expiry/revocation logic needs no changes to
// support it (ADR-014 §5).
package walletlogin

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/openinfra/network/internal/userauth"
)

const (
	// loginDomain matches the join/heartbeat domain-separation
	// convention (internal/providerjoin) exactly.
	loginDomain  = "openinfra-dashboard-login-v1\x00"
	challengeTTL = 5 * time.Minute
	sessionTTL   = 24 * time.Hour
)

// Scheme identifies a wallet account's signature algorithm. Defined now
// (matching wallet_accounts.scheme) so the schema never needs a later
// migration, even though Login only accepts Ed25519 until a later slice
// adds Schnorrkel (Sr25519) verification -- see ADR-014 §3/§7: most real
// Polkadot.js-generated accounts default to Sr25519, so this is a real,
// tracked gap, not a hypothetical one.
type Scheme byte

const (
	SchemeEd25519 Scheme = 0
	SchemeSr25519 Scheme = 1
)

var (
	ErrChallengeNotFound  = errors.New("challenge not found, expired, or already used")
	ErrInvalidSignature   = errors.New("signature does not verify for the given account")
	ErrSchemeNotSupported = errors.New("this signature scheme is not yet supported")
)

type Challenge struct {
	ChallengeID string
	Nonce       [32]byte
	ExpiresAt   time.Time
}

type Session struct {
	APIKey    string
	ExpiresAt time.Time
	UserID    string
}

// Repository is the persistence surface walletlogin needs.
type Repository interface {
	CreateChallenge(ctx context.Context, challengeID string, nonce [32]byte, expiresAt time.Time) error
	// LiveChallengeNonce returns a challenge's nonce if it exists, is
	// unexpired, and has not yet been consumed -- ErrChallengeNotFound
	// otherwise. Deliberately read-only (does not consume): a failed
	// signature verification can be retried against the same challenge
	// rather than forcing the whole flow to restart.
	LiveChallengeNonce(ctx context.Context, challengeID string) ([32]byte, error)
	// ConsumeChallenge atomically marks a still-live challenge used.
	// Re-checks liveness at consume time, not just at LiveChallengeNonce's
	// earlier read, so a challenge that expired (or that a concurrent
	// request already consumed) between the two calls fails here even if
	// it passed LiveChallengeNonce.
	ConsumeChallenge(ctx context.Context, challengeID string) error
	// FindOrCreateUserByAccount looks up the user linked to account, or
	// creates both a new users row and the wallet_accounts link if this
	// is the account's first successful login (ADR-014 §4). Concurrent
	// first logins for the same never-seen account must not create two
	// users rows -- implementations serialize that critical section
	// themselves (PostgresRepository uses a transaction-scoped advisory
	// lock keyed by the account).
	FindOrCreateUserByAccount(ctx context.Context, account [32]byte, scheme Scheme) (userID string, err error)
}

// APIKeyMinter is the one userauth capability walletlogin needs --
// narrowed from the full userauth.Repository interface so this package
// doesn't depend on capabilities (CreateUser, RevokeAPIKey, ...) it
// never calls.
type APIKeyMinter interface {
	CreateAPIKeyWithExpiry(ctx context.Context, userID string, expiresAt *time.Time) (userauth.APIKey, error)
}

type Service struct {
	repository Repository
	keys       APIKeyMinter
	now        func() time.Time
}

func NewService(repository Repository, keys APIKeyMinter) *Service {
	return &Service{repository: repository, keys: keys, now: time.Now}
}

// NewChallenge issues a fresh, single-use, short-lived nonce.
func (s *Service) NewChallenge(ctx context.Context) (Challenge, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Challenge{}, err
	}
	challenge := Challenge{ChallengeID: uuid.NewString(), Nonce: nonce, ExpiresAt: s.now().UTC().Add(challengeTTL)}
	if err := s.repository.CreateChallenge(ctx, challenge.ChallengeID, nonce, challenge.ExpiresAt); err != nil {
		return Challenge{}, err
	}
	return challenge, nil
}

// Login verifies signature over loginDomain+nonce for account under
// scheme, and on success mints a session key for the (possibly newly
// created) user that account belongs to.
func (s *Service) Login(ctx context.Context, challengeID string, account [32]byte, scheme Scheme, signature []byte) (Session, error) {
	if scheme != SchemeEd25519 {
		return Session{}, ErrSchemeNotSupported
	}
	nonce, err := s.repository.LiveChallengeNonce(ctx, challengeID)
	if err != nil {
		return Session{}, err
	}
	message := append([]byte(loginDomain), nonce[:]...)
	if !ed25519.Verify(account[:], message, signature) {
		return Session{}, ErrInvalidSignature
	}
	if err := s.repository.ConsumeChallenge(ctx, challengeID); err != nil {
		return Session{}, err
	}
	userID, err := s.repository.FindOrCreateUserByAccount(ctx, account, scheme)
	if err != nil {
		return Session{}, err
	}
	expiresAt := s.now().UTC().Add(sessionTTL)
	key, err := s.keys.CreateAPIKeyWithExpiry(ctx, userID, &expiresAt)
	if err != nil {
		return Session{}, err
	}
	return Session{APIKey: key.Raw, ExpiresAt: expiresAt, UserID: userID}, nil
}
