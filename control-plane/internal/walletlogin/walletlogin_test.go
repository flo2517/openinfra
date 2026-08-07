package walletlogin_test

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/openinfra/network/internal/userauth"
	"github.com/openinfra/network/internal/walletlogin"
)

type fakeChallenge struct {
	nonce     [32]byte
	expiresAt time.Time
	consumed  bool
}

type fakeRepository struct {
	challenges   map[string]*fakeChallenge
	users        map[[32]byte]string
	nextUserID   int
	consumeCalls int
}

func newFakeRepository() *fakeRepository {
	return &fakeRepository{challenges: map[string]*fakeChallenge{}, users: map[[32]byte]string{}}
}

func (r *fakeRepository) CreateChallenge(_ context.Context, challengeID string, nonce [32]byte, expiresAt time.Time) error {
	r.challenges[challengeID] = &fakeChallenge{nonce: nonce, expiresAt: expiresAt}
	return nil
}

func (r *fakeRepository) LiveChallengeNonce(_ context.Context, challengeID string) ([32]byte, error) {
	c, ok := r.challenges[challengeID]
	if !ok || c.consumed || time.Now().After(c.expiresAt) {
		return [32]byte{}, walletlogin.ErrChallengeNotFound
	}
	return c.nonce, nil
}

func (r *fakeRepository) ConsumeChallenge(_ context.Context, challengeID string) error {
	r.consumeCalls++
	c, ok := r.challenges[challengeID]
	if !ok || c.consumed || time.Now().After(c.expiresAt) {
		return walletlogin.ErrChallengeNotFound
	}
	c.consumed = true
	return nil
}

func (r *fakeRepository) FindOrCreateUserByAccount(_ context.Context, account [32]byte, _ walletlogin.Scheme) (string, error) {
	if id, ok := r.users[account]; ok {
		return id, nil
	}
	r.nextUserID++
	id := "user-" + string(rune('a'+r.nextUserID))
	r.users[account] = id
	return id, nil
}

type fakeKeyMinter struct {
	calls []string
}

func (m *fakeKeyMinter) CreateAPIKeyWithExpiry(_ context.Context, userID string, expiresAt *time.Time) (userauth.APIKey, error) {
	m.calls = append(m.calls, userID)
	if expiresAt == nil {
		panic("walletlogin must always request an expiring session key")
	}
	return userauth.APIKey{KeyID: "key-1", UserID: userID, Raw: "oiu_session", ExpiresAt: expiresAt}, nil
}

func TestNewChallengeGeneratesDistinctNonces(t *testing.T) {
	repository := newFakeRepository()
	service := walletlogin.NewService(repository, &fakeKeyMinter{})
	first, err := service.NewChallenge(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.NewChallenge(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first.ChallengeID == second.ChallengeID || first.Nonce == second.Nonce {
		t.Fatalf("expected distinct challenges, got %+v and %+v", first, second)
	}
}

func TestLoginSucceedsWithAValidSignatureAndMintsAnExpiringSessionKey(t *testing.T) {
	repository := newFakeRepository()
	keys := &fakeKeyMinter{}
	service := walletlogin.NewService(repository, keys)
	challenge, err := service.NewChallenge(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(private, append([]byte("openinfra-dashboard-login-v1\x00"), challenge.Nonce[:]...))
	var account [32]byte
	copy(account[:], public)

	session, err := service.Login(context.Background(), challenge.ChallengeID, account, walletlogin.SchemeEd25519, signature)
	if err != nil {
		t.Fatalf("Login(): %v", err)
	}
	if session.APIKey == "" || session.UserID == "" {
		t.Fatalf("expected a populated session, got %+v", session)
	}
	if len(keys.calls) != 1 || keys.calls[0] != session.UserID {
		t.Fatalf("expected exactly one session key minted for %q, got calls=%v", session.UserID, keys.calls)
	}
}

func TestLoginRejectsAnInvalidSignatureWithoutConsumingTheChallengeAndAllowsARetry(t *testing.T) {
	repository := newFakeRepository()
	service := walletlogin.NewService(repository, &fakeKeyMinter{})
	challenge, err := service.NewChallenge(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	var account [32]byte
	copy(account[:], public)

	_, err = service.Login(context.Background(), challenge.ChallengeID, account, walletlogin.SchemeEd25519, make([]byte, ed25519.SignatureSize))
	if err != walletlogin.ErrInvalidSignature {
		t.Fatalf("Login() error = %v, want ErrInvalidSignature", err)
	}
	if repository.consumeCalls != 0 {
		t.Fatal("a failed verification must not consume the challenge -- the caller should be able to retry")
	}

	// Proof the challenge really is still live: a correctly signed retry
	// against the same challenge_id succeeds.
	signature := ed25519.Sign(private, append([]byte("openinfra-dashboard-login-v1\x00"), challenge.Nonce[:]...))
	if _, err := service.Login(context.Background(), challenge.ChallengeID, account, walletlogin.SchemeEd25519, signature); err != nil {
		t.Fatalf("expected the retry with a correct signature to succeed, got %v", err)
	}
}

func TestLoginRejectsAnUnsupportedScheme(t *testing.T) {
	repository := newFakeRepository()
	service := walletlogin.NewService(repository, &fakeKeyMinter{})
	challenge, err := service.NewChallenge(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var account [32]byte
	_, err = service.Login(context.Background(), challenge.ChallengeID, account, walletlogin.SchemeSr25519, make([]byte, ed25519.SignatureSize))
	if err != walletlogin.ErrSchemeNotSupported {
		t.Fatalf("Login() error = %v, want ErrSchemeNotSupported", err)
	}
	if repository.consumeCalls != 0 {
		t.Fatal("an unsupported scheme must be rejected before touching the challenge at all")
	}
}

func TestLoginRejectsAnUnknownOrExpiredChallenge(t *testing.T) {
	repository := newFakeRepository()
	service := walletlogin.NewService(repository, &fakeKeyMinter{})
	var account [32]byte
	_, err := service.Login(context.Background(), "never-issued", account, walletlogin.SchemeEd25519, make([]byte, ed25519.SignatureSize))
	if err != walletlogin.ErrChallengeNotFound {
		t.Fatalf("Login() error = %v, want ErrChallengeNotFound", err)
	}
}

func TestLoginConsumesTheChallengeOnSuccessSoItCannotBeReplayed(t *testing.T) {
	repository := newFakeRepository()
	service := walletlogin.NewService(repository, &fakeKeyMinter{})
	challenge, err := service.NewChallenge(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(private, append([]byte("openinfra-dashboard-login-v1\x00"), challenge.Nonce[:]...))
	var account [32]byte
	copy(account[:], public)

	if _, err := service.Login(context.Background(), challenge.ChallengeID, account, walletlogin.SchemeEd25519, signature); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Login(context.Background(), challenge.ChallengeID, account, walletlogin.SchemeEd25519, signature); err != walletlogin.ErrChallengeNotFound {
		t.Fatalf("replaying an already-used challenge = %v, want ErrChallengeNotFound", err)
	}
}
