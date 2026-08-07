package dashboard

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	schnorrkel "github.com/ChainSafe/go-schnorrkel"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/openinfra/network/internal/ratelimit"
	"github.com/openinfra/network/internal/userauth"
	"github.com/openinfra/network/internal/walletlogin"
	"github.com/openinfra/network/migrations"
	"github.com/redis/go-redis/v9"
)

// newAuthTestServer isolates each test into its own Postgres schema
// (OPENINFRA_TEST_DATABASE_URL, the same convention every other package's
// Postgres integration test uses) and wires a real Server with a real
// walletlogin.Service and userauth.Repository -- these tests exercise the
// actual HTTP handlers end to end, not the underlying services in
// isolation (those already have their own unit/integration tests).
func newAuthTestServer(t *testing.T) (context.Context, *Server, *pgxpool.Pool) {
	t.Helper()
	databaseURL := os.Getenv("OPENINFRA_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("OPENINFRA_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "dashboard_auth_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, fmt.Sprintf(`CREATE SCHEMA %q`, schema)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(ctx, fmt.Sprintf(`DROP SCHEMA %q CASCADE`, schema)) })

	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := migrations.Apply(ctx, pool); err != nil {
		t.Fatal(err)
	}

	users := userauth.NewPostgresRepository(pool)
	wallet := walletlogin.NewService(walletlogin.NewPostgresRepository(pool), users)
	server := New(pool, nil, nil, wallet, users, nil) // nil redis/chain/limiter: unused by the auth endpoints under test
	return ctx, server, pool
}

type challengeResponse struct {
	ChallengeID string `json:"challenge_id"`
	Nonce       string `json:"nonce"`
}

func doJSON(t *testing.T, handler http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	return doJSONFrom(t, handler, method, path, "203.0.113.1:12345", body)
}

func doJSONFrom(t *testing.T, handler http.Handler, method, path, remoteAddr string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(encoded)
	} else {
		reader = bytes.NewReader(nil)
	}
	request := httptest.NewRequest(method, path, reader)
	request.RemoteAddr = remoteAddr
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func TestChallengeThenLoginSucceedsEndToEnd(t *testing.T) {
	_, server, _ := newAuthTestServer(t)
	handler := server.Handler()

	challengeRecorder := doJSON(t, handler, http.MethodPost, "/api/v1/auth/challenge", nil)
	if challengeRecorder.Code != http.StatusOK {
		t.Fatalf("challenge status = %d, body = %s", challengeRecorder.Code, challengeRecorder.Body.String())
	}
	var challenge challengeResponse
	if err := json.Unmarshal(challengeRecorder.Body.Bytes(), &challenge); err != nil {
		t.Fatal(err)
	}
	nonce, err := hex.DecodeString(challenge.Nonce)
	if err != nil || len(nonce) != 32 {
		t.Fatalf("unexpected nonce: %q", challenge.Nonce)
	}

	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(private, append([]byte("openinfra-dashboard-login-v1\x00"), nonce...))

	loginRecorder := doJSON(t, handler, http.MethodPost, "/api/v1/auth/login", loginRequest{
		ChallengeID: challenge.ChallengeID,
		Account:     hex.EncodeToString(public),
		Scheme:      0,
		Signature:   hex.EncodeToString(signature),
	})
	if loginRecorder.Code != http.StatusOK {
		t.Fatalf("login status = %d, body = %s", loginRecorder.Code, loginRecorder.Body.String())
	}
	var login struct {
		SessionKey string `json:"session_key"`
	}
	if err := json.Unmarshal(loginRecorder.Body.Bytes(), &login); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(login.SessionKey, "oiu_") {
		t.Fatalf("session_key = %q, expected an oiu_-prefixed API key", login.SessionKey)
	}

	// Replaying the same (now-consumed) challenge must fail.
	replay := doJSON(t, handler, http.MethodPost, "/api/v1/auth/login", loginRequest{
		ChallengeID: challenge.ChallengeID,
		Account:     hex.EncodeToString(public),
		Scheme:      0,
		Signature:   hex.EncodeToString(signature),
	})
	if replay.Code != http.StatusUnauthorized {
		t.Fatalf("replay status = %d, want 401", replay.Code)
	}
}

func TestLoginRejectsMalformedInputWithoutTouchingTheChallenge(t *testing.T) {
	_, server, _ := newAuthTestServer(t)
	handler := server.Handler()

	cases := []struct {
		name string
		body loginRequest
	}{
		{"bad challenge_id", loginRequest{ChallengeID: "not-a-uuid", Account: strings.Repeat("00", 32), Signature: strings.Repeat("00", 64)}},
		{"short account", loginRequest{ChallengeID: uuid.NewString(), Account: "00", Signature: strings.Repeat("00", 64)}},
		{"short signature", loginRequest{ChallengeID: uuid.NewString(), Account: strings.Repeat("00", 32), Signature: "00"}},
		{"non-hex account", loginRequest{ChallengeID: uuid.NewString(), Account: strings.Repeat("zz", 32), Signature: strings.Repeat("00", 64)}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			recorder := doJSON(t, handler, http.MethodPost, "/api/v1/auth/login", c.body)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400, body = %s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestLoginRejectsAnUnsupportedSchemeOverHTTP(t *testing.T) {
	_, server, _ := newAuthTestServer(t)
	handler := server.Handler()
	challengeRecorder := doJSON(t, handler, http.MethodPost, "/api/v1/auth/challenge", nil)
	var challenge challengeResponse
	if err := json.Unmarshal(challengeRecorder.Body.Bytes(), &challenge); err != nil {
		t.Fatal(err)
	}
	recorder := doJSON(t, handler, http.MethodPost, "/api/v1/auth/login", loginRequest{
		ChallengeID: challenge.ChallengeID,
		Account:     strings.Repeat("00", 32),
		Scheme:      2, // neither Ed25519 (0) nor Sr25519 (1) -- both are supported now
		Signature:   strings.Repeat("00", 64),
	})
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401, body = %s", recorder.Code, recorder.Body.String())
	}
}

func TestChallengeThenSr25519LoginSucceedsEndToEnd(t *testing.T) {
	_, server, _ := newAuthTestServer(t)
	handler := server.Handler()

	challengeRecorder := doJSON(t, handler, http.MethodPost, "/api/v1/auth/challenge", nil)
	var challenge challengeResponse
	if err := json.Unmarshal(challengeRecorder.Body.Bytes(), &challenge); err != nil {
		t.Fatal(err)
	}
	nonce, err := hex.DecodeString(challenge.Nonce)
	if err != nil {
		t.Fatal(err)
	}

	secretKey, publicKey, err := schnorrkel.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	message := append([]byte("openinfra-dashboard-login-v1\x00"), nonce...)
	transcript := schnorrkel.NewSigningContext([]byte("substrate"), message)
	signature, err := secretKey.Sign(transcript)
	if err != nil {
		t.Fatal(err)
	}
	encodedSignature := signature.Encode()
	account := publicKey.Encode()

	loginRecorder := doJSON(t, handler, http.MethodPost, "/api/v1/auth/login", loginRequest{
		ChallengeID: challenge.ChallengeID,
		Account:     hex.EncodeToString(account[:]),
		Scheme:      1, // Sr25519
		Signature:   hex.EncodeToString(encodedSignature[:]),
	})
	if loginRecorder.Code != http.StatusOK {
		t.Fatalf("login status = %d, body = %s", loginRecorder.Code, loginRecorder.Body.String())
	}
	var login struct {
		SessionKey string `json:"session_key"`
	}
	if err := json.Unmarshal(loginRecorder.Body.Bytes(), &login); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(login.SessionKey, "oiu_") {
		t.Fatalf("session_key = %q, expected an oiu_-prefixed API key", login.SessionKey)
	}
}

func TestAuthChallengeIsRateLimitedByCallerIP(t *testing.T) {
	_, server, _ := newAuthTestServer(t)
	redisURL := os.Getenv("OPENINFRA_TEST_REDIS_URL")
	if redisURL == "" {
		t.Skip("OPENINFRA_TEST_REDIS_URL is not set")
	}
	options, err := redis.ParseURL(redisURL)
	if err != nil {
		t.Fatal(err)
	}
	client := redis.NewClient(options)
	t.Cleanup(func() { _ = client.Close() })
	server.limiter = ratelimit.NewRedisLimiter(client, 2, 60)
	handler := server.Handler()
	// A fresh, unique fake source IP per run so this test's rate-limit
	// state can never collide with a previous run's within the same
	// window.
	remoteAddr := fmt.Sprintf("198.51.100.%d:12345", uuid.New().ID()%254+1)

	for i := 0; i < 2; i++ {
		recorder := doJSONFrom(t, handler, http.MethodPost, "/api/v1/auth/challenge", remoteAddr, nil)
		if recorder.Code != http.StatusOK {
			t.Fatalf("call %d: status = %d, want 200", i, recorder.Code)
		}
	}
	recorder := doJSONFrom(t, handler, http.MethodPost, "/api/v1/auth/challenge", remoteAddr, nil)
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("call 3: status = %d, want 429", recorder.Code)
	}
}

func TestIssueAPIKeyRequiresAuthentication(t *testing.T) {
	_, server, _ := newAuthTestServer(t)
	handler := server.Handler()
	recorder := doJSON(t, handler, http.MethodPost, "/api/v1/auth/api-keys", nil)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", recorder.Code)
	}
}

func TestIssueAPIKeySucceedsWithAValidSessionKeyAndTheKeyActuallyAuthenticates(t *testing.T) {
	ctx, server, pool := newAuthTestServer(t)
	handler := server.Handler()

	// Log in first to get a session key, the same way a real client would.
	challengeRecorder := doJSON(t, handler, http.MethodPost, "/api/v1/auth/challenge", nil)
	var challenge challengeResponse
	if err := json.Unmarshal(challengeRecorder.Body.Bytes(), &challenge); err != nil {
		t.Fatal(err)
	}
	nonce, _ := hex.DecodeString(challenge.Nonce)
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(private, append([]byte("openinfra-dashboard-login-v1\x00"), nonce...))
	loginRecorder := doJSON(t, handler, http.MethodPost, "/api/v1/auth/login", loginRequest{
		ChallengeID: challenge.ChallengeID, Account: hex.EncodeToString(public), Scheme: 0, Signature: hex.EncodeToString(signature),
	})
	var login struct {
		SessionKey string `json:"session_key"`
	}
	if err := json.Unmarshal(loginRecorder.Body.Bytes(), &login); err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/api-keys", nil)
	request.Header.Set("Authorization", "Bearer "+login.SessionKey)
	request.RemoteAddr = "203.0.113.1:12345"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var issued struct {
		APIKey string `json:"api_key"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}

	// Prove the newly issued key is real: authenticate with it directly,
	// and confirm it has no expiry (unlike the session key that minted it).
	users := userauth.NewPostgresRepository(pool)
	if _, err := users.Authenticate(ctx, userauth.HashAPIKey(issued.APIKey)); err != nil {
		t.Fatalf("the self-service-issued key must itself authenticate: %v", err)
	}
	hash := userauth.HashAPIKey(issued.APIKey)
	var expiresAt *time.Time
	if err := pool.QueryRow(ctx, `SELECT expires_at FROM api_keys WHERE key_hash = $1`, hash[:]).Scan(&expiresAt); err != nil {
		t.Fatal(err)
	}
	if expiresAt != nil {
		t.Fatalf("expected the self-service key to have no expiry, got %v", expiresAt)
	}
}
