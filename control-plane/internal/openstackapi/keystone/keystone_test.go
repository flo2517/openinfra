package keystone_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/openinfra/network/internal/openstackapi/keystone"
	"github.com/openinfra/network/internal/projects"
	"github.com/openinfra/network/internal/testsupport"
	"github.com/openinfra/network/internal/userauth"
	"github.com/openinfra/network/migrations"
)

// newTestPool isolates each test run into its own schema against
// OPENINFRA_TEST_DATABASE_URL -- the same convention every other
// Postgres-backed test package uses. keystone's handlers are exercised
// against the real userauth/projects Postgres repositories, not fakes,
// so the token bridge is tested through the actual persistence layer
// it depends on end to end.
func newTestPool(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	databaseURL := testsupport.RequireDatabaseURL(t)
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "keystone_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
	return ctx, pool
}

type testServer struct {
	handler  http.Handler
	pool     *pgxpool.Pool
	users    *userauth.PostgresRepository
	projects *projects.PostgresRepository
}

func newTestServer(t *testing.T) (context.Context, testServer) {
	t.Helper()
	ctx, pool := newTestPool(t)
	users := userauth.NewPostgresRepository(pool)
	projectsRepo := projects.NewPostgresRepository(pool)
	server := keystone.New(users, projectsRepo, "https://control-plane.example:8087", nil)
	mux := http.NewServeMux()
	server.Register(mux)
	return ctx, testServer{handler: mux, pool: pool, users: users, projects: projectsRepo}
}

func passwordAuthBody(rawAPIKey string) []byte {
	body := map[string]any{
		"auth": map[string]any{
			"identity": map[string]any{
				"methods": []string{"password"},
				"password": map[string]any{
					"user": map[string]any{"name": "irrelevant", "password": rawAPIKey},
				},
			},
		},
	}
	encoded, _ := json.Marshal(body)
	return encoded
}

func scopedPasswordAuthBody(rawAPIKey, projectID string) []byte {
	body := map[string]any{
		"auth": map[string]any{
			"identity": map[string]any{
				"methods": []string{"password"},
				"password": map[string]any{
					"user": map[string]any{"name": "irrelevant", "password": rawAPIKey},
				},
			},
			"scope": map[string]any{
				"project": map[string]any{"id": projectID},
			},
		},
	}
	encoded, _ := json.Marshal(body)
	return encoded
}

func tokenAuthBody(existingToken string) []byte {
	body := map[string]any{
		"auth": map[string]any{
			"identity": map[string]any{
				"methods": []string{"token"},
				"token":   map[string]any{"id": existingToken},
			},
		},
	}
	encoded, _ := json.Marshal(body)
	return encoded
}

func decodeKeystoneError(t *testing.T, body []byte) (code int, title, message string) {
	t.Helper()
	var decoded struct {
		Error struct {
			Code    int    `json:"code"`
			Title   string `json:"title"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("response is not the Keystone error shape: %v (%s)", err, body)
	}
	return decoded.Error.Code, decoded.Error.Title, decoded.Error.Message
}

type tokenResponseBody struct {
	Token struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		Project *struct {
			ID string `json:"id"`
		} `json:"project"`
		Roles []struct {
			Name string `json:"name"`
		} `json:"roles"`
		Catalog   []map[string]any `json:"catalog"`
		ExpiresAt string           `json:"expires_at"`
	} `json:"token"`
}

func TestIssueTokenAcceptsAValidAPIKey(t *testing.T) {
	ctx, server := newTestServer(t)
	user, err := server.users.CreateUser(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	key, err := server.users.CreateAPIKey(ctx, user.UserID)
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "/v3/auth/tokens", bytes.NewReader(passwordAuthBody(key.Raw)))
	recorder := httptest.NewRecorder()
	server.handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusCreated, recorder.Body.String())
	}
	subjectToken := recorder.Header().Get("X-Subject-Token")
	if subjectToken == "" {
		t.Fatal("expected X-Subject-Token header to be set")
	}
	var body tokenResponseBody
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Token.User.ID != user.UserID {
		t.Fatalf("token.user.id = %q, want %q", body.Token.User.ID, user.UserID)
	}
	if body.Token.Project != nil {
		t.Fatalf("token.project = %+v, want nil (unscoped request)", body.Token.Project)
	}

	// The minted token must itself authenticate.
	authenticated, err := server.users.Authenticate(ctx, userauth.HashAPIKey(subjectToken))
	if err != nil || authenticated.UserID != user.UserID {
		t.Fatalf("Authenticate(subjectToken) = %+v, %v, want user %q", authenticated, err, user.UserID)
	}
}

func TestIssueTokenRejectsAnInvalidAPIKey(t *testing.T) {
	_, server := newTestServer(t)

	request := httptest.NewRequest(http.MethodPost, "/v3/auth/tokens", bytes.NewReader(passwordAuthBody("oiu_never-issued")))
	recorder := httptest.NewRecorder()
	server.handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusUnauthorized, recorder.Body.String())
	}
	code, title, _ := decodeKeystoneError(t, recorder.Body.Bytes())
	if code != http.StatusUnauthorized || title == "" {
		t.Fatalf("error body code/title = %d/%q, want %d/non-empty", code, title, http.StatusUnauthorized)
	}
}

// TestIssueTokenRejectsARevokedAPIKey is the task's explicit
// "invalid/revoked key -> rejected" case.
func TestIssueTokenRejectsARevokedAPIKey(t *testing.T) {
	ctx, server := newTestServer(t)
	user, err := server.users.CreateUser(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	key, err := server.users.CreateAPIKey(ctx, user.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.users.RevokeAPIKey(ctx, key.KeyID); err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "/v3/auth/tokens", bytes.NewReader(passwordAuthBody(key.Raw)))
	recorder := httptest.NewRecorder()
	server.handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
}

func TestIssueTokenRejectsMalformedJSON(t *testing.T) {
	_, server := newTestServer(t)

	request := httptest.NewRequest(http.MethodPost, "/v3/auth/tokens", bytes.NewReader([]byte("{not json")))
	recorder := httptest.NewRecorder()
	server.handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
}

func TestIssueTokenRejectsAnUnsupportedIdentityMethod(t *testing.T) {
	_, server := newTestServer(t)

	body := []byte(`{"auth":{"identity":{"methods":["totp"]}}}`)
	request := httptest.NewRequest(http.MethodPost, "/v3/auth/tokens", bytes.NewReader(body))
	recorder := httptest.NewRecorder()
	server.handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
	}
}

// TestIssueTokenScopesToAProjectTheUserIsAMemberOf is the task's
// "project/membership: a user only sees/acts within projects they're a
// member of" positive case.
func TestIssueTokenScopesToAProjectTheUserIsAMemberOf(t *testing.T) {
	ctx, server := newTestServer(t)
	user, err := server.users.CreateUser(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	key, err := server.users.CreateAPIKey(ctx, user.UserID)
	if err != nil {
		t.Fatal(err)
	}
	project, err := server.projects.CreateProject(ctx, "alpha", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := server.projects.AddMembership(ctx, project.ProjectID, user.UserID, projects.RoleAdmin); err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "/v3/auth/tokens", bytes.NewReader(scopedPasswordAuthBody(key.Raw, project.ProjectID)))
	recorder := httptest.NewRecorder()
	server.handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusCreated, recorder.Body.String())
	}
	var body tokenResponseBody
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Token.Project == nil || body.Token.Project.ID != project.ProjectID {
		t.Fatalf("token.project = %+v, want %q", body.Token.Project, project.ProjectID)
	}
	if len(body.Token.Roles) != 1 || body.Token.Roles[0].Name != "admin" {
		t.Fatalf("token.roles = %+v, want [{admin}]", body.Token.Roles)
	}
	if len(body.Token.Catalog) == 0 {
		t.Fatal("expected a non-empty service catalog for a scoped token")
	}

	// The scoped token authenticates with the project attached.
	subjectToken := recorder.Header().Get("X-Subject-Token")
	_, projectID, err := server.users.AuthenticateScoped(ctx, userauth.HashAPIKey(subjectToken))
	if err != nil || projectID == nil || *projectID != project.ProjectID {
		t.Fatalf("AuthenticateScoped(subjectToken) project = %v, %v, want %q", projectID, err, project.ProjectID)
	}
}

// TestIssueTokenDeniesScopeToAProjectTheUserIsNotAMemberOf is the task's
// explicit "cross-project access attempts are rejected explicitly" case
// -- ADR-031's own named threat-model item.
func TestIssueTokenDeniesScopeToAProjectTheUserIsNotAMemberOf(t *testing.T) {
	ctx, server := newTestServer(t)
	user, err := server.users.CreateUser(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	key, err := server.users.CreateAPIKey(ctx, user.UserID)
	if err != nil {
		t.Fatal(err)
	}
	// A project alice is NOT a member of.
	otherProject, err := server.projects.CreateProject(ctx, "beta", "")
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "/v3/auth/tokens", bytes.NewReader(scopedPasswordAuthBody(key.Raw, otherProject.ProjectID)))
	recorder := httptest.NewRecorder()
	server.handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusUnauthorized, recorder.Body.String())
	}
}

// TestIssueTokenDeniesScopeToANonexistentProjectIdentically proves a
// nonexistent-project scope request fails exactly the same way a
// real-but-foreign-project request does -- no enumeration oracle.
func TestIssueTokenDeniesScopeToANonexistentProjectIdentically(t *testing.T) {
	ctx, server := newTestServer(t)
	user, err := server.users.CreateUser(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	key, err := server.users.CreateAPIKey(ctx, user.UserID)
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "/v3/auth/tokens", bytes.NewReader(scopedPasswordAuthBody(key.Raw, uuid.NewString())))
	recorder := httptest.NewRecorder()
	server.handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
}

func TestIssueTokenAcceptsTheTokenMethodToReAuthenticate(t *testing.T) {
	ctx, server := newTestServer(t)
	user, err := server.users.CreateUser(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	key, err := server.users.CreateAPIKey(ctx, user.UserID)
	if err != nil {
		t.Fatal(err)
	}
	firstRequest := httptest.NewRequest(http.MethodPost, "/v3/auth/tokens", bytes.NewReader(passwordAuthBody(key.Raw)))
	firstRecorder := httptest.NewRecorder()
	server.handler.ServeHTTP(firstRecorder, firstRequest)
	if firstRecorder.Code != http.StatusCreated {
		t.Fatalf("first issue: status = %d, body=%s", firstRecorder.Code, firstRecorder.Body.String())
	}
	firstToken := firstRecorder.Header().Get("X-Subject-Token")

	secondRequest := httptest.NewRequest(http.MethodPost, "/v3/auth/tokens", bytes.NewReader(tokenAuthBody(firstToken)))
	secondRecorder := httptest.NewRecorder()
	server.handler.ServeHTTP(secondRecorder, secondRequest)

	if secondRecorder.Code != http.StatusCreated {
		t.Fatalf("token-method reauth: status = %d, want %d; body=%s", secondRecorder.Code, http.StatusCreated, secondRecorder.Body.String())
	}
	secondToken := secondRecorder.Header().Get("X-Subject-Token")
	if secondToken == "" || secondToken == firstToken {
		t.Fatal("expected a freshly minted, different token from the token-method reauth")
	}
}

func TestValidateTokenAcceptsAFreshlyIssuedToken(t *testing.T) {
	ctx, server := newTestServer(t)
	user, err := server.users.CreateUser(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	key, err := server.users.CreateAPIKey(ctx, user.UserID)
	if err != nil {
		t.Fatal(err)
	}
	issueRequest := httptest.NewRequest(http.MethodPost, "/v3/auth/tokens", bytes.NewReader(passwordAuthBody(key.Raw)))
	issueRecorder := httptest.NewRecorder()
	server.handler.ServeHTTP(issueRecorder, issueRequest)
	subjectToken := issueRecorder.Header().Get("X-Subject-Token")

	validateRequest := httptest.NewRequest(http.MethodGet, "/v3/auth/tokens", nil)
	validateRequest.Header.Set("X-Subject-Token", subjectToken)
	validateRecorder := httptest.NewRecorder()
	server.handler.ServeHTTP(validateRecorder, validateRequest)

	if validateRecorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", validateRecorder.Code, http.StatusOK, validateRecorder.Body.String())
	}
	var body tokenResponseBody
	if err := json.Unmarshal(validateRecorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Token.User.ID != user.UserID {
		t.Fatalf("validated token.user.id = %q, want %q", body.Token.User.ID, user.UserID)
	}
}

func TestValidateTokenRejectsAnUnknownToken(t *testing.T) {
	_, server := newTestServer(t)

	request := httptest.NewRequest(http.MethodGet, "/v3/auth/tokens", nil)
	request.Header.Set("X-Subject-Token", "oiu_never-issued")
	recorder := httptest.NewRecorder()
	server.handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
}

func TestValidateTokenRejectsAMissingHeader(t *testing.T) {
	_, server := newTestServer(t)

	request := httptest.NewRequest(http.MethodGet, "/v3/auth/tokens", nil)
	recorder := httptest.NewRecorder()
	server.handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
}

func TestRevokeTokenRevokesAndValidationFailsAfterwards(t *testing.T) {
	ctx, server := newTestServer(t)
	user, err := server.users.CreateUser(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	key, err := server.users.CreateAPIKey(ctx, user.UserID)
	if err != nil {
		t.Fatal(err)
	}
	issueRequest := httptest.NewRequest(http.MethodPost, "/v3/auth/tokens", bytes.NewReader(passwordAuthBody(key.Raw)))
	issueRecorder := httptest.NewRecorder()
	server.handler.ServeHTTP(issueRecorder, issueRequest)
	subjectToken := issueRecorder.Header().Get("X-Subject-Token")

	revokeRequest := httptest.NewRequest(http.MethodDelete, "/v3/auth/tokens", nil)
	revokeRequest.Header.Set("X-Subject-Token", subjectToken)
	revokeRecorder := httptest.NewRecorder()
	server.handler.ServeHTTP(revokeRecorder, revokeRequest)
	if revokeRecorder.Code != http.StatusNoContent {
		t.Fatalf("revoke status = %d, want %d; body=%s", revokeRecorder.Code, http.StatusNoContent, revokeRecorder.Body.String())
	}

	validateRequest := httptest.NewRequest(http.MethodGet, "/v3/auth/tokens", nil)
	validateRequest.Header.Set("X-Subject-Token", subjectToken)
	validateRecorder := httptest.NewRecorder()
	server.handler.ServeHTTP(validateRecorder, validateRequest)
	if validateRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("validate-after-revoke status = %d, want %d", validateRecorder.Code, http.StatusUnauthorized)
	}

	// Revoking the same (now-revoked) token again must not silently
	// succeed a second time.
	replayRequest := httptest.NewRequest(http.MethodDelete, "/v3/auth/tokens", nil)
	replayRequest.Header.Set("X-Subject-Token", subjectToken)
	replayRecorder := httptest.NewRecorder()
	server.handler.ServeHTTP(replayRecorder, replayRequest)
	if replayRecorder.Code != http.StatusNotFound {
		t.Fatalf("re-revoke status = %d, want %d (not a silent second success)", replayRecorder.Code, http.StatusNotFound)
	}
}

func TestRevokeTokenRejectsAMissingHeader(t *testing.T) {
	_, server := newTestServer(t)

	request := httptest.NewRequest(http.MethodDelete, "/v3/auth/tokens", nil)
	recorder := httptest.NewRecorder()
	server.handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
}

// TestIssueTokenMintsATimeBoundedToken proves the issued token actually
// carries a real, bounded expiry rather than the no-expiry default
// CreateAPIKey (dashboard/controlplane-admin's own long-lived keys) uses
// -- issue #23's "token expiry" acceptance criterion.
func TestIssueTokenMintsATimeBoundedToken(t *testing.T) {
	ctx, server := newTestServer(t)
	user, err := server.users.CreateUser(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	key, err := server.users.CreateAPIKey(ctx, user.UserID)
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "/v3/auth/tokens", bytes.NewReader(passwordAuthBody(key.Raw)))
	recorder := httptest.NewRecorder()
	server.handler.ServeHTTP(recorder, request)
	subjectToken := recorder.Header().Get("X-Subject-Token")

	var body tokenResponseBody
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	expiresAt, err := time.Parse(time.RFC3339, body.Token.ExpiresAt)
	if err != nil {
		t.Fatalf("expires_at %q did not parse as RFC3339: %v", body.Token.ExpiresAt, err)
	}
	if !expiresAt.After(time.Now()) || expiresAt.After(time.Now().Add(2*time.Hour)) {
		t.Fatalf("expires_at = %v, want roughly one hour from now", expiresAt)
	}

	// Simulate the token already having expired, and confirm the bridge
	// (via the underlying api_keys.expires_at column) actually enforces
	// it -- not just that the response body claims an expiry.
	hash := userauth.HashAPIKey(subjectToken)
	if _, err := server.pool.Exec(ctx, `UPDATE api_keys SET expires_at = now() - interval '1 minute' WHERE key_hash = $1`, hash[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := server.users.Authenticate(ctx, userauth.HashAPIKey(subjectToken)); err != userauth.ErrInvalidKey {
		t.Fatalf("Authenticate() on an expired bridged token = %v, want ErrInvalidKey", err)
	}
}
