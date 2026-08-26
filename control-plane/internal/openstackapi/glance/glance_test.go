package glance_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/openinfra/network/internal/openstackapi/glance"
	"github.com/openinfra/network/internal/projects"
	"github.com/openinfra/network/internal/testsupport"
	"github.com/openinfra/network/internal/userauth"
	"github.com/openinfra/network/migrations"
)

// validDigest is a well-formed 64-lowercase-hex sha256 digest -- the
// exact shape ADR-033's vm/image.rs::validate_sha256_hex and this
// package's own ValidateDigestSHA256 require.
const validDigest = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

// newTestPool isolates each test run into its own schema against
// OPENINFRA_TEST_DATABASE_URL -- the same convention
// internal/openstackapi/keystone's own tests already use.
func newTestPool(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	databaseURL := testsupport.RequireDatabaseURL(t)
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "glance_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
	users    *userauth.PostgresRepository
	projects *projects.PostgresRepository
}

func newTestServer(t *testing.T) (context.Context, testServer) {
	t.Helper()
	ctx, pool := newTestPool(t)
	users := userauth.NewPostgresRepository(pool)
	projectsRepo := projects.NewPostgresRepository(pool)
	server := glance.New(users, glance.NewPostgresRepository(pool), nil)
	mux := http.NewServeMux()
	server.Register(mux)
	return ctx, testServer{handler: mux, users: users, projects: projectsRepo}
}

// scopedToken creates a user, a project, and returns a raw API key
// scoped to that project -- the credential every glance route requires
// in X-Auth-Token.
func scopedToken(t *testing.T, ctx context.Context, server testServer, projectName string) (rawToken, projectID string) {
	t.Helper()
	user, err := server.users.CreateUser(ctx, "user-"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	project, err := server.projects.CreateProject(ctx, projectName, "")
	if err != nil {
		t.Fatal(err)
	}
	key, err := server.users.CreateAPIKeyForProject(ctx, user.UserID, project.ProjectID, nil)
	if err != nil {
		t.Fatal(err)
	}
	return key.Raw, project.ProjectID
}

// unscopedToken creates a user with a plain, unscoped API key -- used to
// prove every glance route rejects a token with no project scope.
func unscopedToken(t *testing.T, ctx context.Context, server testServer) string {
	t.Helper()
	user, err := server.users.CreateUser(ctx, "user-"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	key, err := server.users.CreateAPIKey(ctx, user.UserID)
	if err != nil {
		t.Fatal(err)
	}
	return key.Raw
}

func createImageBody(name, directURL, digest, visibility string) []byte {
	body := map[string]any{
		"name":          name,
		"direct_url":    directURL,
		"os_hash_value": digest,
	}
	if visibility != "" {
		body["visibility"] = visibility
	}
	encoded, _ := json.Marshal(body)
	return encoded
}

type imageBody struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Owner       string `json:"owner"`
	Visibility  string `json:"visibility"`
	Status      string `json:"status"`
	OSHashValue string `json:"os_hash_value"`
	DirectURL   string `json:"direct_url"`
}

type imagesListResponse struct {
	Images []imageBody `json:"images"`
}

func decodeKeystoneError(t *testing.T, body []byte) (code int, title string) {
	t.Helper()
	var decoded struct {
		Error struct {
			Code  int    `json:"code"`
			Title string `json:"title"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("response is not the Keystone error shape: %v (%s)", err, body)
	}
	return decoded.Error.Code, decoded.Error.Title
}

func doRequest(t *testing.T, server testServer, method, path, token string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	} else {
		reader = bytes.NewReader(nil)
	}
	request := httptest.NewRequest(method, path, reader)
	if token != "" {
		request.Header.Set("X-Auth-Token", token)
	}
	recorder := httptest.NewRecorder()
	server.handler.ServeHTTP(recorder, request)
	return recorder
}

func TestCreateImageRegistersAWellFormedImage(t *testing.T) {
	ctx, server := newTestServer(t)
	token, projectID := scopedToken(t, ctx, server, "alpha")

	recorder := doRequest(t, server, http.MethodPost, "/v2/images", token,
		createImageBody("ubuntu-base", "https://example.invalid/ubuntu.qcow2", validDigest, ""))

	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusCreated, recorder.Body.String())
	}
	var body imageBody
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if _, err := uuid.Parse(body.ID); err != nil {
		t.Fatalf("id = %q is not a UUID", body.ID)
	}
	if body.Owner != projectID {
		t.Fatalf("owner = %q, want %q", body.Owner, projectID)
	}
	if body.Visibility != glance.VisibilityPrivate {
		t.Fatalf("visibility = %q, want %q (the default)", body.Visibility, glance.VisibilityPrivate)
	}
	if body.Status != "active" {
		t.Fatalf("status = %q, want \"active\"", body.Status)
	}
	if body.OSHashValue != validDigest {
		t.Fatalf("os_hash_value = %q, want %q", body.OSHashValue, validDigest)
	}
	if body.DirectURL != "https://example.invalid/ubuntu.qcow2" {
		t.Fatalf("direct_url = %q, want the submitted source", body.DirectURL)
	}
}

// TestCreateImageRejectsANonWellFormedDigest is the task's explicit
// "rejection of a non-well-formed digest" case -- covering too-short,
// uppercase, and non-hex variants, the same trio
// provider-agent/crates/agent-executor/src/vm/image.rs's own
// validate_sha256_hex test pins.
func TestCreateImageRejectsANonWellFormedDigest(t *testing.T) {
	ctx, server := newTestServer(t)
	token, _ := scopedToken(t, ctx, server, "alpha")

	cases := map[string]string{
		"too_short":       validDigest[:63],
		"uppercase":       strings.ToUpper(validDigest),
		"not_hex_at_all":  "not-a-real-digest-at-all-not-a-real-digest-at-all-not-a-real-d",
		"sha256_prefixed": "sha256:" + validDigest,
	}
	for name, digest := range cases {
		t.Run(name, func(t *testing.T) {
			recorder := doRequest(t, server, http.MethodPost, "/v2/images", token,
				createImageBody("bad-digest-image", "https://example.invalid/image.qcow2", digest, ""))
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
			}
			code, title := decodeKeystoneError(t, recorder.Body.Bytes())
			if code != http.StatusBadRequest || title == "" {
				t.Fatalf("error body code/title = %d/%q", code, title)
			}
		})
	}
}

func TestCreateImageRejectsAnUnauthenticatedRequest(t *testing.T) {
	_, server := newTestServer(t)

	recorder := doRequest(t, server, http.MethodPost, "/v2/images", "",
		createImageBody("ubuntu-base", "https://example.invalid/ubuntu.qcow2", validDigest, ""))

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusUnauthorized, recorder.Body.String())
	}
}

// TestCreateImageRejectsAnUnscopedToken proves a token with no project
// scope cannot register an image -- every image is project-owned, so
// there is no meaningful unscoped create.
func TestCreateImageRejectsAnUnscopedToken(t *testing.T) {
	ctx, server := newTestServer(t)
	token := unscopedToken(t, ctx, server)

	recorder := doRequest(t, server, http.MethodPost, "/v2/images", token,
		createImageBody("ubuntu-base", "https://example.invalid/ubuntu.qcow2", validDigest, ""))

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusUnauthorized, recorder.Body.String())
	}
}

func TestGetImageReturnsAFreshlyRegisteredImage(t *testing.T) {
	ctx, server := newTestServer(t)
	token, _ := scopedToken(t, ctx, server, "alpha")

	createRecorder := doRequest(t, server, http.MethodPost, "/v2/images", token,
		createImageBody("ubuntu-base", "https://example.invalid/ubuntu.qcow2", validDigest, ""))
	var created imageBody
	if err := json.Unmarshal(createRecorder.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	getRecorder := doRequest(t, server, http.MethodGet, "/v2/images/"+created.ID, token, nil)
	if getRecorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", getRecorder.Code, http.StatusOK, getRecorder.Body.String())
	}
	var got imageBody
	if err := json.Unmarshal(getRecorder.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.ID != created.ID || got.OSHashValue != validDigest {
		t.Fatalf("got = %+v, want id=%q digest=%q", got, created.ID, validDigest)
	}
}

func TestGetImageRejectsAnUnknownID(t *testing.T) {
	ctx, server := newTestServer(t)
	token, _ := scopedToken(t, ctx, server, "alpha")

	recorder := doRequest(t, server, http.MethodGet, "/v2/images/"+uuid.NewString(), token, nil)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNotFound)
	}
}

// TestGetImageDeniesCrossProjectAccessToAPrivateImage is the task's
// explicit "cross-project access denial" case.
func TestGetImageDeniesCrossProjectAccessToAPrivateImage(t *testing.T) {
	ctx, server := newTestServer(t)
	ownerToken, _ := scopedToken(t, ctx, server, "alpha")
	otherToken, _ := scopedToken(t, ctx, server, "beta")

	createRecorder := doRequest(t, server, http.MethodPost, "/v2/images", ownerToken,
		createImageBody("private-image", "https://example.invalid/private.qcow2", validDigest, glance.VisibilityPrivate))
	var created imageBody
	if err := json.Unmarshal(createRecorder.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	recorder := doRequest(t, server, http.MethodGet, "/v2/images/"+created.ID, otherToken, nil)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d (not found, not forbidden -- no enumeration oracle); body=%s", recorder.Code, http.StatusNotFound, recorder.Body.String())
	}
}

// TestGetImageAllowsCrossProjectAccessToAPublicImage proves the
// visibility escape hatch actually works the other direction: a public
// image IS visible cross-project.
func TestGetImageAllowsCrossProjectAccessToAPublicImage(t *testing.T) {
	ctx, server := newTestServer(t)
	ownerToken, _ := scopedToken(t, ctx, server, "alpha")
	otherToken, _ := scopedToken(t, ctx, server, "beta")

	createRecorder := doRequest(t, server, http.MethodPost, "/v2/images", ownerToken,
		createImageBody("public-image", "https://example.invalid/public.qcow2", validDigest, glance.VisibilityPublic))
	var created imageBody
	if err := json.Unmarshal(createRecorder.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	recorder := doRequest(t, server, http.MethodGet, "/v2/images/"+created.ID, otherToken, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
}

func TestListImagesReturnsOwnImagesAndOtherProjectsPublicImages(t *testing.T) {
	ctx, server := newTestServer(t)
	ownerToken, ownerProjectID := scopedToken(t, ctx, server, "alpha")
	otherToken, _ := scopedToken(t, ctx, server, "beta")

	doRequest(t, server, http.MethodPost, "/v2/images", ownerToken,
		createImageBody("owner-private", "https://example.invalid/1.qcow2", validDigest, glance.VisibilityPrivate))
	doRequest(t, server, http.MethodPost, "/v2/images", ownerToken,
		createImageBody("owner-public", "https://example.invalid/2.qcow2", validDigest, glance.VisibilityPublic))

	recorder := doRequest(t, server, http.MethodGet, "/v2/images", otherToken, nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var listed imagesListResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	// beta must see the owner's public image, and must NOT see the
	// owner's private one.
	sawPublic, sawPrivate := false, false
	for _, image := range listed.Images {
		if image.Name == "owner-public" {
			sawPublic = true
		}
		if image.Name == "owner-private" {
			sawPrivate = true
		}
		if image.Owner != ownerProjectID && image.Visibility != glance.VisibilityPublic {
			t.Fatalf("listed a non-public image %+v not owned by the caller", image)
		}
	}
	if !sawPublic {
		t.Fatal("expected the owner's public image in beta's listing")
	}
	if sawPrivate {
		t.Fatal("did not expect the owner's private image in beta's listing")
	}
}

func TestDeleteImageRemovesAnOwnedImage(t *testing.T) {
	ctx, server := newTestServer(t)
	token, _ := scopedToken(t, ctx, server, "alpha")

	createRecorder := doRequest(t, server, http.MethodPost, "/v2/images", token,
		createImageBody("to-delete", "https://example.invalid/delete-me.qcow2", validDigest, ""))
	var created imageBody
	if err := json.Unmarshal(createRecorder.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	deleteRecorder := doRequest(t, server, http.MethodDelete, "/v2/images/"+created.ID, token, nil)
	if deleteRecorder.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d, want %d; body=%s", deleteRecorder.Code, http.StatusNoContent, deleteRecorder.Body.String())
	}

	getRecorder := doRequest(t, server, http.MethodGet, "/v2/images/"+created.ID, token, nil)
	if getRecorder.Code != http.StatusNotFound {
		t.Fatalf("get-after-delete status = %d, want %d", getRecorder.Code, http.StatusNotFound)
	}
}

// TestDeleteImageDeniesCrossProjectDeletionOfAPublicImage proves
// visibility=public only grants read access, never delete -- only the
// owning project may ever delete its own image.
func TestDeleteImageDeniesCrossProjectDeletionOfAPublicImage(t *testing.T) {
	ctx, server := newTestServer(t)
	ownerToken, _ := scopedToken(t, ctx, server, "alpha")
	otherToken, _ := scopedToken(t, ctx, server, "beta")

	createRecorder := doRequest(t, server, http.MethodPost, "/v2/images", ownerToken,
		createImageBody("public-image", "https://example.invalid/public.qcow2", validDigest, glance.VisibilityPublic))
	var created imageBody
	if err := json.Unmarshal(createRecorder.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	recorder := doRequest(t, server, http.MethodDelete, "/v2/images/"+created.ID, otherToken, nil)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusNotFound, recorder.Body.String())
	}

	// Confirm it is genuinely still there for the owner.
	getRecorder := doRequest(t, server, http.MethodGet, "/v2/images/"+created.ID, ownerToken, nil)
	if getRecorder.Code != http.StatusOK {
		t.Fatalf("owner get-after-denied-delete status = %d, want %d", getRecorder.Code, http.StatusOK)
	}
}

func TestDeleteImageRejectsAnUnauthenticatedRequest(t *testing.T) {
	_, server := newTestServer(t)

	recorder := doRequest(t, server, http.MethodDelete, "/v2/images/"+uuid.NewString(), "", nil)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
}

func TestListImagesRejectsAnUnauthenticatedRequest(t *testing.T) {
	_, server := newTestServer(t)

	recorder := doRequest(t, server, http.MethodGet, "/v2/images", "", nil)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
}
