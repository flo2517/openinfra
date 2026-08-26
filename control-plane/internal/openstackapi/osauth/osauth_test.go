package osauth_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openinfra/network/internal/openstackapi/osauth"
	"github.com/openinfra/network/internal/userauth"
)

type fakeAuthenticator struct {
	user      userauth.User
	projectID *string
	err       error
}

func (f fakeAuthenticator) AuthenticateScoped(context.Context, [32]byte) (userauth.User, *string, error) {
	if f.err != nil {
		return userauth.User{}, nil, f.err
	}
	return f.user, f.projectID, nil
}

func TestRequireTokenRejectsAMissingHeader(t *testing.T) {
	called := false
	handler := osauth.RequireToken(fakeAuthenticator{}, func(http.ResponseWriter, *http.Request) { called = true })

	recorder := httptest.NewRecorder()
	handler(recorder, httptest.NewRequest(http.MethodGet, "/", nil))

	if called {
		t.Fatal("next handler ran without a token")
	}
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
	assertKeystoneErrorShape(t, recorder.Body.Bytes())
}

func TestRequireTokenRejectsAnInvalidToken(t *testing.T) {
	called := false
	handler := osauth.RequireToken(fakeAuthenticator{err: userauth.ErrInvalidKey}, func(http.ResponseWriter, *http.Request) { called = true })

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("X-Auth-Token", "not-a-real-token")
	recorder := httptest.NewRecorder()
	handler(recorder, request)

	if called {
		t.Fatal("next handler ran with an invalid token")
	}
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
}

// TestRequireTokenFailsClosedOnARepositoryError proves an unreachable
// repository denies the request rather than defaulting to permissive --
// the same fail-closed posture userauth's own gRPC interceptor requires
// for a rate-limiter failure.
func TestRequireTokenFailsClosedOnARepositoryError(t *testing.T) {
	called := false
	handler := osauth.RequireToken(fakeAuthenticator{err: errors.New("connection refused")}, func(http.ResponseWriter, *http.Request) { called = true })

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("X-Auth-Token", "some-token")
	recorder := httptest.NewRecorder()
	handler(recorder, request)

	if called {
		t.Fatal("next handler ran despite a repository error")
	}
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
}

func TestRequireTokenAttachesIdentityForAValidToken(t *testing.T) {
	projectID := "project-a"
	authenticator := fakeAuthenticator{user: userauth.User{UserID: "user-1", Role: userauth.RoleTenant}, projectID: &projectID}

	var gotIdentity osauth.Identity
	var gotOK bool
	handler := osauth.RequireToken(authenticator, func(w http.ResponseWriter, r *http.Request) {
		gotIdentity, gotOK = osauth.FromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("X-Auth-Token", "a-valid-token")
	recorder := httptest.NewRecorder()
	handler(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if !gotOK {
		t.Fatal("FromContext() found no identity in the wrapped handler")
	}
	if gotIdentity.UserID != "user-1" || gotIdentity.ProjectID == nil || *gotIdentity.ProjectID != "project-a" {
		t.Fatalf("identity = %+v, want UserID=user-1 ProjectID=project-a", gotIdentity)
	}
}

// TestRequireTokenReportsNoScopeForAnUnscopedToken proves an unscoped
// token (ProjectID nil) is passed through with ProjectID nil rather than
// e.g. an empty string a caller might mistake for a real project ID.
func TestRequireTokenReportsNoScopeForAnUnscopedToken(t *testing.T) {
	authenticator := fakeAuthenticator{user: userauth.User{UserID: "user-1"}, projectID: nil}

	var gotIdentity osauth.Identity
	handler := osauth.RequireToken(authenticator, func(w http.ResponseWriter, r *http.Request) {
		gotIdentity, _ = osauth.FromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("X-Auth-Token", "a-valid-token")
	recorder := httptest.NewRecorder()
	handler(recorder, request)

	if gotIdentity.ProjectID != nil {
		t.Fatalf("ProjectID = %v, want nil for an unscoped token", gotIdentity.ProjectID)
	}
}

func TestFromContextReportsNotOKWithoutRequireToken(t *testing.T) {
	if _, ok := osauth.FromContext(context.Background()); ok {
		t.Fatal("FromContext() on a bare context reported ok=true")
	}
}

func assertKeystoneErrorShape(t *testing.T, body []byte) {
	t.Helper()
	var decoded struct {
		Error struct {
			Code    int    `json:"code"`
			Title   string `json:"title"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("response body is not the Keystone error shape: %v (%s)", err, body)
	}
	if decoded.Error.Code == 0 || decoded.Error.Title == "" || decoded.Error.Message == "" {
		t.Fatalf("Keystone error body missing a field: %+v", decoded.Error)
	}
}
