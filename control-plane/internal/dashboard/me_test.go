package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openinfra/network/internal/userauth"
)

func getMe(t *testing.T, server *Server, rawKey string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	if rawKey != "" {
		request.Header.Set("Authorization", "Bearer "+rawKey)
	}
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	return recorder
}

func decodeIdentity(t *testing.T, recorder *httptest.ResponseRecorder) SessionIdentity {
	t.Helper()
	var identity SessionIdentity
	if err := json.Unmarshal(recorder.Body.Bytes(), &identity); err != nil {
		t.Fatalf("decode /api/v1/me body %q: %v", recorder.Body.String(), err)
	}
	return identity
}

func TestMeRejectsAnUnauthenticatedCaller(t *testing.T) {
	_, server, _ := newAuthTestServer(t)

	if code := getMe(t, server, "").Code; code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", code)
	}
}

func TestMeReportsTheCallersOwnRole(t *testing.T) {
	_, server, _ := newAuthTestServer(t)

	for _, role := range []string{userauth.RoleTenant, userauth.RoleOperatorReadOnly, userauth.RoleOperatorAdmin} {
		rawKey := issueSessionKey(t, server, role)
		recorder := getMe(t, server, rawKey)
		if recorder.Code != http.StatusOK {
			t.Fatalf("role %q: status = %d, want 200", role, recorder.Code)
		}
		identity := decodeIdentity(t, recorder)
		if identity.Role != role {
			t.Fatalf("role = %q, want %q", identity.Role, role)
		}
		if identity.UserID == "" {
			t.Fatalf("role %q: user_id is empty", role)
		}
	}
}

// The client renders its operator panel from this response, so a grant
// that only takes effect after the user's session expires would look like
// the grant silently failed. Reading the role per request rather than
// freezing it into the login response is what makes the next page load
// enough.
func TestMeReflectsARoleGrantWithoutANewLogin(t *testing.T) {
	ctx, server, _ := newAuthTestServer(t)

	user, err := server.users.CreateUser(ctx, "me-test-user")
	if err != nil {
		t.Fatal(err)
	}
	key, err := server.users.CreateAPIKey(ctx, user.UserID)
	if err != nil {
		t.Fatal(err)
	}

	if role := decodeIdentity(t, getMe(t, server, key.Raw)).Role; role != userauth.RoleTenant {
		t.Fatalf("role before grant = %q, want %q", role, userauth.RoleTenant)
	}

	if err := server.users.SetRole(ctx, user.UserID, userauth.RoleOperatorReadOnly); err != nil {
		t.Fatal(err)
	}

	// Same credential, no re-login.
	if role := decodeIdentity(t, getMe(t, server, key.Raw)).Role; role != userauth.RoleOperatorReadOnly {
		t.Fatalf("role after grant = %q, want %q", role, userauth.RoleOperatorReadOnly)
	}
}

// /api/v1/me is an identity echo, not a privilege escalation path: being
// able to read your own role must never imply being able to read
// operator data. Pins that the operator routes stay gated for a caller
// who has just successfully called /api/v1/me.
func TestMeDoesNotGrantAccessToOperatorRoutes(t *testing.T) {
	_, server, _ := newAuthTestServer(t)
	rawKey := issueSessionKey(t, server, userauth.RoleTenant)

	if code := getMe(t, server, rawKey).Code; code != http.StatusOK {
		t.Fatalf("/api/v1/me status = %d, want 200", code)
	}

	for _, path := range []string{"/api/v1/operator/queue", "/api/v1/operator/workers", "/api/v1/operator/audit", "/api/v1/operator/health"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Header.Set("Authorization", "Bearer "+rawKey)
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, request)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("%s status = %d, want 403", path, recorder.Code)
		}
	}
}
