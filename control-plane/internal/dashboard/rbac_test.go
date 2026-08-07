package dashboard

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openinfra/network/internal/userauth"
)

// issueSessionKey is a small test helper: creates a user with the given
// role and returns a raw API key that authenticates as them --
// deliberately going through the real userauth.PostgresRepository (via
// newAuthTestServer), not a fake, so these tests exercise requireRole
// against the actual Authenticate/Role round trip a real request would.
func issueSessionKey(t *testing.T, server *Server, role string) string {
	t.Helper()
	user, err := server.users.CreateUser(t.Context(), "rbac-test-user")
	if err != nil {
		t.Fatal(err)
	}
	if role != userauth.RoleTenant {
		if err := server.users.SetRole(t.Context(), user.UserID, role); err != nil {
			t.Fatal(err)
		}
	}
	key, err := server.users.CreateAPIKey(t.Context(), user.UserID)
	if err != nil {
		t.Fatal(err)
	}
	return key.Raw
}

func TestRequireRoleRejectsAnUnauthenticatedCaller(t *testing.T) {
	_, server, _ := newAuthTestServer(t)
	handler := server.requireRole(userauth.RoleTenant, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("the wrapped handler must not run for an unauthenticated caller")
	})

	request := httptest.NewRequest(http.MethodGet, "/protected", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", recorder.Code)
	}
}

func TestRequireRoleAllowsATenantThroughATenantGate(t *testing.T) {
	_, server, _ := newAuthTestServer(t)
	rawKey := issueSessionKey(t, server, userauth.RoleTenant)

	ran := false
	handler := server.requireRole(userauth.RoleTenant, func(w http.ResponseWriter, r *http.Request) {
		ran = true
		w.WriteHeader(http.StatusOK)
	})

	request := httptest.NewRequest(http.MethodGet, "/protected", nil)
	request.Header.Set("Authorization", "Bearer "+rawKey)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if !ran {
		t.Fatal("expected the wrapped handler to run for a tenant at a tenant gate")
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
}

func TestRequireRoleRejectsATenantAtAnOperatorGate(t *testing.T) {
	_, server, _ := newAuthTestServer(t)
	rawKey := issueSessionKey(t, server, userauth.RoleTenant)

	handler := server.requireRole(userauth.RoleOperator, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("the wrapped handler must not run for an under-privileged caller")
	})

	request := httptest.NewRequest(http.MethodGet, "/protected", nil)
	request.Header.Set("Authorization", "Bearer "+rawKey)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	// 403, not 401 -- the caller has a real, valid credential; they are
	// simply the wrong role. See requireRole's doc comment for why this
	// distinction matters.
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", recorder.Code)
	}
}

func TestRequireRoleAllowsAnOperatorThroughATenantGate(t *testing.T) {
	_, server, _ := newAuthTestServer(t)
	rawKey := issueSessionKey(t, server, userauth.RoleOperator)

	ran := false
	handler := server.requireRole(userauth.RoleTenant, func(w http.ResponseWriter, r *http.Request) {
		ran = true
		w.WriteHeader(http.StatusOK)
	})

	request := httptest.NewRequest(http.MethodGet, "/protected", nil)
	request.Header.Set("Authorization", "Bearer "+rawKey)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if !ran {
		t.Fatal("expected an operator to satisfy a tenant-tier gate too (ADR-016 §1's ranked roles)")
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
}

func TestRequireRoleAllowsAnOperatorThroughAnOperatorGate(t *testing.T) {
	_, server, _ := newAuthTestServer(t)
	rawKey := issueSessionKey(t, server, userauth.RoleOperator)

	ran := false
	handler := server.requireRole(userauth.RoleOperator, func(w http.ResponseWriter, r *http.Request) {
		ran = true
		w.WriteHeader(http.StatusOK)
	})

	request := httptest.NewRequest(http.MethodGet, "/protected", nil)
	request.Header.Set("Authorization", "Bearer "+rawKey)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if !ran {
		t.Fatal("expected an operator to satisfy an operator-tier gate")
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
}

func TestRequireRoleRejectsARevokedKey(t *testing.T) {
	_, server, _ := newAuthTestServer(t)
	user, err := server.users.CreateUser(t.Context(), "rbac-test-user")
	if err != nil {
		t.Fatal(err)
	}
	key, err := server.users.CreateAPIKey(t.Context(), user.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.users.RevokeAPIKey(t.Context(), key.KeyID); err != nil {
		t.Fatal(err)
	}

	handler := server.requireRole(userauth.RoleTenant, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("the wrapped handler must not run for a revoked key")
	})
	request := httptest.NewRequest(http.MethodGet, "/protected", nil)
	request.Header.Set("Authorization", "Bearer "+key.Raw)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", recorder.Code)
	}
}
