package dashboard

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSecurityHeaders(t *testing.T) {
	handler := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	request := httptest.NewRequest(http.MethodGet, "/api/v1/overview", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("missing content security policy")
	}
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
}

func TestAbbreviateProviderIdentity(t *testing.T) {
	if got := abbreviate("0123456789abcdef0123456789abcdef"); got != "0123456789ab…" {
		t.Fatalf("abbreviate() = %q", got)
	}
	if got := abbreviate("short"); got != "short" {
		t.Fatalf("short value changed to %q", got)
	}
}
