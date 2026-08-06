package dashboard

import (
	"encoding/json"
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

// A degraded validator-set read must serialize as -1, never 0: the
// dashboard's whole point is not reporting false success on a failed
// chain read (ADR-011). This pins the JSON contract so a refactor can't
// silently drop the sentinel back to Go's int zero value.
func TestOverviewReportsUnavailableValidatorSetDistinctlyFromZero(t *testing.T) {
	degraded := Overview{ValidatorsActive: -1, Providers: []Provider{}, Workloads: []Workload{}}
	encoded, err := json.Marshal(degraded)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	got, ok := decoded["validators_active"]
	if !ok {
		t.Fatal("expected a validators_active field even when zero-valued/unavailable")
	}
	if got != float64(-1) {
		t.Fatalf("validators_active = %v, want -1", got)
	}

	healthy := Overview{ValidatorsActive: 0, Providers: []Provider{}, Workloads: []Workload{}}
	encoded, err = json.Marshal(healthy)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	decoded = nil
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded["validators_active"] != float64(0) {
		t.Fatalf("a genuinely empty validator set must still read as 0, got %v", decoded["validators_active"])
	}
}
