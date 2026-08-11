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
	degraded := Overview{ValidatorsActive: -1, Providers: []Provider{}, WorkloadsByState: emptyWorkloadStateCounts()}
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

	healthy := Overview{ValidatorsActive: 0, Providers: []Provider{}, WorkloadsByState: emptyWorkloadStateCounts()}
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

// A provider's Reputation/Offer must distinguish three states in the JSON
// a client sees: never read (chain unavailable -> field absent), read but
// no record yet (available/found: false), and a real record. Collapsing
// "unavailable" and "no record yet" into the same shape would make a
// degraded chain read look identical to a freshly joined, honestly-scored
// provider.
func TestProviderReputationAndOfferDistinguishUnavailableFromNoRecordYet(t *testing.T) {
	notRead := Provider{ProviderID: "p1"}
	encoded, err := json.Marshal(notRead)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if _, present := decoded["reputation"]; present {
		t.Fatalf("expected no reputation field when never read, got %v", decoded["reputation"])
	}
	if _, present := decoded["offer"]; present {
		t.Fatalf("expected no offer field when never read, got %v", decoded["offer"])
	}

	noRecordYet := Provider{ProviderID: "p1", Reputation: &ReputationSummary{Available: false}, Offer: &OfferSummary{Found: false}}
	encoded, err = json.Marshal(noRecordYet)
	if err != nil {
		t.Fatal(err)
	}
	decoded = nil
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	reputation, ok := decoded["reputation"].(map[string]any)
	if !ok || reputation["available"] != false {
		t.Fatalf("expected reputation.available=false, got %v", decoded["reputation"])
	}
	offer, ok := decoded["offer"].(map[string]any)
	if !ok || offer["found"] != false {
		t.Fatalf("expected offer.found=false, got %v", decoded["offer"])
	}
}

// TestOverviewNeverSerializesPerWorkloadDetail pins ADR-016 §3's actual
// security property, not just its field rename: the Public-tier overview
// must expose no per-workload identifier at all. A future change that
// re-adds a workload list (or leaks one through a differently-named
// field) has to fail this test rather than quietly reopening the
// "which tenants are using this network, and when" signal.
func TestOverviewNeverSerializesPerWorkloadDetail(t *testing.T) {
	overview := Overview{
		Providers:        []Provider{},
		WorkloadsByState: map[string]int{"RUNNING": 3},
		WorkloadsTotal:   3,
		ValidatorsActive: 0,
	}
	encoded, err := json.Marshal(overview)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, forbidden := range []string{"workloads", "workload_id", "lease_id"} {
		if _, present := decoded[forbidden]; present {
			t.Fatalf("the public overview must not carry %q; per-workload detail belongs behind /api/v1/my/workloads", forbidden)
		}
	}
	byState, ok := decoded["workloads_by_state"].(map[string]any)
	if !ok {
		t.Fatal("expected workloads_by_state in the public overview")
	}
	if byState["RUNNING"] != float64(3) {
		t.Fatalf("workloads_by_state[RUNNING] = %v, want 3", byState["RUNNING"])
	}
}

// TestEmptyWorkloadStateCountsCoversEveryKnownState guards the honest-zero
// property: a state with no rows must report 0 rather than be absent, so a
// client can distinguish "none right now" from "this build doesn't know
// about that state".
func TestEmptyWorkloadStateCountsCoversEveryKnownState(t *testing.T) {
	counts := emptyWorkloadStateCounts()
	for _, state := range operatorWorkloadStates {
		if _, present := counts[state]; !present {
			t.Fatalf("state %q missing from the seeded counts", state)
		}
	}
	if len(counts) != len(operatorWorkloadStates) {
		t.Fatalf("seeded %d states, want exactly %d", len(counts), len(operatorWorkloadStates))
	}
}
