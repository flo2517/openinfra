package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A failed chain read must not serialize as an earned balance of zero.
// "You have earned nothing" and "we could not ask the chain" are
// different statements to make to a provider, and pallet-rewards'
// ValueQuery declaration means a genuine zero is a perfectly normal
// answer -- so the distinction cannot live in the number alone.
//
// Same shape as TestOverviewReportsUnavailableValidatorSetDistinctlyFromZero,
// and for the same reason: pin the JSON contract so a later refactor
// cannot quietly drop the flag and leave the number speaking for itself.
func TestProviderEarningsDistinguishUnavailableFromZero(t *testing.T) {
	unavailable, err := json.Marshal(ProviderEarnings{Available: false})
	if err != nil {
		t.Fatal(err)
	}
	genuineZero, err := json.Marshal(ProviderEarnings{Available: true, RewardPoints: 0})
	if err != nil {
		t.Fatal(err)
	}
	if string(unavailable) == string(genuineZero) {
		t.Fatalf("a failed read and a real zero balance serialize identically: %s", unavailable)
	}
	if want := `{"available":false,"reward_points":0}`; string(unavailable) != want {
		t.Fatalf("unavailable = %s, want %s", unavailable, want)
	}
}

// Three distinct proof states, none of which may collapse into another:
// the read failed, the read succeeded and there is no proof yet, and
// there is a proof. Reporting "no proof yet" as 0 % availability would
// invent a damning measurement for a provider that has simply just
// joined.
func TestProviderProofDistinguishesUnavailableFromAbsentFromPresent(t *testing.T) {
	encoded := map[string]string{}
	for name, proof := range map[string]ProviderProof{
		"unavailable": {Available: false},
		"absent":      {Available: true, Found: false},
		"present":     {Available: true, Found: true, Sequence: 3, AvailabilityBps: 9500, SuccessfulSamples: 95, TotalSamples: 100},
	} {
		body, err := json.Marshal(proof)
		if err != nil {
			t.Fatal(err)
		}
		encoded[name] = string(body)
	}
	if encoded["unavailable"] == encoded["absent"] {
		t.Fatalf("a failed read and an absent proof serialize identically: %s", encoded["absent"])
	}
	if encoded["absent"] == encoded["present"] {
		t.Fatal("an absent proof and a real proof serialize identically")
	}
	// availability_bps is omitempty, so an absent proof carries no
	// availability figure at all rather than an implied 0%.
	if got := encoded["absent"]; got != `{"available":true,"found":false}` {
		t.Fatalf("absent proof = %s", got)
	}
}

// The route exists, is reachable without authentication (it serves
// finalized consensus state anyone can read off the node), and resolves
// the provider before touching the chain -- so an unknown provider_id is
// a 404 rather than a chain round trip.
func TestProviderOnChainRejectsAnUnknownProvider(t *testing.T) {
	_, server, _ := newAuthTestServer(t)

	request := httptest.NewRequest(http.MethodGet, "/api/v1/provider/does-not-exist/onchain", nil)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body: %s)", recorder.Code, recorder.Body.String())
	}
}

func TestProviderOnChainRejectsAnOversizedProviderID(t *testing.T) {
	_, server, _ := newAuthTestServer(t)

	oversized := make([]byte, maxProviderIDLength+1)
	for i := range oversized {
		oversized[i] = 'a'
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/provider/"+string(oversized)+"/onchain", nil)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body: %s)", recorder.Code, recorder.Body.String())
	}
}
