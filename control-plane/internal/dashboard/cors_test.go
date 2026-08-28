package dashboard

import (
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openinfra/network/internal/frontendrelease"
)

// signedReleaseWithOrigins is releaseWithOrigins's signed counterpart --
// the adversarial CORS tests below need a release that either does or
// does not verify against a particular key, not just one with the right
// AllowedLoginOrigins shape.
func signedReleaseWithOrigins(t *testing.T, priv ed25519.PrivateKey, origins []string) frontendrelease.Release {
	t.Helper()
	unsigned, err := frontendrelease.BuildManifest("bafy-test-cid", []frontendrelease.ManifestFile{
		{Path: "index.html", SHA256: strings.Repeat("a", 64), Size: 1},
	}, "https://api.example.org", origins, "", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	signed, err := frontendrelease.Sign(priv, unsigned)
	if err != nil {
		t.Fatal(err)
	}
	return frontendrelease.FromManifest(signed)
}

func newCORSTestServer(allowedOrigins []string, releases *fakeReleaseRepository) *Server {
	s := &Server{now: time.Now, allowedOrigins: allowedOrigins}
	if releases != nil {
		s.releases = releases
	}
	return s
}

func recordingHandler(called *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*called = true
		w.WriteHeader(http.StatusOK)
	})
}

// TestCORSAllowlistAllowsAllowedOriginAndProceedsToHandler proves the
// happy path: a credentialed request from an explicitly allowlisted
// origin gets Access-Control-Allow-Origin set and reaches the real
// handler -- ADR-037 §4's canonical-tier login flow.
func TestCORSAllowlistAllowsAllowedOriginAndProceedsToHandler(t *testing.T) {
	server := newCORSTestServer([]string{"https://dashboard.example.org"}, nil)
	called := false
	handler := server.corsAllowlist(recordingHandler(&called))

	request := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	request.Header.Set("Origin", "https://dashboard.example.org")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if !called {
		t.Fatal("an allowed origin's request never reached the wrapped handler")
	}
	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "https://dashboard.example.org" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want the allowed origin echoed back", got)
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 from the wrapped handler", recorder.Code)
	}
}

// TestCORSAllowlistRejectsDisallowedOriginOnCredentialedPath is ADR-037
// §4's actual phishing-resistance control: a phishing clone served from
// some other origin must never reach a credentialed endpoint's handler,
// regardless of what credential it presents.
func TestCORSAllowlistRejectsDisallowedOriginOnCredentialedPath(t *testing.T) {
	server := newCORSTestServer([]string{"https://dashboard.example.org"}, nil)
	called := false
	handler := server.corsAllowlist(recordingHandler(&called))

	request := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	request.Header.Set("Origin", "https://evil-gateway.example")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if called {
		t.Fatal("a disallowed origin's request reached the wrapped handler -- CORS gate did not block it")
	}
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", recorder.Code)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want unset for a rejected origin", got)
	}
}

// TestCORSAllowlistRejectsDisallowedOriginEvenWithACredentialPresent
// proves the CORS gate runs *before* any credential is even inspected --
// a phishing clone presenting a stolen or forged bearer token from the
// wrong origin is rejected the same way as one presenting nothing.
func TestCORSAllowlistRejectsDisallowedOriginEvenWithACredentialPresent(t *testing.T) {
	server := newCORSTestServer([]string{"https://dashboard.example.org"}, nil)
	called := false
	handler := server.corsAllowlist(recordingHandler(&called))

	request := httptest.NewRequest(http.MethodGet, "/api/v1/my/workloads", nil)
	request.Header.Set("Origin", "https://evil-gateway.example/ipfs/some-other-cid")
	request.Header.Set("Authorization", "Bearer oiu_doesnotmatter")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if called {
		t.Fatal("a disallowed-origin credentialed request reached the handler despite a bearer token being present")
	}
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", recorder.Code)
	}
}

// TestCORSAllowlistDoesNotBlockPublicPathsForDisallowedOrigins proves the
// allowlist is scoped to credentialed endpoints only (ADR-016 §3's public,
// aggregate-only data stays reachable cross-origin, just without
// Access-Control-Allow-Origin -- a browser cannot read the response, but
// the request itself is not refused).
func TestCORSAllowlistDoesNotBlockPublicPathsForDisallowedOrigins(t *testing.T) {
	server := newCORSTestServer([]string{"https://dashboard.example.org"}, nil)
	called := false
	handler := server.corsAllowlist(recordingHandler(&called))

	request := httptest.NewRequest(http.MethodGet, "/api/v1/overview", nil)
	request.Header.Set("Origin", "https://some-mirror-gateway.example")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if !called {
		t.Fatal("a public, non-credentialed path was blocked by the CORS allowlist")
	}
	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want unset (no cross-origin read grant) for a non-allowlisted origin", got)
	}
}

// TestCORSAllowlistAllowsSameOriginRequestRegardlessOfStaticList proves
// same-origin requests (e.g. the direct-serve /dashboard/ path calling
// its own control-plane's API) are never broken by this middleware, even
// with an empty/unrelated allowedOrigins list -- the existing, pre-
// ADR-037 same-origin dev flow.
func TestCORSAllowlistAllowsSameOriginRequestRegardlessOfStaticList(t *testing.T) {
	server := newCORSTestServer(nil, nil)
	called := false
	handler := server.corsAllowlist(recordingHandler(&called))

	request := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	request.Host = "dashboard.local:8080"
	request.Header.Set("Origin", "http://dashboard.local:8080")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if !called {
		t.Fatal("a same-origin request was rejected by the CORS allowlist")
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
}

// TestCORSAllowlistRequestWithNoOriginHeaderAlwaysProceeds documents the
// deliberate, ADR-037 §4-acknowledged scope of this control: a
// non-browser caller (curl, a server-side relay, this package's own
// other tests) that sends no Origin header at all is not something CORS
// -- a browser-enforced mechanism -- can gate in the first place.
func TestCORSAllowlistRequestWithNoOriginHeaderAlwaysProceeds(t *testing.T) {
	server := newCORSTestServer([]string{"https://dashboard.example.org"}, nil)
	called := false
	handler := server.corsAllowlist(recordingHandler(&called))

	request := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if !called {
		t.Fatal("a request with no Origin header was blocked -- CORS cannot and should not gate this case")
	}
}

// TestCORSAllowlistConsultsActiveReleaseOrigins proves the dynamic half
// of ADR-037 §4/§7: an origin trusted only by the currently active
// frontend release (not the static allowedOrigins config) is still
// honored.
func TestCORSAllowlistConsultsActiveReleaseOrigins(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	releases := &fakeReleaseRepository{latest: signedReleaseWithOrigins(t, priv, []string{"https://gateway.example.org"})}
	server := newCORSTestServer(nil, releases)
	server.releaseTrustedKey = pub
	called := false
	handler := server.corsAllowlist(recordingHandler(&called))

	request := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	request.Header.Set("Origin", "https://gateway.example.org")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if !called {
		t.Fatal("an origin trusted only by the active release was rejected")
	}
	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "https://gateway.example.org" {
		t.Fatalf("Access-Control-Allow-Origin = %q", got)
	}
}

// TestCORSAllowlistFailsClosedWhenNoActiveRelease proves a revoked/absent
// release grants no additional trust -- the ADR-037 §7 step 3 cutoff:
// once a release stops being "latest, non-revoked," its
// allowed_login_origins stop being honored immediately.
func TestCORSAllowlistFailsClosedWhenNoActiveRelease(t *testing.T) {
	releases := &fakeReleaseRepository{}
	server := newCORSTestServer(nil, releases)
	called := false
	handler := server.corsAllowlist(recordingHandler(&called))

	request := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	request.Header.Set("Origin", "https://gateway.example.org")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if called {
		t.Fatal("an origin was trusted with no active release published at all")
	}
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", recorder.Code)
	}
}

// TestCORSAllowlistDoesNotTrustOriginsSignedByAnAttackerKey is the
// internal security review's own adversarial scenario applied to the
// CORS allowlist: a release row whose signature does not verify against
// the server's configured trusted key (e.g. inserted by whoever had
// direct Postgres write access, self-signed with an attacker-controlled
// key) must never grant its allowed_login_origins trust, even though the
// signature field is well-formed and non-empty.
func TestCORSAllowlistDoesNotTrustOriginsSignedByAnAttackerKey(t *testing.T) {
	trusted, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, attackerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	releases := &fakeReleaseRepository{latest: signedReleaseWithOrigins(t, attackerPriv, []string{"https://evil-gateway.example.org"})}
	server := newCORSTestServer(nil, releases)
	server.releaseTrustedKey = trusted
	called := false
	handler := server.corsAllowlist(recordingHandler(&called))

	request := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	request.Header.Set("Origin", "https://evil-gateway.example.org")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if called {
		t.Fatal("an origin from an attacker-signed release reached the wrapped handler")
	}
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", recorder.Code)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want unset for an attacker-signed release's origin", got)
	}
}

// TestCORSAllowlistDoesNotTrustOriginsWithNoTrustedKeyConfigured proves
// an absent FRONTEND_RELEASE_PUBLIC_KEY (server.releaseTrustedKey left
// nil/zero) makes the dynamic half of the allowlist inert -- never
// silently "everything verifies" -- even when a validly self-consistent,
// signed release exists in the repository.
func TestCORSAllowlistDoesNotTrustOriginsWithNoTrustedKeyConfigured(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	releases := &fakeReleaseRepository{latest: signedReleaseWithOrigins(t, priv, []string{"https://gateway.example.org"})}
	server := newCORSTestServer(nil, releases)
	called := false
	handler := server.corsAllowlist(recordingHandler(&called))

	request := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	request.Header.Set("Origin", "https://gateway.example.org")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if called {
		t.Fatal("an origin was trusted with no trusted release-signing public key configured at all")
	}
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", recorder.Code)
	}
}

// TestCORSAllowlistDoesNotTrustOriginsFromAnUnsignedRelease covers a
// truly empty Signature field, distinct from the wrong-key case above.
func TestCORSAllowlistDoesNotTrustOriginsFromAnUnsignedRelease(t *testing.T) {
	trusted, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	releases := &fakeReleaseRepository{latest: releaseWithOrigins(t, []string{"https://unsigned.example.org"})}
	server := newCORSTestServer(nil, releases)
	server.releaseTrustedKey = trusted
	called := false
	handler := server.corsAllowlist(recordingHandler(&called))

	request := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	request.Header.Set("Origin", "https://unsigned.example.org")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if called {
		t.Fatal("an origin from an unsigned release reached the wrapped handler")
	}
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", recorder.Code)
	}
}

// TestCORSAllowlistPreflightRespondsWithoutReachingHandler proves an
// OPTIONS preflight from an allowed origin gets a 204 with the CORS
// headers a browser needs to then send the real request, and never
// reaches the wrapped handler (which would not know how to answer
// OPTIONS itself).
func TestCORSAllowlistPreflightRespondsWithoutReachingHandler(t *testing.T) {
	server := newCORSTestServer([]string{"https://dashboard.example.org"}, nil)
	called := false
	handler := server.corsAllowlist(recordingHandler(&called))

	request := httptest.NewRequest(http.MethodOptions, "/api/v1/auth/login", nil)
	request.Header.Set("Origin", "https://dashboard.example.org")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if called {
		t.Fatal("an OPTIONS preflight reached the wrapped handler")
	}
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", recorder.Code)
	}
	if recorder.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Fatal("preflight response missing Access-Control-Allow-Methods")
	}
}
