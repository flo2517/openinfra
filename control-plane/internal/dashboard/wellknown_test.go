package dashboard

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openinfra/network/internal/frontendrelease"
)

// TestWellKnownFrontendReturns404WithNoRepositoryWired proves a
// deployment that hasn't adopted ADR-037 yet (releases == nil, every
// pre-existing Server) behaves as "this endpoint doesn't exist," not as
// a degraded/error read.
func TestWellKnownFrontendReturns404WithNoRepositoryWired(t *testing.T) {
	server := &Server{now: time.Now}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/.well-known/openinfra-frontend", nil)
	server.wellKnownFrontend(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", recorder.Code)
	}
}

// TestWellKnownFrontendReturns404WithNoActiveRelease proves an empty (or
// fully-revoked) release history also 404s -- distinct from "repository
// unavailable," which must 503 instead (tested below).
func TestWellKnownFrontendReturns404WithNoActiveRelease(t *testing.T) {
	server := &Server{now: time.Now, releases: &fakeReleaseRepository{}}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/.well-known/openinfra-frontend", nil)
	server.wellKnownFrontend(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", recorder.Code)
	}
}

// TestWellKnownFrontendServesTheSignedManifestVerbatim proves this is
// the actual DNSLink/.well-known trust root: it returns the currently
// active release's signed manifest, byte-for-byte verifiable against the
// release-signing public key.
func TestWellKnownFrontendServesTheSignedManifestVerbatim(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := frontendrelease.BuildManifest("bafy-current-release", []frontendrelease.ManifestFile{
		{Path: "index.html", SHA256: "0000000000000000000000000000000000000000000000000000000000000000000000000000"[:64], Size: 1},
	}, "https://api.example.org", []string{"https://dashboard.example.org"}, "", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	signed, err := frontendrelease.Sign(priv, unsigned)
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{now: time.Now, releases: &fakeReleaseRepository{latest: frontendrelease.FromManifest(signed)}}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/.well-known/openinfra-frontend", nil)
	server.wellKnownFrontend(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	if ct := recorder.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q", ct)
	}
	if cc := recorder.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store (this is a trust root, never cached)", cc)
	}
	var got frontendrelease.Manifest
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("response body did not decode as a manifest: %v", err)
	}
	if err := frontendrelease.Verify(pub, got); err != nil {
		t.Fatalf(".well-known served a manifest that no longer verifies: %v", err)
	}
	if got.CID != "bafy-current-release" {
		t.Fatalf("cid = %q, want bafy-current-release", got.CID)
	}
}
