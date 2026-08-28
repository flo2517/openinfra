package dashboard

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{now: time.Now, releases: &fakeReleaseRepository{}, releaseTrustedKey: pub}
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
	server := &Server{now: time.Now, releases: &fakeReleaseRepository{latest: frontendrelease.FromManifest(signed)}, releaseTrustedKey: pub}

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

// TestWellKnownFrontendFailsClosedWhenSignedByAnAttackerKey is the
// internal security review's own adversarial scenario: a release row
// signed by a key other than the server's configured trusted key (e.g.
// inserted by whoever had direct Postgres write access, or a
// self-signed/attacker-controlled key) must never be served as the trust
// root, even though it is a validly-formed, non-empty signature.
func TestWellKnownFrontendFailsClosedWhenSignedByAnAttackerKey(t *testing.T) {
	trusted, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, attackerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := frontendrelease.BuildManifest("bafy-attacker-cid", []frontendrelease.ManifestFile{
		{Path: "index.html", SHA256: strings.Repeat("a", 64), Size: 1},
	}, "https://api.example.org", []string{"https://evil.example.org"}, "", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	signedByAttacker, err := frontendrelease.Sign(attackerPriv, unsigned)
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{now: time.Now, releases: &fakeReleaseRepository{latest: frontendrelease.FromManifest(signedByAttacker)}, releaseTrustedKey: trusted}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/.well-known/openinfra-frontend", nil)
	server.wellKnownFrontend(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (an attacker-signed release must never be served as the trust root)", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), "bafy-attacker-cid") {
		t.Fatal("response body leaked the unverified release's cid")
	}
}

// TestWellKnownFrontendFailsClosedForUnsignedRelease proves an empty
// signature (frontendrelease.PostgresRepository.Publish's own minimal
// pre-ADR-037 check) is just as untrusted as a wrong-key signature -- the
// finding's own literal "entirely unsigned-but-non-empty-string" case is
// covered by the attacker-key test above; this covers a truly empty
// Signature field.
func TestWellKnownFrontendFailsClosedForUnsignedRelease(t *testing.T) {
	trusted, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := frontendrelease.BuildManifest("bafy-unsigned", []frontendrelease.ManifestFile{
		{Path: "index.html", SHA256: strings.Repeat("a", 64), Size: 1},
	}, "https://api.example.org", nil, "", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{now: time.Now, releases: &fakeReleaseRepository{latest: frontendrelease.FromManifest(unsigned)}, releaseTrustedKey: trusted}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/.well-known/openinfra-frontend", nil)
	server.wellKnownFrontend(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 for an unsigned release", recorder.Code)
	}
}

// TestWellKnownFrontendFailsClosedWithNoTrustedKeyConfigured proves an
// absent FRONTEND_RELEASE_PUBLIC_KEY (server.releaseTrustedKey left
// nil/zero) makes the trust root inert -- never silently "everything
// verifies" -- even when a validly self-consistent, signed release
// exists in the repository.
func TestWellKnownFrontendFailsClosedWithNoTrustedKeyConfigured(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := frontendrelease.BuildManifest("bafy-no-key-configured", []frontendrelease.ManifestFile{
		{Path: "index.html", SHA256: strings.Repeat("a", 64), Size: 1},
	}, "https://api.example.org", nil, "", time.Now().UTC())
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

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 when no trusted release-signing public key is configured", recorder.Code)
	}
}
