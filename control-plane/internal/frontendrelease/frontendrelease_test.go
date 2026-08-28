package frontendrelease

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"
)

func testManifest(t *testing.T) Manifest {
	t.Helper()
	files := []ManifestFile{
		{Path: "index.html", SHA256: strings.Repeat("a", 64), Size: 100},
		{Path: "app.js", SHA256: strings.Repeat("b", 64), Size: 200},
	}
	manifest, err := BuildManifest("bafy-test-cid", files, "https://api.example.org", []string{"https://dashboard.example.org"}, "", time.Date(2026, 8, 27, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	return manifest
}

func TestBuildManifestIsDeterministicRegardlessOfFileOrder(t *testing.T) {
	filesA := []ManifestFile{{Path: "b.js", SHA256: strings.Repeat("1", 64), Size: 1}, {Path: "a.js", SHA256: strings.Repeat("2", 64), Size: 2}}
	filesB := []ManifestFile{{Path: "a.js", SHA256: strings.Repeat("2", 64), Size: 2}, {Path: "b.js", SHA256: strings.Repeat("1", 64), Size: 1}}
	when := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	manifestA, err := BuildManifest("cid", filesA, "", nil, "", when)
	if err != nil {
		t.Fatal(err)
	}
	manifestB, err := BuildManifest("cid", filesB, "", nil, "", when)
	if err != nil {
		t.Fatal(err)
	}
	if manifestA.ManifestSHA256 != manifestB.ManifestSHA256 {
		t.Fatalf("manifest_sha256 depends on file order: %s vs %s", manifestA.ManifestSHA256, manifestB.ManifestSHA256)
	}
	if manifestA.ReleaseID != manifestB.ReleaseID {
		t.Fatalf("release_id depends on file order: %s vs %s", manifestA.ReleaseID, manifestB.ReleaseID)
	}
}

func TestBuildManifestReleaseIDDerivesFromHash(t *testing.T) {
	manifest := testManifest(t)
	if !strings.HasPrefix(manifest.ReleaseID, "2026-08-27T00:00:00Z-") {
		t.Fatalf("release_id = %q, want a 2026-08-27T00:00:00Z-<hash> prefix", manifest.ReleaseID)
	}
	if !strings.HasSuffix(manifest.ReleaseID, manifest.ManifestSHA256[:12]) {
		t.Fatalf("release_id = %q, want it to end with the first 12 hex chars of manifest_sha256 (%s)", manifest.ReleaseID, manifest.ManifestSHA256)
	}
}

func TestSignThenVerifySucceeds(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	unsigned := testManifest(t)
	signed, err := Sign(priv, unsigned)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if signed.Signature == "" {
		t.Fatal("Sign left Signature empty")
	}
	if err := Verify(pub, signed); err != nil {
		t.Fatalf("Verify(valid signature) = %v, want nil", err)
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := Sign(priv, testManifest(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(otherPub, signed); err != ErrInvalidSignature {
		t.Fatalf("Verify(wrong key) = %v, want ErrInvalidSignature", err)
	}
}

func TestVerifyRejectsTamperedField(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := Sign(priv, testManifest(t))
	if err != nil {
		t.Fatal(err)
	}
	// Tamper with api_origin *after* signing, leaving manifest_sha256 and
	// signature untouched -- this must be caught even though the
	// signature bytes themselves are still a valid Ed25519 signature over
	// the (now-stale) original manifest_sha256/cid pair.
	signed.APIOrigin = "https://evil.example/"
	if err := Verify(pub, signed); err != ErrManifestTampered {
		t.Fatalf("Verify(tampered api_origin) = %v, want ErrManifestTampered", err)
	}
}

func TestVerifyRejectsCorruptSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := Sign(priv, testManifest(t))
	if err != nil {
		t.Fatal(err)
	}
	signed.Signature = "not-hex"
	if err := Verify(pub, signed); err != ErrInvalidSignature {
		t.Fatalf("Verify(corrupt signature) = %v, want ErrInvalidSignature", err)
	}
}

func TestSigningMessageIsDomainSeparatedFromOtherFlows(t *testing.T) {
	message := SigningMessage("deadbeef", "cid-value")
	if !strings.HasPrefix(string(message), "openinfra-frontend-release-v1\x00") {
		t.Fatalf("SigningMessage does not start with the release-signing domain prefix: %q", message)
	}
	// Distinct from providerjoin's joinDomain/heartbeatDomain and
	// walletlogin's loginDomain by construction (a different literal
	// prefix), so a signature produced for one flow can never verify
	// against another -- this test only pins the prefix's own value so a
	// future edit can't silently drop the "\x00" separator or v1 suffix.
	if !strings.Contains(string(message), "v1\x00") {
		t.Fatalf("SigningMessage prefix lost its version/NUL separator: %q", message)
	}
}

func TestIsAllowedOrigin(t *testing.T) {
	allowed := []string{"https://dashboard.example.org", "https://gateway.example.org"}
	cases := []struct {
		origin string
		want   bool
	}{
		{"https://dashboard.example.org", true},
		{"https://gateway.example.org", true},
		{"https://evil-gateway.example/ipfs/some-other-cid", false},
		{"", false},
		{"https://dashboard.example.org.evil.com", false},
	}
	for _, c := range cases {
		if got := IsAllowedOrigin(c.origin, allowed); got != c.want {
			t.Errorf("IsAllowedOrigin(%q) = %v, want %v", c.origin, got, c.want)
		}
	}
}
