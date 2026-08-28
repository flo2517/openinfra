package frontendrelease

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeCID is a CIDComputer that returns a fixed value without shelling
// out to a real kubo binary -- these tests exercise BuildRelease's own
// orchestration logic (copy, config.json, CSP rewrite, secret scan,
// hashing), not kubo's actual CID algorithm, which KuboCIDComputer only
// wraps via subprocess and is not itself unit-testable without a real
// `ipfs` binary installed (documented, not faked, in build.go).
type fakeCID struct{ cid string }

func (f fakeCID) ComputeCID(ctx context.Context, dir string) (string, error) {
	if f.cid == "" {
		return "", errors.New("fakeCID: no cid configured")
	}
	return f.cid, nil
}

func writeAssets(t *testing.T, dir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte(`<html><head><meta http-equiv="Content-Security-Policy" content="default-src 'self'; connect-src 'self'; img-src 'self'"></head></html>`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte(`console.log("hi");`), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestScanForSecretsFindsNothingInCleanTree(t *testing.T) {
	dir := t.TempDir()
	writeAssets(t, dir)
	findings, err := ScanForSecrets(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("ScanForSecrets found %v in a clean tree", findings)
	}
}

func TestScanForSecretsCatchesAnAPIKey(t *testing.T) {
	dir := t.TempDir()
	writeAssets(t, dir)
	leaked := "oiu_" + "deadbeef00112233445566778899aabbccddeeff0011223344556677889900aa"
	if err := os.WriteFile(filepath.Join(dir, "leaked.js"), []byte("const key = '"+leaked+"';"), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err := ScanForSecrets(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("ScanForSecrets did not catch a leaked oiu_ API key")
	}
	for _, finding := range findings {
		if strings.Contains(finding, leaked) {
			t.Fatalf("finding %q must not itself contain the leaked secret", finding)
		}
	}
}

func TestScanForSecretsCatchesAPEMPrivateKey(t *testing.T) {
	dir := t.TempDir()
	writeAssets(t, dir)
	pem := "-----BEGIN PRIVATE KEY-----\nMC4CAQ...\n-----END PRIVATE KEY-----"
	if err := os.WriteFile(filepath.Join(dir, "oops.txt"), []byte(pem), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err := ScanForSecrets(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("ScanForSecrets did not catch a PEM private key header")
	}
}

func TestBuildReleaseProducesConfigJSONAndRewritesCSP(t *testing.T) {
	assetsDir := t.TempDir()
	writeAssets(t, assetsDir)

	manifest, buildDir, err := BuildRelease(context.Background(), BuildOptions{
		AssetsDir:           assetsDir,
		APIOrigin:           "https://api.example.org",
		AllowedLoginOrigins: []string{"https://dashboard.example.org"},
		CID:                 fakeCID{cid: "bafy-fixed-test-cid"},
	})
	if err != nil {
		t.Fatalf("BuildRelease: %v", err)
	}
	defer os.RemoveAll(buildDir)

	if manifest.CID != "bafy-fixed-test-cid" {
		t.Fatalf("manifest.CID = %q", manifest.CID)
	}
	if manifest.Signature != "" {
		t.Fatal("BuildRelease must return an unsigned manifest")
	}

	configBytes, err := os.ReadFile(filepath.Join(buildDir, "config.json"))
	if err != nil {
		t.Fatalf("config.json missing from build tree: %v", err)
	}
	var config releaseConfig
	if err := json.Unmarshal(configBytes, &config); err != nil {
		t.Fatal(err)
	}
	if config.APIOrigin != "https://api.example.org" {
		t.Fatalf("config.json api_origin = %q", config.APIOrigin)
	}

	indexBytes, err := os.ReadFile(filepath.Join(buildDir, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(indexBytes), "connect-src 'self' https://api.example.org") {
		t.Fatalf("index.html CSP was not rewritten for the api_origin: %s", indexBytes)
	}

	// The manifest must describe every file actually in the tree,
	// including the config.json BuildRelease itself wrote.
	found := map[string]bool{}
	for _, f := range manifest.Files {
		found[f.Path] = true
	}
	for _, want := range []string{"index.html", "app.js", "config.json"} {
		if !found[want] {
			t.Errorf("manifest.Files missing %q", want)
		}
	}
}

func TestBuildReleaseRefusesToBuildOverASecret(t *testing.T) {
	assetsDir := t.TempDir()
	writeAssets(t, assetsDir)
	leaked := "oiu_" + "deadbeef00112233445566778899aabbccddeeff0011223344556677889900aa"
	if err := os.WriteFile(filepath.Join(assetsDir, "leaked.js"), []byte(leaked), 0o644); err != nil {
		t.Fatal(err)
	}

	_, _, err := BuildRelease(context.Background(), BuildOptions{
		AssetsDir: assetsDir,
		CID:       fakeCID{cid: "bafy-should-not-be-reached"},
	})
	var secretsErr *ErrSecretsFound
	if !errors.As(err, &secretsErr) {
		t.Fatalf("BuildRelease with a leaked secret = %v, want *ErrSecretsFound", err)
	}
}

func TestKuboCIDComputerFailsClosedWithoutABinary(t *testing.T) {
	dir := t.TempDir()
	computer := KuboCIDComputer{IPFSBinary: "definitely-not-a-real-binary-openinfra-test"}
	if _, err := computer.ComputeCID(context.Background(), dir); err == nil {
		t.Fatal("ComputeCID with a nonexistent binary must fail, not fabricate a CID")
	}
}
