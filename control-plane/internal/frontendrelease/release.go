package frontendrelease

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// BuildOptions configures BuildRelease.
type BuildOptions struct {
	// AssetsDir is the directory of already-final static files to
	// release -- control-plane/internal/dashboard/assets in production
	// use (ADR-037 Context: "no frontend build pipeline of any kind ...
	// no bundler, no transpilation step").
	AssetsDir string
	// APIOrigin is written into the built config.json and, if non-empty,
	// used to widen index.html's CSP connect-src (ADR-037 §2/§5). Empty
	// means "same-origin relative," the direct-serve/dev default.
	APIOrigin string
	// AllowedLoginOrigins is written into config.json (ADR-037 §2) --
	// the canonical DNSLink origin and self-hosted gateway origin,
	// nothing else, per §4.
	AllowedLoginOrigins []string
	// PreviousCID is the release being superseded, if any (ADR-037 §2
	// step 3's previous_cid, and the basis of §9 rollback).
	PreviousCID string
	CID         CIDComputer
	Now         func() time.Time
}

// BuildRelease assembles a temporary, content-addressed build tree from
// opts.AssetsDir (a copy plus a generated config.json, with index.html's
// CSP widened for opts.APIOrigin if set), refuses to continue if
// ScanForSecrets finds anything (ADR-037 §6), computes its CID via
// opts.CID, hashes every file, and returns an unsigned Manifest plus the
// build directory's path (caller's responsibility to os.RemoveAll it).
func BuildRelease(ctx context.Context, opts BuildOptions) (Manifest, string, error) {
	if opts.AssetsDir == "" {
		return Manifest{}, "", fmt.Errorf("frontendrelease: AssetsDir is required")
	}
	if opts.CID == nil {
		return Manifest{}, "", fmt.Errorf("frontendrelease: CID computer is required")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}

	buildDir, err := os.MkdirTemp("", "openinfra-frontend-release-*")
	if err != nil {
		return Manifest{}, "", err
	}
	if err := copyTree(opts.AssetsDir, buildDir); err != nil {
		os.RemoveAll(buildDir)
		return Manifest{}, "", fmt.Errorf("frontendrelease: copy assets tree: %w", err)
	}

	config := releaseConfig{
		APIOrigin:           opts.APIOrigin,
		AllowedLoginOrigins: opts.AllowedLoginOrigins,
	}
	configBytes, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		os.RemoveAll(buildDir)
		return Manifest{}, "", err
	}
	if err := os.WriteFile(filepath.Join(buildDir, "config.json"), configBytes, 0o644); err != nil {
		os.RemoveAll(buildDir)
		return Manifest{}, "", fmt.Errorf("frontendrelease: write config.json: %w", err)
	}

	if err := rewriteCSPForAPIOrigin(buildDir, opts.APIOrigin); err != nil {
		os.RemoveAll(buildDir)
		return Manifest{}, "", fmt.Errorf("frontendrelease: rewrite CSP for api_origin: %w", err)
	}

	findings, err := ScanForSecrets(buildDir)
	if err != nil {
		os.RemoveAll(buildDir)
		return Manifest{}, "", err
	}
	if len(findings) > 0 {
		os.RemoveAll(buildDir)
		return Manifest{}, "", &ErrSecretsFound{Findings: findings}
	}

	files, err := hashTree(buildDir)
	if err != nil {
		os.RemoveAll(buildDir)
		return Manifest{}, "", err
	}

	cid, err := opts.CID.ComputeCID(ctx, buildDir)
	if err != nil {
		os.RemoveAll(buildDir)
		return Manifest{}, "", err
	}

	manifest, err := BuildManifest(cid, files, opts.APIOrigin, opts.AllowedLoginOrigins, opts.PreviousCID, now())
	if err != nil {
		os.RemoveAll(buildDir)
		return Manifest{}, "", err
	}
	return manifest, buildDir, nil
}

// releaseConfig is ADR-037 §2's config.json -- the one new file folded
// into the CID-addressed tree alongside the existing assets/*, read by
// the frontend at load time (via a synchronous same-origin XHR in
// index.html, before app.js/auth.js/tenant.js/operator.js run) to learn
// which API origin to call instead of a same-origin-relative path.
type releaseConfig struct {
	APIOrigin           string   `json:"api_origin"`
	AllowedLoginOrigins []string `json:"allowed_login_origins"`
}

// SignAndFinalize signs an unsigned Manifest (from BuildRelease) with
// priv, returning the signed Manifest ready to publish.
func SignAndFinalize(priv ed25519.PrivateKey, unsigned Manifest) (Manifest, error) {
	return Sign(priv, unsigned)
}
