// Command frontendrelease implements ADR-037 §2's build/sign/publish/
// rollback/revoke pipeline for the dashboard's content-addressed static
// frontend bundle. Offline tooling in the same spirit as
// cmd/controlplane-admin: a real DATABASE_URL-connected operation run by
// whoever holds the release-signing private key (repository owner or
// CI), never a self-service RPC any dashboard user can reach.
//
// Subcommands:
//
//	frontendrelease keygen  -out <path>
//	    Generates a new Ed25519 release-signing keypair, writing the raw
//	    32-byte private key to <path> (0600, matching agent-core's
//	    write_private_key convention exactly) and the hex-encoded public
//	    key to <path>.pub.hex.
//
//	frontendrelease build   -assets <dir> -api-origin <url> -allowed-origins <csv> [-previous-cid <cid>] -out <manifest.json>
//	    Builds a content-addressed release tree from <dir> (via a real
//	    `ipfs add -Q -r --cid-version=1 --raw-leaves`, ADR-037 §2 step 2)
//	    and writes an *unsigned* manifest to <manifest.json>.
//
//	frontendrelease sign    -key <path> -manifest <manifest.json> -out <signed.json>
//	    Signs an unsigned manifest, writing the signed manifest.
//
//	frontendrelease verify  -pubkey <path.hex> -manifest <signed.json>
//	    Verifies a signed manifest's integrity and signature; exits
//	    non-zero on any failure.
//
//	frontendrelease publish -manifest <signed.json>
//	    Verifies (never trusts an already-signed file blindly) then
//	    inserts the release into Postgres (DATABASE_URL), so
//	    GET /.well-known/openinfra-frontend and the dashboard's CORS
//	    allowlist immediately see it as the new "latest, non-revoked"
//	    release.
//
//	frontendrelease rollback -release-id <id>
//	    Republishes a fresh, freshly-signed manifest pointing back at an
//	    older, still-pinned release's exact CID/files (ADR-037 §9) --
//	    requires -key, since a rollback is a new signed release, not a
//	    mutation of the old one.
//
//	frontendrelease revoke   -release-id <id> -reason <text>
//	    Marks a release revoked (ADR-037 §7) -- the load-bearing cutoff:
//	    its allowed_login_origins stop being trusted by the CORS
//	    allowlist the instant this commits, independent of whether any
//	    external IPFS gateway or pinning service ever removes the bytes.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/openinfra/network/internal/frontendrelease"
	"github.com/openinfra/network/migrations"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "frontendrelease:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usageError()
	}
	ctx := context.Background()
	switch args[0] {
	case "keygen":
		return runKeygen(args[1:])
	case "build":
		return runBuild(ctx, args[1:])
	case "manifest":
		return runManifest(args[1:])
	case "sign":
		return runSign(args[1:])
	case "verify":
		return runVerify(args[1:])
	case "publish":
		return runPublish(ctx, args[1:])
	case "rollback":
		return runRollback(ctx, args[1:])
	case "revoke":
		return runRevoke(ctx, args[1:])
	default:
		return usageError()
	}
}

func usageError() error {
	return errors.New("usage: frontendrelease {keygen|build|sign|verify|publish|rollback|revoke} [flags]")
}

// --- keygen ---

func runKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := fs.String("out", "", "path to write the raw 32-byte private key (0600); public key written to <out>.pub.hex")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("usage: frontendrelease keygen -out <path>")
	}
	if _, err := os.Stat(*out); err == nil {
		return fmt.Errorf("%s already exists -- refusing to overwrite a release-signing key", *out)
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	// Raw 32-byte seed, 0600 -- the exact write_private_key convention
	// provider-agent/crates/agent-core/src/identity.rs already uses for
	// the Agent's own Ed25519 identity (ADR-037 §2: "reusing the pattern
	// ... not the key itself").
	seed := priv.Seed()
	if err := os.WriteFile(*out, seed, 0o600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	pubPath := *out + ".pub.hex"
	if err := os.WriteFile(pubPath, []byte(hex.EncodeToString(pub)+"\n"), 0o644); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}
	fmt.Printf("wrote release-signing private key to %s (0600) and public key to %s\n", *out, pubPath)
	return nil
}

func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	seed, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key %s: %w", path, err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("private key %s is %d bytes, want the raw %d-byte Ed25519 seed", path, len(seed), ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func loadPublicKey(path string) (ed25519.PublicKey, error) {
	hexBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key %s: %w", path, err)
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(hexBytes)))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key %s is not %d hex-encoded bytes", path, ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// --- build ---

func runBuild(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	assetsDir := fs.String("assets", "", "directory of already-final static files (e.g. control-plane/internal/dashboard/assets)")
	apiOrigin := fs.String("api-origin", "", "canonical API origin the built config.json/CSP will point at (empty = same-origin relative)")
	allowedOrigins := fs.String("allowed-origins", "", "comma-separated allowed_login_origins for config.json")
	previousCID := fs.String("previous-cid", "", "the release being superseded, if any")
	ipfsBinary := fs.String("ipfs-binary", "", "ipfs (kubo) binary to invoke (default: \"ipfs\" on PATH)")
	out := fs.String("out", "", "path to write the unsigned manifest JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *assetsDir == "" || *out == "" {
		return errors.New("usage: frontendrelease build -assets <dir> -out <manifest.json> [-api-origin <url>] [-allowed-origins <csv>] [-previous-cid <cid>]")
	}
	var allowed []string
	if *allowedOrigins != "" {
		allowed = strings.Split(*allowedOrigins, ",")
	}
	manifest, buildDir, err := frontendrelease.BuildRelease(ctx, frontendrelease.BuildOptions{
		AssetsDir:           *assetsDir,
		APIOrigin:           *apiOrigin,
		AllowedLoginOrigins: allowed,
		PreviousCID:         *previousCID,
		CID:                 frontendrelease.KuboCIDComputer{IPFSBinary: *ipfsBinary},
		Now:                 time.Now,
	})
	if err != nil {
		return err
	}
	defer os.RemoveAll(buildDir)
	return writeManifest(*out, manifest)
}

func writeManifest(path string, manifest frontendrelease.Manifest) error {
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote manifest for release %s (cid=%s) to %s\n", manifest.ReleaseID, manifest.CID, path)
	return nil
}

func readManifest(path string) (frontendrelease.Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return frontendrelease.Manifest{}, err
	}
	var manifest frontendrelease.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return frontendrelease.Manifest{}, fmt.Errorf("decode manifest %s: %w", path, err)
	}
	return manifest, nil
}

// --- manifest (build without a CID computation step) ---

// runManifest is `build` minus the ipfs-add step: it hashes -dir exactly
// as build does, but takes an already-known -cid instead of computing
// one, for a caller that pinned the tree out of band (a remote pinning
// service, or -- as tests/e2e/suites/40-content-addressed-frontend.sh
// does -- a kubo daemon running in a different container this process
// has no local `ipfs` binary path to). Does not run config.json
// generation, CSP rewriting, or the secret scan (those are `build`'s job,
// applied to the source tree *before* it gets pinned) -- this only
// re-derives the manifest for a tree that already reflects a real,
// already-pinned CID.
func runManifest(args []string) error {
	fs := flag.NewFlagSet("manifest", flag.ContinueOnError)
	dir := fs.String("dir", "", "directory to hash (already pinned as -cid, out of band)")
	cid := fs.String("cid", "", "the CID -dir was already pinned as")
	apiOrigin := fs.String("api-origin", "", "")
	allowedOrigins := fs.String("allowed-origins", "", "comma-separated allowed_login_origins")
	previousCID := fs.String("previous-cid", "", "")
	out := fs.String("out", "", "path to write the unsigned manifest JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" || *cid == "" || *out == "" {
		return errors.New("usage: frontendrelease manifest -dir <dir> -cid <cid> -out <manifest.json> [-api-origin <url>] [-allowed-origins <csv>] [-previous-cid <cid>]")
	}
	files, err := frontendrelease.HashTree(*dir)
	if err != nil {
		return err
	}
	var allowed []string
	if *allowedOrigins != "" {
		allowed = strings.Split(*allowedOrigins, ",")
	}
	manifest, err := frontendrelease.BuildManifest(*cid, files, *apiOrigin, allowed, *previousCID, time.Now())
	if err != nil {
		return err
	}
	return writeManifest(*out, manifest)
}

// --- sign / verify ---

func runSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	keyPath := fs.String("key", "", "release-signing private key (raw 32-byte seed)")
	manifestPath := fs.String("manifest", "", "unsigned manifest JSON")
	out := fs.String("out", "", "path to write the signed manifest JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" || *manifestPath == "" || *out == "" {
		return errors.New("usage: frontendrelease sign -key <path> -manifest <manifest.json> -out <signed.json>")
	}
	priv, err := loadPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	unsigned, err := readManifest(*manifestPath)
	if err != nil {
		return err
	}
	signed, err := frontendrelease.Sign(priv, unsigned)
	if err != nil {
		return err
	}
	return writeManifest(*out, signed)
}

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	pubkeyPath := fs.String("pubkey", "", "release-signing public key (hex)")
	manifestPath := fs.String("manifest", "", "signed manifest JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *pubkeyPath == "" || *manifestPath == "" {
		return errors.New("usage: frontendrelease verify -pubkey <path.hex> -manifest <signed.json>")
	}
	pub, err := loadPublicKey(*pubkeyPath)
	if err != nil {
		return err
	}
	manifest, err := readManifest(*manifestPath)
	if err != nil {
		return err
	}
	if err := frontendrelease.Verify(pub, manifest); err != nil {
		return err
	}
	fmt.Printf("OK: release %s (cid=%s) verifies against %s\n", manifest.ReleaseID, manifest.CID, *pubkeyPath)
	return nil
}

// --- publish / rollback / revoke (Postgres-backed) ---

func openRepository(ctx context.Context) (*frontendrelease.PostgresRepository, func(), error) {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		return nil, nil, errors.New("DATABASE_URL is required")
	}
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, nil, fmt.Errorf("configure PostgreSQL: %w", err)
	}
	if err := migrations.Apply(ctx, pool); err != nil {
		pool.Close()
		return nil, nil, fmt.Errorf("migrate PostgreSQL: %w", err)
	}
	return frontendrelease.NewPostgresRepository(pool), pool.Close, nil
}

func runPublish(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("publish", flag.ContinueOnError)
	pubkeyPath := fs.String("pubkey", "", "release-signing public key (hex) to verify against before publishing")
	manifestPath := fs.String("manifest", "", "signed manifest JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *pubkeyPath == "" || *manifestPath == "" {
		return errors.New("usage: frontendrelease publish -pubkey <path.hex> -manifest <signed.json>")
	}
	pub, err := loadPublicKey(*pubkeyPath)
	if err != nil {
		return err
	}
	manifest, err := readManifest(*manifestPath)
	if err != nil {
		return err
	}
	if err := frontendrelease.Verify(pub, manifest); err != nil {
		return fmt.Errorf("refusing to publish an unverifiable manifest: %w", err)
	}
	repository, closeFn, err := openRepository(ctx)
	if err != nil {
		return err
	}
	defer closeFn()
	if err := repository.Publish(ctx, frontendrelease.FromManifest(manifest)); err != nil {
		return err
	}
	fmt.Printf("published release %s (cid=%s) -- now the latest, active release\n", manifest.ReleaseID, manifest.CID)
	return nil
}

func runRollback(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("rollback", flag.ContinueOnError)
	targetID := fs.String("release-id", "", "the release_id to roll back to")
	keyPath := fs.String("key", "", "release-signing private key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *targetID == "" || *keyPath == "" {
		return errors.New("usage: frontendrelease rollback -release-id <id> -key <path>")
	}
	priv, err := loadPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	repository, closeFn, err := openRepository(ctx)
	if err != nil {
		return err
	}
	defer closeFn()
	target, err := repository.Get(ctx, *targetID)
	if err != nil {
		return fmt.Errorf("load target release %s: %w", *targetID, err)
	}
	// ADR-037 §9: rollback is a freshly signed manifest pointing cid back
	// at the target's still-pinned bytes -- never a mutation of the old
	// row, and never a re-signing that trusts the old row's own
	// signature (a new signature is minted here, over a new manifest).
	unsigned, err := frontendrelease.BuildManifest(target.CID, target.Manifest.Files, target.APIOrigin, target.AllowedLoginOrigins, target.CID, time.Now())
	if err != nil {
		return err
	}
	signed, err := frontendrelease.Sign(priv, unsigned)
	if err != nil {
		return err
	}
	if err := repository.Publish(ctx, frontendrelease.FromManifest(signed)); err != nil {
		return err
	}
	fmt.Printf("rolled back to %s's content: published new release %s (cid=%s, unchanged)\n", *targetID, signed.ReleaseID, signed.CID)
	return nil
}

func runRevoke(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	releaseID := fs.String("release-id", "", "the release_id to revoke")
	reason := fs.String("reason", "", "why this release is being revoked (recorded, never optional -- ADR-037 §7)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *releaseID == "" || *reason == "" {
		return errors.New("usage: frontendrelease revoke -release-id <id> -reason <text>")
	}
	repository, closeFn, err := openRepository(ctx)
	if err != nil {
		return err
	}
	defer closeFn()
	if err := repository.Revoke(ctx, *releaseID, *reason); err != nil {
		return err
	}
	fmt.Printf("revoked release %s -- its allowed_login_origins stop being trusted immediately; unpin its CID from kubo/any external pinning service separately (ADR-037 §7 step 1)\n", *releaseID)
	return nil
}
