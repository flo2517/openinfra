package frontendrelease_test

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/openinfra/network/internal/frontendrelease"
	"github.com/openinfra/network/internal/testsupport"
	"github.com/openinfra/network/migrations"
)

// newTestPool follows the exact convention internal/walletlogin's own
// Postgres integration tests use: an isolated schema per test run against
// OPENINFRA_TEST_DATABASE_URL, skipped when that env var is unset.
func newTestPool(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	databaseURL := testsupport.RequireDatabaseURL(t)
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "frontendrelease_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, fmt.Sprintf(`CREATE SCHEMA %q`, schema)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(ctx, fmt.Sprintf(`DROP SCHEMA %q CASCADE`, schema)) })

	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := migrations.Apply(ctx, pool); err != nil {
		t.Fatal(err)
	}
	return ctx, pool
}

func signedRelease(t *testing.T, apiOrigin string, allowed []string, releasedAt time.Time) (frontendrelease.Release, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := frontendrelease.BuildManifest("bafy-"+uuid.NewString(), []frontendrelease.ManifestFile{
		{Path: "index.html", SHA256: strings.Repeat("a", 64), Size: 10},
	}, apiOrigin, allowed, "", releasedAt)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := frontendrelease.Sign(priv, unsigned)
	if err != nil {
		t.Fatal(err)
	}
	return frontendrelease.FromManifest(signed), pub
}

func TestPostgresRepositoryPublishAndLatestRoundTrip(t *testing.T) {
	ctx, pool := newTestPool(t)
	repo := frontendrelease.NewPostgresRepository(pool)

	release, pub := signedRelease(t, "https://api.example.org", []string{"https://dashboard.example.org"}, time.Now().UTC())
	if err := repo.Publish(ctx, release); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	latest, err := repo.Latest(ctx)
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if latest.ReleaseID != release.ReleaseID || latest.CID != release.CID {
		t.Fatalf("Latest() = %+v, want release_id/cid matching %+v", latest, release)
	}
	if err := frontendrelease.Verify(pub, latest.Manifest); err != nil {
		t.Fatalf("the round-tripped manifest_json no longer verifies: %v", err)
	}
	if len(latest.AllowedLoginOrigins) != 1 || latest.AllowedLoginOrigins[0] != "https://dashboard.example.org" {
		t.Fatalf("allowed_login_origins round-trip = %v", latest.AllowedLoginOrigins)
	}
}

func TestPostgresRepositoryLatestSkipsRevokedReleases(t *testing.T) {
	ctx, pool := newTestPool(t)
	repo := frontendrelease.NewPostgresRepository(pool)

	older, _ := signedRelease(t, "https://api.example.org", []string{"https://good.example.org"}, time.Now().UTC().Add(-time.Hour))
	newer, _ := signedRelease(t, "https://api.example.org", []string{"https://compromised.example.org"}, time.Now().UTC())
	if err := repo.Publish(ctx, older); err != nil {
		t.Fatal(err)
	}
	if err := repo.Publish(ctx, newer); err != nil {
		t.Fatal(err)
	}

	latest, err := repo.Latest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if latest.ReleaseID != newer.ReleaseID {
		t.Fatalf("Latest() before revocation = %s, want the newer release", latest.ReleaseID)
	}

	// ADR-037 §7 step 3: revoking the compromised release must make
	// Latest() immediately stop reporting its allowed_login_origins --
	// the load-bearing cutoff the dashboard's CORS middleware relies on.
	if err := repo.Revoke(ctx, newer.ReleaseID, "compromised release key"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	latest, err = repo.Latest(ctx)
	if err != nil {
		t.Fatalf("Latest() after revocation: %v", err)
	}
	if latest.ReleaseID != older.ReleaseID {
		t.Fatalf("Latest() after revoking the newest release = %s, want it to fall back to %s", latest.ReleaseID, older.ReleaseID)
	}
	for _, origin := range latest.AllowedLoginOrigins {
		if origin == "https://compromised.example.org" {
			t.Fatal("the compromised release's allowed_login_origins must not still be reported as active")
		}
	}
}

func TestPostgresRepositoryLatestReturnsErrNoActiveReleaseWhenEmpty(t *testing.T) {
	ctx, pool := newTestPool(t)
	repo := frontendrelease.NewPostgresRepository(pool)
	if _, err := repo.Latest(ctx); err != frontendrelease.ErrNoActiveRelease {
		t.Fatalf("Latest() on an empty table = %v, want ErrNoActiveRelease", err)
	}
}

func TestPostgresRepositoryRevokeUnknownReleaseReturnsErrNotFound(t *testing.T) {
	ctx, pool := newTestPool(t)
	repo := frontendrelease.NewPostgresRepository(pool)
	if err := repo.Revoke(ctx, "does-not-exist", "reason"); err != frontendrelease.ErrNotFound {
		t.Fatalf("Revoke(unknown) = %v, want ErrNotFound", err)
	}
}

func TestPostgresRepositoryListOrdersNewestFirst(t *testing.T) {
	ctx, pool := newTestPool(t)
	repo := frontendrelease.NewPostgresRepository(pool)
	base := time.Now().UTC().Add(-time.Hour)
	first, _ := signedRelease(t, "", nil, base)
	second, _ := signedRelease(t, "", nil, base.Add(10*time.Minute))
	if err := repo.Publish(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := repo.Publish(ctx, second); err != nil {
		t.Fatal(err)
	}
	releases, err := repo.List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(releases) != 2 || releases[0].ReleaseID != second.ReleaseID || releases[1].ReleaseID != first.ReleaseID {
		t.Fatalf("List() order = %+v, want newest first", releases)
	}
}
