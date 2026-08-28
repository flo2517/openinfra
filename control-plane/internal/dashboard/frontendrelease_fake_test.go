package dashboard

import (
	"context"
	"testing"
	"time"

	"github.com/openinfra/network/internal/frontendrelease"
)

// releaseWithOrigins builds a signed, valid frontendrelease.Release for
// tests that only care about its AllowedLoginOrigins/manifest shape, not
// which key signed it.
func releaseWithOrigins(t *testing.T, origins []string) frontendrelease.Release {
	t.Helper()
	unsigned, err := frontendrelease.BuildManifest("bafy-test-cid", []frontendrelease.ManifestFile{
		{Path: "index.html", SHA256: "0000000000000000000000000000000000000000000000000000000000000000000000000000"[:64], Size: 1},
	}, "https://api.example.org", origins, "", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	return frontendrelease.FromManifest(unsigned)
}

// fakeReleaseRepository is a minimal, in-memory frontendrelease.Repository
// for cors_test.go/wellknown_test.go -- these tests exercise the HTTP
// handler/middleware shape, not frontendrelease's own Postgres
// persistence (that has its own postgres_test.go), so a real database is
// deliberately not required to run them.
type fakeReleaseRepository struct {
	latest    frontendrelease.Release
	latestErr error
}

func (f *fakeReleaseRepository) Publish(ctx context.Context, release frontendrelease.Release) error {
	f.latest = release
	f.latestErr = nil
	return nil
}
func (f *fakeReleaseRepository) Latest(ctx context.Context) (frontendrelease.Release, error) {
	if f.latestErr != nil {
		return frontendrelease.Release{}, f.latestErr
	}
	if f.latest.ReleaseID == "" {
		return frontendrelease.Release{}, frontendrelease.ErrNoActiveRelease
	}
	return f.latest, nil
}
func (f *fakeReleaseRepository) Get(ctx context.Context, releaseID string) (frontendrelease.Release, error) {
	if f.latest.ReleaseID == releaseID {
		return f.latest, nil
	}
	return frontendrelease.Release{}, frontendrelease.ErrNotFound
}
func (f *fakeReleaseRepository) List(ctx context.Context, limit int) ([]frontendrelease.Release, error) {
	return []frontendrelease.Release{f.latest}, nil
}
func (f *fakeReleaseRepository) Revoke(ctx context.Context, releaseID, reason string) error {
	if f.latest.ReleaseID == releaseID {
		f.latestErr = frontendrelease.ErrNoActiveRelease
	}
	return nil
}
