package dashboard

import (
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// TestLoadOverviewPagesProvidersAgainstALiveDatabase proves the
// LIMIT/OFFSET + COUNT(*) pairing actually round-trips against a real
// Postgres: page 1 must return the newest ProvidersLimit rows (by
// registered_at DESC, this endpoint's existing order), page 2 the rest,
// and ProvidersTotal must stay the true total on every page rather than
// shrinking to whatever that page happened to return.
func TestLoadOverviewPagesProvidersAgainstALiveDatabase(t *testing.T) {
	ctx, server, pool := newValidatorScoresTestServer(t)
	// loadOverview also reads Redis for per-provider heartbeat liveness --
	// newValidatorScoresTestServer leaves redis nil (unneeded by the
	// validator-scores endpoint it was built for), so this test wires its
	// own, the same OPENINFRA_TEST_REDIS_URL convention
	// internal/ratelimit and auth_test.go's rate-limit test already use.
	redisURL := os.Getenv("OPENINFRA_TEST_REDIS_URL")
	if redisURL == "" {
		t.Skip("OPENINFRA_TEST_REDIS_URL is not set")
	}
	redisOptions, err := redis.ParseURL(redisURL)
	if err != nil {
		t.Fatal(err)
	}
	redisClient := redis.NewClient(redisOptions)
	t.Cleanup(func() { _ = redisClient.Close() })
	server.redis = redisClient

	base := time.Now().UTC().Truncate(time.Second)
	providerIDs := []string{"page-test-a", "page-test-b", "page-test-c"}
	for i, id := range providerIDs {
		publicKey := make([]byte, 32)
		publicKey[0] = byte(i + 1)
		if _, err := pool.Exec(ctx, `
			INSERT INTO providers (provider_id, public_key, protocol_version, agent_version, capabilities, status, registered_at)
			VALUES ($1, $2, '1', 'test', $3, 2, $4)`,
			id, publicKey, []byte{}, base.Add(time.Duration(i)*time.Minute),
		); err != nil {
			t.Fatal(err)
		}
	}
	// providerIDs was inserted oldest-first; registered_at DESC means the
	// last inserted (page-test-c) sorts first.
	wantDescOrder := []string{"page-test-c", "page-test-b", "page-test-a"}

	firstPage, err := server.loadOverview(ctx, overviewPagination{ProvidersLimit: 2, ProvidersOffset: 0, WorkloadsLimit: 100})
	if err != nil {
		t.Fatalf("load first page: %v", err)
	}
	if firstPage.ProvidersTotal < len(providerIDs) {
		t.Fatalf("providers_total = %d, want at least %d", firstPage.ProvidersTotal, len(providerIDs))
	}
	if len(firstPage.Providers) != 2 {
		t.Fatalf("first page returned %d providers, want 2", len(firstPage.Providers))
	}
	for i, want := range wantDescOrder[:2] {
		if firstPage.Providers[i].fullID != want {
			t.Fatalf("first page provider[%d] = %s, want %s", i, firstPage.Providers[i].fullID, want)
		}
	}

	secondPage, err := server.loadOverview(ctx, overviewPagination{ProvidersLimit: 2, ProvidersOffset: 2, WorkloadsLimit: 100})
	if err != nil {
		t.Fatalf("load second page: %v", err)
	}
	if secondPage.ProvidersTotal != firstPage.ProvidersTotal {
		t.Fatalf("providers_total changed between pages: %d vs %d", firstPage.ProvidersTotal, secondPage.ProvidersTotal)
	}
	foundThirdRow := false
	for _, p := range secondPage.Providers {
		if p.fullID == wantDescOrder[2] {
			foundThirdRow = true
		}
		// Pages must not overlap: nothing already on page one should
		// reappear on page two.
		if p.fullID == wantDescOrder[0] || p.fullID == wantDescOrder[1] {
			t.Fatalf("provider %s appeared on both pages", p.fullID)
		}
	}
	if !foundThirdRow {
		t.Fatalf("expected %s on the second page, got %+v", wantDescOrder[2], secondPage.Providers)
	}
}
