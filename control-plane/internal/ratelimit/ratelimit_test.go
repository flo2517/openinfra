package ratelimit_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/openinfra/network/internal/ratelimit"
	"github.com/redis/go-redis/v9"
)

// newTestClient connects to OPENINFRA_TEST_REDIS_URL (the local dev
// stack's Redis works fine here -- every key this test touches is
// prefixed with a fresh UUID, so it can never collide with real traffic)
// and skips when unset, matching workloadapi's Postgres integration test
// convention.
func newTestClient(t *testing.T) *redis.Client {
	t.Helper()
	url := os.Getenv("OPENINFRA_TEST_REDIS_URL")
	if url == "" {
		t.Skip("OPENINFRA_TEST_REDIS_URL is not set")
	}
	options, err := redis.ParseURL(url)
	if err != nil {
		t.Fatal(err)
	}
	client := redis.NewClient(options)
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Ping(context.Background()).Err(); err != nil {
		t.Skipf("Redis unavailable at %s: %v", url, err)
	}
	return client
}

func TestRedisLimiterAllowsUpToTheLimitThenDenies(t *testing.T) {
	client := newTestClient(t)
	limiter := ratelimit.NewRedisLimiter(client, 3, 60)
	key := uuid.NewString()
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		allowed, err := limiter.Allow(ctx, key)
		if err != nil {
			t.Fatalf("Allow() call %d: %v", i, err)
		}
		if !allowed {
			t.Fatalf("Allow() call %d denied, expected allowed within the limit", i)
		}
	}
	allowed, err := limiter.Allow(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("expected the 4th call within the window to be denied")
	}
}

func TestRedisLimiterTracksDistinctKeysIndependently(t *testing.T) {
	client := newTestClient(t)
	limiter := ratelimit.NewRedisLimiter(client, 1, 60)
	ctx := context.Background()
	keyA, keyB := uuid.NewString(), uuid.NewString()

	if allowed, err := limiter.Allow(ctx, keyA); err != nil || !allowed {
		t.Fatalf("Allow(keyA) = %v, %v", allowed, err)
	}
	if allowed, err := limiter.Allow(ctx, keyB); err != nil || !allowed {
		t.Fatalf("Allow(keyB) = %v, %v, expected a different key to have its own budget", allowed, err)
	}
	if allowed, err := limiter.Allow(ctx, keyA); err != nil || allowed {
		t.Fatalf("Allow(keyA) second call = %v, %v, expected keyA's own budget to already be spent", allowed, err)
	}
}

func TestRedisLimiterWindowExpiresAndResets(t *testing.T) {
	client := newTestClient(t)
	limiter := ratelimit.NewRedisLimiter(client, 1, 1) // 1-second window
	key := uuid.NewString()
	ctx := context.Background()

	if allowed, err := limiter.Allow(ctx, key); err != nil || !allowed {
		t.Fatalf("first Allow() = %v, %v", allowed, err)
	}
	if allowed, err := limiter.Allow(ctx, key); err != nil || allowed {
		t.Fatalf("second Allow() = %v, %v, expected denial within the same window", allowed, err)
	}
	time.Sleep(1200 * time.Millisecond)
	if allowed, err := limiter.Allow(ctx, key); err != nil || !allowed {
		t.Fatalf("Allow() after window expiry = %v, %v, expected a fresh window", allowed, err)
	}
}
