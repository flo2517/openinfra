package pki

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// newTestRedisClient connects to OPENINFRA_TEST_REDIS_URL and skips when
// unset, matching internal/ratelimit's Redis integration test convention.
// Every key this test touches is a fresh UUID-prefixed provider_id, so it
// can never collide with real traffic even against a shared dev Redis.
func newTestRedisClient(t *testing.T) *redis.Client {
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

func TestRedisRevocationStoreAddThenIsRevoked(t *testing.T) {
	client := newTestRedisClient(t)
	store := NewRedisRevocationStore(client)
	ctx := context.Background()
	providerID := uuid.NewString()

	revoked, err := store.IsRevoked(ctx, providerID)
	if err != nil {
		t.Fatalf("IsRevoked before Add: %v", err)
	}
	if revoked {
		t.Fatal("a provider that was never added must not be reported revoked")
	}

	if err := store.Add(ctx, providerID); err != nil {
		t.Fatalf("Add: %v", err)
	}
	revoked, err = store.IsRevoked(ctx, providerID)
	if err != nil {
		t.Fatalf("IsRevoked after Add: %v", err)
	}
	if !revoked {
		t.Fatal("a provider that was added must be reported revoked")
	}

	// Idempotent: adding again must not error or change the outcome.
	if err := store.Add(ctx, providerID); err != nil {
		t.Fatalf("second Add must be idempotent: %v", err)
	}
}

func TestReconcilerConvergesRedisFromSourceOnEveryTick(t *testing.T) {
	client := newTestRedisClient(t)
	store := NewRedisRevocationStore(client)
	providerID := uuid.NewString()
	source := &fakeRevokedSource{}

	reconciler := NewReconciler(source, store, 10*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go reconciler.Run(ctx)

	// Not yet revoked in Postgres (the source): Redis must not consider it
	// revoked either.
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		revoked, err := store.IsRevoked(context.Background(), providerID)
		if err != nil {
			t.Fatalf("IsRevoked: %v", err)
		}
		if revoked {
			t.Fatal("Reconciler must not mark a provider revoked before the source reports it")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// The operator's revoke-provider command lands in Postgres; the next
	// reconciliation tick must mirror it into Redis without a Control
	// Plane restart.
	source.setIDs([]string{providerID})
	deadline = time.Now().Add(2 * time.Second)
	for {
		revoked, err := store.IsRevoked(context.Background(), providerID)
		if err != nil {
			t.Fatalf("IsRevoked: %v", err)
		}
		if revoked {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("Reconciler did not converge Redis to the source's revoked set within the deadline")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestReconcilerReadFailureIsNonFatal(t *testing.T) {
	source := &fakeRevokedSource{err: errors.New("postgres unavailable")}
	// store is intentionally nil: a read failure must return before ever
	// touching the store, so this also proves reconcileOnce doesn't panic
	// on a nil store when the source itself is unavailable.
	reconciler := NewReconciler(source, nil, time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() {
		reconciler.Run(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Reconciler.Run did not return after context cancellation")
	}
}

type fakeRevokedSource struct {
	mu  sync.Mutex
	ids []string
	err error
}

func (f *fakeRevokedSource) ListRevokedProviderIDs(context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return append([]string(nil), f.ids...), nil
}

func (f *fakeRevokedSource) setIDs(ids []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ids = ids
}
