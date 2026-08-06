package providerjoin

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

type chainRegistrationRow struct {
	publicKey    []byte
	state        string
	attemptCount int
	nextAttempt  time.Time
	lastError    string
}

// fakeChainStore is an in-memory ChainRegistrationStore + Activator double.
// Unlike memoryRepository in service_test.go, it only implements what the
// Reconciler needs, and models state transitions explicitly so tests can
// assert on them (state, attempt_count, next_attempt_at, last_error) the
// same way the real Postgres columns would be inspected.
type fakeChainStore struct {
	rows        map[string]*chainRegistrationRow
	activated   map[string]ChainFinalization
	activateErr error
}

func newFakeChainStore() *fakeChainStore {
	return &fakeChainStore{
		rows:      make(map[string]*chainRegistrationRow),
		activated: make(map[string]ChainFinalization),
	}
}

func (s *fakeChainStore) addReady(providerID string, publicKey []byte) {
	s.rows[providerID] = &chainRegistrationRow{publicKey: publicKey, state: "READY"}
}

func (s *fakeChainStore) DueChainRegistrations(_ context.Context, limit int) ([]PendingChainRegistration, error) {
	var due []PendingChainRegistration
	for providerID, row := range s.rows {
		if row.state != "READY" && row.state != "RETRY" {
			continue
		}
		if !row.nextAttempt.IsZero() && row.nextAttempt.After(time.Now()) {
			continue
		}
		due = append(due, PendingChainRegistration{ProviderID: providerID, PublicKey: row.publicKey, AttemptCount: row.attemptCount})
		if len(due) == limit {
			break
		}
	}
	return due, nil
}

func (s *fakeChainStore) RecordChainRegistrationFailure(_ context.Context, providerID string, attemptErr error, nextAttemptAt time.Time, terminal bool) error {
	row, ok := s.rows[providerID]
	if !ok {
		return ErrProviderNotFound
	}
	row.attemptCount++
	row.lastError = attemptErr.Error()
	if terminal {
		row.state = "FAILED"
		row.nextAttempt = time.Time{}
	} else {
		row.state = "RETRY"
		row.nextAttempt = nextAttemptAt
	}
	return nil
}

func (s *fakeChainStore) ActivateProvider(_ context.Context, providerID string, finalization ChainFinalization) (Completion, error) {
	if s.activateErr != nil {
		return Completion{}, s.activateErr
	}
	row, ok := s.rows[providerID]
	if !ok {
		return Completion{}, ErrProviderNotFound
	}
	row.state = "FINALIZED"
	s.activated[providerID] = finalization
	return Completion{ProviderID: providerID, Status: 2}, nil
}

// fakeRegistrar lets each test control EnsureActive's outcome per call,
// including failing N times before succeeding to exercise retry/backoff.
type fakeRegistrar struct {
	behavior func(calls int) ([]byte, []byte, uint64, error)
	calls    map[string]int
}

func newFakeRegistrar(behavior func(calls int) ([]byte, []byte, uint64, error)) *fakeRegistrar {
	return &fakeRegistrar{behavior: behavior, calls: make(map[string]int)}
}

func (r *fakeRegistrar) EnsureActive(_ context.Context, provider [ed25519.PublicKeySize]byte) ([]byte, []byte, uint64, error) {
	key := string(provider[:])
	r.calls[key]++
	return r.behavior(r.calls[key])
}

func testPublicKey(seed byte) []byte {
	key := make([]byte, ed25519.PublicKeySize)
	for i := range key {
		key[i] = seed
	}
	return key
}

func TestReconcileOnceActivatesASuccessfulReadyRegistration(t *testing.T) {
	store := newFakeChainStore()
	store.addReady("provider-1", testPublicKey(1))
	registrar := newFakeRegistrar(func(int) ([]byte, []byte, uint64, error) {
		return []byte("extrinsic"), []byte("block"), 42, nil
	})
	reconciler := NewReconciler(store, store, registrar, DefaultReconcilerConfig())

	reconciler.ReconcileOnce(context.Background())

	if store.rows["provider-1"].state != "FINALIZED" {
		t.Fatalf("expected FINALIZED, got %s", store.rows["provider-1"].state)
	}
	if finalization, ok := store.activated["provider-1"]; !ok || finalization.FinalizedBlockNumber != 42 {
		t.Fatalf("expected ActivateProvider to be called with the registrar's finalization, got %+v", finalization)
	}
}

func TestReconcileOnceSchedulesRetryWithBackoffOnFailure(t *testing.T) {
	store := newFakeChainStore()
	store.addReady("provider-1", testPublicKey(1))
	failure := errors.New("substrate rpc unavailable")
	registrar := newFakeRegistrar(func(int) ([]byte, []byte, uint64, error) {
		return nil, nil, 0, failure
	})
	cfg := DefaultReconcilerConfig()
	cfg.MaxAttempts = 10
	reconciler := NewReconciler(store, store, registrar, cfg)

	before := time.Now()
	reconciler.ReconcileOnce(context.Background())

	row := store.rows["provider-1"]
	if row.state != "RETRY" {
		t.Fatalf("expected RETRY, got %s", row.state)
	}
	if row.attemptCount != 1 {
		t.Fatalf("expected attempt_count 1, got %d", row.attemptCount)
	}
	if row.lastError != failure.Error() {
		t.Fatalf("expected last_error to be recorded, got %q", row.lastError)
	}
	if !row.nextAttempt.After(before) {
		t.Fatalf("expected next_attempt_at to be scheduled in the future")
	}
}

func TestReconcileMarksFailedAfterMaxAttempts(t *testing.T) {
	store := newFakeChainStore()
	store.addReady("provider-1", testPublicKey(1))
	failure := errors.New("provider has unsupported on-chain status")
	registrar := newFakeRegistrar(func(int) ([]byte, []byte, uint64, error) {
		return nil, nil, 0, failure
	})
	cfg := DefaultReconcilerConfig()
	cfg.MaxAttempts = 3
	cfg.BaseBackoff = time.Millisecond // keep the test fast
	reconciler := NewReconciler(store, store, registrar, cfg)

	for i := 0; i < 3; i++ {
		reconciler.ReconcileOnce(context.Background())
		// Force the next row due regardless of backoff so each loop
		// iteration actually attempts again (unit test, not real time).
		store.rows["provider-1"].nextAttempt = time.Time{}
	}

	row := store.rows["provider-1"]
	if row.state != "FAILED" {
		t.Fatalf("expected FAILED after exceeding MaxAttempts, got %s (attempts=%d)", row.state, row.attemptCount)
	}
	if row.attemptCount != 3 {
		t.Fatalf("expected 3 recorded attempts, got %d", row.attemptCount)
	}
	// A FAILED row must stop being picked up -- it is a terminal, explicit
	// failure, not a silent infinite retry loop.
	due, err := store.DueChainRegistrations(context.Background(), 10)
	if err != nil {
		t.Fatalf("DueChainRegistrations: %v", err)
	}
	if len(due) != 0 {
		t.Fatalf("expected a FAILED registration to no longer be due, got %+v", due)
	}
}

func TestReconcileRejectsMalformedPublicKeyWithoutCallingTheRegistrar(t *testing.T) {
	store := newFakeChainStore()
	store.addReady("provider-1", []byte("too-short"))
	registrar := newFakeRegistrar(func(int) ([]byte, []byte, uint64, error) {
		t.Fatal("registrar must not be called for a malformed stored key")
		return nil, nil, 0, nil
	})
	reconciler := NewReconciler(store, store, registrar, DefaultReconcilerConfig())

	reconciler.ReconcileOnce(context.Background())

	row := store.rows["provider-1"]
	if row.state != "FAILED" {
		t.Fatalf("expected an immediate terminal FAILED for malformed data, got %s", row.state)
	}
}

func TestReconcileOnceProcessesAWholeDueBatch(t *testing.T) {
	store := newFakeChainStore()
	store.addReady("provider-1", testPublicKey(1))
	store.addReady("provider-2", testPublicKey(2))
	store.addReady("provider-3", testPublicKey(3))
	registrar := newFakeRegistrar(func(int) ([]byte, []byte, uint64, error) {
		return []byte("extrinsic"), []byte("block"), 1, nil
	})
	reconciler := NewReconciler(store, store, registrar, DefaultReconcilerConfig())

	reconciler.ReconcileOnce(context.Background())

	for _, providerID := range []string{"provider-1", "provider-2", "provider-3"} {
		if store.rows[providerID].state != "FINALIZED" {
			t.Fatalf("expected %s to be FINALIZED, got %s", providerID, store.rows[providerID].state)
		}
	}
}

func TestReconcilerSurvivesRestartByReadingAttemptCountFromTheStore(t *testing.T) {
	// Simulates a Control Plane restart: attempt state lives only in the
	// store (as it would in Postgres), never in the Reconciler's memory, so
	// a brand new Reconciler instance continues backoff/attempt counting
	// correctly instead of resetting it.
	store := newFakeChainStore()
	store.addReady("provider-1", testPublicKey(1))
	failure := errors.New("chain unavailable")
	registrar := newFakeRegistrar(func(int) ([]byte, []byte, uint64, error) {
		return nil, nil, 0, failure
	})
	cfg := DefaultReconcilerConfig()
	cfg.BaseBackoff = time.Millisecond

	first := NewReconciler(store, store, registrar, cfg)
	first.ReconcileOnce(context.Background())
	if store.rows["provider-1"].attemptCount != 1 {
		t.Fatalf("expected attempt_count 1 after first reconciler's pass")
	}

	store.rows["provider-1"].nextAttempt = time.Time{} // force due again
	second := NewReconciler(store, store, registrar, cfg)
	second.ReconcileOnce(context.Background())
	if store.rows["provider-1"].attemptCount != 2 {
		t.Fatalf("expected attempt_count 2 after the 'restarted' reconciler's pass, got %d", store.rows["provider-1"].attemptCount)
	}
}

func TestReconcileOnceIsIdempotentAgainstDuplicateDelivery(t *testing.T) {
	// A FINALIZED row must never be reprocessed, whether the duplicate
	// trigger is a second reconcile pass or a concurrent Agent CompleteJoin
	// retry racing the Reconciler for the same provider.
	store := newFakeChainStore()
	store.addReady("provider-1", testPublicKey(1))
	activations := 0
	registrar := newFakeRegistrar(func(int) ([]byte, []byte, uint64, error) {
		return []byte("extrinsic"), []byte("block"), 7, nil
	})
	reconciler := NewReconciler(store, activationCountingStore{store, &activations}, registrar, DefaultReconcilerConfig())

	reconciler.ReconcileOnce(context.Background())
	reconciler.ReconcileOnce(context.Background())
	reconciler.ReconcileOnce(context.Background())

	if activations != 1 {
		t.Fatalf("expected exactly one activation despite repeated reconcile passes, got %d", activations)
	}
	if registrar.calls[string(testPublicKey(1))] != 1 {
		t.Fatalf("expected the registrar to be called exactly once once FINALIZED, got %d calls", registrar.calls[string(testPublicKey(1))])
	}
}

// activationCountingStore wraps fakeChainStore's Activator to count calls
// without changing fakeChainStore's own behavior/assertions elsewhere.
type activationCountingStore struct {
	*fakeChainStore
	count *int
}

func (s activationCountingStore) ActivateProvider(ctx context.Context, providerID string, finalization ChainFinalization) (Completion, error) {
	*s.count++
	return s.fakeChainStore.ActivateProvider(ctx, providerID, finalization)
}

func TestReconcileOnceIgnoresRegistrationsNotYetDue(t *testing.T) {
	store := newFakeChainStore()
	store.addReady("provider-1", testPublicKey(1))
	store.rows["provider-1"].state = "RETRY"
	store.rows["provider-1"].nextAttempt = time.Now().Add(time.Hour)
	registrar := newFakeRegistrar(func(int) ([]byte, []byte, uint64, error) {
		t.Fatal("registrar must not be called before next_attempt_at")
		return nil, nil, 0, nil
	})
	reconciler := NewReconciler(store, store, registrar, DefaultReconcilerConfig())

	reconciler.ReconcileOnce(context.Background())
}

func TestBackoffForDoublesAndCapsAtMaxBackoff(t *testing.T) {
	cfg := ReconcilerConfig{BaseBackoff: time.Second, MaxBackoff: 10 * time.Second}
	reconciler := NewReconciler(newFakeChainStore(), newFakeChainStore(), nil, cfg)

	cases := []struct {
		attempt int
		want    time.Duration
	}{
		{1, time.Second},
		{2, 2 * time.Second},
		{3, 4 * time.Second},
		{4, 8 * time.Second},
		{5, 10 * time.Second}, // would be 16s uncapped
		{100, 10 * time.Second},
	}
	for _, tc := range cases {
		if got := reconciler.backoffFor(tc.attempt); got != tc.want {
			t.Errorf("backoffFor(%d) = %v, want %v", tc.attempt, got, tc.want)
		}
	}
}

func TestRunStopsWhenContextIsCancelled(t *testing.T) {
	store := newFakeChainStore()
	registrar := newFakeRegistrar(func(int) ([]byte, []byte, uint64, error) { return nil, nil, 0, nil })
	cfg := DefaultReconcilerConfig()
	cfg.Interval = time.Millisecond
	reconciler := NewReconciler(store, store, registrar, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		reconciler.Run(ctx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after context cancellation")
	}
}
