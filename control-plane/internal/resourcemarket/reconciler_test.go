package resourcemarket

import (
	"context"
	"errors"
	"testing"

	"github.com/openinfra/network/internal/agentmanager"
	"github.com/openinfra/network/internal/blockchainbridge"
	sharedv1 "github.com/openinfra/network/protocol/generated/go/shared/v1"
)

type fakeDirectory struct {
	providers []agentmanager.SchedulableProvider
	err       error
}

func (d fakeDirectory) ListSchedulableProviders(context.Context) ([]agentmanager.SchedulableProvider, error) {
	return d.providers, d.err
}

type fakeMarket struct {
	head          string
	headErr       error
	offers        map[[32]byte]blockchainbridge.ResourceOffer
	readErr       map[[32]byte]error
	announceCalls []blockchainbridge.ResourceOffer
	announceErr   error
	removeCalls   [][32]byte
	// removeAttempts counts every RemoveOfferFor invocation regardless of
	// outcome -- removeCalls only records successful ones, so a test
	// asserting on retry-cap behavior against a permanently failing
	// removeErr needs this instead to see how many submissions were
	// actually attempted.
	removeAttempts int
	removeErr      error
}

func newFakeMarket() *fakeMarket {
	return &fakeMarket{head: "0xhead", offers: make(map[[32]byte]blockchainbridge.ResourceOffer), readErr: make(map[[32]byte]error)}
}

func (m *fakeMarket) FinalizedHead(context.Context) (string, error) { return m.head, m.headErr }

func (m *fakeMarket) FinalizedOffer(_ context.Context, provider [32]byte, _ string) (blockchainbridge.ResourceOffer, bool, error) {
	if err, ok := m.readErr[provider]; ok {
		return blockchainbridge.ResourceOffer{}, false, err
	}
	offer, found := m.offers[provider]
	return offer, found, nil
}

func (m *fakeMarket) AnnounceOfferFor(_ context.Context, provider [32]byte, offer blockchainbridge.ResourceOffer) error {
	if m.announceErr != nil {
		return m.announceErr
	}
	m.announceCalls = append(m.announceCalls, offer)
	m.offers[provider] = offer
	return nil
}

func (m *fakeMarket) RemoveOfferFor(_ context.Context, provider [32]byte) error {
	m.removeAttempts++
	if m.removeErr != nil {
		return m.removeErr
	}
	m.removeCalls = append(m.removeCalls, provider)
	delete(m.offers, provider)
	return nil
}

func testProvider(id string, seed byte, cpuTotal float32, ramTotalMb, storageTotalGb int64) agentmanager.SchedulableProvider {
	key := make([]byte, 32)
	for i := range key {
		key[i] = seed
	}
	return agentmanager.SchedulableProvider{
		RegisteredProvider: agentmanager.RegisteredProvider{ProviderID: id, PublicKey: key, AgentEndpoint: "https://" + id},
		Capabilities: &sharedv1.ResourceCapability{
			CpuTotal: cpuTotal, CpuAvailable: cpuTotal,
			RamTotalMb: ramTotalMb, RamAvailableMb: ramTotalMb,
			StorageTotalGb: storageTotalGb, StorageAvailableGb: storageTotalGb,
		},
	}
}

func TestReconcileOnceAnnouncesANewProvider(t *testing.T) {
	directory := fakeDirectory{providers: []agentmanager.SchedulableProvider{testProvider("p1", 1, 2, 4096, 100)}}
	market := newFakeMarket()
	reconciler := NewReconciler(directory, market, ReconcilerConfig{})

	reconciler.ReconcileOnce(context.Background())

	if len(market.announceCalls) != 1 {
		t.Fatalf("expected exactly one announce call, got %d", len(market.announceCalls))
	}
	got := market.announceCalls[0]
	if got.CPUMillicores != 2000 || got.RAMMB != 4096 || got.StorageGB != 100 {
		t.Fatalf("unexpected offer: %+v", got)
	}
}

func TestReconcileOnceSkipsAnAlreadyCorrectOffer(t *testing.T) {
	provider := testProvider("p1", 1, 2, 4096, 100)
	var key [32]byte
	copy(key[:], provider.PublicKey)
	directory := fakeDirectory{providers: []agentmanager.SchedulableProvider{provider}}
	market := newFakeMarket()
	market.offers[key] = blockchainbridge.ResourceOffer{CPUMillicores: 2000, RAMMB: 4096, StorageGB: 100}
	reconciler := NewReconciler(directory, market, ReconcilerConfig{})

	reconciler.ReconcileOnce(context.Background())

	if len(market.announceCalls) != 0 {
		t.Fatalf("expected no announce call for an already-correct offer, got %d", len(market.announceCalls))
	}
}

func TestReconcileOnceUpdatesAChangedOffer(t *testing.T) {
	provider := testProvider("p1", 1, 4, 8192, 200) // capacity grew
	var key [32]byte
	copy(key[:], provider.PublicKey)
	directory := fakeDirectory{providers: []agentmanager.SchedulableProvider{provider}}
	market := newFakeMarket()
	market.offers[key] = blockchainbridge.ResourceOffer{CPUMillicores: 2000, RAMMB: 4096, StorageGB: 100} // stale, smaller
	reconciler := NewReconciler(directory, market, ReconcilerConfig{})

	reconciler.ReconcileOnce(context.Background())

	if len(market.announceCalls) != 1 || market.announceCalls[0].CPUMillicores != 4000 {
		t.Fatalf("expected the offer to be updated to the new capacity, calls=%+v", market.announceCalls)
	}
}

func TestReconcileWithdrawsAProviderThatDropsOutOfTheSchedulableSet(t *testing.T) {
	provider := testProvider("p1", 1, 2, 4096, 100)
	var key [32]byte
	copy(key[:], provider.PublicKey)
	market := newFakeMarket()
	reconciler := NewReconciler(fakeDirectory{providers: []agentmanager.SchedulableProvider{provider}}, market, ReconcilerConfig{})

	reconciler.ReconcileOnce(context.Background())
	if len(market.announceCalls) != 1 {
		t.Fatalf("expected the first pass to announce, got %d calls", len(market.announceCalls))
	}

	// Second pass: the provider is gone (deregistered, or heartbeat went stale).
	reconciler.directory = fakeDirectory{providers: nil}
	reconciler.ReconcileOnce(context.Background())

	if len(market.removeCalls) != 1 || market.removeCalls[0] != key {
		t.Fatalf("expected the vanished provider's offer to be withdrawn, removeCalls=%+v", market.removeCalls)
	}
	if _, stillTracked := reconciler.offering[provider.ProviderID]; stillTracked {
		t.Fatal("expected the withdrawn provider to be forgotten")
	}
}

func TestReconcileOnceSkipsProvidersWithoutAUsableKeyOrCapabilities(t *testing.T) {
	noKey := agentmanager.SchedulableProvider{RegisteredProvider: agentmanager.RegisteredProvider{ProviderID: "no-key", PublicKey: []byte{1, 2, 3}}, Capabilities: &sharedv1.ResourceCapability{CpuTotal: 1}}
	noCapabilities := agentmanager.SchedulableProvider{RegisteredProvider: agentmanager.RegisteredProvider{ProviderID: "no-caps", PublicKey: make([]byte, 32)}}
	directory := fakeDirectory{providers: []agentmanager.SchedulableProvider{noKey, noCapabilities}}
	market := newFakeMarket()
	reconciler := NewReconciler(directory, market, ReconcilerConfig{})

	reconciler.ReconcileOnce(context.Background())

	if len(market.announceCalls) != 0 {
		t.Fatalf("expected no announce calls for unusable candidates, got %d", len(market.announceCalls))
	}
}

func TestReconcileOnceToleratesADirectoryFailureWithoutPanicking(t *testing.T) {
	directory := fakeDirectory{err: errors.New("redis unavailable")}
	market := newFakeMarket()
	reconciler := NewReconciler(directory, market, ReconcilerConfig{})
	reconciler.ReconcileOnce(context.Background()) // must not panic
	if len(market.announceCalls) != 0 {
		t.Fatal("expected no announce calls when the directory read failed")
	}
}

func TestReconcileOnceKeepsRetryingAFailedAnnounce(t *testing.T) {
	provider := testProvider("p1", 1, 2, 4096, 100)
	directory := fakeDirectory{providers: []agentmanager.SchedulableProvider{provider}}
	market := newFakeMarket()
	market.announceErr = errors.New("chain unavailable")
	reconciler := NewReconciler(directory, market, ReconcilerConfig{})

	reconciler.ReconcileOnce(context.Background())
	if _, tracked := reconciler.offering[provider.ProviderID]; tracked {
		t.Fatal("a failed announce must not be recorded as offering, or a real removal would never be attempted")
	}

	market.announceErr = nil
	reconciler.ReconcileOnce(context.Background())
	if len(market.announceCalls) != 1 {
		t.Fatalf("expected the retry to succeed on the next pass, got %d calls", len(market.announceCalls))
	}
}

// TestReconcileStopsRetryingWithdrawalAfterMaxAttempts is issue #138's
// resourcemarket fix: unbounded remove_offer_for retries against a
// provider that has permanently dropped out of ListSchedulableProviders
// produced a real, confirmed-live "1014: Priority is too low" tx-pool
// collision. After MaxWithdrawAttempts consecutive failures, the
// reconciler must stop resubmitting the extrinsic -- while still tracking
// the provider (not silently dropping it) so it stays observable.
func TestReconcileStopsRetryingWithdrawalAfterMaxAttempts(t *testing.T) {
	provider := testProvider("p1", 1, 2, 4096, 100)
	var key [32]byte
	copy(key[:], provider.PublicKey)
	market := newFakeMarket()
	market.removeErr = errors.New("chain unavailable")
	reconciler := NewReconciler(fakeDirectory{providers: []agentmanager.SchedulableProvider{provider}}, market, ReconcilerConfig{MaxWithdrawAttempts: 2})

	reconciler.ReconcileOnce(context.Background()) // announce
	reconciler.directory = fakeDirectory{providers: nil}

	reconciler.ReconcileOnce(context.Background()) // withdrawal attempt 1: fails
	reconciler.ReconcileOnce(context.Background()) // withdrawal attempt 2: fails, now at cap
	reconciler.ReconcileOnce(context.Background()) // must NOT attempt a 3rd remove_offer_for call

	if market.removeAttempts != 2 {
		t.Fatalf("expected exactly 2 remove_offer_for attempts (capped at MaxWithdrawAttempts), got %d", market.removeAttempts)
	}
	if _, stillTracked := reconciler.offering[provider.ProviderID]; !stillTracked {
		t.Fatal("a withdrawal-exhausted provider must stay tracked (observable), not be silently forgotten")
	}
	if reconciler.withdrawAttempts[provider.ProviderID] != 2 {
		t.Fatalf("withdrawAttempts = %d, want 2", reconciler.withdrawAttempts[provider.ProviderID])
	}
}

// TestReconcileWithdrawalSelfHealsWhenFinalizedOfferIsAlreadyGone is the
// "a fresh state read clears it" half of the same fix: once the on-chain
// offer is observed gone (whether from a successful-but-lost previous
// remove_offer_for, or an operator clearing it directly), the reconciler
// stops tracking the provider without needing to resubmit anything --
// including a provider that had already exhausted MaxWithdrawAttempts.
func TestReconcileWithdrawalSelfHealsWhenFinalizedOfferIsAlreadyGone(t *testing.T) {
	provider := testProvider("p1", 1, 2, 4096, 100)
	var key [32]byte
	copy(key[:], provider.PublicKey)
	market := newFakeMarket()
	market.removeErr = errors.New("chain unavailable")
	reconciler := NewReconciler(fakeDirectory{providers: []agentmanager.SchedulableProvider{provider}}, market, ReconcilerConfig{MaxWithdrawAttempts: 1})

	reconciler.ReconcileOnce(context.Background()) // announce
	reconciler.directory = fakeDirectory{providers: nil}
	reconciler.ReconcileOnce(context.Background()) // withdrawal attempt 1: fails, now at cap
	reconciler.ReconcileOnce(context.Background()) // stuck: no further remove_offer_for calls

	if market.removeAttempts != 1 {
		t.Fatalf("expected withdrawal to have stopped retrying, got %d remove_offer_for attempts", market.removeAttempts)
	}

	// The offer is now observed gone on-chain by some other means (e.g. an
	// operator cleared it, or an earlier remove_offer_for actually
	// succeeded and only its response was lost).
	delete(market.offers, key)
	market.removeErr = errors.New("must not be called again")

	reconciler.ReconcileOnce(context.Background())

	if market.removeAttempts != 1 {
		t.Fatalf("a fresh FinalizedOffer read showing the offer gone must not trigger another remove_offer_for attempt, got %d", market.removeAttempts)
	}
	if _, stillTracked := reconciler.offering[provider.ProviderID]; stillTracked {
		t.Fatal("expected the self-healed provider to be forgotten")
	}
	if _, stillTracked := reconciler.withdrawAttempts[provider.ProviderID]; stillTracked {
		t.Fatal("expected withdrawAttempts to be cleared once self-healed")
	}
}

// TestReconcileWithdrawalResetsAttemptsWhenProviderReappears confirms a
// provider that comes back into ListSchedulableProviders after some
// failed withdrawal attempts starts with a clean slate if it ever drops
// out again, rather than carrying over a stale attempt count toward a cap
// it hasn't actually been retrying against.
func TestReconcileWithdrawalResetsAttemptsWhenProviderReappears(t *testing.T) {
	provider := testProvider("p1", 1, 2, 4096, 100)
	market := newFakeMarket()
	market.removeErr = errors.New("chain unavailable")
	reconciler := NewReconciler(fakeDirectory{providers: []agentmanager.SchedulableProvider{provider}}, market, ReconcilerConfig{MaxWithdrawAttempts: 5})

	reconciler.ReconcileOnce(context.Background()) // announce
	reconciler.directory = fakeDirectory{providers: nil}
	reconciler.ReconcileOnce(context.Background()) // withdrawal attempt 1: fails

	if reconciler.withdrawAttempts[provider.ProviderID] != 1 {
		t.Fatalf("withdrawAttempts = %d, want 1", reconciler.withdrawAttempts[provider.ProviderID])
	}

	reconciler.directory = fakeDirectory{providers: []agentmanager.SchedulableProvider{provider}}
	reconciler.ReconcileOnce(context.Background())

	if _, tracked := reconciler.withdrawAttempts[provider.ProviderID]; tracked {
		t.Fatal("expected withdrawAttempts to be cleared once the provider is schedulable again")
	}
}

func TestClampToUint32(t *testing.T) {
	cases := []struct {
		in   int64
		want uint32
	}{
		{-1, 0},
		{0, 0},
		{1000, 1000},
		{int64(^uint32(0)), ^uint32(0)},
		{int64(^uint32(0)) + 1, ^uint32(0)},
	}
	for _, c := range cases {
		if got := clampToUint32(c.in); got != c.want {
			t.Errorf("clampToUint32(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}
