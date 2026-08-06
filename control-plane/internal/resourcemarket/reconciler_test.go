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
	removeErr     error
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
