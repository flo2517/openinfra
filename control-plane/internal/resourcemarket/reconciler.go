// Package resourcemarket keeps pallet-resource-market's on-chain Offers in
// sync with each provider's actual capacity, closing the gap issue #15
// found: the pallet existed with zero Go-side integration, so an offer's
// on-chain state could drift arbitrarily far from reality.
package resourcemarket

import (
	"context"
	"crypto/ed25519"
	"log/slog"
	"time"

	"github.com/openinfra/network/internal/agentmanager"
	"github.com/openinfra/network/internal/blockchainbridge"
	"github.com/openinfra/network/internal/workloadapi"
)

// Directory is the same live provider view the scheduler ranks against.
type Directory interface {
	ListSchedulableProviders(ctx context.Context) ([]agentmanager.SchedulableProvider, error)
}

// Market is the on-chain publish/read surface, satisfied by
// *blockchainbridge.Registrar (writes) and *blockchainbridge.RPCClient
// (reads) together -- main.go wires the same chainClient/registrar pair
// already used everywhere else.
type Market interface {
	AnnounceOfferFor(ctx context.Context, provider [32]byte, offer blockchainbridge.ResourceOffer) error
	RemoveOfferFor(ctx context.Context, provider [32]byte) error
	FinalizedOffer(ctx context.Context, provider [32]byte, blockHash string) (blockchainbridge.ResourceOffer, bool, error)
	FinalizedHead(ctx context.Context) (string, error)
}

type ReconcilerConfig struct {
	Interval time.Duration
}

func DefaultReconcilerConfig() ReconcilerConfig {
	return ReconcilerConfig{Interval: 30 * time.Second}
}

// Reconciler publishes/updates each currently-schedulable provider's offer
// from its declared *total* capacity (the ceiling the scheduler's atomic
// capacity check already uses -- not the fast-changing "available" figure,
// which stays off-chain in Redis by design; publishing that to the chain
// on every workload placement would be both far too chatty for a
// blockchain and pointless, since AGENTS.md already treats Redis as the
// authoritative reconstructible store for exactly this kind of data), and
// withdraws offers for providers that drop out of that set.
//
// Withdrawal tracking (offering, below) is in-memory, not persisted: after
// a restart, a provider that vanished during the outage keeps a stale
// offer for up to one reconcile interval before it's noticed and removed.
// This is a deliberately bounded, self-healing gap, not a security
// control -- no scheduling decision consults on-chain offers yet (that
// integration is separate, still-open work for #15), so a briefly-stale
// offer has no live consequence today.
type Reconciler struct {
	directory Directory
	market    Market
	cfg       ReconcilerConfig
	// offering maps ProviderID to the 32-byte key used to publish its
	// offer, for every provider this process believes currently holds
	// one -- needed for withdrawal, since a provider that drops out of
	// ListSchedulableProviders can no longer be looked up there.
	offering map[string][32]byte
}

func NewReconciler(directory Directory, market Market, cfg ReconcilerConfig) *Reconciler {
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultReconcilerConfig().Interval
	}
	return &Reconciler{directory: directory, market: market, cfg: cfg, offering: make(map[string][32]byte)}
}

func (r *Reconciler) Run(ctx context.Context) {
	ticker := time.NewTicker(r.cfg.Interval)
	defer ticker.Stop()
	for {
		r.ReconcileOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// ReconcileOnce processes a single pass and returns without waiting on the
// ticker -- exported so tests can drive it deterministically.
func (r *Reconciler) ReconcileOnce(ctx context.Context) {
	providers, err := r.directory.ListSchedulableProviders(ctx)
	if err != nil {
		slog.Error("resourcemarket: failed to list schedulable providers", "error", err)
		return
	}
	head, err := r.market.FinalizedHead(ctx)
	if err != nil {
		slog.Error("resourcemarket: failed to resolve finalized head", "error", err)
		return
	}

	seen := make(map[string]struct{}, len(providers))
	for _, provider := range providers {
		if len(provider.PublicKey) != ed25519.PublicKeySize || provider.Capabilities == nil {
			continue
		}
		var key [32]byte
		copy(key[:], provider.PublicKey)
		seen[provider.ProviderID] = struct{}{}

		desired := blockchainbridge.ResourceOffer{
			CPUMillicores: clampToUint32(workloadapi.CPUCoresToMillicores(provider.Capabilities.CpuTotal)),
			RAMMB:         uint64(provider.Capabilities.RamTotalMb),
			StorageGB:     uint64(provider.Capabilities.StorageTotalGb),
		}
		current, found, err := r.market.FinalizedOffer(ctx, key, head)
		if err != nil {
			slog.Warn("resourcemarket: finalized offer read failed; will retry next pass", "provider_id", provider.ProviderID, "error", err)
			continue
		}
		if found && offersEqual(current, desired) {
			r.offering[provider.ProviderID] = key
			continue
		}
		if err := r.market.AnnounceOfferFor(ctx, key, desired); err != nil {
			slog.Error("resourcemarket: announce_offer_for failed", "provider_id", provider.ProviderID, "error", err)
			continue
		}
		r.offering[provider.ProviderID] = key
	}

	for providerID, key := range r.offering {
		if _, stillSchedulable := seen[providerID]; stillSchedulable {
			continue
		}
		if err := r.market.RemoveOfferFor(ctx, key); err != nil {
			slog.Error("resourcemarket: remove_offer_for failed; will retry next pass", "provider_id", providerID, "error", err)
			continue
		}
		delete(r.offering, providerID)
	}
}

// offersEqual ignores Capabilities: this reconciler never sets it (nothing
// downstream reads it yet -- capability tags are future work), so
// comparing it would force a redundant announce_offer_for on every pass.
func offersEqual(a, b blockchainbridge.ResourceOffer) bool {
	return a.CPUMillicores == b.CPUMillicores && a.RAMMB == b.RAMMB && a.StorageGB == b.StorageGB
}

// clampToUint32 protects the on-chain u32 field from a CPU total large
// enough to overflow it (millicores of ~4.29 million cores) rather than
// silently wrapping.
func clampToUint32(value int64) uint32 {
	if value < 0 {
		return 0
	}
	if value > int64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(value)
}
