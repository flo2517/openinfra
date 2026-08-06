package blockchainbridge

import (
	"context"
	"encoding/binary"
	"errors"
)

const (
	resourceMarketPalletIndex = 11
	announceOfferForCallIndex = 2
	removeOfferForCallIndex   = 3
)

// ResourceOffer mirrors pallet-resource-market's on-chain ResourceOffer.
// Units are this bridge's own documented convention -- the pallet's u32/
// u64 fields carry no unit by themselves, and issue #15 explicitly asks
// for units to be defined, not left implicit:
//
//   - CPUMillicores: millicores (1000 = one whole core), matching the same
//     conversion workloadapi.CPUCoresToMillicores and the scheduler use
//     for every other CPU comparison in this codebase.
//   - RAMMB: megabytes, matching ResourceCapability.ram_*_mb on the wire.
//   - StorageGB: gigabytes, matching ResourceCapability.storage_*_gb.
type ResourceOffer struct {
	CPUMillicores uint32
	RAMMB         uint64
	StorageGB     uint64
	Capabilities  []byte
}

// AnnounceOfferFor publishes or replaces provider's resource offer via
// pallet-resource-market's announce_offer_for, gated by AnnounceOrigin
// (EnsureRoot -- this bridge's sudo account) since the Provider Agent
// never talks to the chain directly (AGENTS.md). Idempotent: replacing an
// existing offer is a normal call, not an error, matching the pallet.
//
// Mirrors EnsureActive's submission shape exactly (serialize nonce use,
// sudo-wrap, sign, submit) but does not wait for finalization itself --
// callers that need that guarantee should follow up with a
// FinalizedOffer read, the same separation ActivateProvider/
// finalizedProvider already use for provider registration.
func (r *Registrar) AnnounceOfferFor(ctx context.Context, provider [32]byte, offer ResourceOffer) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	version, err := r.rpc.RuntimeVersion(ctx)
	if err != nil {
		return err
	}
	genesisHex, err := r.rpc.BlockHash(ctx, 0)
	if err != nil {
		return err
	}
	genesis, err := fixedHash(genesisHex)
	if err != nil {
		return err
	}
	nonce, err := r.finalizedAccountNonce(ctx)
	if err != nil {
		return err
	}

	inner := []byte{resourceMarketPalletIndex, announceOfferForCallIndex}
	inner = append(inner, provider[:]...)
	cpu := make([]byte, 4)
	binary.LittleEndian.PutUint32(cpu, offer.CPUMillicores)
	inner = append(inner, cpu...)
	ram := make([]byte, 8)
	binary.LittleEndian.PutUint64(ram, offer.RAMMB)
	inner = append(inner, ram...)
	storage := make([]byte, 8)
	binary.LittleEndian.PutUint64(storage, offer.StorageGB)
	inner = append(inner, storage...)
	inner = append(inner, encodeBoundedBytes(offer.Capabilities)...)

	return r.submitSigned(ctx, append([]byte{sudoPalletIndex, sudoCallIndex}, inner...), nonce, version, genesis)
}

// RemoveOfferFor withdraws provider's offer via remove_offer_for. Same
// origin/submission shape as AnnounceOfferFor.
func (r *Registrar) RemoveOfferFor(ctx context.Context, provider [32]byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	version, err := r.rpc.RuntimeVersion(ctx)
	if err != nil {
		return err
	}
	genesisHex, err := r.rpc.BlockHash(ctx, 0)
	if err != nil {
		return err
	}
	genesis, err := fixedHash(genesisHex)
	if err != nil {
		return err
	}
	nonce, err := r.finalizedAccountNonce(ctx)
	if err != nil {
		return err
	}

	inner := []byte{resourceMarketPalletIndex, removeOfferForCallIndex}
	inner = append(inner, provider[:]...)

	return r.submitSigned(ctx, append([]byte{sudoPalletIndex, sudoCallIndex}, inner...), nonce, version, genesis)
}

// FinalizedOffer reads pallet-resource-market's Offers map at blockHash
// for provider. found is false when no offer is published -- a normal
// state (never announced, or withdrawn), not a read failure.
func (c *RPCClient) FinalizedOffer(ctx context.Context, provider [32]byte, blockHash string) (ResourceOffer, bool, error) {
	value, found, err := c.Storage(ctx, resourceMarketOfferStorageKey(provider), blockHash)
	if err != nil {
		return ResourceOffer{}, false, err
	}
	if !found {
		return ResourceOffer{}, false, nil
	}
	offer, err := decodeResourceOffer(value)
	if err != nil {
		return ResourceOffer{}, false, err
	}
	return offer, true, nil
}

func resourceMarketOfferStorageKey(provider [32]byte) string {
	return mapStorageKey("ResourceMarket", "Offers", provider)
}

// decodeResourceOffer decodes cpu(u32 LE) + ram(u64 LE) + storage(u64 LE)
// + capabilities(compact-length-prefixed bytes), in the field order
// pallet_resource_market::pallet::ResourceOffer declares them.
func decodeResourceOffer(data []byte) (ResourceOffer, error) {
	if len(data) < 20 {
		return ResourceOffer{}, errors.New("resource offer is shorter than its fixed-size fields")
	}
	offer := ResourceOffer{
		CPUMillicores: binary.LittleEndian.Uint32(data[0:4]),
		RAMMB:         binary.LittleEndian.Uint64(data[4:12]),
		StorageGB:     binary.LittleEndian.Uint64(data[12:20]),
	}
	length, offset, err := decodeCompactUint(data[20:])
	if err != nil {
		return ResourceOffer{}, err
	}
	start := 20 + offset
	end := start + int(length)
	if end > len(data) {
		return ResourceOffer{}, errors.New("resource offer capabilities length exceeds the encoded value")
	}
	offer.Capabilities = append([]byte(nil), data[start:end]...)
	if end != len(data) {
		return ResourceOffer{}, errors.New("resource offer has trailing bytes past its capabilities field")
	}
	return offer, nil
}

// encodeBoundedBytes SCALE-encodes a BoundedVec<u8, _>/Vec<u8>: a compact
// length prefix followed by the raw bytes -- the same shape
// decodeResourceOffer's capabilities field decodes.
func encodeBoundedBytes(value []byte) []byte {
	encoded := compactUint(uint64(len(value)))
	return append(encoded, value...)
}
