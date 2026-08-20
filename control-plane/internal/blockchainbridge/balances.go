package blockchainbridge

import "context"

// pallet_balances lives at construct_runtime! pallet_index 3
// (blockchain/runtime/src/lib.rs); transfer_allow_death is call_index 0
// (pallet-balances's #[pallet::call_index(0)] pub fn
// transfer_allow_death -- confirmed directly against the pinned
// pallet-balances source, not assumed from convention).
const (
	balancesPalletIndex         = 3
	transferAllowDeathCallIndex = 0
)

// multiAddressIdTag is MultiAddress::Id's SCALE enum variant tag (0), the
// only MultiAddress variant this bridge ever constructs: a plain
// AccountId32 destination, no lookup indirection.
const multiAddressIdTag = 0

// FundAccount submits pallet_balances::transfer_allow_death, moving
// amount (in the runtime's u64 Balance unit -- AccountData<u64>, no
// floats per AGENTS.md) from this Registrar's own free balance to dest,
// signed directly by this Registrar's own account and never sudo-wrapped
// -- an ordinary balance transfer needs no elevated origin.
//
// This exists for deployments/scripts/bootstrap-network-validators.sh:
// pallet-network-validator's register_validator (see RegisterValidator's
// doc comment) reserves its stake out of the caller's own free balance,
// but a freshly generated Network Validator signing key starts with zero
// balance. The Control Plane's own bridge/sudo account is the only
// account endowed at genesis (blockchain/node/src/chain_spec.rs), so
// bootstrapping a new validator's stake runs this method with a
// Registrar built from that same bridge key, then a second, separate
// Registrar built from the validator's own key calls RegisterValidator --
// the same two-account split ADR-011 §2 requires everywhere else
// (validators never sign with, or share state with, the bridge account).
func (r *Registrar) FundAccount(ctx context.Context, dest [32]byte, amount uint64) error {
	return r.SubmitDirect(ctx, encodeTransferAllowDeathCall(dest, amount))
}

// encodeTransferAllowDeathCall is split out from FundAccount so its exact
// byte layout can be unit tested without a live/mock RPC round trip,
// matching encodeSubmitEvidenceCall/encodeCloseRoundCall's existing
// pattern (networkvalidatorregistrar.go). Field order is dest
// (MultiAddress -- one tag byte plus 32 raw AccountId bytes for the Id
// variant this bridge always uses), then value as a SCALE-compact Balance
// (unlike this pallet's own fixed-width fields elsewhere in this
// package, pallet_balances declares its transfer amount
// #[pallet::compact], so compactUint -- already used for nonce/call
// length elsewhere in this package -- applies here too).
func encodeTransferAllowDeathCall(dest [32]byte, amount uint64) []byte {
	call := []byte{balancesPalletIndex, transferAllowDeathCallIndex, multiAddressIdTag}
	call = append(call, dest[:]...)
	call = append(call, compactUint(amount)...)
	return call
}
