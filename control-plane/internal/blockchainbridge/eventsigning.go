package blockchainbridge

import "crypto/ed25519"

// PublicKey implements eventlog.Signer -- an alias for Account(), so
// internal/eventlog can depend on a small local interface (see its Signer
// doc comment) instead of importing this package.
func (r *Registrar) PublicKey() [ed25519.PublicKeySize]byte {
	return r.account
}

// Sign implements eventlog.Signer: a raw Ed25519 signature over payload
// using this Registrar's existing bridge-account private key -- the exact
// key EnsureActive/EnsureLeaseActive/EnsureLeaseCompleted already use to
// sign every on-chain extrinsic this Control Plane submits (registrar.go,
// "Substrate signer key must use Ed25519"). ADR-039 §3 reuses this key
// for Control-Plane-originated event_log entries specifically so no new
// key type or enrollment ceremony is introduced: this is a raw Ed25519
// signature over payload directly (not the SCALE-encoded extrinsic
// envelope signCall builds for a chain submission) -- an event_log entry
// is never itself submitted as a chain extrinsic, so it has no SCALE
// payload, era, nonce, or runtime-version binding to include.
func (r *Registrar) Sign(payload []byte) [ed25519.SignatureSize]byte {
	var signature [ed25519.SignatureSize]byte
	copy(signature[:], ed25519.Sign(r.privateKey, payload))
	return signature
}
