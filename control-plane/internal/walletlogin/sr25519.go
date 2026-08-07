package walletlogin

import (
	schnorrkel "github.com/ChainSafe/go-schnorrkel"
)

// sr25519SigningContext is Substrate's own standard signing context for
// "sign this raw message" (as opposed to signing an extrinsic payload,
// which uses a different transcript construction entirely) --
// sr25519::Pair::sign in polkadot-sdk builds its transcript via
// signing_context(b"substrate"), and every wallet built on that stack
// (Polkadot.js's extension signRaw, Talisman, etc.) inherits the same
// constant. This is not an OpenInfra-specific choice: it must match
// exactly what a real wallet already produces, or no real Sr25519 account
// could ever log in.
var sr25519SigningContext = []byte("substrate")

// verifySr25519 checks signature against message for account, using
// Substrate's standard signing context (see sr25519SigningContext).
// message is this package's own domain-separated login message
// (loginDomain+nonce) -- identical to what the Ed25519 path verifies,
// only the signature scheme differs.
//
// Known verification gap: this has been proven correct against
// go-schnorrkel's own sign/verify round trip (see sr25519_test.go), but
// has not been exercised against a signature actually produced by a real
// browser wallet extension in this sandbox (no such extension is
// reachable here) -- the signing-context constant above is Substrate's
// well-established public convention, not a guess, but a live
// cross-check against a real wallet is still owed before this is
// presented as production-ready in the browser UI (which doesn't yet
// offer Sr25519/extension login at all -- see ADR-014 §7's "Deferred"
// note; this change is server-side verification support only).
func verifySr25519(account [32]byte, message, signature []byte) bool {
	if len(signature) != schnorrkel.SignatureSize {
		return false
	}
	publicKey, err := schnorrkel.NewPublicKey(account)
	if err != nil {
		return false
	}
	var signatureBytes [schnorrkel.SignatureSize]byte
	copy(signatureBytes[:], signature)
	var decoded schnorrkel.Signature
	if err := decoded.Decode(signatureBytes); err != nil {
		return false
	}
	transcript := schnorrkel.NewSigningContext(sr25519SigningContext, message)
	ok, err := publicKey.Verify(&decoded, transcript)
	return err == nil && ok
}
