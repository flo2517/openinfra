package blockchainbridge

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

// TestRegistrarSignAndPublicKeyImplementEventlogSigner confirms
// blockchainbridge.Registrar's PublicKey/Sign pair (ADR-039 §3's reused
// bridge-account key) produces a signature that verifies against the
// account's public key with plain ed25519.Verify -- exactly what
// internal/eventlog.VerifyEntry does on the receiving/witness side.
func TestRegistrarSignAndPublicKeyImplementEventlogSigner(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	registrar := &Registrar{privateKey: privateKey}
	copy(registrar.account[:], publicKey)

	if registrar.PublicKey() != registrar.Account() {
		t.Fatal("expected PublicKey() to be an alias for Account()")
	}

	payload := []byte("openinfra-eventlog-v1 test payload")
	signature := registrar.Sign(payload)
	if !ed25519.Verify(publicKey, payload, signature[:]) {
		t.Fatal("expected Sign's output to verify against the registrar's own public key")
	}

	tampered := append([]byte{}, payload...)
	tampered[0] ^= 0xFF
	if ed25519.Verify(publicKey, tampered, signature[:]) {
		t.Fatal("expected a signature over a different payload to fail verification")
	}
}
