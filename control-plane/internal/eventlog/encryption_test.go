package eventlog

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

func newX25519Keypair(t *testing.T) (public [32]byte, private [32]byte) {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	copy(public[:], key.PublicKey().Bytes())
	copy(private[:], key.Bytes())
	return public, private
}

// TestEncryptDecryptPayloadRoundTrips exercises ADR-039 §7's structural
// envelope-encryption mechanism end to end: encrypt for a recipient's
// held public key, decrypt with the matching private key, recover the
// exact plaintext, and confirm the returned payloadHash is exactly
// sha256(plaintext) -- the commitment an event_log row would carry.
func TestEncryptDecryptPayloadRoundTrips(t *testing.T) {
	recipientPublic, recipientPrivate := newX25519Keypair(t)
	plaintext := []byte("tenant-private workload metadata")

	envelope, payloadHash, err := EncryptPayload(recipientPublic, plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if bytes.Contains(envelope.Ciphertext, plaintext) {
		t.Fatal("ciphertext must not contain the plaintext verbatim")
	}
	if payloadHash != payloadHashOf(plaintext) {
		t.Fatal("payloadHash must be sha256(plaintext), the commitment ADR-039 §7 requires")
	}

	decrypted, err := DecryptPayload(recipientPrivate, envelope, payloadHash)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("expected round-tripped plaintext %q, got %q", plaintext, decrypted)
	}
}

// TestDecryptPayloadFailsForWrongRecipient: only the holder of the
// matching private key can ever recover the plaintext -- not the Control
// Plane, not a provider, not another tenant's key (ADR-039 §7: "never
// under any Control-Plane- or provider-held key").
func TestDecryptPayloadFailsForWrongRecipient(t *testing.T) {
	recipientPublic, _ := newX25519Keypair(t)
	_, wrongPrivate := newX25519Keypair(t)
	envelope, payloadHash, err := EncryptPayload(recipientPublic, []byte("secret"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := DecryptPayload(wrongPrivate, envelope, payloadHash); err == nil {
		t.Fatal("expected decryption under the wrong private key to fail")
	}
}

// TestDecryptPayloadDetectsCiphertextTamper: flipping a bit in the
// ciphertext must be caught by AES-GCM's own authentication tag, and
// TestDecryptPayloadDetectsHashMismatch confirms DecryptPayload's own
// explicit payloadHash check catches a decryption that succeeds
// cryptographically but does not match what was actually committed to.
func TestDecryptPayloadDetectsCiphertextTamper(t *testing.T) {
	recipientPublic, recipientPrivate := newX25519Keypair(t)
	envelope, payloadHash, err := EncryptPayload(recipientPublic, []byte("secret"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	tampered := *envelope
	tampered.Ciphertext = append([]byte{}, envelope.Ciphertext...)
	tampered.Ciphertext[0] ^= 0xFF
	if _, err := DecryptPayload(recipientPrivate, &tampered, payloadHash); err == nil {
		t.Fatal("expected a tampered ciphertext to fail AES-GCM authentication")
	}
}

func TestDecryptPayloadDetectsHashMismatch(t *testing.T) {
	recipientPublic, recipientPrivate := newX25519Keypair(t)
	envelope, _, err := EncryptPayload(recipientPublic, []byte("secret"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := DecryptPayload(recipientPrivate, envelope, [32]byte{1, 2, 3}); err == nil {
		t.Fatal("expected a wrong wantPayloadHash to be rejected even though decryption itself succeeds")
	}
}
