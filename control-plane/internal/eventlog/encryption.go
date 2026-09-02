package eventlog

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
)

func payloadHashOf(plaintext []byte) [32]byte { return sha256.Sum256(plaintext) }

// EncryptedPayload implements ADR-039 §7's envelope-encryption mechanism,
// structurally: a fresh per-event symmetric Data Encryption Key (DEK)
// encrypts the plaintext (AES-256-GCM); the DEK itself is wrapped
// (asymmetric envelope encryption, X25519 + AES-256-GCM as the KEM/DEM
// pair -- ADR-039 §7 names X25519 explicitly as "e.g.") under the
// tenant's own held public key. Nothing produced here is ever written to
// event_log.payload directly as plaintext: only the ciphertext, the
// wrapped-DEK blob, and payload_hash (a commitment over the *plaintext*,
// per §7's "only a commitment hash... may cross that line") ever leave
// this function.
//
// What this deliberately does NOT do, per ADR-039 §7's own explicit
// scoping ("key ownership and recovery are explicitly not solved by this
// ADR"): generate, store, back up, or recover a tenant's X25519 keypair.
// EncryptPayload/DecryptPayload take a recipient/private key as a plain
// argument and assume the caller already has it from *somewhere* -- no
// such somewhere exists yet in this codebase. This mechanism is therefore
// exercised only by this package's own tests (encryption_test.go), not by
// any real write path in this PR: today's actual wire protocol carries no
// tenant-private field at all (ADR-039 Context, "the actual tenant-private
// surface is smaller than ADR-012 §3's table implies, read honestly"), so
// there is nothing in this PR that needs to call EncryptPayload for real
// yet. It exists so a near-future secrets-injection feature has a ready,
// already-reviewed mechanism to call into on day one, per ADR-039's own
// "Consequences" list.
type EncryptedPayload struct {
	// Ciphertext is AES-256-GCM(DEK, nonce, plaintext) -- what actually
	// occupies event_log.payload for a tenant-private event.
	Ciphertext []byte
	// Nonce is the AES-GCM nonce used for Ciphertext.
	Nonce []byte
	// WrappedDEK is AES-256-GCM(sharedSecret, wrapNonce, DEK) -- the DEK
	// itself, encrypted under the shared secret X25519 derives between an
	// ephemeral keypair (EphemeralPublicKey) and the recipient's held
	// public key. Never decryptable by the Control Plane or any provider
	// -- only by whoever holds the recipient's private key.
	WrappedDEK         []byte
	WrapNonce          []byte
	EphemeralPublicKey []byte
}

// EncryptPayload encrypts plaintext for recipientPublicKey (the tenant's
// held X25519 public key -- custody and recovery for this key are named,
// unsolved, required future work per ADR-039 §7/Open Questions, not
// invented here). Returns the envelope plus payloadHash = sha256(plaintext),
// the commitment this package's Sign/Entry construction expects for a
// tenant-private event.
func EncryptPayload(recipientPublicKey [32]byte, plaintext []byte) (*EncryptedPayload, [32]byte, error) {
	recipient, err := ecdh.X25519().NewPublicKey(recipientPublicKey[:])
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("eventlog: invalid recipient public key: %w", err)
	}
	ephemeralPrivate, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, [32]byte{}, err
	}
	sharedSecret, err := ephemeralPrivate.ECDH(recipient)
	if err != nil {
		return nil, [32]byte{}, err
	}
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, [32]byte{}, err
	}
	ciphertext, nonce, err := aesGCMSeal(dek, plaintext)
	if err != nil {
		return nil, [32]byte{}, err
	}
	wrappedDEK, wrapNonce, err := aesGCMSeal(sharedSecret, dek)
	if err != nil {
		return nil, [32]byte{}, err
	}
	envelope := &EncryptedPayload{
		Ciphertext:         ciphertext,
		Nonce:              nonce,
		WrappedDEK:         wrappedDEK,
		WrapNonce:          wrapNonce,
		EphemeralPublicKey: ephemeralPrivate.PublicKey().Bytes(),
	}
	return envelope, payloadHashOf(plaintext), nil
}

// DecryptPayload reverses EncryptPayload given the recipient's held
// private key -- the exact key whose custody/recovery ADR-039 §7 leaves
// unsolved. Verifies the recomputed plaintext hash matches wantPayloadHash
// (the event_log row's own payload_hash) so a caller never silently
// accepts a decryption that does not match what was actually committed
// to and signed.
func DecryptPayload(recipientPrivateKey [32]byte, envelope *EncryptedPayload, wantPayloadHash [32]byte) ([]byte, error) {
	private, err := ecdh.X25519().NewPrivateKey(recipientPrivateKey[:])
	if err != nil {
		return nil, fmt.Errorf("eventlog: invalid recipient private key: %w", err)
	}
	ephemeral, err := ecdh.X25519().NewPublicKey(envelope.EphemeralPublicKey)
	if err != nil {
		return nil, fmt.Errorf("eventlog: invalid ephemeral public key: %w", err)
	}
	sharedSecret, err := private.ECDH(ephemeral)
	if err != nil {
		return nil, err
	}
	dek, err := aesGCMOpen(sharedSecret, envelope.WrapNonce, envelope.WrappedDEK)
	if err != nil {
		return nil, fmt.Errorf("eventlog: unwrap DEK: %w", err)
	}
	plaintext, err := aesGCMOpen(dek, envelope.Nonce, envelope.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("eventlog: decrypt payload: %w", err)
	}
	if payloadHashOf(plaintext) != wantPayloadHash {
		return nil, errors.New("eventlog: decrypted plaintext does not match the event's committed payload_hash")
	}
	return plaintext, nil
}

func aesGCMSeal(key, plaintext []byte) (ciphertext, nonce []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return gcm.Seal(nil, nonce, plaintext, nil), nonce, nil
}

func aesGCMOpen(key, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}
