package walletlogin

import (
	"testing"

	schnorrkel "github.com/ChainSafe/go-schnorrkel"
)

func TestVerifySr25519AcceptsARealSchnorrkelSignature(t *testing.T) {
	secretKey, publicKey, err := schnorrkel.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("openinfra-dashboard-login-v1\x00" + "some-32-byte-nonce-goes-here...")
	transcript := schnorrkel.NewSigningContext(sr25519SigningContext, message)
	signature, err := secretKey.Sign(transcript)
	if err != nil {
		t.Fatal(err)
	}
	encodedSignature := signature.Encode()

	if !verifySr25519(publicKey.Encode(), message, encodedSignature[:]) {
		t.Fatal("expected a genuine schnorrkel signature to verify")
	}
}

func TestVerifySr25519RejectsAWrongSignature(t *testing.T) {
	_, publicKey, err := schnorrkel.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	otherSecretKey, _, err := schnorrkel.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("some message")
	transcript := schnorrkel.NewSigningContext(sr25519SigningContext, message)
	// Signed by a *different* key than the one we verify against.
	signature, err := otherSecretKey.Sign(transcript)
	if err != nil {
		t.Fatal(err)
	}
	encodedSignature := signature.Encode()

	if verifySr25519(publicKey.Encode(), message, encodedSignature[:]) {
		t.Fatal("expected a signature from a different key to be rejected")
	}
}

func TestVerifySr25519RejectsAWrongMessage(t *testing.T) {
	secretKey, publicKey, err := schnorrkel.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	transcript := schnorrkel.NewSigningContext(sr25519SigningContext, []byte("original message"))
	signature, err := secretKey.Sign(transcript)
	if err != nil {
		t.Fatal(err)
	}
	encodedSignature := signature.Encode()

	if verifySr25519(publicKey.Encode(), []byte("tampered message"), encodedSignature[:]) {
		t.Fatal("expected a signature over a different message to be rejected")
	}
}

func TestVerifySr25519RejectsMalformedInput(t *testing.T) {
	_, publicKey, err := schnorrkel.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if verifySr25519(publicKey.Encode(), []byte("message"), []byte("too short")) {
		t.Fatal("expected an undersized signature to be rejected, not panic or false-accept")
	}
	if verifySr25519(publicKey.Encode(), []byte("message"), make([]byte, 64)) {
		t.Fatal("expected an all-zero signature to be rejected")
	}
}
