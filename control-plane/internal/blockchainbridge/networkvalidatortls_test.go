package blockchainbridge

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"testing"
)

// TestSelfSignedClientCertificateExtractableEd25519Key proves the
// certificate this package builds for a Network Validator's mTLS client
// identity is exactly what the Agent's own verifier
// (provider-agent/crates/agent-cli/src/mtls.rs's
// extract_ed25519_raw_public_key) expects: a parseable, self-signed X.509
// certificate whose subject public key round-trips to the same raw
// 32-byte Ed25519 key the private key was generated from.
func TestSelfSignedClientCertificateExtractableEd25519Key(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tlsCert, err := selfSignedClientCertificate(privateKey)
	if err != nil {
		t.Fatalf("selfSignedClientCertificate: %v", err)
	}
	if len(tlsCert.Certificate) != 1 {
		t.Fatalf("expected exactly one DER certificate, got %d", len(tlsCert.Certificate))
	}
	parsed, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatalf("parse generated certificate: %v", err)
	}
	// Self-signed: verifying the certificate against itself as its own
	// root must succeed.
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	if _, err := parsed.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("self-signed certificate did not verify against itself: %v", err)
	}
	extracted, ok := parsed.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("certificate public key is %T, want ed25519.PublicKey", parsed.PublicKey)
	}
	if !bytes.Equal(extracted, publicKey) {
		t.Fatalf("extracted public key %x does not match the original %x", extracted, publicKey)
	}
}

func TestRegistrarClientIdentityUsesItsOwnAccountKey(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	registrar := &Registrar{privateKey: privateKey}
	copy(registrar.account[:], publicKey)

	tlsCert, err := registrar.ClientIdentity()
	if err != nil {
		t.Fatalf("ClientIdentity: %v", err)
	}
	parsed, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	extracted, ok := parsed.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("certificate public key is %T, want ed25519.PublicKey", parsed.PublicKey)
	}
	if !bytes.Equal(extracted, publicKey) {
		t.Fatalf("ClientIdentity's certificate key does not match the Registrar's own account")
	}
}
