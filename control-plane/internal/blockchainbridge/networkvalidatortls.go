package blockchainbridge

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

// selfSignedCertValidity is generous on purpose: this certificate's only
// job is to let the Agent's mTLS allowlist check
// (provider-agent/crates/agent-cli/src/mtls.rs's
// AllowlistClientCertVerifier) extract this validator's raw Ed25519
// public key -- it carries no authorization by itself (the heartbeat-
// pushed allowlist is the actual authorization), so there is no security
// benefit to a short-lived cert here, only an operational cost (this
// binary would need to regenerate and somehow republish it, and there is
// nowhere to republish it to). A long validity keeps the daemon's client
// identity stable across restarts without adding a persistence
// requirement this slice doesn't otherwise need.
const selfSignedCertValidity = 10 * 365 * 24 * time.Hour

// ClientIdentity builds the self-signed X.509 certificate this Registrar
// presents as its mTLS client identity when dialing a Provider Agent
// (ADR-013 §3/§6): self-signed over this Registrar's own Ed25519
// chain-signing key -- one identity, two uses (chain extrinsics and
// Agent mTLS) -- never CA-issued, matching ADR-011 §2's explicit "no
// separate validator PKI" decision. The Agent does not validate this
// certificate's chain; it extracts the raw 32-byte Ed25519 public key
// from it (mtls.rs's extract_ed25519_raw_public_key) and checks that key
// against the most recently heartbeat-pushed validator allowlist. So the
// only hard requirements on this certificate are: (1) a validly-formed,
// parseable X.509 certificate, (2) subject public key exactly equal to
// this Registrar's Ed25519 public key (Account()), and (3) the TLS
// handshake proving possession of the matching private key -- which
// crypto/tls's normal handshake already does for a tls.Certificate built
// from a real key pair. Self-signing satisfies all three without any CA
// material.
func (r *Registrar) ClientIdentity() (tls.Certificate, error) {
	return selfSignedClientCertificate(r.privateKey)
}

func selfSignedClientCertificate(privateKey ed25519.PrivateKey) (tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate certificate serial: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "openinfra-network-validator"},
		NotBefore:    time.Now().Add(-5 * time.Minute), // clock-skew tolerant
		NotAfter:     time.Now().Add(selfSignedCertValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create self-signed validator certificate: %w", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  privateKey,
	}, nil
}
