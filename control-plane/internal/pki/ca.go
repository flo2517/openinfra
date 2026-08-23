// Package pki implements ADR-027's Control-Plane-operated certificate
// authority: issuing short-lived Provider Agent leaf certificates
// (enrollment via CompleteJoin, renewal via RenewCertificate), verifying
// the dual trust basis (CA chain, or a bootstrap self-signed certificate
// scoped to BeginJoin/CompleteJoin only) at the mTLS handshake, and
// enforcing revocation on both new handshakes and every RPC on an
// already-open connection.
//
// The CA private key never leaves this process: LoadCA reads it once from
// the filesystem path the Control Plane's own runtime environment already
// grants it (never mounted into the provider-agent container, per ADR-027
// §5), and nothing in this package returns it, logs it, or serializes it
// back out. Issuance and verification log only provider_id, serial number,
// and expiry, matching AGENTS.md's blanket "never log secrets" rule.
package pki

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

const (
	// DefaultLeafTTL is ADR-027 §3's certificate lifetime: short enough to
	// bound the blast radius of a leaked leaf key to at most a day of
	// unauthorized connectivity, long enough that renewal traffic (about
	// once a day per provider) stays a rounding error next to the ~15s
	// heartbeat cadence.
	DefaultLeafTTL = 24 * time.Hour
	// RenewalThreshold is the fraction of DefaultLeafTTL elapsed before an
	// Agent should attempt renewal (50%, giving a 12h overlap window).
	// Exported so the Agent-side renewal timer (documented, not
	// implemented, in this Go package) and any Control-Plane-side test
	// fixture agree on the same number without hard-coding it twice.
	RenewalThreshold = 0.5
	// leafClockSkewTolerance backdates a freshly issued leaf certificate's
	// NotBefore so a caller whose clock is slightly behind the Control
	// Plane's doesn't see the certificate as "not yet valid" the moment it
	// receives it.
	leafClockSkewTolerance = 5 * time.Minute
)

// ErrNotEd25519Key reports that a certificate's or request's public key
// isn't the raw 32-byte Ed25519 key ADR-027 §2/§3 require.
var ErrNotEd25519Key = errors.New("pki: public key is not a 32-byte Ed25519 key")

// CA holds the Control Plane's certificate authority: its own certificate
// (used as the sole trust root for verifying provider leaf certificates)
// and the private key used to sign new leaves. The private key's concrete
// type is left to whatever generate-dev-certs.sh (or a real external CA in
// a non-dev deployment) produced -- ADR-027's open question leaves the
// root's algorithm unresolved, so LoadCA accepts any crypto.Signer PEM
// parses to (RSA today, matching generate-dev-certs.sh's ca.key).
type CA struct {
	cert    *x509.Certificate
	certDER []byte
	signer  crypto.Signer
	roots   *x509.CertPool
}

// LoadCA parses a CA certificate and its private key, both PEM-encoded, as
// produced by deployments/scripts/generate-dev-certs.sh's ca.crt/ca.key
// (or an equivalent real CA in a non-dev deployment). The returned *CA's
// roots pool contains exactly this one certificate -- the Control Plane
// operates a single CA per ADR-027 §1, not a chain of intermediates.
func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, errors.New("pki: no PEM block found in CA certificate")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("pki: parse CA certificate: %w", err)
	}
	signer, err := parsePrivateKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("pki: parse CA private key: %w", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return &CA{cert: cert, certDER: certBlock.Bytes, signer: signer, roots: roots}, nil
}

func parsePrivateKey(keyPEM []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, errors.New("PKCS8 key does not implement crypto.Signer")
		}
		return signer, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, errors.New("unrecognized private key encoding (tried PKCS8, PKCS1, EC)")
}

// IssuedCertificate is the result of a successful leaf issuance: the
// caller (providerjoin's CompleteJoin/RenewCertificate handlers) turns
// this directly into the wire response fields.
type IssuedCertificate struct {
	CertificatePEM string
	Serial         string
	ExpiresAt      time.Time
}

// IssueLeaf certifies publicKey as providerID's mTLS leaf identity, valid
// for ttl (ADR-027 recommends DefaultLeafTTL for both enrollment and
// renewal -- callers pass it explicitly rather than this function
// hard-coding it, so a test can exercise a short TTL without waiting real
// hours). The certificate's Subject Common Name is providerID exactly --
// IdentityFromCertificate reads it back the same way, and revocation
// checks (RevocationChecker.IsRevoked) key off that same string, so this
// binding is the one place a provider's on-the-wire identity and its
// certificate's bound identity are tied together.
func (ca *CA) IssueLeaf(providerID string, publicKey ed25519.PublicKey, now time.Time, ttl time.Duration) (IssuedCertificate, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return IssuedCertificate{}, ErrNotEd25519Key
	}
	if providerID == "" {
		return IssuedCertificate{}, errors.New("pki: provider_id is required to issue a leaf certificate")
	}
	serial, err := randomSerial()
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("pki: generate serial: %w", err)
	}
	notBefore := now.Add(-leafClockSkewTolerance).UTC()
	notAfter := now.Add(ttl).UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: providerID},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, publicKey, ca.signer)
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("pki: sign leaf certificate: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return IssuedCertificate{
		CertificatePEM: string(certPEM),
		Serial:         serial.String(),
		ExpiresAt:      notAfter,
	}, nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

// ChainVerified reports whether cert chains to this CA's root, is
// currently valid at now (neither expired nor not-yet-valid), and is
// authorized for client authentication. Used identically by the TLS
// handshake's VerifyPeerCertificate callback and by the unary interceptor
// re-deriving the same fact for an already-open connection -- both must
// agree, so both call this one function rather than duplicating the
// x509.Verify options.
func (ca *CA) ChainVerified(cert *x509.Certificate, now time.Time) bool {
	_, err := cert.Verify(x509.VerifyOptions{
		Roots:       ca.roots,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	return err == nil
}

// IsSelfSigned reports whether cert's signature cryptographically verifies
// against its own public key -- the ADR-027 §2 bootstrap trust class
// accepts "any well-formed, self-signed certificate," not an arbitrary
// unverified blob. Deliberately uses CheckSignature, not CheckSignatureFrom
// (which also enforces CA BasicConstraints/KeyUsageCertSign, requirements
// a bootstrap leaf-shaped certificate has no reason to satisfy): the only
// property this needs to prove is "the presenter holds the private key
// matching this certificate's own public key," the same proof-of-
// possession property client_auth already relies on the TLS handshake
// itself for.
func IsSelfSigned(cert *x509.Certificate) bool {
	return cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}

// IdentityFromCertificate extracts the provider_id ADR-027 §2 binds into a
// leaf certificate's Subject Common Name at issuance (see IssueLeaf). ok is
// false for an empty Common Name -- never treated as a valid identity.
func IdentityFromCertificate(cert *x509.Certificate) (providerID string, ok bool) {
	if cert == nil || cert.Subject.CommonName == "" {
		return "", false
	}
	return cert.Subject.CommonName, true
}
