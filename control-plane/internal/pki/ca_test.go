package pki

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"
)

// testCA is a from-scratch, self-signed Ed25519 CA fixture (test-only --
// the real deployment's root stays RSA per generate-dev-certs.sh, but
// LoadCA/parsePrivateKey accept any crypto.Signer, so this exercises the
// same code paths with a much cheaper keypair to generate).
type testCA struct {
	ca      *CA
	certPEM []byte
	keyPEM  []byte
}

func newTestCA(t *testing.T) testCA {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "openinfra-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatalf("self-sign CA certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal CA key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	ca, err := LoadCA(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	return testCA{ca: ca, certPEM: certPEM, keyPEM: keyPEM}
}

// selfSignedCert builds a bootstrap-style self-signed certificate with a
// freshly generated Ed25519 keypair, unrelated to any CA -- models what a
// brand-new Provider Agent presents for BeginJoin/CompleteJoin.
func selfSignedCert(t *testing.T) *x509.Certificate {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate bootstrap key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "bootstrap"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatalf("self-sign bootstrap certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse self-signed certificate: %v", err)
	}
	return cert
}

func issueLeaf(t *testing.T, ca *CA, providerID string, now time.Time, ttl time.Duration) *x509.Certificate {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	issued, err := ca.IssueLeaf(providerID, pub, now, ttl)
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	block, _ := pem.Decode([]byte(issued.CertificatePEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse issued leaf: %v", err)
	}
	return cert
}

func TestIssueLeafBindsProviderIDAndExpiry(t *testing.T) {
	fixture := newTestCA(t)
	now := time.Now()
	cert := issueLeaf(t, fixture.ca, "provider-a", now, DefaultLeafTTL)

	id, ok := IdentityFromCertificate(cert)
	if !ok || id != "provider-a" {
		t.Fatalf("expected identity provider-a, got %q ok=%v", id, ok)
	}
	if !fixture.ca.ChainVerified(cert, now) {
		t.Fatal("freshly issued leaf must chain-verify at issuance time")
	}
}

func TestIssueLeafRejectsNonEd25519Key(t *testing.T) {
	fixture := newTestCA(t)
	_, err := fixture.ca.IssueLeaf("provider-a", []byte{0x01, 0x02}, time.Now(), DefaultLeafTTL)
	if !errors.Is(err, ErrNotEd25519Key) {
		t.Fatalf("expected ErrNotEd25519Key, got %v", err)
	}
}

// --- Category 1: expired ---

func TestExpiredLeafCertificateIsRejected(t *testing.T) {
	fixture := newTestCA(t)
	issuedAt := time.Now().Add(-2 * time.Hour)
	cert := issueLeaf(t, fixture.ca, "provider-a", issuedAt, time.Hour) // NotAfter = issuedAt+1h, already in the past

	if fixture.ca.ChainVerified(cert, time.Now()) {
		t.Fatal("an expired leaf certificate must not chain-verify")
	}
	verifier := fixture.ca.ClientCertVerifier(alwaysNotRevoked{})
	if err := verifier([][]byte{cert.Raw}, nil); err == nil {
		t.Fatal("ClientCertVerifier must reject an expired leaf certificate")
	}
}

// --- Category 2: revoked ---

func TestRevokedLeafCertificateIsRejectedAtHandshake(t *testing.T) {
	fixture := newTestCA(t)
	cert := issueLeaf(t, fixture.ca, "provider-revoked", time.Now(), DefaultLeafTTL)

	verifier := fixture.ca.ClientCertVerifier(fixedRevocation{"provider-revoked": true})
	if err := verifier([][]byte{cert.Raw}, nil); err == nil {
		t.Fatal("ClientCertVerifier must reject a revoked, still cryptographically valid certificate")
	}
}

func TestNonRevokedLeafCertificateIsAcceptedAtHandshake(t *testing.T) {
	fixture := newTestCA(t)
	cert := issueLeaf(t, fixture.ca, "provider-active", time.Now(), DefaultLeafTTL)

	verifier := fixture.ca.ClientCertVerifier(fixedRevocation{"provider-revoked": true})
	if err := verifier([][]byte{cert.Raw}, nil); err != nil {
		t.Fatalf("a non-revoked, chain-verified certificate must be accepted: %v", err)
	}
}

func TestRevocationCheckErrorFailsClosedAtHandshake(t *testing.T) {
	fixture := newTestCA(t)
	cert := issueLeaf(t, fixture.ca, "provider-a", time.Now(), DefaultLeafTTL)

	verifier := fixture.ca.ClientCertVerifier(erroringRevocation{})
	if err := verifier([][]byte{cert.Raw}, nil); err == nil {
		t.Fatal("a revocation-store error must fail closed (reject), not silently admit the connection")
	}
}

// --- Category 3: wrong CA ---

func TestLeafIssuedByADifferentCAIsRejected(t *testing.T) {
	fixture := newTestCA(t)
	otherCA := newTestCA(t)
	cert := issueLeaf(t, otherCA.ca, "provider-a", time.Now(), DefaultLeafTTL)

	if fixture.ca.ChainVerified(cert, time.Now()) {
		t.Fatal("a certificate issued by a different CA must not chain-verify against this CA's roots")
	}
	verifier := fixture.ca.ClientCertVerifier(alwaysNotRevoked{})
	if err := verifier([][]byte{cert.Raw}, nil); err == nil {
		t.Fatal("ClientCertVerifier must reject a certificate chained to the wrong CA (it is not self-signed either)")
	}
}

// --- Category 4: rotation, both certs valid during the overlap window ---

func TestBothCertificatesAreValidDuringTheRenewalOverlapWindow(t *testing.T) {
	fixture := newTestCA(t)
	issuedAt := time.Now().Add(-12 * time.Hour) // 50% elapsed of a 24h cert
	oldCert := issueLeaf(t, fixture.ca, "provider-a", issuedAt, DefaultLeafTTL)
	newCert := issueLeaf(t, fixture.ca, "provider-a", time.Now(), DefaultLeafTTL)

	now := time.Now()
	if !fixture.ca.ChainVerified(oldCert, now) {
		t.Fatal("the old certificate must remain valid for the rest of its own lifetime during the overlap window")
	}
	if !fixture.ca.ChainVerified(newCert, now) {
		t.Fatal("the newly renewed certificate must be valid immediately")
	}
	if oldCert.SerialNumber.Cmp(newCert.SerialNumber) == 0 {
		t.Fatal("renewal must mint a distinct serial, never reuse the previous one")
	}
}

// --- Category 5: clock skew ---

func TestLeafCertificateToleratesBackdatedClockSkew(t *testing.T) {
	fixture := newTestCA(t)
	now := time.Now()
	cert := issueLeaf(t, fixture.ca, "provider-a", now, DefaultLeafTTL)

	withinTolerance := now.Add(-4 * time.Minute) // leafClockSkewTolerance is 5 minutes
	if !fixture.ca.ChainVerified(cert, withinTolerance) {
		t.Fatal("a verifier clock running up to leafClockSkewTolerance behind must still accept a freshly issued certificate")
	}
}

func TestLeafCertificateRejectsClockSkewBeyondTolerance(t *testing.T) {
	fixture := newTestCA(t)
	now := time.Now()
	cert := issueLeaf(t, fixture.ca, "provider-a", now, DefaultLeafTTL)

	beyondTolerance := now.Add(-10 * time.Minute)
	if fixture.ca.ChainVerified(cert, beyondTolerance) {
		t.Fatal("clock skew beyond leafClockSkewTolerance must not be tolerated")
	}
}

// --- Bootstrap trust class ---

func TestWellFormedSelfSignedCertificateIsAcceptedAsBootstrap(t *testing.T) {
	fixture := newTestCA(t)
	cert := selfSignedCert(t)

	verifier := fixture.ca.ClientCertVerifier(alwaysNotRevoked{})
	if err := verifier([][]byte{cert.Raw}, nil); err != nil {
		t.Fatalf("a well-formed self-signed certificate must be accepted at the TLS layer (bootstrap trust class): %v", err)
	}
}

func TestMalformedCertificateIsRejected(t *testing.T) {
	fixture := newTestCA(t)
	verifier := fixture.ca.ClientCertVerifier(alwaysNotRevoked{})
	if err := verifier([][]byte{[]byte("not a certificate")}, nil); err == nil {
		t.Fatal("an unparsable certificate must be rejected")
	}
}

func TestNoCertificatePresentedIsRejected(t *testing.T) {
	fixture := newTestCA(t)
	verifier := fixture.ca.ClientCertVerifier(alwaysNotRevoked{})
	if err := verifier(nil, nil); err == nil {
		t.Fatal("an empty certificate list must be rejected")
	}
}

// --- test doubles ---

type alwaysNotRevoked struct{}

func (alwaysNotRevoked) IsRevoked(context.Context, string) (bool, error) { return false, nil }

type fixedRevocation map[string]bool

func (f fixedRevocation) IsRevoked(_ context.Context, providerID string) (bool, error) {
	return f[providerID], nil
}

type erroringRevocation struct{}

func (erroringRevocation) IsRevoked(context.Context, string) (bool, error) {
	return false, errors.New("redis unavailable")
}
