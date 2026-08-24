package providerjoin

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/openinfra/network/internal/pki"
	controlplanev1 "github.com/openinfra/network/protocol/generated/go/controlplane/v1"
	sharedv1 "github.com/openinfra/network/protocol/generated/go/shared/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// newFixtureCA builds a from-scratch self-signed Ed25519 CA usable with
// pki.LoadCA -- mirrors internal/pki's own test fixture (kept package-
// local since test helpers aren't exported across packages).
func newFixtureCA(t *testing.T) *pki.CA {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatalf("self-sign CA: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal PKCS8 key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	ca, err := pki.LoadCA(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	return ca
}

// leafPeerContext builds a context carrying cert as the mTLS peer
// certificate, the same shape pki's own interceptor tests use --
// RenewCertificate reads the caller's bound identity this way, never from
// the request body alone.
func leafPeerContext(cert *x509.Certificate) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.IPAddr{},
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}},
		},
	})
}

func issueTestLeaf(t *testing.T, ca *pki.CA, providerID string, now time.Time, ttl time.Duration) (*x509.Certificate, pki.IssuedCertificate) {
	t.Helper()
	issued, err := ca.IssueLeaf(providerID, mustEd25519Public(t), now, ttl)
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	cert := parseFirstCertificate(t, issued.CertificatePEM)
	return cert, issued
}

func mustEd25519Public(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub
}

func parseFirstCertificate(t *testing.T, certPEM string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatal("certificate PEM did not decode")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

// providerFixture generates a long-term Ed25519 identity and registers it
// in the given status in an in-memory repository -- the shape
// RenewCertificate needs from ProviderIdentity. providerID is derived the
// same way service.go's CompleteJoin derives it (sha256(public_key) hex).
func providerFixture(status sharedv1.NodeStatus) (*memoryRepository, string, ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	repository := newMemoryRepository()
	digest := sha256.Sum256(pub)
	providerID := fmt.Sprintf("%x", digest)
	repository.completion[uuid.NewString()] = Completion{
		ProviderID: providerID,
		Challenge:  Challenge{PublicKey: pub},
		Status:     status,
	}
	return repository, providerID, pub, priv
}

type memoryNonceStore struct {
	mu   sync.Mutex
	last map[string]uint64
}

func newMemoryNonceStore() *memoryNonceStore {
	return &memoryNonceStore{last: make(map[string]uint64)}
}

func (s *memoryNonceStore) Accept(_ context.Context, providerID string, nonce uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if last, ok := s.last[providerID]; ok && nonce <= last {
		return ErrRenewalReplay
	}
	s.last[providerID] = nonce
	return nil
}

func signRenewal(priv ed25519.PrivateKey, newKey []byte, serial string, timestamp *timestamppb.Timestamp, nonce uint64) []byte {
	return ed25519.Sign(priv, renewalSigningPayload(newKey, serial, timestamp, nonce))
}

func TestCompleteJoinIssuesCertificateWhenTLSPublicKeyProvided(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	service := NewService(newMemoryRepository(), newMemoryHeartbeatStore(), &memoryRegistrar{})
	service.SetCertificateAuthority(newFixtureCA(t))
	begin, err := service.BeginJoin(context.Background(), &controlplanev1.BeginJoinRequest{
		RequestId: uuid.NewString(), PublicKey: publicKey, ProtocolVersion: "1", AgentVersion: "0.1.0",
	})
	if err != nil {
		t.Fatalf("begin join: %v", err)
	}
	signature := ed25519.Sign(privateKey, append([]byte(joinDomain), begin.ChallengeNonce...))
	tlsPub := mustEd25519Public(t)
	completed, err := service.CompleteJoin(context.Background(), &controlplanev1.CompleteJoinRequest{
		RequestId: uuid.NewString(), ChallengeId: begin.ChallengeId, ChallengeSignature: signature,
		Capabilities: &sharedv1.ResourceCapability{CpuTotal: 8, RamTotalMb: 16_384},
		TlsPublicKey: tlsPub,
	})
	if err != nil {
		t.Fatalf("complete join: %v", err)
	}
	if completed.CertificatePem == "" {
		t.Fatal("expected a certificate_pem when tls_public_key is provided")
	}
	if completed.CertificateExpiresAt == nil {
		t.Fatal("expected certificate_expires_at to be set")
	}
}

func TestCompleteJoinFailsLoudlyWhenTLSPublicKeyProvidedButNoCA(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	service := NewService(newMemoryRepository(), newMemoryHeartbeatStore(), &memoryRegistrar{})
	begin, err := service.BeginJoin(context.Background(), &controlplanev1.BeginJoinRequest{
		RequestId: uuid.NewString(), PublicKey: publicKey, ProtocolVersion: "1", AgentVersion: "0.1.0",
	})
	if err != nil {
		t.Fatalf("begin join: %v", err)
	}
	signature := ed25519.Sign(privateKey, append([]byte(joinDomain), begin.ChallengeNonce...))
	_, err = service.CompleteJoin(context.Background(), &controlplanev1.CompleteJoinRequest{
		RequestId: uuid.NewString(), ChallengeId: begin.ChallengeId, ChallengeSignature: signature,
		Capabilities: &sharedv1.ResourceCapability{CpuTotal: 8, RamTotalMb: 16_384},
		TlsPublicKey: mustEd25519Public(t),
	})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %s, want Unavailable", status.Code(err))
	}
}

func TestRenewCertificateHappyPath(t *testing.T) {
	ca := newFixtureCA(t)
	repository, providerID, _, priv := providerFixture(sharedv1.NodeStatus_NODE_STATUS_ACTIVE)
	now := time.Now().UTC()
	leaf, issued := issueTestLeaf(t, ca, providerID, now, pki.DefaultLeafTTL)

	service := NewService(repository, newMemoryHeartbeatStore(), &memoryRegistrar{})
	service.now = func() time.Time { return now.Add(12 * time.Hour) }
	service.SetCertificateAuthority(ca)
	service.SetRenewalNonceStore(newMemoryNonceStore())

	ctx := leafPeerContext(leaf)
	newKey := mustEd25519Public(t)
	timestamp := timestamppb.New(service.now())
	request := &controlplanev1.RenewCertificateRequest{
		RequestId:                uuid.NewString(),
		ProviderId:               providerID,
		NewTlsPublicKey:          newKey,
		CurrentCertificateSerial: issued.Serial,
		Timestamp:                timestamp,
		Nonce:                    1,
		Signature:                signRenewal(priv, newKey, issued.Serial, timestamp, 1),
	}
	response, err := service.RenewCertificate(ctx, request)
	if err != nil {
		t.Fatalf("RenewCertificate: %v", err)
	}
	if response.CertificatePem == "" || response.CertificateSerial == issued.Serial {
		t.Fatalf("expected a fresh certificate with a new serial, got serial=%s", response.CertificateSerial)
	}
}

func TestRenewCertificateRejectsBootstrapConnection(t *testing.T) {
	ca := newFixtureCA(t)
	repository, providerID, _, priv := providerFixture(sharedv1.NodeStatus_NODE_STATUS_ACTIVE)
	now := time.Now().UTC()

	// A self-signed certificate (never issued by ca) models the bootstrap
	// connection CompleteJoin uses -- RenewCertificate must never accept
	// this, per ADR-027 §3.
	selfSignedPub, selfSignedPriv, _ := ed25519.GenerateKey(rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: providerID},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, _ := x509.CreateCertificate(rand.Reader, template, template, selfSignedPub, selfSignedPriv)
	bootstrapCert, _ := x509.ParseCertificate(der)

	service := NewService(repository, newMemoryHeartbeatStore(), &memoryRegistrar{})
	service.now = func() time.Time { return now }
	service.SetCertificateAuthority(ca)
	service.SetRenewalNonceStore(newMemoryNonceStore())

	newKey := mustEd25519Public(t)
	timestamp := timestamppb.New(now)
	request := &controlplanev1.RenewCertificateRequest{
		RequestId: uuid.NewString(), ProviderId: providerID, NewTlsPublicKey: newKey,
		CurrentCertificateSerial: "1", Timestamp: timestamp, Nonce: 1,
		Signature: signRenewal(priv, newKey, "1", timestamp, 1),
	}
	_, err := service.RenewCertificate(leafPeerContext(bootstrapCert), request)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %s, want Unauthenticated", status.Code(err))
	}
}

func TestRenewCertificateRejectsSerialMismatch(t *testing.T) {
	ca := newFixtureCA(t)
	repository, providerID, _, priv := providerFixture(sharedv1.NodeStatus_NODE_STATUS_ACTIVE)
	now := time.Now().UTC()
	leaf, issued := issueTestLeaf(t, ca, providerID, now, pki.DefaultLeafTTL)

	service := NewService(repository, newMemoryHeartbeatStore(), &memoryRegistrar{})
	service.now = func() time.Time { return now }
	service.SetCertificateAuthority(ca)
	service.SetRenewalNonceStore(newMemoryNonceStore())

	newKey := mustEd25519Public(t)
	timestamp := timestamppb.New(now)
	wrongSerial := issued.Serial + "0"
	request := &controlplanev1.RenewCertificateRequest{
		RequestId: uuid.NewString(), ProviderId: providerID, NewTlsPublicKey: newKey,
		CurrentCertificateSerial: wrongSerial, Timestamp: timestamp, Nonce: 1,
		Signature: signRenewal(priv, newKey, wrongSerial, timestamp, 1),
	}
	_, err := service.RenewCertificate(leafPeerContext(leaf), request)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %s, want Unauthenticated", status.Code(err))
	}
}

func TestRenewCertificateRejectsReplayedNonce(t *testing.T) {
	ca := newFixtureCA(t)
	repository, providerID, _, priv := providerFixture(sharedv1.NodeStatus_NODE_STATUS_ACTIVE)
	now := time.Now().UTC()
	leaf, issued := issueTestLeaf(t, ca, providerID, now, pki.DefaultLeafTTL)

	service := NewService(repository, newMemoryHeartbeatStore(), &memoryRegistrar{})
	service.now = func() time.Time { return now }
	service.SetCertificateAuthority(ca)
	service.SetRenewalNonceStore(newMemoryNonceStore())

	newKey := mustEd25519Public(t)
	timestamp := timestamppb.New(now)
	request := &controlplanev1.RenewCertificateRequest{
		RequestId: uuid.NewString(), ProviderId: providerID, NewTlsPublicKey: newKey,
		CurrentCertificateSerial: issued.Serial, Timestamp: timestamp, Nonce: 5,
		Signature: signRenewal(priv, newKey, issued.Serial, timestamp, 5),
	}
	if _, err := service.RenewCertificate(leafPeerContext(leaf), request); err != nil {
		t.Fatalf("first renewal: %v", err)
	}
	request.RequestId = uuid.NewString()
	if _, err := service.RenewCertificate(leafPeerContext(leaf), request); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("replayed nonce code = %s, want FailedPrecondition", status.Code(err))
	}
}

func TestRenewCertificateRejectsClockSkewBeyondTolerance(t *testing.T) {
	ca := newFixtureCA(t)
	repository, providerID, _, priv := providerFixture(sharedv1.NodeStatus_NODE_STATUS_ACTIVE)
	now := time.Now().UTC()
	leaf, issued := issueTestLeaf(t, ca, providerID, now, pki.DefaultLeafTTL)

	service := NewService(repository, newMemoryHeartbeatStore(), &memoryRegistrar{})
	service.now = func() time.Time { return now }
	service.SetCertificateAuthority(ca)
	service.SetRenewalNonceStore(newMemoryNonceStore())

	newKey := mustEd25519Public(t)
	skewed := timestamppb.New(now.Add(-10 * time.Minute)) // beyond maxRenewalClockSkew
	request := &controlplanev1.RenewCertificateRequest{
		RequestId: uuid.NewString(), ProviderId: providerID, NewTlsPublicKey: newKey,
		CurrentCertificateSerial: issued.Serial, Timestamp: skewed, Nonce: 1,
		Signature: signRenewal(priv, newKey, issued.Serial, skewed, 1),
	}
	_, err := service.RenewCertificate(leafPeerContext(leaf), request)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %s, want InvalidArgument", status.Code(err))
	}
}

func TestRenewCertificateRejectsRevokedProvider(t *testing.T) {
	ca := newFixtureCA(t)
	repository, providerID, _, priv := providerFixture(sharedv1.NodeStatus_NODE_STATUS_REVOKED)
	now := time.Now().UTC()
	leaf, issued := issueTestLeaf(t, ca, providerID, now, pki.DefaultLeafTTL)

	service := NewService(repository, newMemoryHeartbeatStore(), &memoryRegistrar{})
	service.now = func() time.Time { return now }
	service.SetCertificateAuthority(ca)
	service.SetRenewalNonceStore(newMemoryNonceStore())

	newKey := mustEd25519Public(t)
	timestamp := timestamppb.New(now)
	request := &controlplanev1.RenewCertificateRequest{
		RequestId: uuid.NewString(), ProviderId: providerID, NewTlsPublicKey: newKey,
		CurrentCertificateSerial: issued.Serial, Timestamp: timestamp, Nonce: 1,
		Signature: signRenewal(priv, newKey, issued.Serial, timestamp, 1),
	}
	_, err := service.RenewCertificate(leafPeerContext(leaf), request)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %s, want FailedPrecondition", status.Code(err))
	}
}
