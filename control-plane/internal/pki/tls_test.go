package pki

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"
)

// serverIdentity builds a throwaway server TLS certificate (models the
// Control Plane's own long-lived server identity, unaffected by ADR-027 --
// see ServerTLSConfig's doc comment).
func serverIdentity(t *testing.T) tls.Certificate {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "control-plane"},
		DNSNames:     []string{"control-plane.local"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatalf("self-sign server certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

// dial performs a real TLS 1.3 handshake against a real server using
// clientCert as the presented client identity, and returns the handshake
// error (nil on success).
func dial(t *testing.T, serverConfig *tls.Config, clientCert tls.Certificate) error {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		tlsConn := tls.Server(conn, serverConfig)
		acceptErr <- tlsConn.Handshake()
	}()

	roots := x509.NewCertPool()
	serverLeaf, _ := x509.ParseCertificate(serverConfig.Certificates[0].Certificate[0])
	roots.AddCert(serverLeaf)
	clientConfig := &tls.Config{
		RootCAs:      roots,
		Certificates: []tls.Certificate{clientCert},
		ServerName:   "control-plane.local",
		MinVersion:   tls.VersionTLS13,
	}
	rawConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rawConn.Close()
	clientConn := tls.Client(rawConn, clientConfig)
	clientErr := clientConn.Handshake()

	serverErr := <-acceptErr
	if clientErr != nil {
		return clientErr
	}
	return serverErr
}

func leafClientCert(t *testing.T, ca *CA, providerID string) (tls.Certificate, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	issued, err := ca.IssueLeaf(providerID, pub, time.Now(), DefaultLeafTTL)
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	block, _ := pem.Decode([]byte(issued.CertificatePEM))
	if block == nil {
		t.Fatal("issued certificate PEM did not decode")
	}
	return tls.Certificate{Certificate: [][]byte{block.Bytes}, PrivateKey: priv}, pub
}

func TestFullHandshakeAcceptsCAChainedLeafCertificate(t *testing.T) {
	fixture := newTestCA(t)
	serverConfig := ServerTLSConfig(serverIdentity(t), fixture.ca, alwaysNotRevoked{})
	clientCert, _ := leafClientCert(t, fixture.ca, "provider-a")

	if err := dial(t, serverConfig, clientCert); err != nil {
		t.Fatalf("expected a CA-chained leaf certificate to complete the handshake: %v", err)
	}
}

func TestFullHandshakeAcceptsBootstrapSelfSignedCertificate(t *testing.T) {
	fixture := newTestCA(t)
	serverConfig := ServerTLSConfig(serverIdentity(t), fixture.ca, alwaysNotRevoked{})
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate bootstrap key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      pkix.Name{CommonName: "bootstrap"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatalf("self-sign bootstrap certificate: %v", err)
	}
	clientCert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}

	if err := dial(t, serverConfig, clientCert); err != nil {
		t.Fatalf("expected a well-formed self-signed bootstrap certificate to complete the handshake: %v", err)
	}
}

func TestFullHandshakeRejectsRevokedLeafCertificate(t *testing.T) {
	fixture := newTestCA(t)
	serverConfig := ServerTLSConfig(serverIdentity(t), fixture.ca, fixedRevocation{"provider-revoked": true})
	clientCert, _ := leafClientCert(t, fixture.ca, "provider-revoked")

	if err := dial(t, serverConfig, clientCert); err == nil {
		t.Fatal("expected the handshake to fail for a revoked provider's certificate")
	}
}

func TestFullHandshakeRejectsWrongCACertificate(t *testing.T) {
	fixture := newTestCA(t)
	otherCA := newTestCA(t)
	serverConfig := ServerTLSConfig(serverIdentity(t), fixture.ca, alwaysNotRevoked{})
	clientCert, _ := leafClientCert(t, otherCA.ca, "provider-a")

	if err := dial(t, serverConfig, clientCert); err == nil {
		t.Fatal("expected the handshake to fail for a certificate chained to a different CA")
	}
}
