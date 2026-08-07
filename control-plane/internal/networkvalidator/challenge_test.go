package networkvalidator

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openinfra/network/internal/blockchainbridge"
	agentv1 "github.com/openinfra/network/protocol/generated/go/agent/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// fakeAgentServer reproduces agent-api's real solve_challenge handler
// (provider-agent/crates/agent-api/src/lib.rs) exactly, in Go, so this
// test exercises the validator's actual verification logic against a
// byte-for-byte faithful re-implementation of what the real Agent
// computes -- not a stub that just echoes back whatever would make the
// test pass.
type fakeAgentServer struct {
	agentv1.UnimplementedProviderAgentServiceServer
	privateKey ed25519.PrivateKey
	// tamperSignature/tamperResult let individual tests corrupt an
	// otherwise-correct response to prove the validator's verification
	// actually rejects a bad response, not just accepts a good one.
	tamperSignature bool
	tamperResult    bool
}

func (s *fakeAgentServer) SolveChallenge(_ context.Context, req *agentv1.SolveChallengeRequest) (*agentv1.SolveChallengeResponse, error) {
	sum := sha256.Sum256(req.Payload)
	result := sum[:]
	signed := signedChallengeBytes(req.ChallengeId, int32(req.Type), result)
	signature := ed25519.Sign(s.privateKey, signed)
	if s.tamperResult {
		result = append([]byte{}, result...)
		result[0] ^= 0xFF
	}
	if s.tamperSignature {
		signature = append([]byte{}, signature...)
		signature[0] ^= 0xFF
	}
	return &agentv1.SolveChallengeResponse{
		ChallengeId:  req.ChallengeId,
		ResourceType: "network",
		Result:       result,
		DurationMs:   1,
		Signature:    signature,
	}, nil
}

// testAgentHarness wires up a real TLS-terminated gRPC server (the fake
// Agent) plus an httptest dashboard server serving the agent-endpoint
// discovery JSON, so ChallengeClient.Challenge is tested end to end:
// discovery -> mTLS dial -> RPC -> verification.
type testAgentHarness struct {
	grpcServer *grpc.Server
	listener   net.Listener
	dashboard  *httptest.Server
	agentPub   ed25519.PublicKey
	providerID string
}

func startTestAgentHarness(t *testing.T, fake *fakeAgentServer) *testAgentHarness {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	serverTLSCert := generateSelfSignedTestServerCert(t, "127.0.0.1")
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverTLSCert},
		ClientAuth:   tls.RequireAnyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	agentv1.RegisterProviderAgentServiceServer(grpcServer, fake)
	go func() { _ = grpcServer.Serve(listener) }()

	publicKey := fake.privateKey.Public().(ed25519.PublicKey)
	providerID := "test-provider-id"
	dashboard := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"agent_endpoint": "https://" + listener.Addr().String(),
			"public_key":     hex.EncodeToString(publicKey),
		})
	}))

	return &testAgentHarness{grpcServer: grpcServer, listener: listener, dashboard: dashboard, agentPub: publicKey, providerID: providerID}
}

func (h *testAgentHarness) close() {
	h.grpcServer.Stop()
	h.dashboard.Close()
}

func generateSelfSignedTestServerCert(t *testing.T, host string) tls.Certificate {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP(host)},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, priv.Public(), priv)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

// testValidatorClientCert builds a validator's mTLS client identity the
// same way cmd/networkvalidator does in production: a PKCS#8 PEM key
// file loaded through blockchainbridge.NewRegistrarFromPKCS8File, then
// Registrar.ClientIdentity() -- exercising the real production code path
// rather than reimplementing certificate construction in this test.
func testValidatorClientCert(t *testing.T) tls.Certificate {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate validator key: %v", err)
	}
	pemBytes, err := marshalPKCS8(priv)
	if err != nil {
		t.Fatalf("marshal PKCS8 key: %v", err)
	}
	keyFile := filepath.Join(t.TempDir(), "validator-key.pem")
	if err := os.WriteFile(keyFile, pemBytes, 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	rpc, err := blockchainbridge.NewRPCClient("http://127.0.0.1:1", &http.Client{})
	if err != nil {
		t.Fatalf("new RPC client stub: %v", err)
	}
	registrar, err := blockchainbridge.NewRegistrarFromPKCS8File(rpc, keyFile)
	if err != nil {
		t.Fatalf("load registrar: %v", err)
	}
	cert, err := registrar.ClientIdentity()
	if err != nil {
		t.Fatalf("build client identity: %v", err)
	}
	return cert
}

func newChallengeClient(t *testing.T, harness *testAgentHarness) *ChallengeClient {
	t.Helper()
	resolver, err := NewEndpointResolver(harness.dashboard.URL)
	if err != nil {
		t.Fatalf("new endpoint resolver: %v", err)
	}
	return NewChallengeClient(ChallengeClientConfig{
		Resolver:          resolver,
		ClientCertificate: testValidatorClientCert(t),
		AgentServerCAPool: nil, // InsecureSkipVerify path; harness uses an ad hoc self-signed cert
		DialTimeout:       2 * time.Second,
		ChallengeTimeout:  2 * time.Second,
	})
}

func TestChallengeSucceedsAgainstAFaithfulAgentReimplementation(t *testing.T) {
	_, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}
	harness := startTestAgentHarness(t, &fakeAgentServer{privateKey: agentPriv})
	defer harness.close()

	client := newChallengeClient(t, harness)
	result, err := client.Challenge(context.Background(), harness.providerID, blockchainbridge.DimensionNetwork)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	if result.ScoreBps != passingScoreBps {
		t.Fatalf("ScoreBps = %d, want %d (reason=%q)", result.ScoreBps, passingScoreBps, result.Reason)
	}
	if result.SampleCount != 1 {
		t.Fatalf("SampleCount = %d, want 1", result.SampleCount)
	}
}

func TestChallengeFailsOnTamperedSignature(t *testing.T) {
	_, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}
	harness := startTestAgentHarness(t, &fakeAgentServer{privateKey: agentPriv, tamperSignature: true})
	defer harness.close()

	client := newChallengeClient(t, harness)
	result, err := client.Challenge(context.Background(), harness.providerID, blockchainbridge.DimensionCompute)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	if result.ScoreBps != failingScoreBps {
		t.Fatalf("ScoreBps = %d, want %d for a tampered signature", result.ScoreBps, failingScoreBps)
	}
}

func TestChallengeFailsOnTamperedResult(t *testing.T) {
	_, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}
	harness := startTestAgentHarness(t, &fakeAgentServer{privateKey: agentPriv, tamperResult: true})
	defer harness.close()

	client := newChallengeClient(t, harness)
	result, err := client.Challenge(context.Background(), harness.providerID, blockchainbridge.DimensionStorage)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	if result.ScoreBps != failingScoreBps {
		t.Fatalf("ScoreBps = %d, want %d for a tampered result hash", result.ScoreBps, failingScoreBps)
	}
}

func TestChallengeReportsFailureForUnreachableAgent(t *testing.T) {
	// A dashboard that resolves to a closed port -- the Agent is
	// unreachable, which must score 0 with a reason, not return an error
	// from Challenge itself (see the doc comment on Challenge).
	dashboard := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"agent_endpoint": "https://127.0.0.1:1", // reserved, nothing listens here
			"public_key":     hex.EncodeToString(make([]byte, 32)),
		})
	}))
	defer dashboard.Close()

	resolver, err := NewEndpointResolver(dashboard.URL)
	if err != nil {
		t.Fatalf("new endpoint resolver: %v", err)
	}
	client := NewChallengeClient(ChallengeClientConfig{
		Resolver:          resolver,
		ClientCertificate: testValidatorClientCert(t),
		DialTimeout:       1 * time.Second,
		ChallengeTimeout:  1 * time.Second,
	})
	result, err := client.Challenge(context.Background(), "irrelevant", blockchainbridge.DimensionReliability)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	if result.ScoreBps != failingScoreBps {
		t.Fatalf("ScoreBps = %d, want %d for an unreachable agent", result.ScoreBps, failingScoreBps)
	}
	if result.Reason == "" {
		t.Fatal("expected a non-empty failure reason")
	}
}

func TestChallengeTypeForDimensionCoversEveryDimension(t *testing.T) {
	cases := map[blockchainbridge.ScoreDimension]agentv1.SolveChallengeRequest_Type{
		blockchainbridge.DimensionCompute:      agentv1.SolveChallengeRequest_TYPE_COMPUTE,
		blockchainbridge.DimensionStorage:      agentv1.SolveChallengeRequest_TYPE_STORAGE,
		blockchainbridge.DimensionNetwork:      agentv1.SolveChallengeRequest_TYPE_NETWORK,
		blockchainbridge.DimensionAvailability: agentv1.SolveChallengeRequest_TYPE_AVAILABILITY,
		blockchainbridge.DimensionReliability:  agentv1.SolveChallengeRequest_TYPE_RELIABILITY,
	}
	for dimension, want := range cases {
		got, err := challengeTypeForDimension(dimension)
		if err != nil {
			t.Fatalf("challengeTypeForDimension(%s): %v", dimension, err)
		}
		if got != want {
			t.Fatalf("challengeTypeForDimension(%s) = %v, want %v", dimension, got, want)
		}
	}
	if _, err := challengeTypeForDimension(blockchainbridge.ScoreDimension(99)); err == nil {
		t.Fatal("expected an error for an unknown dimension")
	}
}
