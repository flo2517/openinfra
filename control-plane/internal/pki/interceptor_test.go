package pki

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func peerContext(cert *x509.Certificate) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.IPAddr{},
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}},
		},
	})
}

func noopHandler(_ context.Context, _ interface{}) (interface{}, error) {
	return "ok", nil
}

func TestInterceptorAllowsBootstrapCertificateOnlyForJoinMethods(t *testing.T) {
	fixture := newTestCA(t)
	cert := selfSignedCert(t)
	ctx := peerContext(cert)
	interceptor := UnaryServerInterceptor(fixture.ca, alwaysNotRevoked{})

	for _, method := range []string{
		"/openinfra.controlplane.v1.ControlPlaneService/BeginJoin",
		"/openinfra.controlplane.v1.ControlPlaneService/CompleteJoin",
	} {
		_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: method}, noopHandler)
		if err != nil {
			t.Fatalf("bootstrap certificate must be allowed to call %s: %v", method, err)
		}
	}

	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/openinfra.controlplane.v1.ControlPlaneService/ReportHeartbeat"}, noopHandler)
	if code := status.Code(err); code != codes.Unauthenticated {
		t.Fatalf("bootstrap certificate must be rejected for ReportHeartbeat with Unauthenticated, got %v (%v)", code, err)
	}
}

func TestInterceptorAllowsChainVerifiedCertificateForAnyMethod(t *testing.T) {
	fixture := newTestCA(t)
	cert := issueLeaf(t, fixture.ca, "provider-a", time.Now(), DefaultLeafTTL)
	ctx := peerContext(cert)
	interceptor := UnaryServerInterceptor(fixture.ca, alwaysNotRevoked{})

	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/openinfra.controlplane.v1.ControlPlaneService/ReportHeartbeat"}, noopHandler)
	if err != nil {
		t.Fatalf("a CA-chained certificate must be allowed to call any RPC: %v", err)
	}
}

func TestInterceptorRejectsRevokedProviderOnEveryCall(t *testing.T) {
	fixture := newTestCA(t)
	cert := issueLeaf(t, fixture.ca, "provider-revoked", time.Now(), DefaultLeafTTL)
	ctx := peerContext(cert)
	interceptor := UnaryServerInterceptor(fixture.ca, fixedRevocation{"provider-revoked": true})

	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/openinfra.controlplane.v1.ControlPlaneService/ReportHeartbeat"}, noopHandler)
	if code := status.Code(err); code != codes.PermissionDenied {
		t.Fatalf("a revoked provider's next RPC (not just its next heartbeat) must be rejected with PermissionDenied, got %v (%v)", code, err)
	}
}

func TestInterceptorRevocationErrorFailsClosed(t *testing.T) {
	fixture := newTestCA(t)
	cert := issueLeaf(t, fixture.ca, "provider-a", time.Now(), DefaultLeafTTL)
	ctx := peerContext(cert)
	interceptor := UnaryServerInterceptor(fixture.ca, erroringRevocation{})

	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/openinfra.controlplane.v1.ControlPlaneService/ReportHeartbeat"}, noopHandler)
	if err == nil {
		t.Fatal("a revocation-store error on the per-RPC interceptor must fail closed, not silently allow the call")
	}
}

func TestInterceptorRejectsMissingPeerCertificate(t *testing.T) {
	fixture := newTestCA(t)
	interceptor := UnaryServerInterceptor(fixture.ca, alwaysNotRevoked{})
	_, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/openinfra.controlplane.v1.ControlPlaneService/CompleteJoin"}, noopHandler)
	if err == nil {
		t.Fatal("a connection with no peer certificate at all must be rejected, even for CompleteJoin")
	}
}
