package pki

import (
	"context"
	"crypto/x509"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// bootstrapAllowedMethods are the only two RPCs ADR-027 §2 permits over a
// connection authenticated with a bootstrap (non-CA-chained, self-signed)
// certificate. Matched against the trailing path segment of
// grpc.UnaryServerInfo.FullMethod (e.g.
// "/openinfra.controlplane.v1.ControlPlaneService/CompleteJoin") so this
// doesn't need to import the generated service constants and stays correct
// even if the service is renamed.
var bootstrapAllowedMethods = map[string]bool{
	"/BeginJoin":    true,
	"/CompleteJoin": true,
}

// PeerCertificate extracts the leaf certificate the caller presented on
// this RPC's underlying mTLS connection. ok is false for any non-mTLS
// connection (plaintext dev mode, or a connection with no peer
// certificate) -- callers in that case must fail closed, not assume a
// permissive default.
func PeerCertificate(ctx context.Context) (cert *x509.Certificate, ok bool) {
	p, present := peer.FromContext(ctx)
	if !present {
		return nil, false
	}
	tlsInfo, isTLS := p.AuthInfo.(credentials.TLSInfo)
	if !isTLS || len(tlsInfo.State.PeerCertificates) == 0 {
		return nil, false
	}
	return tlsInfo.State.PeerCertificates[0], true
}

// PeerIdentity resolves the calling provider's identity and whether its
// certificate chains to ca (a previously enrolled/renewed leaf) or is only
// a bootstrap self-signed certificate. providerID/serial are read directly
// off the presented certificate -- providerjoin's RenewCertificate handler
// uses this to enforce "must match the connection this request arrives
// on," per ADR-027 §3, without a separate server-side certificate store.
func PeerIdentity(ctx context.Context, ca *CA) (providerID, serial string, chainVerified bool, ok bool) {
	cert, present := PeerCertificate(ctx)
	if !present {
		return "", "", false, false
	}
	id, idOK := IdentityFromCertificate(cert)
	if !idOK {
		return "", "", false, false
	}
	return id, cert.SerialNumber.String(), ca.ChainVerified(cert, time.Now()), true
}

// UnaryServerInterceptor enforces ADR-027 §4's connectivity-revocation
// requirement and §2's bootstrap-scope restriction on every RPC, not only
// at the TLS handshake: a certificate accepted at handshake time (which
// only checked revocation once, at connect time) does not stay trusted
// forever on an already-open connection -- this runs the same revocation
// check on every single call, bounding a revoked provider's remaining
// connectivity to "at most one more RPC after the operator's
// revoke-provider command lands," not "until this connection happens to
// close." Fails closed: any ambiguity (no peer certificate, unresolvable
// identity, revocation-store error) rejects the call.
func UnaryServerInterceptor(ca *CA, revocation RevocationChecker) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		providerID, _, chainVerified, ok := PeerIdentity(ctx, ca)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "no client certificate identity on this connection")
		}
		if !chainVerified {
			if bootstrapAllowedMethods[methodSuffix(info.FullMethod)] {
				return handler(ctx, req)
			}
			return nil, status.Error(codes.Unauthenticated, "a bootstrap (self-signed) certificate may only call BeginJoin/CompleteJoin")
		}
		if revocation != nil {
			revoked, err := revocation.IsRevoked(ctx, providerID)
			if err != nil {
				return nil, status.Error(codes.Unavailable, "revocation status is unavailable")
			}
			if revoked {
				return nil, status.Error(codes.PermissionDenied, "provider is revoked")
			}
		}
		return handler(ctx, req)
	}
}

// methodSuffix returns the trailing "/Method" segment of a gRPC
// FullMethod ("/pkg.Service/Method" -> "/Method").
func methodSuffix(fullMethod string) string {
	idx := strings.LastIndex(fullMethod, "/")
	if idx < 0 {
		return fullMethod
	}
	return fullMethod[idx:]
}
