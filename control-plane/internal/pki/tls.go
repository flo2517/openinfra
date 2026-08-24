package pki

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"time"
)

// ClientCertVerifier returns a crypto/tls VerifyPeerCertificate callback
// implementing ADR-027 §2's dual trust basis for the Control Plane's mTLS
// listener -- the Go-side mirror of provider-agent's
// AllowlistClientCertVerifier (ADR-013 §3), same shape, opposite
// direction:
//
//  1. If the presented certificate chains to this CA, the connection is a
//     previously enrolled/renewed provider. Its bound identity is checked
//     against revocation (ADR-027 §4 "new handshakes") before the
//     handshake is allowed to complete -- a revoked provider's
//     cryptographically valid, CA-chained certificate is rejected
//     outright, not just excluded from scheduling.
//  2. Otherwise, if the certificate is at least a well-formed self-signed
//     certificate, the handshake is allowed to proceed -- this is the
//     ADR-027 §2 bootstrap trust class for BeginJoin/CompleteJoin. The TLS
//     layer grants no authorization by itself here: UnaryServerInterceptor
//     is what actually restricts a non-CA-chained connection to exactly
//     those two RPCs, and CompleteJoin's own Ed25519 challenge-signature
//     check is what actually authorizes anything.
//  3. Anything else (unparsable, or neither chained nor self-signed) is
//     rejected.
//
// The server must set ClientAuth: tls.RequireAnyClientCert (not
// RequireAndVerifyClientCert) so Go's own default chain verification --
// which would reject a self-signed certificate before this callback ever
// runs -- is not performed; this callback is the sole verifier.
func (ca *CA) ClientCertVerifier(revocation RevocationChecker) func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("pki: no client certificate presented")
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("pki: parse client certificate: %w", err)
		}
		now := time.Now()
		if ca.ChainVerified(cert, now) {
			providerID, idOK := IdentityFromCertificate(cert)
			if !idOK {
				return fmt.Errorf("pki: CA-chained certificate has no bound provider identity")
			}
			if revocation != nil {
				// Fail closed: ADR-027 leaves the "revocation store
				// unavailable" case unresolved, and this is the trust
				// boundary between every Agent and the Control Plane, so a
				// Redis outage rejects new handshakes rather than risk
				// admitting a revoked provider. This does mean a Redis
				// outage temporarily blocks all new mTLS connections
				// system-wide -- a deliberate availability-for-security
				// trade-off, called out in the implementing PR, not an
				// oversight.
				revoked, revErr := revocation.IsRevoked(context.Background(), providerID)
				if revErr != nil {
					slog.Warn("pki: revocation check unavailable during handshake; rejecting", "provider_id", providerID, "error", revErr)
					return fmt.Errorf("pki: revocation status unavailable for provider %s", providerID)
				}
				if revoked {
					return fmt.Errorf("pki: provider %s is revoked", providerID)
				}
			}
			return nil
		}
		if IsSelfSigned(cert) {
			return nil
		}
		return fmt.Errorf("pki: client certificate is neither Control-Plane-issued nor a well-formed self-signed bootstrap certificate")
	}
}

// ServerTLSConfig builds the *tls.Config for the Control Plane's gRPC
// listener: serverCert is the Control Plane's own long-lived identity
// (unchanged by ADR-027, still generated the way
// deployments/scripts/generate-dev-certs.sh's server.crt/server.key are
// today); ca is the same CA used for leaf issuance, doubling here as the
// client verifier; revocation may be nil only in tests that don't exercise
// revocation.
func ServerTLSConfig(serverCert tls.Certificate, ca *CA, revocation RevocationChecker) *tls.Config {
	return &tls.Config{
		MinVersion:            tls.VersionTLS13,
		Certificates:          []tls.Certificate{serverCert},
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: ca.ClientCertVerifier(revocation),
	}
}
