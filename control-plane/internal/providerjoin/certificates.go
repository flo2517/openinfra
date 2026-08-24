package providerjoin

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/openinfra/network/internal/pki"
	controlplanev1 "github.com/openinfra/network/protocol/generated/go/controlplane/v1"
	sharedv1 "github.com/openinfra/network/protocol/generated/go/shared/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// renewDomain is the exact domain-separation prefix ADR-027 §3 specifies
// for RenewCertificateRequest.signature, the renewal-specific sibling of
// service.go's joinDomain/heartbeatDomain.
const renewDomain = "openinfra-cert-renew-v1\x00"

// maxRenewalClockSkew mirrors maxHeartbeatClockSkew -- ADR-027 §3
// explicitly models RenewCertificateRequest.timestamp's replay-protection
// shape on ReportHeartbeat's observed_at/maxHeartbeatClockSkew convention,
// so this reuses the same tolerance rather than inventing a new number.
const maxRenewalClockSkew = maxHeartbeatClockSkew

var ErrRenewalReplay = errors.New("renewal nonce is not increasing")

// RenewalNonceStore enforces the nonce half of ADR-027 §3's
// timestamp+nonce replay-protection shape: nonce must strictly increase
// per provider, mirroring HeartbeatStore.Accept's sequence check. Unlike
// the heartbeat store, this holds no payload -- a renewal's authorization
// comes from the signature check plus the connection's own bound identity
// (see RenewCertificate), not from idempotent-retry payload matching.
type RenewalNonceStore interface {
	Accept(ctx context.Context, providerID string, nonce uint64) error
}

// RenewCertificate implements ADR-027 §3: issues a fresh leaf certificate
// for a provider that already holds one, reachable only over a connection
// currently authenticated with a still-valid, previously Control-Plane-
// issued leaf certificate -- never over the bootstrap self-signed path
// CompleteJoin uses for first enrollment. That "never over bootstrap"
// requirement, and the "must match the connection this request arrives
// on" requirement for current_certificate_serial, are both enforced here
// by reading the actual presented peer certificate off the connection
// (pki.PeerIdentity) rather than trusting anything the request body
// claims about itself.
func (s *Service) RenewCertificate(ctx context.Context, request *controlplanev1.RenewCertificateRequest) (*controlplanev1.RenewCertificateResponse, error) {
	if s.ca == nil {
		return nil, status.Error(codes.Unavailable, "certificate issuance is unavailable")
	}
	if s.renewalNonces == nil {
		return nil, status.Error(codes.Unavailable, "renewal replay protection is unavailable")
	}
	if err := validateRenewCertificate(request); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	peerProviderID, peerSerial, chainVerified, ok := pki.PeerIdentity(ctx, s.ca)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no client certificate identity on this connection")
	}
	if !chainVerified {
		return nil, status.Error(codes.Unauthenticated, "renewal requires a connection authenticated with a previously issued leaf certificate, not the bootstrap enrollment path")
	}
	if peerProviderID != request.ProviderId {
		return nil, status.Error(codes.Unauthenticated, "provider_id does not match this connection's certificate identity")
	}
	if peerSerial != request.CurrentCertificateSerial {
		return nil, status.Error(codes.Unauthenticated, "current_certificate_serial does not match this connection's certificate")
	}

	identity, err := s.repository.ProviderIdentity(ctx, request.ProviderId)
	if err != nil {
		return nil, repositoryError(err)
	}
	if identity.Status != sharedv1.NodeStatus_NODE_STATUS_ACTIVE {
		return nil, status.Error(codes.FailedPrecondition, "provider is not active")
	}

	now := s.now().UTC()
	if err := validateRenewalTimestamp(request.Timestamp, now); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	signed := renewalSigningPayload(request.NewTlsPublicKey, request.CurrentCertificateSerial, request.Timestamp, request.Nonce)
	if !ed25519.Verify(ed25519.PublicKey(identity.PublicKey), signed, request.Signature) {
		return nil, status.Error(codes.Unauthenticated, "invalid renewal signature")
	}
	if err := s.renewalNonces.Accept(ctx, request.ProviderId, request.Nonce); err != nil {
		if errors.Is(err, ErrRenewalReplay) {
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		}
		return nil, status.Error(codes.Internal, "renewal replay check failed")
	}

	issued, err := s.ca.IssueLeaf(request.ProviderId, ed25519.PublicKey(request.NewTlsPublicKey), now, pki.DefaultLeafTTL)
	if err != nil {
		return nil, status.Error(codes.Internal, "certificate issuance failed")
	}
	return &controlplanev1.RenewCertificateResponse{
		CertificatePem:       issued.CertificatePEM,
		CertificateExpiresAt: timestamppb.New(issued.ExpiresAt),
		CertificateSerial:    issued.Serial,
	}, nil
}

func validateRenewCertificate(request *controlplanev1.RenewCertificateRequest) error {
	if request == nil {
		return errors.New("request is required")
	}
	if _, err := uuid.Parse(request.RequestId); err != nil {
		return errors.New("request_id must be a UUID")
	}
	if len(request.ProviderId) != 64 {
		return errors.New("provider_id must be a 64-character hexadecimal identifier")
	}
	if len(request.NewTlsPublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("new_tls_public_key must be %d bytes", ed25519.PublicKeySize)
	}
	if request.CurrentCertificateSerial == "" {
		return errors.New("current_certificate_serial is required")
	}
	if request.Nonce == 0 {
		return errors.New("nonce must be positive")
	}
	if len(request.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("signature must be %d bytes", ed25519.SignatureSize)
	}
	if err := request.Timestamp.CheckValid(); err != nil {
		return errors.New("timestamp must be a valid timestamp")
	}
	return nil
}

func validateRenewalTimestamp(timestamp *timestamppb.Timestamp, now time.Time) error {
	signedAt := timestamp.AsTime()
	if signedAt.Before(now.Add(-maxRenewalClockSkew)) || signedAt.After(now.Add(maxRenewalClockSkew)) {
		return errors.New("timestamp is outside the allowed clock skew")
	}
	return nil
}

// renewalSigningPayload builds the exact byte layout
// RenewCertificateRequest.signature covers (see that field's proto doc
// comment): a domain prefix, then each field at either a fixed width or
// explicitly length-prefixed, so no two distinct sets of field values can
// ever concatenate to the same byte string. new_tls_public_key is always
// exactly 32 bytes (fixed, no prefix needed); current_certificate_serial
// is variable-length text, so it gets a 1-byte length prefix (a decimal
// big.Int serial is nowhere near the 255-byte ceiling that allows); the
// protobuf Timestamp is encoded as its own two fixed-width fields, exactly
// mirroring how prost/protobuf-go represent it, so both language
// implementations only need to agree on seconds/nanos, not on a shared
// serialization library.
func renewalSigningPayload(newTLSPublicKey []byte, currentCertificateSerial string, timestamp *timestamppb.Timestamp, nonce uint64) []byte {
	serial := []byte(currentCertificateSerial)
	payload := make([]byte, 0, len(renewDomain)+len(newTLSPublicKey)+1+len(serial)+8+4+8)
	payload = append(payload, []byte(renewDomain)...)
	payload = append(payload, newTLSPublicKey...)
	payload = append(payload, byte(len(serial)))
	payload = append(payload, serial...)
	var seconds [8]byte
	binary.BigEndian.PutUint64(seconds[:], uint64(timestamp.GetSeconds()))
	payload = append(payload, seconds[:]...)
	var nanos [4]byte
	binary.BigEndian.PutUint32(nanos[:], uint32(timestamp.GetNanos()))
	payload = append(payload, nanos[:]...)
	var nonceBytes [8]byte
	binary.BigEndian.PutUint64(nonceBytes[:], nonce)
	payload = append(payload, nonceBytes[:]...)
	return payload
}
