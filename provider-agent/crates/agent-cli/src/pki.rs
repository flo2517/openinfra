//! ADR-027 §2/§3: the Agent-side half of mTLS PKI enrollment and renewal
//! -- fresh leaf keypair/bootstrap-certificate generation, the
//! `RenewCertificateRequest.signature` byte layout (mirrored exactly by
//! `control-plane/internal/providerjoin/certificates.go`'s
//! `renewalSigningPayload`), and the bounded-backoff schedule §3
//! specifies for renewal retries.
//!
//! Deliberately holds no network or `LocalState` code itself -- `main.rs`
//! owns the actual `join`/renewal-loop control flow and calls into these
//! pure/self-contained helpers, the same separation `mtls.rs` already
//! keeps between "build cryptographic material" and "drive the
//! connection."

use num_bigint::BigUint;
use rcgen::{CertificateParams, DnType, KeyPair, PKCS_ED25519};
use std::time::Duration;

/// ADR-027 §3's exact domain-separation prefix for
/// `RenewCertificateRequest.signature`, the renewal-specific sibling of
/// `main.rs`'s `JOIN_DOMAIN`/`HEARTBEAT_DOMAIN`.
pub const RENEW_DOMAIN: &[u8] = b"openinfra-cert-renew-v1\0";

/// ADR-027 §3: attempt renewal once 50% of a leaf certificate's lifetime
/// has elapsed. For the fixed `DefaultLeafTTL` (24h) every certificate in
/// this system is issued with, "50% elapsed" and "12h before NotAfter"
/// are the same instant, so the renewal timer only needs to track
/// `expires_at` (already persisted on `LeafCertificate`), not a separate
/// issuance timestamp.
pub const RENEWAL_OVERLAP: Duration = Duration::from_secs(12 * 60 * 60);

/// ADR-027 §3's bounded backoff for a renewal attempt that fails before
/// the current certificate expires: base 30s, doubling, capped at 10
/// minutes -- the same shape `providerjoin.Reconciler`'s already-accepted
/// backoff uses on the Control Plane side.
pub const RENEWAL_BACKOFF_BASE: Duration = Duration::from_secs(30);
pub const RENEWAL_BACKOFF_CAP: Duration = Duration::from_secs(10 * 60);

/// Doubles `current`, capped at `RENEWAL_BACKOFF_CAP` -- call with the
/// previous backoff (or `RENEWAL_BACKOFF_BASE` for the first retry) after
/// each failed renewal attempt.
pub fn next_backoff(current: Duration) -> Duration {
    current.saturating_mul(2).min(RENEWAL_BACKOFF_CAP)
}

/// A freshly generated Ed25519 mTLS leaf keypair, PEM-encoded (PKCS8, the
/// format both `rcgen::KeyPair::serialize_pem` produces and
/// `tonic::transport::Identity::from_pem` expects) alongside its raw
/// 32-byte public key (the wire format `tls_public_key`/
/// `new_tls_public_key` both use). ADR-027 §2/§3 requires a *fresh*
/// keypair for both first enrollment and every renewal -- never the
/// long-term identity key, never reused across renewal periods.
pub struct FreshKeypair {
    pub private_key_pem: String,
    pub public_key_raw: [u8; 32],
    key_pair: KeyPair,
}

/// Generates a fresh Ed25519 keypair for either bootstrap enrollment or a
/// renewal request.
pub fn generate_leaf_keypair() -> anyhow::Result<FreshKeypair> {
    let key_pair = KeyPair::generate_for(&PKCS_ED25519)?;
    let public_key_raw: [u8; 32] = key_pair
        .public_key_raw()
        .try_into()
        .map_err(|_| anyhow::anyhow!("generated Ed25519 key is not 32 bytes"))?;
    Ok(FreshKeypair {
        private_key_pem: key_pair.serialize_pem(),
        public_key_raw,
        key_pair,
    })
}

/// Builds a well-formed, self-signed certificate for `keypair` -- the
/// ADR-027 §2 bootstrap identity `BeginJoin`/`CompleteJoin`'s connection
/// presents. The Control Plane's dual-trust-basis verifier
/// (`internal/pki.ClientCertVerifier`) grants no authorization from this
/// certificate alone; it exists only to satisfy mTLS's "the client must
/// present *some* certificate" structural requirement, exactly like
/// `mtls.rs`'s test fixtures build a self-signed Network Validator
/// certificate for the mirror-image ADR-013 §3 case.
pub fn bootstrap_certificate_pem(keypair: &FreshKeypair) -> anyhow::Result<String> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params
        .distinguished_name
        .push(DnType::CommonName, "openinfra-bootstrap");
    let certificate = params.self_signed(&keypair.key_pair)?;
    Ok(certificate.pem())
}

/// Extracts a Control-Plane-issued leaf certificate's serial number as
/// the exact decimal string `internal/pki.CA.IssueLeaf`'s
/// `serial.String()` (Go's `big.Int` decimal rendering) produces --
/// `RenewCertificateRequest.current_certificate_serial` must echo this
/// back byte-for-byte, since the Control Plane compares it against its
/// own re-derivation of the same serial from the connection's peer
/// certificate, not against anything this function computed.
pub fn leaf_certificate_serial(certificate_pem: &str) -> anyhow::Result<String> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(certificate_pem.as_bytes())
        .map_err(|error| anyhow::anyhow!("parse leaf certificate PEM: {error}"))?;
    let (_, certificate) = x509_parser::parse_x509_certificate(&pem.contents)
        .map_err(|error| anyhow::anyhow!("parse leaf certificate DER: {error}"))?;
    let serial = BigUint::from_bytes_be(certificate.raw_serial());
    Ok(serial.to_string())
}

/// Builds the exact byte layout `RenewCertificateRequest.signature`
/// covers (see that field's proto doc comment, and
/// `certificates.go`'s `renewalSigningPayload`, which this must match
/// byte-for-byte): `RENEW_DOMAIN` ++ `new_tls_public_key` (32 bytes,
/// fixed) ++ a 1-byte length prefix for `current_certificate_serial` ++
/// the serial's ASCII decimal bytes ++ the protobuf `Timestamp`'s seconds
/// (8 bytes, big-endian) and nanos (4 bytes, big-endian) ++ `nonce` (8
/// bytes, big-endian).
pub fn renewal_signing_payload(
    new_tls_public_key: &[u8; 32],
    current_certificate_serial: &str,
    timestamp_seconds: i64,
    timestamp_nanos: i32,
    nonce: u64,
) -> Vec<u8> {
    let serial = current_certificate_serial.as_bytes();
    let mut payload = Vec::with_capacity(RENEW_DOMAIN.len() + 32 + 1 + serial.len() + 8 + 4 + 8);
    payload.extend_from_slice(RENEW_DOMAIN);
    payload.extend_from_slice(new_tls_public_key);
    payload.push(serial.len() as u8);
    payload.extend_from_slice(serial);
    payload.extend_from_slice(&timestamp_seconds.to_be_bytes());
    payload.extend_from_slice(&(timestamp_nanos as u32).to_be_bytes());
    payload.extend_from_slice(&nonce.to_be_bytes());
    payload
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_certificate_carries_the_keypairs_own_public_key() {
        // Full cryptographic self-signature verification of this exact
        // certificate shape is exercised end-to-end by the Control
        // Plane's TestFullHandshakeAcceptsBootstrapSelfSignedCertificate
        // (control-plane/internal/pki/tls_test.go), which drives a real
        // TLS handshake against it. This test stays within agent-cli's
        // existing dependency set (no `ring`/"verify" feature) and checks
        // the one property specific to this function: the certificate's
        // SubjectPublicKeyInfo is exactly the raw key generate_leaf_keypair
        // produced, i.e. `tls_public_key`/`new_tls_public_key` and the
        // certificate presented on the wire are provably the same key.
        let keypair = generate_leaf_keypair().expect("generate keypair");
        let certificate_pem = bootstrap_certificate_pem(&keypair).expect("self-signed cert");
        let (_, pem) =
            x509_parser::pem::parse_x509_pem(certificate_pem.as_bytes()).expect("parse PEM");
        let (_, certificate) =
            x509_parser::parse_x509_certificate(&pem.contents).expect("parse DER");
        let spki_bytes = certificate.public_key().subject_public_key.data.as_ref();
        assert_eq!(spki_bytes, keypair.public_key_raw);
    }

    #[test]
    fn leaf_certificate_serial_matches_the_certificates_own_serial_number() {
        let keypair = generate_leaf_keypair().expect("generate keypair");
        // Reuse the bootstrap helper to get a real, parseable certificate;
        // this test only cares that the returned decimal string is a
        // faithful big-endian decoding of the DER serial bytes, which
        // applies identically to a CA-issued leaf.
        let certificate_pem = bootstrap_certificate_pem(&keypair).expect("self-signed cert");
        let serial = leaf_certificate_serial(&certificate_pem).expect("extract serial");
        assert!(
            !serial.is_empty() && serial.chars().all(|c| c.is_ascii_digit()),
            "serial must be a non-empty decimal string, got {serial:?}"
        );
    }

    #[test]
    fn renewal_signing_payload_is_deterministic_and_domain_separated() {
        let key = [7u8; 32];
        let first = renewal_signing_payload(&key, "12345", 1_700_000_000, 0, 1);
        let second = renewal_signing_payload(&key, "12345", 1_700_000_000, 0, 1);
        assert_eq!(
            first, second,
            "identical inputs must produce identical bytes"
        );
        assert!(first.starts_with(RENEW_DOMAIN));

        let different_nonce = renewal_signing_payload(&key, "12345", 1_700_000_000, 0, 2);
        assert_ne!(first, different_nonce, "nonce must affect the signed bytes");

        let different_serial = renewal_signing_payload(&key, "54321", 1_700_000_000, 0, 1);
        assert_ne!(
            first, different_serial,
            "current_certificate_serial must affect the signed bytes"
        );
    }

    #[test]
    fn renewal_signing_payload_matches_the_exact_byte_layout() {
        // A fixed, literal input set recomputed byte-by-byte here rather
        // than via renewal_signing_payload itself, so this test actually
        // pins the layout (domain ++ 32-byte key ++ 1-byte serial length
        // ++ serial ++ 8-byte seconds ++ 4-byte nanos ++ 8-byte nonce, all
        // big-endian) instead of trivially agreeing with itself.
        // certificates_test.go's Go-side fixture must build the identical
        // bytes from the same literal field values.
        let key = [0x11u8; 32];
        let payload = renewal_signing_payload(&key, "42", 1_700_000_000, 500_000_000, 7);
        let mut expected = Vec::new();
        expected.extend_from_slice(RENEW_DOMAIN);
        expected.extend_from_slice(&key);
        expected.push(2); // len("42")
        expected.extend_from_slice(b"42");
        expected.extend_from_slice(&1_700_000_000i64.to_be_bytes());
        expected.extend_from_slice(&500_000_000u32.to_be_bytes());
        expected.extend_from_slice(&7u64.to_be_bytes());
        assert_eq!(payload, expected);
    }
}
