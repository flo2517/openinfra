//! Second mTLS client class for the Agent's gRPC server (ADR-013 §3).
//!
//! Before this module, the Agent trusted exactly one thing: a client
//! certificate chaining to the Control Plane's CA
//! (`tonic::transport::ServerTlsConfig::client_ca_root`). ADR-013 adds a
//! second, independent trust basis: a client certificate is also accepted
//! if its raw Ed25519 public key is in the most recently
//! `ReportHeartbeat`-pushed Network Validator allowlist, even though that
//! certificate is self-signed and never chains to the Control Plane's CA
//! (ADR-011 §2's explicit no-separate-validator-PKI decision).
//!
//! `tonic::transport::ServerTlsConfig` has no hook to plug in a custom
//! `rustls::server::ClientCertVerifier` -- it always builds one of
//! rustls's two fixed verifiers
//! (`AllowAnyAuthenticatedClient`/`AllowAnyAnonymousOrAuthenticatedClient`)
//! internally from a single CA `Certificate`
//! (see the vendored `tonic-0.10.2/src/transport/service/tls.rs`, which is
//! not part of tonic's public API). So this module drops one layer lower:
//! it builds a `rustls::ServerConfig` by hand with a custom verifier, then
//! feeds `tokio_rustls::TlsAcceptor`-wrapped connections into
//! `tonic::transport::Server::serve_with_incoming`, tonic's public escape
//! hatch for exactly this case. `tokio_rustls::server::TlsStream<T>`
//! already implements tonic's `Connected` trait (`tonic`'s "tls" feature
//! provides a blanket impl for the very type `tokio_rustls::TlsAcceptor`
//! produces), so no adapter type is needed to satisfy
//! `serve_with_incoming`'s bounds.

use rustls::server::{AllowAnyAuthenticatedClient, ClientCertVerified, ClientCertVerifier};
use rustls::{Certificate, DistinguishedName, PrivateKey, RootCertStore};
use std::collections::HashSet;
use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::server::TlsStream;
use tokio_stream::wrappers::ReceiverStream;
use tracing::warn;

const ALPN_H2: &[u8] = b"h2";

/// The most recently `ReportHeartbeat`-pushed set of active Network
/// Validators' raw 32-byte Ed25519 public keys. `set` fully replaces the
/// previous contents rather than merging into it: a validator that drops
/// out of the active set on one heartbeat is no longer trusted by the very
/// next mTLS handshake evaluated after that heartbeat lands, matching
/// ADR-013's "refreshed every heartbeat" contract and the "expired
/// allowlist entry rejected" test both ADR-011 and ADR-013 call for.
#[derive(Clone, Default)]
pub struct ValidatorAllowlist {
    keys: Arc<RwLock<HashSet<[u8; 32]>>>,
}

impl ValidatorAllowlist {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&self, keys: impl IntoIterator<Item = [u8; 32]>) {
        let mut guard = self
            .keys
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = keys.into_iter().collect();
    }

    pub fn contains(&self, key: &[u8; 32]) -> bool {
        let guard = self
            .keys
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.contains(key)
    }
}

/// Accepts a client certificate under either trust basis ADR-013 §3
/// describes. `verify_client_cert` tries the unchanged Control-Plane-CA
/// chain check first; only on its failure does it fall back to an exact
/// raw-public-key match against `allowlist`. The fallback can only ever
/// *add* acceptance on top of the pre-existing CA path -- it never runs,
/// and can never override, a successful CA verification.
///
/// Signature verification (that the peer actually holds the private key
/// for the certificate it presented) is unaffected: `ClientCertVerifier`'s
/// default `verify_tls12_signature`/`verify_tls13_signature` (not
/// overridden here) validate the handshake signature against whatever
/// certificate was presented, independent of how that certificate's trust
/// was established. A validator cannot pass this verifier without a valid
/// signature over its self-signed certificate's own key, matching how a
/// Control-Plane-issued client can't either.
struct AllowlistClientCertVerifier {
    ca: AllowAnyAuthenticatedClient,
    allowlist: ValidatorAllowlist,
}

impl AllowlistClientCertVerifier {
    fn new(client_ca_roots: RootCertStore, allowlist: ValidatorAllowlist) -> Self {
        Self {
            ca: AllowAnyAuthenticatedClient::new(client_ca_roots),
            allowlist,
        }
    }
}

impl ClientCertVerifier for AllowlistClientCertVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn client_auth_root_subjects(&self) -> &[DistinguishedName] {
        self.ca.client_auth_root_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        now: SystemTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        if let Ok(verified) = self.ca.verify_client_cert(end_entity, intermediates, now) {
            return Ok(verified);
        }
        match extract_ed25519_raw_public_key(&end_entity.0) {
            Some(key) if self.allowlist.contains(&key) => Ok(ClientCertVerified::assertion()),
            _ => Err(rustls::Error::General(
                "client certificate is neither Control-Plane-issued nor an allowlisted Network Validator key"
                    .into(),
            )),
        }
    }
}

/// Parses `der` as an X.509 certificate and returns its raw 32-byte
/// Ed25519 public key, or `None` if it isn't an Ed25519 certificate or
/// fails to parse. A real ASN.1/X.509 parse (via `x509-parser`), not a
/// byte-offset heuristic: the extracted bytes gate the allowlist decision,
/// so extracting the wrong bytes here would be a real authorization bug,
/// not just a cosmetic one.
fn extract_ed25519_raw_public_key(der: &[u8]) -> Option<[u8; 32]> {
    let (_, certificate) = x509_parser::parse_x509_certificate(der).ok()?;
    let spki = certificate.public_key();
    if spki.algorithm.algorithm != x509_parser::oid_registry::OID_SIG_ED25519 {
        return None;
    }
    <[u8; 32]>::try_from(spki.subject_public_key.data.as_ref()).ok()
}

fn load_cert_chain(pem: &[u8]) -> anyhow::Result<Vec<Certificate>> {
    rustls_pemfile::certs(&mut Cursor::new(pem))
        .map(|certs| certs.into_iter().map(Certificate).collect())
        .map_err(|_| anyhow::anyhow!("invalid Agent TLS certificate PEM"))
}

fn load_private_key(pem: &[u8]) -> anyhow::Result<PrivateKey> {
    let mut cursor = Cursor::new(pem);
    loop {
        match rustls_pemfile::read_one(&mut cursor)? {
            Some(
                rustls_pemfile::Item::RSAKey(key)
                | rustls_pemfile::Item::PKCS8Key(key)
                | rustls_pemfile::Item::ECKey(key),
            ) => return Ok(PrivateKey(key)),
            Some(_) => continue,
            None => anyhow::bail!("no private key found in Agent TLS key PEM"),
        }
    }
}

fn load_root_store(pem: &[u8]) -> anyhow::Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    let parsed = rustls_pemfile::certs(&mut Cursor::new(pem))
        .map_err(|_| anyhow::anyhow!("invalid client CA PEM"))?;
    let (_, ignored) = roots.add_parsable_certificates(&parsed);
    if ignored != 0 {
        anyhow::bail!("client CA PEM contained unparsable certificates");
    }
    Ok(roots)
}

/// Builds the `rustls::ServerConfig` backing the Agent's mTLS listener:
/// server identity from `certificate_pem`/`private_key_pem`, and the dual
/// CA-chain-or-allowlisted-key client verifier described on
/// `AllowlistClientCertVerifier`. `allowlist` is a live handle -- the
/// caller updates it after each successful heartbeat, and every
/// subsequent handshake reads whatever is currently there.
pub fn build_server_config(
    certificate_pem: &[u8],
    private_key_pem: &[u8],
    client_ca_pem: &[u8],
    allowlist: ValidatorAllowlist,
) -> anyhow::Result<rustls::ServerConfig> {
    let cert_chain = load_cert_chain(certificate_pem)?;
    let private_key = load_private_key(private_key_pem)?;
    let roots = load_root_store(client_ca_pem)?;
    let verifier = Arc::new(AllowlistClientCertVerifier::new(roots, allowlist));
    let mut config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_client_cert_verifier(verifier)
        .with_single_cert(cert_chain, private_key)?;
    config.alpn_protocols.push(ALPN_H2.to_vec());
    Ok(config)
}

/// Binds `addr` and returns a stream of TLS-terminated connections ready
/// for `tonic::transport::Server::serve_with_incoming`. Each accepted TCP
/// connection's handshake runs on its own task so one slow or hostile
/// client can't stall new connections; a failed accept() or handshake is
/// logged and dropped, never forwarded through the stream -- yielding an
/// `Err` there would abort tonic's whole accept loop (see
/// `tonic-0.10.2/src/transport/server/incoming.rs`'s `try_stream!`, which
/// propagates the first `Err` with `?`), which one bad client must not be
/// able to trigger.
pub fn incoming(
    listener: TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
) -> ReceiverStream<Result<TlsStream<TcpStream>, std::io::Error>> {
    let (sender, receiver) = tokio::sync::mpsc::channel(64);
    tokio::spawn(async move {
        loop {
            let (stream, _peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(error) => {
                    warn!(%error, "mTLS listener accept failed");
                    continue;
                }
            };
            let acceptor = acceptor.clone();
            let sender = sender.clone();
            tokio::spawn(async move {
                match acceptor.accept(stream).await {
                    Ok(tls) => {
                        let _ = sender.send(Ok(tls)).await;
                    }
                    Err(error) => {
                        warn!(%error, "mTLS handshake rejected");
                    }
                }
            });
        }
    });
    ReceiverStream::new(receiver)
}

/// Convenience wrapper combining `build_server_config` and `incoming` the
/// way `handle_start`'s non-dev branch needs them.
pub async fn serve_incoming(
    addr: SocketAddr,
    certificate_pem: &[u8],
    private_key_pem: &[u8],
    client_ca_pem: &[u8],
    allowlist: ValidatorAllowlist,
) -> anyhow::Result<ReceiverStream<Result<TlsStream<TcpStream>, std::io::Error>>> {
    let config = build_server_config(certificate_pem, private_key_pem, client_ca_pem, allowlist)?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(addr).await?;
    Ok(incoming(listener, acceptor))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, PKCS_ED25519};
    use std::time::SystemTime;

    fn empty_params() -> CertificateParams {
        CertificateParams::new(Vec::<String>::new()).unwrap()
    }

    /// A minimal, self-contained PKI fixture: a CA, a client cert it
    /// issued (models the Control Plane's client cert), and an unrelated
    /// self-signed cert with its own known raw Ed25519 key (models a
    /// Network Validator's cert, per ADR-011 §2).
    struct Fixture {
        client_ca_pem: Vec<u8>,
        ca_issued_client_der: Vec<u8>,
        ca_issued_client_key_pem: Vec<u8>,
        self_signed_der: Vec<u8>,
        self_signed_raw_key: [u8; 32],
        server_cert_pem: Vec<u8>,
        server_key_pem: Vec<u8>,
    }

    fn build_fixture() -> Fixture {
        let ca_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let mut ca_params = empty_params();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "openinfra-test-ca");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let client_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let mut client_params = empty_params();
        client_params
            .distinguished_name
            .push(DnType::CommonName, "control-plane-client");
        let client_cert = client_params
            .signed_by(&client_key, &ca_cert, &ca_key)
            .unwrap();

        let validator_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let raw_key: [u8; 32] = validator_key.public_key_raw().try_into().unwrap();
        let mut validator_params = empty_params();
        validator_params
            .distinguished_name
            .push(DnType::CommonName, "network-validator");
        let validator_cert = validator_params.self_signed(&validator_key).unwrap();

        let server_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let server_params = CertificateParams::new(vec!["agent.local".to_string()]).unwrap();
        let server_cert = server_params.self_signed(&server_key).unwrap();

        Fixture {
            client_ca_pem: ca_cert.pem().into_bytes(),
            ca_issued_client_der: client_cert.der().to_vec(),
            ca_issued_client_key_pem: client_key.serialize_pem().into_bytes(),
            self_signed_der: validator_cert.der().to_vec(),
            self_signed_raw_key: raw_key,
            server_cert_pem: server_cert.pem().into_bytes(),
            server_key_pem: server_key.serialize_pem().into_bytes(),
        }
    }

    #[test]
    fn extracts_raw_key_from_self_signed_ed25519_certificate() {
        let fixture = build_fixture();
        let extracted = extract_ed25519_raw_public_key(&fixture.self_signed_der)
            .expect("Ed25519 SPKI should parse");
        assert_eq!(extracted, fixture.self_signed_raw_key);
    }

    #[test]
    fn ca_chained_certificate_is_accepted_without_allowlist_entry() {
        let fixture = build_fixture();
        let roots = load_root_store(&fixture.client_ca_pem).unwrap();
        let verifier =
            AllowlistClientCertVerifier::new(roots, ValidatorAllowlist::new() /* empty */);
        let end_entity = Certificate(fixture.ca_issued_client_der);
        let result = verifier.verify_client_cert(&end_entity, &[], SystemTime::now());
        assert!(
            result.is_ok(),
            "CA-chained certificate must still be accepted: {result:?}"
        );
    }

    #[test]
    fn allowlisted_self_signed_validator_key_is_accepted() {
        let fixture = build_fixture();
        let roots = load_root_store(&fixture.client_ca_pem).unwrap();
        let allowlist = ValidatorAllowlist::new();
        allowlist.set([fixture.self_signed_raw_key]);
        let verifier = AllowlistClientCertVerifier::new(roots, allowlist);
        let end_entity = Certificate(fixture.self_signed_der);
        let result = verifier.verify_client_cert(&end_entity, &[], SystemTime::now());
        assert!(
            result.is_ok(),
            "allowlisted validator key must be accepted: {result:?}"
        );
    }

    #[test]
    fn certificate_neither_ca_chained_nor_allowlisted_is_rejected() {
        let fixture = build_fixture();
        let roots = load_root_store(&fixture.client_ca_pem).unwrap();
        // Allowlist is non-empty but doesn't contain this certificate's key.
        let allowlist = ValidatorAllowlist::new();
        allowlist.set([[0xAA; 32]]);
        let verifier = AllowlistClientCertVerifier::new(roots, allowlist);
        let end_entity = Certificate(fixture.self_signed_der);
        let result = verifier.verify_client_cert(&end_entity, &[], SystemTime::now());
        assert!(
            result.is_err(),
            "neither CA-chained nor allowlisted certificate must be rejected"
        );
    }

    #[test]
    fn superseded_allowlist_entry_is_no_longer_accepted() {
        let fixture = build_fixture();
        let roots = load_root_store(&fixture.client_ca_pem).unwrap();
        let allowlist = ValidatorAllowlist::new();
        allowlist.set([fixture.self_signed_raw_key]);
        let verifier = AllowlistClientCertVerifier::new(roots, allowlist.clone());
        let end_entity = Certificate(fixture.self_signed_der.clone());

        // First handshake: this validator is active, so it's accepted.
        assert!(verifier
            .verify_client_cert(&end_entity, &[], SystemTime::now())
            .is_ok());

        // A newer heartbeat pushes a set that no longer includes this
        // validator (it dropped out of the active set) -- `set` fully
        // replaces, it doesn't merge.
        allowlist.set([[0xBB; 32]]);

        let result = verifier.verify_client_cert(&end_entity, &[], SystemTime::now());
        assert!(
            result.is_err(),
            "a superseded allowlist entry must no longer be accepted: {result:?}"
        );
    }

    #[test]
    fn build_server_config_succeeds_with_valid_pem_material() {
        let fixture = build_fixture();
        let config = build_server_config(
            &fixture.server_cert_pem,
            &fixture.server_key_pem,
            &fixture.client_ca_pem,
            ValidatorAllowlist::new(),
        );
        assert!(config.is_ok(), "server config build failed: {config:?}");
        assert_eq!(config.unwrap().alpn_protocols, vec![ALPN_H2.to_vec()]);
    }

    /// End-to-end sanity check that `build_server_config` + `incoming`'s
    /// `TlsAcceptor` actually complete a real TLS 1.3 handshake against a
    /// real client, on top of the focused `AllowlistClientCertVerifier`
    /// unit tests above (which already cover all four
    /// accept/reject/allowlist-supersession cases directly). This proves
    /// the plumbing (cert/key loading, ALPN, `serve_with_incoming`'s
    /// `TlsAcceptor` usage) works, not just the verifier logic in
    /// isolation.
    #[tokio::test]
    async fn full_handshake_accepts_ca_chained_client() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let fixture = build_fixture();

        let server_config = build_server_config(
            &fixture.server_cert_pem,
            &fixture.server_key_pem,
            &fixture.client_ca_pem,
            ValidatorAllowlist::new(),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            acceptor.accept(stream).await
        });

        let mut client_root_store = RootCertStore::empty();
        for cert in load_cert_chain(&fixture.server_cert_pem).unwrap() {
            client_root_store.add(&cert).unwrap();
        }
        let client_identity = Certificate(fixture.ca_issued_client_der);
        let client_key = load_private_key(&fixture.ca_issued_client_key_pem).unwrap();
        let client_config = tokio_rustls::rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(client_root_store)
            .with_client_auth_cert(vec![client_identity], client_key)
            .unwrap();
        let client_connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let tcp = TcpStream::connect(addr).await.unwrap();
        let server_name = "agent.local".try_into().unwrap();
        let mut client_stream = client_connector.connect(server_name, tcp).await.unwrap();
        client_stream.write_all(b"ping").await.unwrap();

        let mut server_stream = accept_task.await.unwrap().unwrap();
        let mut buffer = [0u8; 4];
        server_stream.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"ping");
    }
}
