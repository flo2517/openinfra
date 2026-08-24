//! ADR-033 §4: VM boot images (qcow2 by convention) are fetched over
//! HTTPS and verified against a pinned SHA-256 digest **before** any
//! caller ever gets a path back to boot from -- the same "never run
//! before the artifact matches what was promised" discipline
//! issue #154/#155 already established for Docker image pulls, applied
//! to the necessarily different (no OCI registry concept for a raw disk
//! image) VM transport.
//!
//! Testability: a real HTTPS fetch needs network access no unit test
//! should depend on, so the fetch itself is behind an injectable
//! `ImageFetcher` trait -- the same `CommandRunner`/`KvmProbe` pattern
//! this codebase already uses for "this needs a real external resource".
//! `fetch_and_verify_image`'s digest-mismatch rejection is fully
//! unit-tested against a `FakeImageFetcher` with canned, wrong-digest
//! bytes -- see this module's tests.

use crate::ExecutorError;
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Fetches a VM boot image's raw bytes from `url`. `HttpsImageFetcher` is
/// the real implementation (reqwest, rustls); tests substitute a
/// `FakeImageFetcher` with canned bytes, never touching the network.
#[async_trait]
pub trait ImageFetcher: Send + Sync {
    async fn fetch(&self, url: &str) -> Result<Vec<u8>, ExecutorError>;
}

pub struct HttpsImageFetcher {
    client: reqwest::Client,
}

impl HttpsImageFetcher {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

impl Default for HttpsImageFetcher {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ImageFetcher for HttpsImageFetcher {
    async fn fetch(&self, url: &str) -> Result<Vec<u8>, ExecutorError> {
        let response =
            self.client.get(url).send().await.map_err(|error| {
                ExecutorError::Engine(format!("fetching VM image {url}: {error}"))
            })?;
        if !response.status().is_success() {
            return Err(ExecutorError::Engine(format!(
                "fetching VM image {url}: HTTP {}",
                response.status()
            )));
        }
        let bytes = response.bytes().await.map_err(|error| {
            ExecutorError::Engine(format!("reading VM image body for {url}: {error}"))
        })?;
        Ok(bytes.to_vec())
    }
}

/// `vm_image_sha256` must be exactly 64 lowercase hex characters --
/// matching `workloadapi.digestImage`'s `name@sha256:<64 hex>`
/// convention on the wire (lowercase only, no ambiguity between two
/// textually-different-but-semantically-equal digest strings).
pub fn validate_sha256_hex(digest_hex: &str) -> Result<(), ExecutorError> {
    if digest_hex.len() != 64
        || !digest_hex.bytes().all(|byte| byte.is_ascii_hexdigit())
        || digest_hex.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(ExecutorError::InvalidRequest(
            "vm_image_sha256 must be exactly 64 lowercase hex characters".to_string(),
        ));
    }
    Ok(())
}

/// Fetches `url` (which must be `https://`) and verifies its SHA-256
/// digest matches `expected_sha256_hex` **before** this function ever
/// returns a path a caller could boot from -- the digest is computed
/// against the fetched bytes in memory first; nothing is written to the
/// content-addressed cache at all on a mismatch, so a wrong-digest fetch
/// can never leave a partially-trusted artifact behind.
///
/// Content-addressed caching (ADR-033 §4): `cache_dir/<digest>.qcow2` is
/// trusted and returned without a re-fetch if it already exists -- its
/// filename *is* its already-verified digest, so a repeated deploy of
/// the same digest never re-downloads. A fresh fetch is written via a
/// temp-file-then-rename so a crash mid-write can never leave a
/// half-written file sitting at the final, trusted cache path.
pub async fn fetch_and_verify_image(
    fetcher: &dyn ImageFetcher,
    cache_dir: &Path,
    url: &str,
    expected_sha256_hex: &str,
) -> Result<PathBuf, ExecutorError> {
    validate_sha256_hex(expected_sha256_hex)?;
    if !url.starts_with("https://") {
        return Err(ExecutorError::InvalidRequest(
            "vm_image_url must use https://".to_string(),
        ));
    }
    let cached_path = cache_dir.join(format!("{expected_sha256_hex}.qcow2"));
    if cached_path.exists() {
        return Ok(cached_path);
    }
    let bytes = fetcher.fetch(url).await?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let actual_hex = hex::encode(<[u8; 32]>::from(hasher.finalize()));
    if actual_hex != expected_sha256_hex {
        return Err(ExecutorError::InvalidRequest(format!(
            "VM image digest mismatch for {url}: expected {expected_sha256_hex}, got {actual_hex}"
        )));
    }
    std::fs::create_dir_all(cache_dir)
        .map_err(|error| ExecutorError::Engine(format!("creating VM image cache dir: {error}")))?;
    let temp_path = cache_dir.join(format!(
        "{expected_sha256_hex}.qcow2.tmp-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::write(&temp_path, &bytes)
        .map_err(|error| ExecutorError::Engine(format!("writing fetched VM image: {error}")))?;
    std::fs::rename(&temp_path, &cached_path).map_err(|error| {
        ExecutorError::Engine(format!("finalizing fetched VM image cache entry: {error}"))
    })?;
    Ok(cached_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    struct FakeImageFetcher {
        bytes: Vec<u8>,
        calls: StdMutex<Vec<String>>,
    }

    impl FakeImageFetcher {
        fn returning(bytes: Vec<u8>) -> Self {
            Self {
                bytes,
                calls: StdMutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl ImageFetcher for FakeImageFetcher {
        async fn fetch(&self, url: &str) -> Result<Vec<u8>, ExecutorError> {
            self.calls.lock().expect("calls lock").push(url.to_string());
            Ok(self.bytes.clone())
        }
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hex::encode(<[u8; 32]>::from(hasher.finalize()))
    }

    #[tokio::test]
    async fn fetches_and_caches_an_image_whose_digest_matches() {
        let directory = tempfile::tempdir().expect("dir");
        let bytes = b"a fake qcow2 image".to_vec();
        let digest = sha256_hex(&bytes);
        let fetcher = FakeImageFetcher::returning(bytes.clone());

        let path = fetch_and_verify_image(
            &fetcher,
            directory.path(),
            "https://example.com/image.qcow2",
            &digest,
        )
        .await
        .expect("verified fetch");

        assert_eq!(std::fs::read(&path).expect("read cached image"), bytes);
        assert_eq!(fetcher.calls.lock().expect("calls").len(), 1);

        // Second call for the same digest must be served from the
        // content-addressed cache, not re-fetched.
        let second = fetch_and_verify_image(
            &fetcher,
            directory.path(),
            "https://example.com/image.qcow2",
            &digest,
        )
        .await
        .expect("cached fetch");
        assert_eq!(second, path);
        assert_eq!(
            fetcher.calls.lock().expect("calls").len(),
            1,
            "a cached digest must never be re-fetched"
        );
    }

    #[tokio::test]
    async fn rejects_a_mismatched_digest_before_writing_anything_to_the_cache() {
        let directory = tempfile::tempdir().expect("dir");
        let fetcher = FakeImageFetcher::returning(b"actual bytes".to_vec());
        let wrong_digest = sha256_hex(b"a completely different image");

        let result = fetch_and_verify_image(
            &fetcher,
            directory.path(),
            "https://example.com/image.qcow2",
            &wrong_digest,
        )
        .await;

        assert!(result.is_err(), "a mismatched digest must be rejected");
        assert!(
            std::fs::read_dir(directory.path())
                .expect("read cache dir")
                .next()
                .is_none(),
            "a rejected image must leave nothing behind in the cache dir -- \
             confirms verification happens before any boot-relevant artifact exists on disk"
        );
    }

    #[tokio::test]
    async fn rejects_a_non_https_url_without_ever_calling_the_fetcher() {
        let directory = tempfile::tempdir().expect("dir");
        let fetcher = FakeImageFetcher::returning(b"irrelevant".to_vec());

        let result = fetch_and_verify_image(
            &fetcher,
            directory.path(),
            "http://example.com/image.qcow2",
            &sha256_hex(b"irrelevant"),
        )
        .await;

        assert!(result.is_err());
        assert!(
            fetcher.calls.lock().expect("calls").is_empty(),
            "a non-https URL must be rejected before ever fetching"
        );
    }

    #[test]
    fn validate_sha256_hex_rejects_wrong_length_and_uppercase() {
        assert!(validate_sha256_hex(&"a".repeat(64)).is_ok());
        assert!(validate_sha256_hex(&"a".repeat(63)).is_err());
        assert!(validate_sha256_hex(&"A".repeat(64)).is_err());
        assert!(validate_sha256_hex("not-hex-at-all").is_err());
    }
}
