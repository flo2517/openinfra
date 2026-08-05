use crate::errors::IdentityError;
use async_trait::async_trait;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

#[async_trait]
pub trait IdentityManager: Send + Sync {
    async fn get_public_key(&self) -> Result<String, IdentityError>;
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, IdentityError>;
    async fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool, IdentityError>;
}

pub struct Ed25519IdentityManager {
    signing_key: SigningKey,
}

impl Ed25519IdentityManager {
    pub fn new(key_path: PathBuf) -> Result<Self, IdentityError> {
        if key_path.exists() {
            let key_data = fs::read(&key_path).map_err(|_| IdentityError::KeyNotFound)?;
            let signing_key = SigningKey::from_bytes(
                key_data
                    .as_slice()
                    .try_into()
                    .map_err(|_| IdentityError::InvalidKey)?,
            );
            Ok(Self { signing_key })
        } else {
            Err(IdentityError::KeyNotFound)
        }
    }

    pub fn generate(key_path: PathBuf) -> Result<Self, IdentityError> {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let bytes = signing_key.to_bytes();
        write_private_key(&key_path, &bytes)?;

        Ok(Self { signing_key })
    }
}

#[cfg(unix)]
fn write_private_key(path: &PathBuf, bytes: &[u8]) -> Result<(), IdentityError> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| IdentityError::KeyGenFailure)?;
    file.write_all(bytes)
        .map_err(|_| IdentityError::KeyGenFailure)
}

#[cfg(not(unix))]
fn write_private_key(path: &PathBuf, bytes: &[u8]) -> Result<(), IdentityError> {
    fs::write(path, bytes).map_err(|_| IdentityError::KeyGenFailure)
}

#[async_trait]
impl IdentityManager for Ed25519IdentityManager {
    async fn get_public_key(&self) -> Result<String, IdentityError> {
        let verifying_key = VerifyingKey::from(&self.signing_key);
        Ok(hex::encode(verifying_key.to_bytes()))
    }

    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, IdentityError> {
        let signature = self.signing_key.sign(message);
        Ok(signature.to_bytes().to_vec())
    }

    async fn verify(
        &self,
        message: &[u8],
        signature_bytes: &[u8],
        public_key_bytes: &[u8],
    ) -> Result<bool, IdentityError> {
        let verifying_key = VerifyingKey::from_bytes(
            public_key_bytes
                .try_into()
                .map_err(|_| IdentityError::InvalidKey)?,
        )
        .map_err(|_| IdentityError::InvalidKey)?;

        let signature =
            Signature::from_slice(signature_bytes).map_err(|_| IdentityError::InvalidKey)?;

        Ok(verifying_key.verify(message, &signature).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn generated_identity_signs_and_verifies() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let key_path = directory.path().join("identity.key");
        let identity =
            Ed25519IdentityManager::generate(key_path.clone()).expect("generate identity");
        let signature = identity.sign(b"openinfra").await.expect("sign message");
        let key = fs::read(key_path).expect("read generated key");
        let signing_key = SigningKey::from_bytes(key.as_slice().try_into().expect("32-byte key"));

        assert!(identity
            .verify(
                b"openinfra",
                &signature,
                signing_key.verifying_key().as_bytes()
            )
            .await
            .expect("verify signature"));
        assert!(!identity
            .verify(
                b"different",
                &signature,
                signing_key.verifying_key().as_bytes()
            )
            .await
            .expect("reject mismatched message"));
    }
}
