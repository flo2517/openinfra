use thiserror::Error;

#[derive(Error, Debug)]
pub enum AgentError {
    #[error("Identity error: {0}")]
    Identity(#[from] IdentityError),
    #[error("Storage error: {0}")]
    Storage(String),
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("Internal error: {0}")]
    Internal(String),
}

#[derive(Error, Debug)]
pub enum IdentityError {
    #[error("Key generation failed")]
    KeyGenFailure,
    #[error("Invalid key format")]
    InvalidKey,
    #[error("Key not found")]
    KeyNotFound,
    #[error("Signature failed")]
    SigningFailure,
    #[error("Verification failed")]
    VerificationFailure,
}
