use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("policy denied the operation: {0}")]
    PolicyDenied(String),
    #[error("authentication failed: {0}")]
    Authentication(String),
    #[error("cryptographic verification failed: {0}")]
    Crypto(String),
    #[error("bundle is expired")]
    Expired,
    #[error("bundle is not valid before {0}")]
    NotYetValid(String),
    #[error("replay protection rejected sequence {sequence} for {sender}")]
    Replay { sender: String, sequence: u64 },
    #[error("resource not found: {0}")]
    NotFound(String),
    #[error("unsafe path rejected: {0}")]
    UnsafePath(PathBuf),
    #[error("operation timed out after {0} seconds")]
    Timeout(u64),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("TOML decode error: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("internal protocol error: {0}")]
    Protocol(String),
}

pub type Result<T> = std::result::Result<T, Error>;
