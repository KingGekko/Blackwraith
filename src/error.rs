use thiserror::Error;

#[derive(Error, Debug)]
pub enum BlackWraithError {
    #[error("Network error: {0}")]
    Network(String),
    #[error("HTTP error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("DNS resolution error: {0}")]
    Dns(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("Permission denied – are you root?")]
    Permission,
    #[error("RF interface error: {0}")]
    Rf(String),
    #[error("Numerical error: {0}")]
    Numerics(String),
    #[error("Hypervisor detection failed: {0}")]
    Hypervisor(String),
    #[error("Adversarial module error: {0}")]
    Adversarial(String),
    #[error("Manifold computation failed: {0}")]
    Manifold(String),
    #[error("Semaphore acquire error: {0}")]
    Semaphore(#[from] tokio::sync::AcquireError),
    #[error("Timeout: {0}")]
    Timeout(#[from] tokio::time::error::Elapsed),
    #[error("Task join error: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("Regex error: {0}")]
    Regex(#[from] regex::Error),
    #[error("Internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, BlackWraithError>;