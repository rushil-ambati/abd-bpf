use std::net::SocketAddr;

use thiserror::Error;

/// Main error type for ABD userspace operations
#[derive(Error, Debug)]
pub enum AbdError {
    /// Network-related errors
    #[error("Network error: {message}")]
    Network {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Protocol-related errors
    #[error("Protocol error: {message}")]
    Protocol {
        message: String,
        peer: Option<SocketAddr>,
    },

    /// Message serialization/deserialization errors
    #[error("Serialization error: {message}")]
    Serialization {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Configuration errors
    #[error("Configuration error: {message}")]
    Config { message: String },

    /// Timeout errors for operations
    #[error("Operation timed out: {operation:?} after {duration_ms}ms")]
    Timeout {
        operation: Operation,
        duration_ms: u64,
    },

    /// Node state errors
    #[error("Invalid node state: {message}")]
    InvalidState { message: String },

    /// I/O errors (wrapper for `std::io::Error`)
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Generic errors for unexpected conditions
    #[error("Internal error: {message}")]
    Internal { message: String },
}

/// Types of operations that can fail
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Read,
    Write,
    QueryPhase,
    PropagationPhase,
    ProxyWrite,
}

impl AbdError {
    pub fn network<E>(message: impl Into<String>, source: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self::Network {
            message: message.into(),
            source: Some(source.into()),
        }
    }
    pub fn network_msg(message: impl Into<String>) -> Self {
        Self::Network {
            message: message.into(),
            source: None,
        }
    }
    pub fn protocol(message: impl Into<String>, peer: Option<SocketAddr>) -> Self {
        Self::Protocol {
            message: message.into(),
            peer,
        }
    }
    pub fn serialization<E>(message: impl Into<String>, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Serialization {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }
    pub fn serialization_msg(message: impl Into<String>) -> Self {
        Self::Serialization {
            message: message.into(),
            source: None,
        }
    }
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config {
            message: message.into(),
        }
    }
    #[must_use]
    pub const fn timeout(operation: Operation, duration_ms: u64) -> Self {
        Self::Timeout {
            operation,
            duration_ms,
        }
    }
    pub fn invalid_state(message: impl Into<String>) -> Self {
        Self::InvalidState {
            message: message.into(),
        }
    }
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal {
            message: message.into(),
        }
    }
}

/// Result type alias for ABD operations
pub type Result<T, E = AbdError> = std::result::Result<T, E>;
