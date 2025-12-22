#![allow(missing_docs)]

use crate::errors::Error;
use uniffi::deps::anyhow;

#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum FfiPubkyError {
    #[error("Authentication error: {message}")]
    Auth { message: String },
    
    #[error("Request error: {message}")]
    Request { message: String },
    
    #[error("Build error: {message}")]
    Build { message: String },
    
    #[error("Invalid input: {message}")]
    InvalidInput { message: String },
    
    #[error("Network error: {message}")]
    Network { message: String },
    
    #[error("Unknown error: {message}")]
    Unknown { message: String },
}

impl From<Error> for FfiPubkyError {
    fn from(err: Error) -> Self {
        match err {
            Error::Authentication(_) => FfiPubkyError::Auth {
                message: err.to_string(),
            },
            Error::Request(_) => FfiPubkyError::Request {
                message: err.to_string(),
            },
            Error::Build(_) => FfiPubkyError::Build {
                message: err.to_string(),
            },
            Error::Parse(_) => FfiPubkyError::InvalidInput {
                message: err.to_string(),
            },
            Error::Pkarr(_) => FfiPubkyError::Network {
                message: err.to_string(),
            },
        }
    }
}

impl From<anyhow::Error> for FfiPubkyError {
    fn from(err: anyhow::Error) -> Self {
        FfiPubkyError::Unknown {
            message: err.to_string(),
        }
    }
}

