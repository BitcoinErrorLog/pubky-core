#![allow(missing_docs)]

use pubky_common::session::SessionInfo as CoreSessionInfo;

#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiSessionInfo {
    pub pubkey: String,
    pub session_secret: Option<String>,
    pub capabilities: Vec<String>,
    pub created_at: u64,
    pub expires_at: Option<u64>,
}

impl From<&CoreSessionInfo> for FfiSessionInfo {
    fn from(info: &CoreSessionInfo) -> Self {
        let caps_vec: Vec<String> = info.capabilities()
            .iter()
            .map(|c| c.to_string())
            .collect();
        
        Self {
            pubkey: info.public_key().to_string(),
            session_secret: None, // Not exposed in pubky-common SessionInfo
            capabilities: caps_vec,
            created_at: info.created_at(),
            expires_at: None, // Not exposed in pubky-common SessionInfo
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiSignupOptions {
    pub capabilities: Option<Vec<String>>,
    pub signup_token: Option<u64>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiAuthFlowInfo {
    pub authorization_url: String,
    pub request_id: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiListItem {
    pub name: String,
    pub is_directory: bool,
}

#[uniffi::export(with_foreign)]
pub trait FfiKeyProvider: Send + Sync {
    fn secret_key(&self) -> Result<Vec<u8>, crate::ffi::errors::FfiPubkyError>;
}

