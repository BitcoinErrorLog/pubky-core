#![allow(missing_docs)]

use crate::ffi::errors::FfiPubkyError;
use crate::ffi::types::{FfiKeyProvider, FfiSignupOptions, FfiAuthFlowInfo};
use crate::ffi::session::FfiPubkySession;
use crate::{Pubky, Capabilities, AuthFlowKind};
use pkarr::{Keypair, PublicKey};
use std::sync::Arc;
use std::collections::HashMap;

#[derive(uniffi::Object)]
pub struct FfiSdk {
    inner: Arc<Pubky>,
    pending_auth_flows: Arc<tokio::sync::Mutex<HashMap<String, crate::PubkyAuthFlow>>>,
}

#[uniffi::export(async_runtime = "tokio")]
impl FfiSdk {
    #[uniffi::constructor]
    pub fn new() -> Result<Arc<Self>, FfiPubkyError> {
        let pubky = Pubky::new()
            .map_err(FfiPubkyError::from)?;
        
        Ok(Arc::new(Self {
            inner: Arc::new(pubky),
            pending_auth_flows: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }))
    }
    
    pub async fn signin(
        &self,
        key_provider: Arc<dyn FfiKeyProvider>,
        homeserver: String,
    ) -> Result<Arc<FfiPubkySession>, FfiPubkyError> {
        let secret_key_bytes = key_provider.secret_key()?;
        
        if secret_key_bytes.len() != 32 {
            return Err(FfiPubkyError::InvalidInput {
                message: "Secret key must be 32 bytes".to_string(),
            });
        }
        
        let mut secret_key = [0u8; 32];
        secret_key.copy_from_slice(&secret_key_bytes);
        
        let keypair = Keypair::from_secret_key(&secret_key);
        
        let signer = self.inner.signer(keypair);
        let session = signer.signin().await
            .map_err(FfiPubkyError::from)?;
        
        Ok(FfiPubkySession::new(session))
    }
    
    pub async fn signup(
        &self,
        key_provider: Arc<dyn FfiKeyProvider>,
        homeserver: String,
        options: Option<FfiSignupOptions>,
    ) -> Result<Arc<FfiPubkySession>, FfiPubkyError> {
        let secret_key_bytes = key_provider.secret_key()?;
        
        if secret_key_bytes.len() != 32 {
            return Err(FfiPubkyError::InvalidInput {
                message: "Secret key must be 32 bytes".to_string(),
            });
        }
        
        let mut secret_key = [0u8; 32];
        secret_key.copy_from_slice(&secret_key_bytes);
        
        let keypair = Keypair::from_secret_key(&secret_key);
        
        let homeserver_pk = PublicKey::try_from(homeserver.as_str())
            .map_err(|e| FfiPubkyError::InvalidInput {
                message: format!("Invalid homeserver public key: {}", e),
            })?;
        
        let signer = self.inner.signer(keypair);
        
        let signup_token_str = options.and_then(|o| o.signup_token).map(|t| t.to_string());
        
        let session = signer.signup(&homeserver_pk, signup_token_str.as_deref()).await
            .map_err(FfiPubkyError::from)?;
        
        Ok(FfiPubkySession::new(session))
    }
    
    pub fn start_auth_flow(&self, capabilities: Vec<String>) -> Result<FfiAuthFlowInfo, FfiPubkyError> {
        let mut caps_builder = Capabilities::builder();
        
        for cap in capabilities {
            caps_builder = caps_builder.write(&cap);
        }
        
        let caps = caps_builder.finish();
        
        let flow = self.inner.start_auth_flow(&caps, AuthFlowKind::SignIn)
            .map_err(FfiPubkyError::from)?;
        
        let auth_url = flow.authorization_url().to_string();
        
        // Use the auth URL as request_id for simplicity (contains unique client_secret)
        let request_id = auth_url.clone();
        
        let mut pending = self.pending_auth_flows.blocking_lock();
        pending.insert(request_id.clone(), flow);
        
        Ok(FfiAuthFlowInfo {
            authorization_url: auth_url,
            request_id,
        })
    }
    
    pub async fn await_approval(&self, request_id: String) -> Result<Arc<FfiPubkySession>, FfiPubkyError> {
        let flow = {
            let mut pending = self.pending_auth_flows.lock().await;
            pending.remove(&request_id)
                .ok_or_else(|| FfiPubkyError::InvalidInput {
                    message: "Invalid or expired request_id".to_string(),
                })?
        };
        
        let session = flow.await_approval().await
            .map_err(FfiPubkyError::from)?;
        
        Ok(FfiPubkySession::new(session))
    }
    
    pub fn public_storage(&self) -> Arc<crate::ffi::storage::FfiPublicStorage> {
        let storage = self.inner.public_storage();
        crate::ffi::storage::FfiPublicStorage::new(storage)
    }
}

