#![allow(missing_docs)]

use crate::ffi::errors::FfiPubkyError;
use crate::ffi::types::FfiSessionInfo;
use crate::ffi::storage::FfiSessionStorage;
use crate::PubkySession as CoreSession;
use std::sync::Arc;

#[derive(uniffi::Object)]
pub struct FfiPubkySession {
    inner: Arc<tokio::sync::Mutex<CoreSession>>,
}

#[uniffi::export(async_runtime = "tokio")]
impl FfiPubkySession {
    pub fn info(&self) -> FfiSessionInfo {
        let inner = self.inner.blocking_lock();
        FfiSessionInfo::from(inner.info())
    }
    
    pub fn storage(&self) -> Arc<FfiSessionStorage> {
        Arc::new(FfiSessionStorage {
            session: self.inner.clone(),
        })
    }
    
    pub async fn signout(&self) -> Result<(), FfiPubkyError> {
        let session = self.inner.lock().await.clone();
        session.signout().await
            .map_err(|(e, _)| FfiPubkyError::from(e))?;
        Ok(())
    }
}

impl FfiPubkySession {
    pub fn new(session: CoreSession) -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::new(tokio::sync::Mutex::new(session)),
        })
    }
}

