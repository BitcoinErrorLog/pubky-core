#![allow(missing_docs)]

use crate::ffi::errors::FfiPubkyError;
use crate::ffi::types::FfiListItem;
use crate::{PubkySession as CoreSession, PublicStorage as CorePublicStorage};
use std::sync::Arc;

#[derive(uniffi::Object)]
pub struct FfiSessionStorage {
    pub(crate) session: Arc<tokio::sync::Mutex<CoreSession>>,
}

#[uniffi::export(async_runtime = "tokio")]
impl FfiSessionStorage {
    pub async fn get(&self, path: String) -> Result<Vec<u8>, FfiPubkyError> {
        let session = self.session.lock().await;
        let storage = session.storage();
        
        let response = storage.get(path).await
            .map_err(FfiPubkyError::from)?;
        
        let bytes = response.bytes().await
            .map_err(|e| FfiPubkyError::Network { 
                message: e.to_string() 
            })?;
        
        Ok(bytes.to_vec())
    }
    
    pub async fn put(&self, path: String, content: Vec<u8>) -> Result<(), FfiPubkyError> {
        let session = self.session.lock().await;
        let storage = session.storage();
        
        storage.put(path, content).await
            .map_err(FfiPubkyError::from)?;
        
        Ok(())
    }
    
    pub async fn delete(&self, path: String) -> Result<(), FfiPubkyError> {
        let session = self.session.lock().await;
        let storage = session.storage();
        
        storage.delete(path).await
            .map_err(FfiPubkyError::from)?;
        
        Ok(())
    }
    
    pub async fn list(&self, path: String) -> Result<Vec<FfiListItem>, FfiPubkyError> {
        let session = self.session.lock().await;
        let storage = session.storage();
        
        let builder = storage.list(path)
            .map_err(FfiPubkyError::from)?;
        
        let resources = builder.send().await
            .map_err(FfiPubkyError::from)?;
        
        let ffi_items = resources.into_iter().map(|resource| {
            let path_str = resource.path.as_str();
            let is_directory = path_str.ends_with('/');
            let name = path_str.trim_end_matches('/').split('/').last().unwrap_or(path_str).to_string();
            
            FfiListItem {
                name,
                is_directory,
            }
        }).collect();
        
        Ok(ffi_items)
    }
}

#[derive(uniffi::Object)]
pub struct FfiPublicStorage {
    inner: CorePublicStorage,
}

#[uniffi::export(async_runtime = "tokio")]
impl FfiPublicStorage {
    pub async fn get(&self, uri: String) -> Result<Vec<u8>, FfiPubkyError> {
        let response = self.inner.get(uri).await
            .map_err(FfiPubkyError::from)?;
        
        let bytes = response.bytes().await
            .map_err(|e| FfiPubkyError::Network { 
                message: e.to_string() 
            })?;
        
        Ok(bytes.to_vec())
    }
    
    pub async fn list(&self, uri: String) -> Result<Vec<FfiListItem>, FfiPubkyError> {
        let builder = self.inner.list(uri)
            .map_err(FfiPubkyError::from)?;
        
        let resources = builder.send().await
            .map_err(FfiPubkyError::from)?;
        
        let ffi_items = resources.into_iter().map(|resource| {
            let path_str = resource.path.as_str();
            let is_directory = path_str.ends_with('/');
            let name = path_str.trim_end_matches('/').split('/').last().unwrap_or(path_str).to_string();
            
            FfiListItem {
                name,
                is_directory,
            }
        }).collect();
        
        Ok(ffi_items)
    }
}

impl FfiPublicStorage {
    pub fn new(storage: CorePublicStorage) -> Arc<Self> {
        Arc::new(Self { inner: storage })
    }
}

