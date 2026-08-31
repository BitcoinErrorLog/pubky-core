use pubky_common::session;

use wasm_bindgen::prelude::*;

use super::keys::PublicKey;

/// Static snapshot of session metadata.
#[wasm_bindgen]
pub struct SessionInfo(pub(crate) session::SessionInfo);

#[wasm_bindgen]
impl SessionInfo {
    /// The user’s public key for this session.
    ///
    /// Use `.z32()` on the returned `PublicKey` to get the string form.
    ///
    /// @returns {PublicKey}
    ///
    /// @example
    /// const who = sessionInfo.publicKey.z32();
    #[wasm_bindgen(js_name = "publicKey", getter)]
    pub fn public_key(&self) -> PublicKey {
        self.0.public_key().clone().into()
    }

    /// Effective capabilities granted to this session.
    ///
    /// @returns {string[]} Normalized capability entries (e.g. `"/pub/app/:rw"`).
    #[wasm_bindgen(js_name = "capabilities", getter)]
    pub fn capabilities(&self) -> Vec<String> {
        self.0
            .capabilities()
            .iter()
            .map(|c| c.to_string())
            .collect()
    }

    /// Unix timestamp (seconds) when this session was created, if the homeserver provided one.
    ///
    /// @returns {bigint}
    #[wasm_bindgen(js_name = "createdAt", getter)]
    pub fn created_at(&self) -> u64 {
        self.0.created_at()
    }

    /// Unix timestamp (seconds) when this session expires, or `undefined` if unknown.
    ///
    /// @returns {bigint|undefined}
    #[wasm_bindgen(js_name = "expiresAt", getter)]
    pub fn expires_at(&self) -> Option<u64> {
        self.0.expires_at()
    }
}
