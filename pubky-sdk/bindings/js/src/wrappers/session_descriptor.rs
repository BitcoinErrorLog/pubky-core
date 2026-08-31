use pubky_common::session;

use wasm_bindgen::prelude::*;

/// Public metadata for one homeserver session. Never includes the session secret.
#[wasm_bindgen]
pub struct SessionDescriptor(pub(crate) session::SessionDescriptor);

#[wasm_bindgen]
impl SessionDescriptor {
    /// Stable session id used to revoke this session.
    ///
    /// @returns {number}
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> i32 {
        self.0.id()
    }

    /// Unix timestamp (seconds) when this session was created.
    ///
    /// @returns {bigint}
    #[wasm_bindgen(js_name = "createdAt", getter)]
    pub fn created_at(&self) -> u64 {
        self.0.created_at()
    }

    /// Unix timestamp (seconds) when this session expires.
    ///
    /// @returns {bigint}
    #[wasm_bindgen(js_name = "expiresAt", getter)]
    pub fn expires_at(&self) -> u64 {
        self.0.expires_at()
    }

    /// Capabilities granted to this session.
    ///
    /// @returns {string[]}
    #[wasm_bindgen(js_name = "capabilities", getter)]
    pub fn capabilities(&self) -> Vec<String> {
        self.0
            .capabilities()
            .iter()
            .map(|c| c.to_string())
            .collect()
    }
}

impl From<session::SessionDescriptor> for SessionDescriptor {
    fn from(value: session::SessionDescriptor) -> Self {
        Self(value)
    }
}
