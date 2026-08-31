//! Pubky homeserver session struct.

use pkarr::PublicKey;
use postcard::{from_bytes, to_allocvec};
use serde::{Deserialize, Serialize};

extern crate alloc;
use alloc::vec::Vec;

use crate::{
    capabilities::{Capabilities, Capability},
    timestamp::Timestamp,
};

/// Wire version that includes [`SessionInfo::expires_at`].
const SESSION_INFO_VERSION_V1: usize = 1;

#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
/// Pubky homeserver session struct.
pub struct SessionInfo {
    version: usize,
    public_key: PublicKey,
    created_at: u64,
    /// Deprecated. Will always be empty.
    name: String,
    /// Deprecated. Will always be empty.
    user_agent: String,
    capabilities: Vec<Capability>,
    /// Unix timestamp (seconds) when this session expires.
    ///
    /// `None` only for version-0 payloads deserialized from older homeservers,
    /// or for locally constructed placeholders that have not been hydrated yet.
    expires_at: Option<u64>,
}

#[derive(Deserialize)]
struct SessionInfoV0 {
    version: usize,
    public_key: PublicKey,
    created_at: u64,
    name: String,
    user_agent: String,
    capabilities: Vec<Capability>,
}

impl SessionInfo {
    /// Create a new session.
    ///
    /// New sessions serialize as version 1. Call [`SessionInfo::set_expires_at`]
    /// before sending the value to a client so the expiry is on the wire.
    pub fn new(
        public_key: &PublicKey,
        capabilities: Capabilities,
        user_agent: Option<String>,
    ) -> Self {
        Self {
            version: SESSION_INFO_VERSION_V1,
            public_key: public_key.clone(),
            created_at: Timestamp::now().as_u64(),
            capabilities: capabilities.to_vec(),
            user_agent: user_agent.as_deref().unwrap_or("").to_string(),
            name: user_agent.as_deref().unwrap_or("").to_string(),
            expires_at: None,
        }
    }

    // === Getters ===

    /// Returns the public_key of this session authorizes for.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Returns the capabilities this session provide on this session's public_key's resources.
    pub fn capabilities(&self) -> &[Capability] {
        &self.capabilities
    }

    /// Returns the timestamp when this session was created.
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Returns the unix timestamp (seconds) when this session expires, if known.
    pub fn expires_at(&self) -> Option<u64> {
        self.expires_at
    }

    // === Setters ===

    /// Set the timestamp when this session was created.
    pub fn set_created_at(&mut self, created_at: u64) -> &mut Self {
        self.created_at = created_at;
        self
    }

    /// Set the unix timestamp (seconds) when this session expires.
    pub fn set_expires_at(&mut self, expires_at: Option<u64>) -> &mut Self {
        self.expires_at = expires_at;
        self
    }

    /// Set this session's capabilities.
    pub fn set_capabilities(&mut self, capabilities: Capabilities) -> &mut Self {
        self.capabilities = capabilities.to_vec();

        self
    }

    // === Public Methods ===

    /// Serialize this session to its canonical binary representation.
    ///
    /// Always emits version 1, which includes [`SessionInfo::expires_at`].
    /// Version 0 payloads remain readable via [`SessionInfo::deserialize`].
    pub fn serialize(&self) -> Vec<u8> {
        let mut wire = self.clone();
        wire.version = SESSION_INFO_VERSION_V1;
        to_allocvec(&wire).expect("SessionInfo::serialize")
    }

    /// Deserialize this session from its canonical binary representation.
    ///
    /// Version 0 (no `expires_at`) is accepted and yields `expires_at: None`.
    /// Version 1 includes `expires_at`. Any other version, empty payload, or
    /// unparseable body is rejected.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() {
            return Err(Error::EmptyPayload);
        }

        match bytes[0] {
            0 => {
                let v0: SessionInfoV0 = from_bytes(bytes)?;
                Ok(Self {
                    version: v0.version,
                    public_key: v0.public_key,
                    created_at: v0.created_at,
                    name: v0.name,
                    user_agent: v0.user_agent,
                    capabilities: v0.capabilities,
                    expires_at: None,
                })
            }
            1 => Ok(from_bytes(bytes)?),
            _ => Err(Error::UnknownVersion),
        }
    }

    // TODO: add `can_read()`, `can_write()` and `is_root()` methods
}

/// Public metadata for one homeserver session.
///
/// This is the enumeration record returned to a key owner. It never includes
/// the session secret (cookie value).
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct SessionDescriptor {
    /// Stable homeserver-assigned session id. Used to revoke a specific session.
    id: i32,
    /// Unix timestamp (seconds) when the session was created.
    created_at: u64,
    /// Unix timestamp (seconds) when the session expires.
    expires_at: u64,
    /// Capabilities granted to this session.
    capabilities: Vec<Capability>,
}

impl SessionDescriptor {
    /// Build a descriptor from stored session metadata.
    pub fn new(id: i32, created_at: u64, expires_at: u64, capabilities: Capabilities) -> Self {
        Self {
            id,
            created_at,
            expires_at,
            capabilities: capabilities.to_vec(),
        }
    }

    /// Stable session id for revocation.
    pub fn id(&self) -> i32 {
        self.id
    }

    /// Unix timestamp (seconds) when the session was created.
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Unix timestamp (seconds) when the session expires.
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Capabilities granted to this session.
    pub fn capabilities(&self) -> &[Capability] {
        &self.capabilities
    }
}

#[derive(thiserror::Error, Debug, PartialEq)]
/// Error deserializing a [SessionInfo].
pub enum Error {
    #[error("Empty payload")]
    /// Empty payload
    EmptyPayload,
    #[error("Unknown version")]
    /// Unknown version
    UnknownVersion,
    #[error(transparent)]
    /// Error parsing the binary representation.
    Parsing(#[from] postcard::Error),
}

#[cfg(test)]
mod tests {
    use crate::{capabilities::Capability, crypto::Keypair};

    use super::*;

    /// Historical version-0 encoding of a session with `created_at = 0`,
    /// `user_agent = "foo"`, and a root capability. Must keep deserializing.
    const V0_SERIALIZED: [u8; 45] = [
        0, 59, 106, 39, 188, 206, 182, 164, 45, 98, 163, 168, 208, 42, 111, 13, 115, 101, 50, 21,
        119, 29, 226, 67, 166, 58, 192, 72, 161, 139, 89, 218, 41, 0, 0, 3, 102, 111, 111, 1, 4,
        47, 58, 114, 119,
    ];

    #[test]
    fn deserialize_v0_sets_expires_at_none() {
        let keypair = Keypair::from_secret_key(&[0; 32]);
        let public_key = keypair.public_key();
        let capabilities = Capabilities::builder().cap(Capability::root()).finish();

        let deserialized = SessionInfo::deserialize(&V0_SERIALIZED).unwrap();

        assert_eq!(deserialized.public_key(), &public_key);
        assert_eq!(deserialized.created_at(), 0);
        assert_eq!(deserialized.expires_at(), None);
        assert_eq!(deserialized.capabilities(), capabilities.as_slice());
    }

    #[test]
    fn serialize_v1_roundtrip_includes_expires_at() {
        let keypair = Keypair::from_secret_key(&[0; 32]);
        let public_key = keypair.public_key();
        let capabilities = Capabilities::builder().cap(Capability::root()).finish();

        let mut session = SessionInfo::new(&public_key, capabilities, Some("foo".to_string()));
        session.set_created_at(0);
        session.set_expires_at(Some(1_700_000_000));

        let serialized = session.serialize();
        assert_eq!(serialized[0], 1);

        let deserialized = SessionInfo::deserialize(&serialized).unwrap();
        assert_eq!(deserialized, session);
        assert_eq!(deserialized.expires_at(), Some(1_700_000_000));
    }

    #[test]
    fn deserialize_empty_and_unknown_version() {
        assert_eq!(SessionInfo::deserialize(&[]), Err(Error::EmptyPayload));
        assert_eq!(
            SessionInfo::deserialize(&[2, 0, 0, 0]),
            Err(Error::UnknownVersion)
        );
    }

    #[test]
    fn session_descriptor_never_holds_a_secret_field() {
        let json = serde_json::to_string(&SessionDescriptor::new(
            7,
            10,
            20,
            Capabilities::builder().cap(Capability::root()).finish(),
        ))
        .unwrap();
        assert!(!json.contains("secret"));
        assert!(json.contains("\"id\":7"));
        assert!(json.contains("\"created_at\":10"));
        assert!(json.contains("\"expires_at\":20"));
    }
}
