#![allow(missing_docs)]

use crate::ffi::errors::FfiPubkyError;

/// X25519 keypair for FFI
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiX25519Keypair {
    pub secret_key: String,
    pub public_key: String,
}

/// Generate a random X25519 keypair
#[uniffi::export]
pub fn x25519_generate_keypair() -> FfiX25519Keypair {
    let (secret_key, public_key) = pubky_noise::x25519_generate_keypair();
    FfiX25519Keypair {
        secret_key: hex::encode(secret_key),
        public_key: hex::encode(public_key),
    }
}

/// Derive the public key from an X25519 secret key
#[uniffi::export]
pub fn x25519_public_from_secret(secret_key_hex: String) -> Result<String, FfiPubkyError> {
    let secret_bytes = hex::decode(&secret_key_hex).map_err(|e| FfiPubkyError::InvalidInput {
        message: format!("Invalid hex for secret key: {e}"),
    })?;

    if secret_bytes.len() != 32 {
        return Err(FfiPubkyError::InvalidInput {
            message: format!("Secret key must be 32 bytes, got {}", secret_bytes.len()),
        });
    }

    let mut secret_array = [0u8; 32];
    secret_array.copy_from_slice(&secret_bytes);

    let public_key = pubky_noise::x25519_public_from_secret(&secret_array);
    Ok(hex::encode(public_key))
}

/// Derive X25519 keypair from seed, device ID, and epoch
#[uniffi::export]
pub fn derive_x25519_for_device_epoch(
    seed_hex: String,
    device_id_hex: String,
    epoch: u32,
) -> Result<FfiX25519Keypair, FfiPubkyError> {
    let seed_bytes = hex::decode(&seed_hex).map_err(|e| FfiPubkyError::InvalidInput {
        message: format!("Invalid hex for seed: {e}"),
    })?;

    if seed_bytes.len() != 32 {
        return Err(FfiPubkyError::InvalidInput {
            message: format!("Seed must be 32 bytes, got {}", seed_bytes.len()),
        });
    }

    let device_id_bytes =
        hex::decode(&device_id_hex).map_err(|e| FfiPubkyError::InvalidInput {
            message: format!("Invalid hex for device ID: {e}"),
        })?;

    let mut seed_array = [0u8; 32];
    seed_array.copy_from_slice(&seed_bytes);

    let secret_key = pubky_noise::kdf::derive_x25519_for_device_epoch(
        &seed_array,
        &device_id_bytes,
        epoch,
    )
    .map_err(|e| FfiPubkyError::Unknown {
        message: format!("Key derivation failed: {e}"),
    })?;

    let public_key = pubky_noise::x25519_public_from_secret(&secret_key);

    Ok(FfiX25519Keypair {
        secret_key: hex::encode(secret_key),
        public_key: hex::encode(public_key),
    })
}

/// Derive a noise seed from an Ed25519 secret key and device ID
#[uniffi::export]
pub fn derive_noise_seed(
    ed25519_secret_hex: String,
    device_id_hex: String,
) -> Result<String, FfiPubkyError> {
    let secret_bytes =
        hex::decode(&ed25519_secret_hex).map_err(|e| FfiPubkyError::InvalidInput {
            message: format!("Invalid hex for Ed25519 secret: {e}"),
        })?;

    if secret_bytes.len() != 32 {
        return Err(FfiPubkyError::InvalidInput {
            message: format!("Ed25519 secret must be 32 bytes, got {}", secret_bytes.len()),
        });
    }

    let device_id_bytes =
        hex::decode(&device_id_hex).map_err(|e| FfiPubkyError::InvalidInput {
            message: format!("Invalid hex for device ID: {e}"),
        })?;

    let mut secret_array = [0u8; 32];
    secret_array.copy_from_slice(&secret_bytes);

    let seed = pubky_noise::kdf::derive_noise_seed(&secret_array, &device_id_bytes).map_err(
        |e| FfiPubkyError::Unknown {
            message: format!("Noise seed derivation failed: {e}"),
        },
    )?;

    Ok(hex::encode(seed))
}

/// Encrypt data using Sealed Blob v1 format
#[uniffi::export]
pub fn sealed_blob_encrypt(
    recipient_pk_hex: String,
    plaintext_hex: String,
    aad: String,
    purpose: Option<String>,
) -> Result<String, FfiPubkyError> {
    let recipient_pk_bytes =
        hex::decode(&recipient_pk_hex).map_err(|e| FfiPubkyError::InvalidInput {
            message: format!("Invalid hex for recipient public key: {e}"),
        })?;

    if recipient_pk_bytes.len() != 32 {
        return Err(FfiPubkyError::InvalidInput {
            message: format!(
                "Recipient public key must be 32 bytes, got {}",
                recipient_pk_bytes.len()
            ),
        });
    }

    let plaintext_bytes =
        hex::decode(&plaintext_hex).map_err(|e| FfiPubkyError::InvalidInput {
            message: format!("Invalid hex for plaintext: {e}"),
        })?;

    let mut recipient_pk_array = [0u8; 32];
    recipient_pk_array.copy_from_slice(&recipient_pk_bytes);

    let envelope_json = pubky_noise::sealed_blob_encrypt(
        &recipient_pk_array,
        &plaintext_bytes,
        &aad,
        purpose.as_deref(),
    )
    .map_err(|e| FfiPubkyError::Unknown {
        message: format!("Sealed blob encryption failed: {e}"),
    })?;

    Ok(envelope_json)
}

/// Decrypt a Sealed Blob v1 envelope
#[uniffi::export]
pub fn sealed_blob_decrypt(
    recipient_sk_hex: String,
    envelope_json: String,
    aad: String,
) -> Result<String, FfiPubkyError> {
    let recipient_sk_bytes =
        hex::decode(&recipient_sk_hex).map_err(|e| FfiPubkyError::InvalidInput {
            message: format!("Invalid hex for recipient secret key: {e}"),
        })?;

    if recipient_sk_bytes.len() != 32 {
        return Err(FfiPubkyError::InvalidInput {
            message: format!(
                "Recipient secret key must be 32 bytes, got {}",
                recipient_sk_bytes.len()
            ),
        });
    }

    let mut recipient_sk_array = [0u8; 32];
    recipient_sk_array.copy_from_slice(&recipient_sk_bytes);

    let plaintext =
        pubky_noise::sealed_blob_decrypt(&recipient_sk_array, &envelope_json, &aad).map_err(
            |e| FfiPubkyError::Unknown {
                message: format!("Sealed blob decryption failed: {e}"),
            },
        )?;

    Ok(hex::encode(plaintext))
}

/// Check if a JSON string is a valid Sealed Blob v1 envelope
#[uniffi::export]
pub fn is_sealed_blob(json: String) -> bool {
    pubky_noise::is_sealed_blob(&json)
}

/// Sign a message with an Ed25519 secret key
#[uniffi::export]
pub fn ed25519_sign(
    ed25519_secret_hex: String,
    message_hex: String,
) -> Result<String, FfiPubkyError> {
    let secret_bytes =
        hex::decode(&ed25519_secret_hex).map_err(|e| FfiPubkyError::InvalidInput {
            message: format!("Invalid hex for Ed25519 secret: {e}"),
        })?;

    if secret_bytes.len() != 32 {
        return Err(FfiPubkyError::InvalidInput {
            message: format!("Ed25519 secret must be 32 bytes, got {}", secret_bytes.len()),
        });
    }

    let message_bytes = hex::decode(&message_hex).map_err(|e| FfiPubkyError::InvalidInput {
        message: format!("Invalid hex for message: {e}"),
    })?;

    let mut secret_array = [0u8; 32];
    secret_array.copy_from_slice(&secret_bytes);

    let signature = pubky_noise::ed25519_sign(&secret_array, &message_bytes).map_err(|e| {
        FfiPubkyError::Unknown {
            message: format!("Ed25519 signing failed: {e}"),
        }
    })?;

    Ok(hex::encode(signature))
}

/// Verify an Ed25519 signature
#[uniffi::export]
pub fn ed25519_verify(
    ed25519_public_hex: String,
    message_hex: String,
    signature_hex: String,
) -> Result<bool, FfiPubkyError> {
    let public_bytes =
        hex::decode(&ed25519_public_hex).map_err(|e| FfiPubkyError::InvalidInput {
            message: format!("Invalid hex for Ed25519 public key: {e}"),
        })?;

    if public_bytes.len() != 32 {
        return Err(FfiPubkyError::InvalidInput {
            message: format!(
                "Ed25519 public key must be 32 bytes, got {}",
                public_bytes.len()
            ),
        });
    }

    let message_bytes = hex::decode(&message_hex).map_err(|e| FfiPubkyError::InvalidInput {
        message: format!("Invalid hex for message: {e}"),
    })?;

    let signature_bytes =
        hex::decode(&signature_hex).map_err(|e| FfiPubkyError::InvalidInput {
            message: format!("Invalid hex for signature: {e}"),
        })?;

    if signature_bytes.len() != 64 {
        return Err(FfiPubkyError::InvalidInput {
            message: format!("Signature must be 64 bytes, got {}", signature_bytes.len()),
        });
    }

    let mut public_array = [0u8; 32];
    public_array.copy_from_slice(&public_bytes);

    let mut signature_array = [0u8; 64];
    signature_array.copy_from_slice(&signature_bytes);

    let is_valid =
        pubky_noise::ed25519_verify(&public_array, &message_bytes, &signature_array).map_err(
            |e| FfiPubkyError::Unknown {
                message: format!("Ed25519 verification failed: {e}"),
            },
        )?;

    Ok(is_valid)
}

