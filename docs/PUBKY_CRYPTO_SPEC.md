# Pubky Cryptographic Specification

**Version**: 2.3  
**Date**: January 2026  
**Status**: Authoritative Reference

This specification defines the cryptographic primitives, key derivation schemes, transport protocols, and envelope formats used across the Pubky ecosystem (pubky-ring, pubky-noise, paykit, bitkit).

---

## Table of Contents

1. [Design Principles](#1-design-principles)
   - 1.3 [Required Properties](#13-required-properties)
   - 1.4 [Live Transport vs Stored Delivery](#14-live-transport-vs-stored-delivery)
2. [Cryptographic Primitives](#2-cryptographic-primitives)
3. [Identity Model](#3-identity-model)
4. [Key Hierarchy and Derivation](#4-key-hierarchy-and-derivation)
5. [Device Authorization](#5-device-authorization)
   - 5.3 [Ring FFI Interface](#53-ring-ffi-interface)
6. [Live Transport (Noise Protocol)](#6-live-transport-noise-protocol)
   - 6.8 [Key Binding and Pinning](#68-key-binding-and-pinning)
7. [Async Messaging (Async Envelopes)](#7-async-messaging-async-envelopes)
   - 7.2 [Sealed Blob v2 Wire Format](#72-sealed-blob-v2-wire-format)
   - 7.3 [Key Derivation (Envelopes)](#73-key-derivation-envelopes)
   - 7.5 [AAD Construction](#75-aad-construction)
   - 7.6 [Optional Sender Signature](#76-optional-sender-signature)
   - 7.7 [ContextId Definition](#77-contextid-definition)
   - 7.8 [Storage Layout](#78-storage-layout-paykit-v0)
   - 7.9 [Encrypted ACK Protocol](#79-encrypted-ack-protocol)
   - 7.12 [Canonical Encoding Rules](#712-canonical-encoding-rules)
   - 7.13 [Resend Defaults](#713-resend-defaults-paykit)
8. [Session and Message Binding](#8-session-and-message-binding)
   - 8.4 [ContextId vs SessionId](#84-contextid-vs-sessionid)
   - 8.5 [PeerPairFingerprint](#85-peerpairfingerprint)
9. [Key Rotation](#9-key-rotation)
10. [Backup and Restore](#10-backup-and-restore)
11. [Security Considerations](#11-security-considerations)
12. [Implementation Reference](#12-implementation-reference)

---

## 1. Design Principles

### 1.1 Core Goals

1. **Deterministic identity**: A device can re-derive the same app-scoped keys after restart or restore from backup.

2. **Cold master secret**: The Ed25519 seed stays in Ring. Apps receive only derived material or perform derivation via Ring callbacks.

3. **No CipherState persistence**: Noise transport keys are never serialized or exported. Sessions re-handshake after disconnect.

4. **Offline async delivery**: Queued messages are decryptable without the sender being online.

5. **Clean separation of concerns**:
   - Ring: seed custody, authorization, derivation
   - pubky-noise: Noise handshake, transport encryption, envelope sealing
   - Apps (Bitkit, Paykit): message formats, outbox semantics, receipts

### 1.2 Threat Model

| Assumption | Description |
|------------|-------------|
| Device OS not actively malicious | We don't claim HSM-grade RAM protection |
| Homeserver untrusted | May delete, delay, reorder, replay stored blobs |
| Network adversary passive | Can observe timing/metadata; active MITM prevented by Noise |
| Traffic analysis out of scope | Timing attacks addressed in future work |

### 1.3 Required Properties

- Message confidentiality against homeserver and passive observers
- Message integrity and sender authenticity when signatures present
- Replay resistance and idempotency at application layer
- **No double encryption**: Stored messages use Sealed Blob only; live messages use Noise only. Wrapping Sealed Blob in Noise or storing Noise ciphertext as Sealed Blob payload is PROHIBITED in shipped code paths.

### 1.4 Live Transport vs Stored Delivery

The Pubky protocol distinguishes between two delivery modes:

| Mode | Encryption | Use Case |
|------|------------|----------|
| **Live Transport** | Noise (ChaCha20-Poly1305) | Real-time bidirectional communication |
| **Stored Delivery** | Sealed Blob (XChaCha20-Poly1305) | Async messages stored on homeserver |

**Invariants**:
1. Live transport uses Noise and encrypts plaintext message schemas
2. Stored delivery uses Sealed Blob and encrypts plaintext message schemas
3. MUST NOT store queued Noise ciphertext on the homeserver
4. MUST NOT double-encrypt (Sealed Blob inside Noise or Noise ciphertext inside Sealed Blob)

**Message Schema Reuse**: Paykit defines plaintext schemas for each message kind. The same schema is:
- Carried inside Noise frames (live transport), OR
- Used as Sealed Blob plaintext payload (stored delivery)

One encryption layer at a time. Never both.

---

## 2. Cryptographic Primitives

### 2.1 Algorithms

| Purpose | Algorithm | Library |
|---------|-----------|---------|
| Identity signing | Ed25519 | `ed25519-dalek` |
| Key exchange | X25519 | `x25519-dalek` |
| Key derivation | HKDF-SHA256 / HKDF-SHA512 | `hkdf` crate |
| Symmetric encryption (transport) | ChaCha20-Poly1305 | `chacha20poly1305` via `snow` |
| Symmetric encryption (envelopes) | XChaCha20-Poly1305 | `chacha20poly1305` crate |
| Hashing | BLAKE2s (Noise), BLAKE3 (tags), SHA-256 (HKDF) | Various |

### 2.2 Key Sizes

| Key Type | Size |
|----------|------|
| Ed25519 seed | 32 bytes |
| Ed25519 public key | 32 bytes |
| Ed25519 signature | 64 bytes |
| X25519 secret key | 32 bytes |
| X25519 public key | 32 bytes |
| Symmetric key | 32 bytes |
| ChaCha20-Poly1305 nonce | 12 bytes |
| XChaCha20-Poly1305 nonce | 24 bytes |
| Poly1305 tag | 16 bytes |

---

## 3. Identity Model

### 3.1 PKARR Identity

A PKARR identity is an Ed25519 keypair. The public key is the identity.

- **Encoding**: z-base-32 (52 characters)
- **URI format**: `pubky://{z32_public_key}`
- **One key = one identity**: No hierarchy within a single PKARR identity

### 3.2 Multiple Identities

A user may control multiple PKARR identities. Each is independent. Cross-identity linking is an application-layer concern.

### 3.3 Identity Publication

PKARR identities may publish signed DNS records via the DHT. Optional metadata includes:
- Homeserver endpoints
- Noise static public keys (per app, per epoch)
- Service capabilities

---

## 4. Key Hierarchy and Derivation

### 4.1 Master Seed

Ring maintains a master secret for each PKARR identity. This is typically the Ed25519 seed (32 bytes).

**Invariant**: The master seed MUST NOT be exported to apps. All derivation happens inside Ring or via Ring-controlled callbacks.

### 4.2 App Seed Derivation

Ring derives an app-scoped seed:

```
APP_SEED = HKDF-SHA256(
  ikm  = MASTER_SEED,
  salt = "pubky-ring/app-seed/v1",
  info = app_id || network_id,
  len  = 32
)
```

- `app_id`: ASCII string (e.g., `"bitkit"`, `"pubky-app"`)
- `network_id`: ASCII string (e.g., `"mainnet"`, `"testnet"`, `"regtest"`)

APP_SEED remains internal to Ring.

### 4.3 Noise Seed Derivation

For apps that need to derive epoch keys locally without calling Ring:

```
NOISE_SEED = HKDF-SHA256(
  ikm  = APP_SEED,
  salt = "pubky-ring/noise-seed/v1",
  info = device_id,
  len  = 32
)
```

NOISE_SEED may be handed off to the app (encrypted) to allow local epoch derivation.

### 4.4 Device Static X25519 Derivation

Per-device, per-epoch Noise static key:

```
raw = HKDF-SHA512(
  ikm  = NOISE_SEED,
  salt = "pubky-noise-x25519:v1",
  info = device_id || epoch_le32 || role,
  len  = 32
)

NOISE_STATIC_SK = X25519_CLAMP(raw)
NOISE_STATIC_PK = X25519_BASEPOINT_MULT(NOISE_STATIC_SK)
```

- `device_id`: 16 bytes, stable per authorized device
- `epoch`: 32-bit little-endian integer, starts at 0
- `role`: ASCII string (e.g., `"transport"`, `"handoff"`) — **optional, for future domain separation**

**Current implementation note**: The `role` parameter is not yet implemented. Current derivation uses `device_id || epoch` only.

### 4.5 X25519 Clamping

Per RFC 7748:
```
sk[0]  &= 248
sk[31] &= 127
sk[31] |= 64
```

### 4.6 Local Archive Key

For encrypting local message history and preferences:

```
LOCAL_ARCHIVE_KEY = HKDF-SHA256(
  ikm  = APP_SEED,
  salt = "pubky-ring/local-archive/v1",
  info = device_id,
  len  = 32
)
```

This key encrypts local data only. MUST NOT be used for outbox envelopes.

### 4.7 Domain Separation for Single X25519 Key (MVP)

For MVP, devices publish a **single X25519 static public key** that serves both:
- Live Noise transport sessions (Noise_XX, Noise_IK patterns)
- Sealed Blob envelopes (async encrypted messages)

This is safe due to **strict domain separation**:

| Protocol | HKDF Info String | Nonce Size | AEAD |
|----------|------------------|------------|------|
| Noise Transport | (per Noise spec) | 12 bytes | ChaCha20-Poly1305 |
| Sealed Blob v2 | `"pubky-envelope/v2"` | 24 bytes | XChaCha20-Poly1305 |

**Security guarantees**:
- Different HKDF info strings produce unrelated derived keys
- Different nonce sizes prevent cross-protocol nonce reuse
- AAD binds envelope ciphertext to storage context

**kid Derivation**:

For O(1) key selection, derive a 16-byte key identifier from any X25519 public key:

```
kid = first_16_bytes(SHA256(x25519_pub))
```

This `kid` is included in Sealed Blob v2 headers (Section 7.2) to enable efficient key lookup.

**Future migration path**: If stronger isolation is required, split into:
- `InboxKey`: X25519 for Sealed Blob envelopes only
- `TransportKey`: X25519 for Noise sessions only

Both keys can be published in PKARR metadata (with their respective `kid` values) without breaking identity.

---

## 5. Device Authorization

### 5.1 Authorization Object

When an app requests authorization from Ring, Ring returns:

```json
{
  "pkarr_pub": "<32 bytes, hex>",
  "device_id": "<16 bytes, hex>",
  "app_id": "bitkit",
  "scopes": ["transport", "storage"],
  "epoch": 0,
  "expires_at": 1704153600,
  "signature": "<64 bytes, hex>"
}
```

The signature covers all fields using the PKARR identity key.

### 5.2 Derived Material Delivery

Two models:

**Model A: Encrypted Handoff**
- Ring encrypts `(NOISE_STATIC_SK, NOISE_SEED, session_secret)` to an app-generated ephemeral X25519 public key
- Stored on homeserver as Sealed Blob
- App fetches, decrypts, caches locally
- Used for same-device Ring→Bitkit handoff

**Model B: On-Demand Derivation**
- App calls Ring to derive keys when needed
- Ring returns via callback, app uses immediately and zeroizes
- Lower secret residency, higher runtime dependency on Ring

### 5.3 Ring FFI Interface

This section defines the recommended FFI surface for Ring integrations.

#### 5.3.1 Core Functions

```rust
// List all inbox public keys for an app
fn list_inbox_pubkeys(app_id: &str) -> Vec<InboxKeyInfo>;

struct InboxKeyInfo {
    x25519_pub: [u8; 32],
    kid: [u8; 16],
    key_version: u32,
}

// Derive an inbox secret handle for decryption (O(1) lookup by kid)
fn derive_inbox_handle_by_kid(app_id: &str, kid: &[u8; 16]) -> Option<EncryptedSkHandle>;

// Derive a transport secret handle for Noise
fn derive_transport_handle(app_id: &str, device_id: &[u8; 16]) -> EncryptedSkHandle;
```

**Key Lookup**: Ring maintains an internal mapping `{ kid -> secret_key }`. Apps provide the `kid` extracted from the envelope header; Ring returns the corresponding handle or `None` if unknown.

#### 5.3.2 EncryptedSkHandle Semantics

`EncryptedSkHandle` is an **opaque reference** to secret material. It can be:

| Type | Description |
|------|-------------|
| Platform keystore reference | Handle to secret stored in iOS Keychain / Android Keystore / TEE |
| Encrypted key blob | Secret wrapped under a Ring master key, unwrappable only by Ring |

**Invariants**:
- Secrets MUST NOT be returned as long-lived raw byte arrays
- If a raw-bytes API exists, it MUST be:
  - Scoped to a single operation
  - Zeroized immediately after use
  - Not stored or logged

#### 5.3.3 FFI Safety Rules

| Rule | Description |
|------|-------------|
| No function pointers | Avoid callbacks that could be hijacked |
| Bytes in, bytes out | All parameters are byte arrays or primitives |
| No persistent handles | Handles are valid only for immediate use |
| Explicit lifetime | Callers must not cache handles across operations |

**Example Usage (Conceptual)**:

```rust
// App wants to decrypt a Sealed Blob
let kid = extract_kid_from_envelope(&envelope);  // 16 bytes from header key 3
let handle = ring.derive_inbox_handle_by_kid("bitkit", &kid)
    .ok_or(Error::KeyNotFound)?;
let plaintext = ring.decrypt_sealed_blob(&envelope, handle);
// handle is invalidated after use
```

---

## 6. Live Transport (Noise Protocol)

### 6.1 Supported Patterns

| Pattern | Use Case |
|---------|----------|
| Noise_XX_25519_ChaChaPoly_BLAKE2s | First contact (TOFU) |
| Noise_IK_25519_ChaChaPoly_BLAKE2s | Subsequent contact (server static pinned) |
| Noise_NN_25519_ChaChaPoly_BLAKE2s | Anonymous/ephemeral (testing only) |

### 6.2 Handshake Flow (XX)

```
Initiator (Client)                    Responder (Server)
     |                                      |
     |  -> e                                |  Step 1: ephemeral
     |  <- e, ee, s, es                     |  Step 2: ephemeral, DH, static
     |  -> s, se [IdentityPayload]          |  Step 3: static, DH, identity
     |                                      |
     |  ====== TRANSPORT MODE ======        |
```

### 6.3 Identity Binding

During handshake, each party sends an `IdentityPayload`:

```rust
struct IdentityPayload {
    ed25519_pub: [u8; 32],      // PKARR identity
    noise_x25519_pub: [u8; 32], // Noise static for this session
    epoch: u32,                  // Key epoch (internal, always 0 for now)
    role: Role,                  // Client or Server
    server_hint: Option<String>, // Routing hint
    expires_at: Option<u64>,     // Unix seconds
    sig: [u8; 64],               // Ed25519 signature over binding message
}
```

### 6.4 Binding Message

```
binding = BLAKE2s(
  "pubky-noise-bind:v1" ||
  pattern_tag ||
  prologue ||
  ed25519_pub ||
  local_noise_pub ||
  remote_noise_pub? ||
  epoch_le32 ||
  role_string ||
  server_hint? ||
  expires_at?
)

sig = Ed25519_Sign(ed25519_sk, binding)
```

### 6.5 Session Identifier

Derived from the Noise handshake transcript hash:

```rust
let session_id = SessionId(hs.get_handshake_hash());
```

This is a 32-byte value unique to each completed handshake. It changes on every new handshake, even between the same parties.

**Important**: Do NOT use `DH(static_a, static_b)` as a session tag. That produces a peer-pair tag which is static across sessions.

### 6.6 Transport Encryption

Post-handshake messages use the Noise transport mode with ChaCha20-Poly1305. The library handles nonce management internally.

### 6.7 No State Persistence

Implementations MUST NOT:
- Export CipherState or transport keys from snow
- Serialize Noise session state for cross-device restore

Implementations MAY persist:
- Peer identity (Ed25519 public key)
- Pinned Noise static (for IK pattern)
- Last seen timestamp
- Session metadata (not secrets)

### 6.8 Key Binding and Pinning

This section defines how X25519 keys are bound to PeerIds and how implementations decide between XX and IK patterns.

#### 6.8.1 KeyBinding Object

A KeyBinding object binds X25519 keys to a PeerId. It is published via PKARR DNS records and can be cached locally.

```rust
struct KeyBinding {
    peerid: [u8; 32],              // Ed25519 identity (PeerId)
    inbox_keys: Vec<InboxKeyEntry>,  // For Sealed Blob encryption
    transport_keys: Vec<TransportKeyEntry>, // For Noise sessions (optional)
    created_at: u64,               // Unix timestamp
    signature: [u8; 64],           // Ed25519 signature by peerid
}

struct InboxKeyEntry {
    x25519_pub: [u8; 32],
    kid: [u8; 16],
    key_version: u32,
}

struct TransportKeyEntry {
    x25519_pub: [u8; 32],
    key_version: u32,
}
```

**Signature Scope**: The signature covers the canonical serialization of all fields except `signature` itself.

#### 6.8.2 Pinning Rules (Normative)

| Condition | Required Pattern | Rationale |
|-----------|------------------|-----------|
| No verified KeyBinding for target PeerId | MUST use XX | No trusted key to encrypt initiator static |
| Verified KeyBinding exists | MAY use IK | Initiator can encrypt static to known responder key |
| KeyBinding expired or revoked | MUST use XX | Treat as unknown |

**Upgrade to IK**:

Implementations MUST NOT upgrade to IK until:
1. A KeyBinding for the target PeerId has been fetched and verified
2. The TransportKey in the KeyBinding has been pinned locally
3. The PeerId has been associated with the pinned TransportKey

**Pin Storage**:

Implementations SHOULD persist pinned keys with:
- `peerid`: The Ed25519 public key
- `transport_x25519_pub`: The pinned Noise static key
- `key_version`: The version from KeyBinding
- `pinned_at`: Timestamp of pinning
- `last_verified`: Last time KeyBinding was re-verified

#### 6.8.3 TOFU Security Considerations

The XX pattern authenticates both parties to each other during the handshake, but is vulnerable to active MITM on first contact:

1. Attacker intercepts XX handshake
2. Attacker completes separate XX handshakes with both parties
3. Both parties believe they are talking to each other

**Detection**: Compare PeerPairFingerprints (Section 8.5) out-of-band. If fingerprints differ, MITM is present.

**Prevention**: Once IK pattern is used with a pinned key, active MITM requires key compromise.

---

## 7. Async Messaging (Async Envelopes)

### 7.1 Purpose

When both parties are not online simultaneously, messages are stored encrypted on the homeserver. The recipient decrypts without the sender being online.

### 7.2 Sealed Blob v2 Wire Format

Sealed Blob v2 uses a binary framing with deterministic CBOR headers:

```
Wire Format:
  magic: 0x53 0x42 0x32 ("SB2", 3 bytes)
  version: u8 (2)
  header_len: u16 (big-endian)
  header_bytes: [u8; header_len] (deterministic CBOR, see 7.12)
  ciphertext: [u8] (remainder, includes 16-byte Poly1305 tag)
```

**Header Fields (Deterministic CBOR map with integer keys)**:

The header is a CBOR map using **integer keys** for compactness (see Section 7.12.3 for encoding rules).

| Key | Field Name | Type | Required | Description |
|-----|------------|------|----------|-------------|
| 0 | `context_id` | bytes(32) | REQUIRED (Paykit) | Thread identifier (see 7.7) |
| 1 | `created_at` | uint | Recommended | Unix timestamp (seconds) |
| 2 | `expires_at` | uint | REQUIRED (Paykit) | Expiration for requests/proposals |
| 3 | `kid` | bytes(16) | **REQUIRED** | Key identifier for recipient key selection |
| 4 | `msg_id` | text | REQUIRED (Paykit) | Idempotency key for deduplication |
| 5 | `nonce` | bytes(24) | **REQUIRED** | XChaCha20-Poly1305 nonce (random per message) |
| 6 | `purpose` | text | Optional | Hint only, e.g. `"handoff"`, `"request"`, `"proposal"` |
| 7 | `recipient_peerid` | bytes(32) | **REQUIRED** | Recipient's Ed25519 public key (PeerId) |
| 8 | `sender_ephemeral_x25519_pub` | bytes(32) | **REQUIRED** | Sender's ephemeral X25519 public key for DH |
| 9 | `sender_peerid` | bytes(32) | **REQUIRED** | Sender's Ed25519 public key (for routing) |
| 10 | `sig` | bytes(64) | Optional | Ed25519 signature for sender authenticity |

**kid Derivation (Normative)**:

```
kid = first_16_bytes(SHA256(recipient_inbox_x25519_pub))
```

The `kid` enables O(1) key lookup in the receiver's keyring. Receivers MUST NOT brute-force multiple keys; if `kid` does not match any known key, return `KeyNotFound`.

**Legacy JSON Format (Deprecated)**:

For backward compatibility with existing implementations, the JSON format is still accepted:

```json
{
  "v": 2,
  "epk": "<base64url: sender ephemeral X25519 public key, 32 bytes>",
  "sender": "<z-base-32: sender PKARR public key>",
  "nonce": "<base64url: 24 bytes>",
  "ct": "<base64url: ciphertext + 16-byte tag>",
  "kid": "<hex: 16 bytes>",
  "purpose": "<string: hint only>",
  "sig": "<base64url: 64 bytes, optional>"
}
```

New implementations SHOULD use the binary wire format. The `kid` field MUST be 16 bytes in both formats.

### 7.3 Key Derivation (Envelopes)

```
shared_secret = X25519(sender_ephemeral_sk, recipient_static_pk)

key = HKDF-SHA256(
  ikm  = shared_secret,
  salt = sender_ephemeral_pk || recipient_static_pk,
  info = "pubky-envelope/v2",
  len  = 32
)
```

**Key Discovery and Selection**:

| Role | Discovery | Selection |
|------|-----------|-----------|
| **Sender** | Fetches recipient's KeyBinding (Section 6.8) from PKARR to obtain `inbox_keys` list. Selects an entry and uses its `x25519_pub` as `recipient_static_pk`, includes its `kid` in header. | Uses recipient's published inbox X25519 public key |
| **Receiver** | N/A | Extracts `kid` from envelope header (key 3), looks up corresponding secret key in local keyring via Ring FFI (Section 5.3) |

**Invariant**: Sender MUST include the `kid` that corresponds to the `recipient_static_pk` used for encryption. Receiver MUST NOT brute-force keys.

### 7.4 Nonce Generation

**Sealed Blob (Stored Delivery)**:
- 24 bytes cryptographically random, generated fresh for each envelope
- Uses XChaCha20-Poly1305 (extended nonce variant)
- No counters, no state required
- Safe for random generation due to 192-bit nonce space (collision-resistant)

**Noise Transport (Live Delivery)**:
- Per-Noise-spec counter nonces (12 bytes)
- Uses ChaCha20-Poly1305
- Library (`snow`) manages counter internally
- Nonces are never exposed or persisted

**Cross-Protocol Nonce Reuse Prevention**:

Cross-protocol nonce reuse is prevented by multiple independent mechanisms:

| Mechanism | Protection |
|-----------|------------|
| Distinct AEAD constructions | XChaCha20 (sealed) vs ChaCha20 (noise) |
| Distinct HKDF info strings | `"pubky-envelope/v2"` vs Noise-internal KDF |
| Different key derivation inputs | Ephemeral DH (sealed) vs handshake transcript (noise) |
| AAD binding | Sealed Blob AAD includes storage context |

**Security Note**: The different nonce sizes (24 vs 12 bytes) are a consequence of the AEAD choice, not a security mechanism. Do not rely on nonce length as a security argument.

### 7.5 AAD Construction

AAD binds ciphertext to its storage context and owner, preventing relocation attacks. All header fields are cryptographically authenticated via inclusion in the AAD.

**Sealed Blob v2 AAD Format (Normative)**:

```
aad = aad_prefix || owner_peerid_bytes || canonical_path_bytes || header_bytes
```

Where:
- `aad_prefix`: ASCII bytes `"pubky-envelope/v2:"` (18 bytes)
- `owner_peerid_bytes`: Raw 32-byte Ed25519 public key of storage owner (who writes the object)
- `canonical_path_bytes`: UTF-8 bytes of canonical storage path (see 7.12 for canonicalization rules)
- `header_bytes`: Deterministic CBOR serialization of the full header (see 7.12)

This construction guarantees that ALL header fields (`sender_ephemeral_x25519_pub`, `recipient_peerid`, `sender_peerid`, `kid`, `nonce`, `msg_id`, `context_id`, `created_at`, `expires_at`, `purpose`) are cryptographically authenticated.

**Why header_bytes in AAD?**

Including the entire serialized header in AAD ensures:
1. No header field can be modified without detection
2. No ambiguity about which fields are authenticated
3. Future header extensions are automatically authenticated

**Legacy Paykit AAD Format (Deprecated)**:

For backward compatibility with existing implementations:

```
aad = "paykit:v0:" || purpose || ":" || owner_z32 || ":" || path || ":" || id
```

Where:
- `purpose`: Object type (`request`, `subscription_proposal`, `ack_request`, `ack_subscription_proposal`, `handoff`)
- `owner_z32`: Normalized z-base-32 pubkey of the storage owner
- `path`: Full storage path (e.g., `/pub/paykit.app/v0/requests/{context_id}/{id}`)
- `id`: Object identifier (request_id, proposal_id, msg_id)

**Migration**: New implementations MUST use the header_bytes AAD format. Legacy format is accepted for decryption only during migration period.

**Examples (Legacy Format)**:

Payment request (sender writes to their storage):
```
paykit:v0:request:8um71us...xyz:/pub/paykit.app/v0/requests/abcd1234.../req_001:req_001
```

Encrypted ACK (recipient writes to their storage):
```
paykit:v0:ack_request:tj1igr...abc:/pub/paykit.app/v0/acks/request/abcd1234.../req_001:req_001
```

Secure handoff (Ring user writes to their storage):
```
paykit:v0:handoff:8um71us...xyz:/pub/paykit.app/v0/handoff/abc123:abc123
```

### 7.6 Optional Sender Signature

For messages requiring strong sender authenticity, the sender may include an Ed25519 signature in the header (key 10).

**Signature Input (v2 wire format)**:

```
header_bytes_without_sig = CBOR_encode(header_map excluding key 10)
sig_input = BLAKE3("pubky-envelope-sig/v2" || header_bytes_without_sig || ciphertext_bytes)
sig = Ed25519_Sign(sender_ed25519_sk, sig_input)
```

Where:
- `header_bytes_without_sig`: Deterministic CBOR encoding of the header map with key 10 (`sig`) omitted
- `ciphertext_bytes`: The raw ciphertext (after the header in the wire format)
- `sig`: 64-byte Ed25519 signature, stored in header key 10

**Verification**:

1. Extract `sig` (key 10) from the header
2. Re-encode the header without key 10 to produce `header_bytes_without_sig`
3. Compute `sig_input = BLAKE3("pubky-envelope-sig/v2" || header_bytes_without_sig || ciphertext_bytes)`
4. Verify `sig` against `sender_peerid` (key 9) using Ed25519

**Trust Rule**: The `sender_peerid` field is authenticated via AAD (tamper-evident), but the sender identity is **trusted** only if `sig` verifies. Without a valid signature, treat `sender_peerid` as routing metadata, not proven identity.

**Legacy JSON Format**:

For backward compatibility with JSON envelopes:

```
sig = Ed25519_Sign(
  sender_ed25519_sk,
  BLAKE3("pubky-envelope-sig/v2" || v || epk || sender || nonce || ct)
)
```

### 7.7 ContextId Definition

ContextId provides a stable, symmetric identifier for a peer pair, used in storage paths for routing and correlation.

**Derivation (Normative)**:

```
context_id = SHA256("paykit:v0:context:" || first_z32 || ":" || second_z32)
```

Where:
- `first_z32` and `second_z32` are normalized z-base-32 pubkeys sorted lexicographically
- **Result is 32 raw bytes** (the SHA-256 output, not hex-encoded)
- Symmetric: same value regardless of which party computes it

**Canonical Form**: The canonical `context_id` is always **32 raw bytes**. All cryptographic operations (AAD computation, CBOR serialization, header encoding) use the raw bytes.

**Display Encodings** (for JSON, URLs, human display):

| Encoding | Format | Example Use |
|----------|--------|-------------|
| `context_id_hex` | `hex(context_id)` (64 lowercase chars) | JSON payloads, logs |
| `context_id_z32` | `z-base-32(context_id)` (52 chars) | Storage paths (preferred) |

**Implementation Rule**: When decoding `context_id` from JSON or display format, implementations MUST decode to 32 raw bytes before computing AAD or performing any cryptographic operation.

**z-base-32 Normalization rules** (for input pubkeys):
1. Trim whitespace
2. Strip `pubky://` prefix if present
3. Strip `pk:` prefix if present
4. Lowercase
5. Validate length (52 chars) and z-base-32 alphabet

### 7.8 Storage Layout (Paykit v0)

| Object Type | Path | Stored On |
|-------------|------|-----------|
| Payment Request | `/pub/paykit.app/v0/requests/{context_id}/{request_id}` | Sender |
| Subscription Proposal | `/pub/paykit.app/v0/subscriptions/proposals/{context_id}/{proposal_id}` | Provider |
| ACK | `/pub/paykit.app/v0/acks/{object_type}/{context_id}/{acked_msg_id}` | Receiver |
| Noise Endpoint | `/pub/paykit.app/v0/noise` | Owner |
| Secure Handoff | `/pub/paykit.app/v0/handoff/{request_id}` | Ring User |

**Notes**:
- `{context_id}` in paths: Use `context_id_z32` (z-base-32, 52 chars) or `context_id_hex` (64 chars) — see Section 7.7
- `{acked_msg_id}` in ACK paths: The original message's `msg_id` being acknowledged
- `object_type`: `request` or `subscription_proposal`
- All objects except Noise Endpoint are Sealed Blob v2 encrypted

### 7.9 Encrypted ACK Protocol

ACKs confirm receipt of async messages, enabling reliable delivery without active connections.

**ACK Payload (Normative)**:

ACKs are stored messages and MUST include their own `msg_id`:

```json
{
  "msg_id": "ack_456",           // ACK's own msg_id (REQUIRED)
  "acked_msg_id": "req_123",     // ID of the message being acknowledged (REQUIRED)
  "context_id": "<64-char hex>", // Same thread as original message (REQUIRED)
  "status": "delivered",         // ACK status (REQUIRED)
  "created_at": 1704067200       // Unix timestamp (REQUIRED)
}
```

**Note**: In JSON payloads, `context_id` is encoded as 64-char lowercase hex. In CBOR headers, `context_id` is 32 raw bytes (key 0). Implementations MUST decode hex to bytes before AAD computation.
```

**ACK Status Values**:

| Status | Description |
|--------|-------------|
| `delivered` | Message received and stored |
| `processed` | Message processed successfully (e.g., payment completed) |
| `rejected` | Message rejected (e.g., invalid format, policy violation) |
| `expired` | Message expired before processing |

**ACK Encryption**:

ACKs are **always** Sealed Blob v2 encrypted. No plaintext ACKs.

- Encrypted to the **original sender's** published X25519 key (from their `/pub/paykit.app/v0/noise` endpoint)
- ACK `context_id` MUST match the original message's `context_id`

**ACK Lifecycle**:

1. Receiver decrypts and processes message (payment request or subscription proposal)
2. Receiver discovers sender's X25519 pubkey via their noise endpoint
3. Receiver creates ACK payload with its own `msg_id` and appropriate `status`
4. Receiver encrypts ACK as Sealed Blob v2 to sender's X25519 key
5. Receiver writes encrypted ACK to their own storage at `/pub/paykit.app/v0/acks/{object_type}/{context_id}/{acked_msg_id}`
6. Sender polls receiver's ACK directory until ACK found or `expires_at` elapsed
7. Sender decrypts ACK with their own Noise secret key
8. Sender stops resending after ACK or expiration
9. ACKs are cleaned up by receiver after 7 days (configurable)

**ACK Idempotency**:

- ACKs have their own `msg_id` for deduplication
- Receivers SHOULD NOT generate multiple ACKs for the same `acked_msg_id`
- If regeneration is required (e.g., status update), use a new `msg_id`

**ACK AAD Construction**:

Uses standard Sealed Blob v2 AAD format (Section 7.5). The path includes `acked_msg_id`:

```
/pub/paykit.app/v0/acks/request/{context_id}/{acked_msg_id}
```

### 7.10 Message Kinds (Reserved/Future)

The `kind` field is **not part of Sealed Blob v2**. It is reserved for a potential future typed message routing protocol.

Current Paykit implementations use the `purpose` field for message type discrimination. The `purpose` field is:
- **Cryptographically authenticated** as part of `header_bytes` in AAD (Section 7.5)
- **Semantic hint only** — MUST NOT be used for security decisions (e.g., access control, trust boundaries)

In other words: tampering with `purpose` is detectable via AAD verification failure, but the value itself carries no protocol-level authority.

**Reserved kind ranges (future use)**:

| Range | Purpose |
|-------|---------|
| 0-99 | Core protocol (ACK, ERROR, PING) |
| 100-199 | Paykit (payment requests, receipts, subscriptions) |
| 200-299 | Pubky App (social, follows, posts) |
| 0xFF00-0xFFFF | Extensions |

### 7.11 Replay and Idempotency

Recipients MUST:
- Treat `msg_id` as idempotency key
- Maintain set of seen `msg_id` per sender
- Ignore duplicates

Ordering is not guaranteed. Applications must handle out-of-order delivery.

### 7.12 Canonical Encoding Rules

This section defines normative encoding rules for interoperability.

#### 7.12.1 PeerId Encoding

| Context | Encoding |
|---------|----------|
| Crypto operations (DH, signatures) | Raw 32-byte Ed25519 public key |
| Storage paths | z-base-32 (52 characters, lowercase) |
| AAD owner field | Raw 32 bytes |
| URIs | `pubky://{z32}` |

**Normalization for z-base-32**:
1. Trim whitespace
2. Strip `pubky://` prefix if present
3. Strip `pk:` prefix if present
4. Lowercase
5. Validate length (52 chars) and z-base-32 alphabet

#### 7.12.2 Path Canonicalization

Canonical path bytes for AAD construction:

| Rule | Description |
|------|-------------|
| Encoding | UTF-8 bytes |
| Leading slash | REQUIRED |
| Trailing slash | PROHIBITED (except root `"/"`) |
| Duplicate slashes | PROHIBITED |
| Dot segments | PROHIBITED (no `.` or `..` segments) |
| Percent encoding | PROHIBITED (paths are literal) |
| Character set | ASCII alphanumeric + `/-_.` |

**Invariant**: Canonical path bytes MUST match the storage API path byte-for-byte. Implementations that disagree on path canonicalization will fail AAD verification.

**Example**:
```
Valid:   /pub/paykit.app/v0/requests/abc123/req_001
Invalid: /pub/paykit.app/v0/requests/abc123/req_001/
Invalid: /pub/paykit.app/v0//requests/abc123/req_001
Invalid: /pub/paykit.app/v0/./requests/abc123/req_001
```

#### 7.12.3 Header Serialization (Deterministic CBOR)

Sealed Blob v2 headers use **Deterministic CBOR** per RFC 8949:

| Rule | Description |
|------|-------------|
| Key ordering | Lexicographic by encoded key bytes |
| Numeric encoding | Shortest form (no leading zeros) |
| String encoding | UTF-8, definite length |
| Bytes encoding | Definite length |
| Map/array encoding | Definite length (no indefinite) |
| Duplicate keys | PROHIBITED |

**Field Key Mapping (Integer Keys for Compactness)**:

| Key | Field Name |
|-----|------------|
| 0 | `context_id` |
| 1 | `created_at` |
| 2 | `expires_at` |
| 3 | `kid` |
| 4 | `msg_id` |
| 5 | `nonce` |
| 6 | `purpose` |
| 7 | `recipient_peerid` |
| 8 | `sender_ephemeral_x25519_pub` |
| 9 | `sender_peerid` |
| 10 | `sig` |

**Rationale**: Integer keys reduce header size. Lexicographic ordering of integer CBOR keys (0 < 1 < ... < 10) matches numeric order for single-byte keys.

**Example CBOR Header** (conceptual):
```
{
  0: h'<32 bytes context_id>',
  1: 1704067200,
  3: h'<16 bytes kid>',
  4: "req_001",
  5: h'<24 bytes nonce>',
  7: h'<32 bytes recipient_peerid>',
  8: h'<32 bytes sender_ephemeral>',
  9: h'<32 bytes sender_peerid>'
}
```

### 7.13 Resend Defaults (Paykit)

This section defines default retry behavior for Paykit stored messages.

**Required Message Fields for Resend**:

Every resendable message MUST include:
- `msg_id`: Idempotency key for deduplication
- `expires_at`: Absolute expiration timestamp (Unix seconds)

**Default Retry Schedule**:

| Retry | Delay After Previous |
|-------|---------------------|
| 1 | 1 minute |
| 2 | 2 minutes |
| 3 | 4 minutes |
| 4 | 8 minutes |
| 5 | 16 minutes |

**Jitter**: Apply +/- 20% random jitter to each interval to prevent thundering herd.

**Maximum Retries**: 5 attempts (6 total including initial send)

**Stop Conditions**:

Sender MUST stop resending when ANY of these conditions is met:
1. ACK received for `msg_id`
2. Current time >= `expires_at`
3. Maximum retries reached

**Example Timeline**:

```
T+0:00   Initial send
T+1:00   Retry 1 (if no ACK)
T+3:00   Retry 2
T+7:00   Retry 3
T+15:00  Retry 4
T+31:00  Retry 5 (final)
```

**Override**: Applications MAY override these defaults based on message criticality. High-value payment requests MAY use more aggressive retry schedules.

---

## 8. Session and Message Binding

### 8.1 Live Session Binding

For messages over active Noise transport:
- Include `session_id` (handshake hash) in message payload
- Receiver verifies session_id matches current session
- Prevents message injection across sessions

### 8.2 Envelope Binding

For async envelopes:
- AAD binds ciphertext to storage path, owner, and full header (including `sender_peerid`)
- `sender_peerid` (header key 9) identifies the claimed originator
- `sig` (header key 10), when present, provides non-repudiation

### 8.3 Peer Identity

**Live transport**: Ed25519 public key from verified `IdentityPayload`

**Async envelope**: `sender_peerid` (header key 9) identifies the claimed sender.
- **Tamper-evident**: `sender_peerid` is authenticated via AAD; modification causes decryption failure
- **Not trusted by default**: Sender identity is only *proven* if `sig` (key 10) verifies for `sender_peerid`
- Without a valid signature, treat `sender_peerid` as routing metadata only

### 8.4 ContextId vs SessionId

- **SessionId**: Derived from Noise handshake transcript hash. Changes on every new handshake. Only available after handshake completes. Used for live session binding.

- **ContextId**: Derived from peer pubkey pair (Section 7.7). Stable across handshakes. Used for storage path routing, app-level correlation, and ACK bookkeeping.

**Important**: ContextId MUST NOT be used to resume half-complete Noise handshakes. Noise provides no built-in handshake resume; ContextId is strictly for app-layer routing and correlation.

### 8.5 PeerPairFingerprint

PeerPairFingerprint provides a stable, human-comparable identifier for out-of-band verification of a peer relationship.

**Purpose**: Enable users to detect TOFU (Trust On First Use) MITM attacks by comparing fingerprints out-of-band (e.g., verbally, via QR code, or secure channel).

**Derivation (Normative)**:

```
sorted_peerids = [min(peerid_a, peerid_b), max(peerid_a, peerid_b)]
fingerprint = BLAKE3("pubky-peerpair/v1" || sorted_peerids[0] || sorted_peerids[1])
```

Where:
- `peerid_a`, `peerid_b`: Raw 32-byte Ed25519 public keys
- `min`/`max`: Lexicographic comparison of raw bytes
- Result: 32-byte BLAKE3 hash

**Display Format**:

```
display = base32(fingerprint[0..10])  // First 10 bytes -> 16 characters
formatted = "XXXX-XXXX-XXXX-XXXX"      // Groups of 4 for readability
```

**Example**:
```
Fingerprint: ABCD-EFGH-IJKL-MNOP
```

**Properties**:
- **Symmetric**: Same value regardless of which party computes it
- **Stable**: Does not change across handshakes or key rotations (derived from PeerIds only)
- **Deterministic**: Same inputs always produce same output

**Security Caveat**:

PeerPairFingerprint is a **hint mechanism** for human verification. It does NOT:
- Provide cryptographic proof of identity
- Replace Noise authentication
- Prevent MITM if fingerprints are not compared

The XX Noise pattern provides authentication against passive observers but is vulnerable to active MITM on first contact. Fingerprint comparison enables detection of MITM attacks through an independent channel.

---

## 9. Key Rotation

### 9.1 Epoch Increment

When rotating Noise static keys:
1. Increment `epoch` in Ring
2. Derive new `NOISE_STATIC_SK` using new epoch
3. Publish new public key to PKARR (optional)
4. Accept messages encrypted to old epoch during grace period

### 9.2 Key Selection for Envelopes

When decrypting envelopes, use the `kid` field (header key 3) for key selection:

**v2 Envelopes (binary wire format)**:

- `kid` is **REQUIRED** (16 bytes)
- v2 envelope without `kid` is **malformed** — reject immediately
- Look up `kid` in local keyring: `{ kid -> X25519_sk }`
- If no match, return `KeyNotFound`

**v1 Envelopes (legacy JSON format)**:

- `kid` is optional (8 bytes if present)
- If `kid` present: look up in keyring
- If `kid` absent: try current epoch key only
- If decryption fails, return `DecryptionFailed`

**Keyring maintenance**:
- Maintain mapping `{ kid -> sk }` for current and N previous epochs
- Retain old keys for ACK TTL period (default 7 days)
- Prune expired keys after grace period

### 9.3 PKARR Publication

Optional: publish current epoch and Noise static public key in PKARR DNS records for discovery.

---

## 10. Backup and Restore

### 10.1 Device Restore

1. Restore PKARR identity seed to Ring
2. Re-derive `APP_SEED`, `NOISE_SEED`, `NOISE_STATIC_SK` from Ring
3. Re-derive `LOCAL_ARCHIVE_KEY` to decrypt local history
4. Poll homeserver outbox folders for missed messages
5. No transport state is restored (re-handshake required)

### 10.2 Homeserver Backup

Only encrypted blobs are backed up. Restoring homeserver state does not expose plaintext.

### 10.3 Local Archive

Optional: encrypt full message history for backup using `LOCAL_ARCHIVE_KEY`. Store separately from outbox envelopes.

---

## 11. Security Considerations

### 11.1 Memory Hygiene

- Use `zeroize` crate for secret buffers
- Wrap secrets in `Zeroizing<[u8; 32]>`
- Minimize copies of key material
- Never log secrets or plaintext

### 11.2 Platform Limitations

iOS/Android do not provide true secure memory. Best-effort mitigations:
- Derive on demand, use immediately, zeroize
- Don't persist transport secrets
- Use platform keychain/keystore for long-term secrets

### 11.3 Invalid Peer Keys

Before performing X25519 DH, verify peer public key is not:
- All zeros
- Low-order point

```rust
fn shared_secret_nonzero(sk: &[u8; 32], pk: &[u8; 32]) -> bool {
    let shared = x25519(*sk, *pk);
    shared.iter().any(|&b| b != 0)
}
```

Reject handshakes with invalid peer keys.

### 11.4 Timing Attacks

ChaCha20-Poly1305 verification is constant-time. No additional measures required for AEAD.

Ed25519 signature verification uses constant-time comparison. No additional measures required.

### 11.5 Forward Secrecy

Live transport: provided by ephemeral X25519 keys in Noise handshake.
Async envelopes: provided by sender's ephemeral X25519 key per message.

### 11.6 Traffic Analysis

Out of scope for initial release. Future mitigations:
- Padding messages to fixed sizes
- Randomized polling intervals
- Decoy traffic

---

## 12. Implementation Reference

### 12.1 Repositories

| Repository | Purpose |
|------------|---------|
| `pubky-ring` | Identity management, seed custody, authorization |
| `pubky-noise` | Noise handshake, transport, envelopes |
| `paykit-rs` | Payment protocols, receipts, subscriptions |
| `bitkit-android` / `bitkit-ios` | Wallet integration |
| `pubky-core` | Homeserver, SDK, storage |

### 12.2 Key Files

| File | Purpose |
|------|---------|
| `pubky-noise/src/kdf.rs` | Key derivation functions |
| `pubky-noise/src/ring.rs` | RingKeyProvider trait |
| `pubky-noise/src/sealed_blob.rs` | Envelope encryption |
| `pubky-noise/src/session_id.rs` | Session identifier |
| `pubky-noise/src/transport.rs` | Noise transport wrapper |
| `pubky-noise/src/identity_payload.rs` | Identity binding |

### 12.3 Test Vectors

Test vectors for interoperability testing are defined in `pubky-noise/tests/`.

---

## Appendix A: Domain Separation Strings

| Constant | Value |
|----------|-------|
| App seed salt | `"pubky-ring/app-seed/v1"` |
| Noise seed salt | `"pubky-ring/noise-seed/v1"` |
| X25519 derivation salt | `"pubky-noise-x25519:v1"` |
| Local archive salt | `"pubky-ring/local-archive/v1"` |
| Identity binding prefix | `"pubky-noise-bind:v1"` |
| Envelope key info | `"pubky-envelope/v2"` |
| Envelope AAD prefix | `"pubky-envelope/v2:"` |
| Envelope signature prefix | `"pubky-envelope-sig/v2"` |
| PeerPairFingerprint prefix | `"pubky-peerpair/v1"` |
| ContextId prefix | `"paykit:v0:context:"` |
| Paykit AAD prefix (legacy) | `"paykit:v0:"` |

---

## Appendix B: Encoding Reference

### B.1 Sealed Blob v2 Wire Format (Normative)

| Component | Encoding |
|-----------|----------|
| Magic bytes | `0x53 0x42 0x32` ("SB2") |
| Version | u8 (2) |
| Header length | u16 big-endian |
| Header | Deterministic CBOR (RFC 8949) with integer keys |
| Ciphertext | Raw bytes (XChaCha20-Poly1305 output) |

### B.2 Legacy JSON Format (Deprecated)

| Data | Encoding |
|------|----------|
| Keys in JSON envelopes | base64url (no padding) |
| `kid` in JSON | hex (16 bytes) |

JSON format is accepted for backward compatibility only. New implementations SHOULD use the binary wire format.

### B.3 General Encodings

| Data | Encoding |
|------|----------|
| PKARR public key in URIs | z-base-32 (52 chars) |
| Keys in handoff payloads | hex |
| Message IDs | hex or base32 |
| Paths | ASCII, alphanumeric + `/-_.` |
| `kid` | 16 bytes (raw in CBOR, hex in JSON) |
| `context_id` | 32 bytes (raw in CBOR, hex or z-base-32 in JSON/paths) |

---

## Appendix C: Comparison with Current Implementation

This section documents gaps between the spec and current implementation.

### C.1 Implemented

| Feature | Status | Location |
|---------|--------|----------|
| X25519 derivation with device_id + epoch | ✅ Implemented | `pubky-noise/src/kdf.rs` |
| Session ID from handshake hash | ✅ Implemented | `pubky-noise/src/session_id.rs` |
| Sealed Blob v2 encryption | ✅ Implemented | `pubky-noise/src/sealed_blob.rs` |
| RingKeyProvider trait | ✅ Implemented | `pubky-noise/src/ring.rs` |
| Identity binding in handshake | ✅ Implemented | `pubky-noise/src/identity_payload.rs` |
| Secure handoff (Ring → Bitkit) | ✅ Implemented | `pubky-ring/src/utils/actions/paykitConnectAction.ts` |
| Domain separation (single X25519 key) | ✅ Specified | Section 4.7 |

### C.2 Specified in v2.3 (Pending Implementation)

| Feature | Status | Notes |
|---------|--------|-------|
| ContextId derivation | 📋 Specified | Section 7.7; requires `paykit-lib` implementation |
| Header-bytes AAD construction | 📋 Specified | Section 7.5; replaces legacy string AAD |
| Encrypted ACK protocol with status | 📋 Specified | Section 7.9; ACKs now have own `msg_id` and `status` |
| PeerPairFingerprint | 📋 Specified | Section 8.5; BLAKE3-based, frozen |
| KeyBinding and pinning rules | 📋 Specified | Section 6.8; XX-to-IK upgrade rules |
| Resend defaults | 📋 Specified | Section 7.13; 1m/2m/4m/8m/16m schedule |
| Ring FFI interface | 📋 Specified | Section 5.3; EncryptedSkHandle semantics |
| Canonical encoding (CBOR headers) | 📋 Specified | Section 7.12; deterministic CBOR per RFC 8949 |
| kid 16-byte derivation | 📋 Specified | Section 7.2; `first_16_bytes(SHA256(pk))` |
| Double encryption prohibition | 📋 Specified | Section 1.4; live vs stored delivery |

### C.3 Not Yet Implemented

| Feature | Status | Notes |
|---------|--------|-------|
| APP_SEED derivation layer | ❌ Not implemented | Currently uses ed25519 seed directly |
| Role parameter in X25519 derivation | ❌ Not implemented | Info is `device_id \|\| epoch` only |
| LOCAL_ARCHIVE_KEY derivation | ❌ Not implemented | Needs new function in kdf.rs |
| kid-based key selection (16 bytes) | ❌ Not implemented | Uses single epoch; keyring lookup needed |
| Binary wire format for Sealed Blob | ❌ Not implemented | JSON format still in use |
| Deterministic CBOR headers | ❌ Not implemented | Requires header serialization update |
| PeerPairFingerprint computation | ❌ Not implemented | Needs BLAKE3 integration |
| KeyBinding via PKARR | ❌ Not implemented | Requires PKARR metadata extension |

---

*This specification is maintained in the Pubky ecosystem repositories.*

