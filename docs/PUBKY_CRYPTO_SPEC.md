# Pubky Cryptographic Specification

**Version**: 2.5  
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
   - 8.4 [ContextId vs SessionId vs PairContextId](#84-contextid-vs-sessionid-vs-paircontextid)
   - 8.5 [PeerPairFingerprint](#85-peerpairfingerprint)
9. [Key Rotation](#9-key-rotation)
10. [Backup and Restore](#10-backup-and-restore)
11. [Security Considerations](#11-security-considerations)
12. [Implementation Reference](#12-implementation-reference)

**Appendices**:
- [Appendix A: Domain Separation Strings](#appendix-a-domain-separation-strings)
- [Appendix B: Encoding Reference](#appendix-b-encoding-reference)
- [Appendix C: Comparison with Current Implementation](#appendix-c-comparison-with-current-implementation)
- [Appendix D: Specification Organization](#appendix-d-specification-organization)

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

6. **Ring network isolation**: Ring **MUST NOT** have network access. All network operations (homeserver communication, PKARR queries, DHT operations) are performed by the app layer. Ring is a local cryptographic component only.

### 1.2 Threat Model

| Assumption | Description |
|------------|-------------|
| Device OS not actively malicious | We don't claim HSM-grade RAM protection |
| Homeserver untrusted | May delete, delay, reorder, replay stored blobs |
| Network adversary passive | Can observe timing/metadata; active MITM prevented by Noise |
| Traffic analysis out of scope | Timing attacks addressed in future work |

**DoS Threat Model**:

| Threat | Mitigation |
|--------|------------|
| Attacker floods with arbitrary inbox_kid | Bounded keyring. Unknown inbox_kid MUST be rejected immediately WITHOUT calling Ring derivation. |
| Attacker floods with arbitrary context_id | Apps MUST NOT create unbounded state keyed by context_id. Limit tracked contexts. |
| Attacker sends oversized CBOR headers | Reject header_len > 2048. Reject depth > 2. Reject > 16 keys. |
| Handshake rate exhaustion | Rate limit per IP (gameable). Defense in depth via homeserver rate limiting. |
| Epoch spoofing via UDP | Remove epoch from wire format entirely. Tracking becomes meaningless. |

**Critical DoS Rule**: When `inbox_kid` in a Sealed Blob header does not match any known key, the receiver MUST drop the message **WITHOUT calling any Ring derivation function**. This prevents attackers from grinding the Ring API with random kid values.

### 1.3 Required Properties

- Message confidentiality against homeserver and passive observers
- Message integrity and sender authenticity when signatures present
- Replay resistance and idempotency at application layer
- **No stored Noise ciphertext**: MUST NOT store Noise transport ciphertext for offline delivery. Noise is live-only.

### 1.4 Live Transport vs Stored Delivery

The Pubky protocol distinguishes between two delivery modes:

| Mode | Encryption | Use Case |
|------|------------|----------|
| **Live Transport** | Noise (ChaCha20-Poly1305) | Real-time bidirectional communication |
| **Stored Delivery** | Sealed Blob (XChaCha20-Poly1305) | Async messages stored on homeserver |

**Invariants**:
1. Live transport uses Noise and encrypts plaintext message schemas
2. Stored delivery uses Sealed Blob and encrypts plaintext message schemas
3. **MUST NOT** store Noise transport ciphertext for offline delivery. Noise session keys are not exported; if session state is lost, queued Noise ciphertext becomes permanently undecryptable. Stored delivery MUST use Sealed Blob only.
4. MUST NOT wrap Sealed Blob inside Noise for stored delivery (anti-pattern: storing Noise-encrypted Sealed Blobs)

**Allowed Exception (Backup Transport)**:

Noise channels MAY be used to transfer already-encrypted backup blobs as a **live transport mechanism**:
- Blobs encrypted under `LOCAL_ARCHIVE_KEY` or a dedicated backup key
- Noise provides transport confidentiality; the blob provides at-rest confidentiality
- This is explicitly allowed because Noise is used for live transfer, not stored delivery

**Message Schema Reuse**: Paykit defines plaintext schemas for each message kind. The same schema is:
- Carried inside Noise frames (live transport), OR
- Used as Sealed Blob plaintext payload (stored delivery)

One encryption layer at a time for the stored delivery primitive. Backup transport is a separate concern.

### 1.5 Relationship to Noise Protocol

This section clarifies what the Noise protocol provides and what Pubky adds on top.

**What Noise Provides** (we rely on):
- Transport confidentiality via ChaCha20-Poly1305
- Mutual authentication via static key verification
- Forward secrecy via ephemeral DH
- Replay protection via nonce counters (in-session)

**What We Add**:
- Sealed Blob for stored delivery (Noise is live-only)
- Identity binding (Ed25519 to X25519)
- Storage location binding via AAD
- Async message delivery via homeserver

**What Noise Provides That We Don't Use**:
- Noise PSK patterns (pre-shared keys)
- Noise fallback patterns
- Noise re-key for long sessions (we re-handshake instead)

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

**XChaCha20-Poly1305 Note**: XChaCha20-Poly1305 is based on IETF draft-irtf-cfrg-xchacha. While not RFC-standardized, it is widely implemented (libsodium, ring, chacha20poly1305 crate) and considered cryptographically sound for production use. The 192-bit nonce eliminates collision risk for random nonce generation.

**Primitive Selection Rationale (Mobile-Optimized)**:

| Choice | Rationale |
|--------|-----------|
| **XChaCha20-Poly1305** for stored delivery | Random nonce safety: 192-bit nonce space eliminates collision risk for independent message encryption. Critical for mobile where counter state is hard to persist reliably. |
| **ChaCha20-Poly1305** for live transport | Noise protocol standard. Counter nonces managed by library, no random generation needed per frame. |
| **BLAKE3** for fingerprints/tags | Performance-optimized for non-RFC contexts. Faster than SHA-256 on mobile ARM. |
| **BLAKE2s** in Noise patterns | Fixed by Noise protocol specification (e.g., `Noise_XX_25519_ChaChaPoly_BLAKE2s`). |
| **Ed25519** for identity | Widely deployed, deterministic signatures, constant-time implementations available. |
| **X25519** for key exchange | Fast, constant-time, compatible with Ed25519 keys via birational map. |

These primitives prioritize: correctness without state (random nonces), mobile ARM performance, and interoperability with existing Noise implementations.

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

- `device_id`: 16 bytes minimum, stable per authorized device
- `epoch`: 32-bit little-endian integer, starts at 0
- `role`: ASCII string (e.g., `"transport"`, `"handoff"`) — **optional, for future domain separation**

**Epoch Encoding (Normative)**:

Epoch MUST be encoded as 32-bit little-endian bytes when used in key derivation. This encoding is normative and MUST be consistent across all implementations.

**Important**: Epoch is Ring-internal derivation state. Applications SHOULD use `key_version` for key management instead of exposing raw epoch values. Epoch MUST NOT appear in any wire format or cross-device protocol message.

**Current implementation note**: The `role` parameter is not yet implemented. Current derivation uses `device_id || epoch` only.

### 4.5 X25519 Clamping

Per RFC 7748:
```
sk[0]  &= 248
sk[31] &= 127
sk[31] |= 64
```

**Entropy Implications**:

X25519 key derivation applies clamping to the 32-byte scalar:
- Bits 0, 1, 2 are cleared (scalar is multiple of 8)
- Bit 255 is cleared
- Bit 254 is set

This clamping is mandatory per RFC 7748 and is applied automatically by the `x25519-dalek` crate. The clamping removes approximately 3 bits of entropy from the derived key, which is acceptable given the 252-bit security level of Curve25519. Implementations **MUST NOT** skip or modify clamping.

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

### 4.8 InboxKey vs TransportKey Separation

This section defines the key role separation for future versions and MVP constraints.

**InboxKey**:
- X25519 key used ONLY for Sealed Blob stored delivery
- Published in PKARR KeyBinding for senders to encrypt to
- `inbox_kid` derived from this key via `first_16_bytes(SHA256(inbox_x25519_pub))`

**TransportKey**:
- X25519 key used ONLY for Noise static key in live transport
- Used in XX and IK handshake patterns
- May be published in PKARR for IK pattern

**Reuse Rule (MVP)**:
- Reusing the same X25519 key for both InboxKey and TransportKey is **PROHIBITED in MVP**
- Domain separation via HKDF info strings provides safety if reuse is ever allowed
- Future versions MAY allow reuse with explicit configuration and domain separation labels

**Rationale**: Separating keys limits blast radius of key compromise and simplifies key rotation.

**Key Discovery**:

| Key Type | Discovery Source |
|----------|------------------|
| InboxKey | PKARR KeyBinding `inbox_keys` list |
| TransportKey | PKARR KeyBinding `transport_keys` list or `/pub/paykit.app/v0/noise` endpoint |

Implementations MUST NOT use TransportKey for Sealed Blob encryption or InboxKey for Noise handshakes.

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
// List all inbox public keys for an app (app builds kid -> key_version cache)
fn list_inbox_pubkeys(app_id: &str) -> Vec<InboxKeyInfo>;

struct InboxKeyInfo {
    x25519_pub: [u8; 32],
    kid: [u8; 16],
    key_version: u32,
}

// Derive an inbox secret handle by version (bounded by max_inbox_key_version)
fn derive_inbox_handle(app_id: &str, key_version: u32) -> Result<EncryptedSkHandle, Error>;

// Derive a transport secret handle for Noise
fn derive_transport_handle(app_id: &str, device_id: &[u8; 16], key_version: u32) -> Result<EncryptedSkHandle, Error>;

// Query current maximum versions (for bounds checking)
fn get_max_inbox_key_version(app_id: &str) -> u32;
fn get_max_transport_key_version(app_id: &str, device_id: &[u8; 16]) -> u32;
```

#### 5.3.2 State Model (Bounded, Not Unbounded)

**Ring stores only counters, not mappings**:

| State | Scope | Description |
|-------|-------|-------------|
| `max_inbox_key_version` | Per `(identity, app_id)` | Maximum valid inbox key version |
| `max_transport_key_version` | Per `(identity, app_id, device_id)` | Maximum valid transport key version |

**App responsibility**: The **app** caches `{ kid -> key_version }` locally. This mapping is:
- Non-secret (derived from public keys)
- Bounded by `max_key_version`
- Built from `list_inbox_pubkeys()` results

**Why this design**:

The previous design ("Ring maintains `{ kid -> secret_key }`") implied unbounded state growth and a trivial DoS vector: an attacker could send envelopes with arbitrary `kid` values, forcing Ring to attempt derivations or store failed lookups. The bounded version design:
- Limits Ring state to small counters
- Makes the attack surface explicit
- Moves the (safe, non-secret) kid lookup to the app layer

**Ring State Bounds (Normative)**:

| Requirement | Description |
|-------------|-------------|
| Bounded state | Ring state MUST be bounded (not unbounded growth) |
| Cache limits | Caches keyed by remote/attacker-controlled inputs MUST have explicit size limits |
| Eviction policy | Caches MUST implement eviction policy (e.g., LRU) |
| Rate limiting | Ring MUST rate-limit derivation calls per app |

**Recommended Defaults** (non-normative):
- MAX 16 active inbox keys per (identity, app_id)
- MAX 4 active transport keys per (identity, app_id, device_id)
- Rate limit: 10 derivation calls per second per app

#### 5.3.3 Derivation Constraints

Ring MUST enforce:

| Constraint | Description |
|------------|-------------|
| Version bounds | `key_version <= max_version` for the requested scope |
| Rate limiting | Derivation calls per app MUST be rate-limited to mitigate compromised-app brute force |
| Monotonic versions | `max_version` only increments, never decrements |

Apps MUST:

| Rule | Description |
|------|-------------|
| Use discovered versions | Only request versions discovered via `list_inbox_pubkeys()` |
| Handle `KeyNotFound` | If `kid` not in local cache, return error (do not guess versions) |
| Bound cache size | Limit cached entries to `max_version + grace_period_versions` |

#### 5.3.4 EncryptedSkHandle Semantics

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

### 5.4 Platform Keychain Integration

**iOS Keychain**:
- Store NOISE_SEED, Ed25519 seeds, and derived secrets in Keychain
- Use access control: `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`
- This provides software-level protection with device binding

**iOS Secure Enclave Limitation**: The iOS Secure Enclave (via CryptoKit `SecureEnclave.P256`) **only supports P-256 keys**, not Ed25519 or X25519. Therefore:
- Ed25519 signing and X25519 key exchange CANNOT be performed directly in Secure Enclave
- Use Keychain with strong accessibility class for Ed25519/X25519 material
- If hardware-backed protection is critical, consider using Secure Enclave for wrapping keys (encrypt Ed25519 seed under a P-256 key stored in SE), but this adds complexity

**Android Keystore / TEE**:
- Store secrets in Android Keystore with hardware backing when available
- Use StrongBox if present
- Android Keystore does support Ed25519 on newer API levels (API 33+)

**Hot Memory Rule**: Keypairs and seeds **MUST NOT** reside in hot memory longer than necessary in production. Derive on demand, use immediately, zeroize.

**DummyRing Warning**: The `DummyRing` implementation in pubky-noise is for **testing only**. Production deployments MUST use platform keychain/keystore integration.

#### 5.3.5 FFI Safety Rules

| Rule | Description |
|------|-------------|
| No function pointers | Avoid callbacks that could be hijacked |
| Bytes in, bytes out | All parameters are byte arrays or primitives |
| No persistent handles | Handles are valid only for immediate use |
| Explicit lifetime | Callers must not cache handles across operations |

**Example Usage (Conceptual)**:

```rust
// App startup: build kid -> key_version cache from Ring
let inbox_keys = ring.list_inbox_pubkeys("bitkit");
let kid_cache: HashMap<[u8; 16], u32> = inbox_keys
    .iter()
    .map(|k| (k.kid, k.key_version))
    .collect();

// App receives a Sealed Blob envelope
let kid = extract_kid_from_envelope(&envelope);  // 16 bytes from header key 3

// App looks up key_version (non-secret, local cache)
let key_version = kid_cache.get(&kid)
    .ok_or(Error::KeyNotFound)?;

// App calls Ring with bounded version (not arbitrary kid)
let handle = ring.derive_inbox_handle("bitkit", *key_version)?;
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

**Prologue Policy (Normative)**:

The prologue MUST be a fixed constant per protocol version. For v1:

```
prologue = b"pubky-noise-v1"  // 14 bytes
```

Arbitrary or caller-supplied prologues are **PROHIBITED** to prevent covert channels and interoperability failures.

**Rationale**: Antoine suggested making prologue a method parameter for flexibility. We chose a fixed constant instead because:
1. Covert channels: Arbitrary prologues could be used to leak information
2. Interoperability: All implementations must agree on prologue for handshake to succeed
3. Simplicity: One less parameter to configure incorrectly
4. Version binding: Prologue changes with protocol version, not per-call

**Multi-Step DH Verification**:

The Noise XX pattern performs multiple Diffie-Hellman operations during the handshake. The `snow` library verifies the result of each DH step internally, rejecting low-order points that would produce all-zero shared secrets. Implementations using `snow` do not need to add additional verification; the library handles this. Implementations using other Noise libraries MUST verify that each DH result is not all-zeros before proceeding.

### 6.3 Identity Binding

During handshake, each party sends an `IdentityPayload`:

```rust
struct IdentityPayload {
    peerid: [u8; 32],              // Ed25519 identity (PKARR public key)
    role: Role,                     // Client or Server (see note)
    server_hint: Option<String>,    // Routing hint (non-normative, see below)
    hint_expires_at: Option<u64>,   // TTL for server_hint only (optional)
    sig: [u8; 64],                  // Ed25519 signature over binding message
}
```

**Design Rationale**:

- **No `epoch`**: Epoch is Ring-internal derivation metadata. Including it in the wire format would leak timing correlation and internal state. Epoch MUST NOT appear in signed payloads.
- **No `noise_x25519_pub`**: The Noise static keys are already carried by the Noise handshake itself (XX/IK patterns). Duplicating them in IdentityPayload adds wire bytes and creates mismatch ambiguity.
- **`hint_expires_at`**: Scoped exclusively to `server_hint` routing metadata. Does NOT affect key validity or session lifetime.

**role Field**: The Noise state machine knows which side it is. The `role` field in IdentityPayload exists for application-layer disambiguation (e.g., logging, debugging). While the field itself is not independently verified, `role` IS cryptographically significant because it is included in the binding message signature (Section 6.4). This provides domain separation: a client's signature cannot be replayed as a server's signature, even with identical keys.

**server_hint (Non-Normative Metadata)**:

The `server_hint` field is **OPTIONAL, non-normative** metadata:
- MAY be omitted from identity payloads
- MAY be rotated freely without affecting identity
- SHOULD NOT be considered part of core identity binding
- If present in signed payloads, authenticity is verified but semantics/reachability are not enforced

### 6.4 Binding Message

The `sig` field in `IdentityPayload` is computed over a binding message that ties the Ed25519 identity to the Noise handshake.

**Binding Message Construction (Normative)**:

```
binding_message = BLAKE3(
    "pubky-noise-binding/v1" ||
    peerid ||                    // 32 bytes: Ed25519 public key
    noise_static_pub ||          // 32 bytes: X25519 public key from handshake
    role_byte ||                 // 1 byte: 0x00=Client, 0x01=Server
    remote_static_pub            // 32 bytes: peer's X25519 public key
)

sig = Ed25519_Sign(peerid_sk, binding_message)
```

Where:
- `peerid`: The sender's Ed25519 public key
- `noise_static_pub`: The sender's X25519 static public key used in this handshake
- `role_byte`: `0x00` for Client, `0x01` for Server
- `remote_static_pub`: The peer's X25519 static public key from the handshake

**Verification**:

1. Extract `peerid` and `sig` from received IdentityPayload
2. Obtain `noise_static_pub` from Noise handshake state (peer's static key)
3. Compute `binding_message` using above formula
4. Verify `sig` against `peerid` using Ed25519

**Security Properties**:
- Binds Ed25519 identity to specific X25519 Noise static key
- Binds to specific handshake instance (includes remote key)
- Prevents identity payload replay across different sessions

**Note**: `epoch` is explicitly excluded from the binding transcript. Key derivation epoch is Ring-internal state and MUST NOT be exposed on the wire.

**Legacy Format (Deprecated)**:

The previous binding format using BLAKE2s and additional fields is deprecated:

```
binding = BLAKE2s(
  "pubky-noise-bind:v1" ||
  pattern_tag ||
  prologue ||
  peerid ||
  local_noise_pub ||
  remote_noise_pub? ||
  role_string ||
  server_hint? ||
  hint_expires_at?
)
```

New implementations MUST use the BLAKE3 format above.

### 6.5 Session Identifier

Derived from the Noise handshake transcript hash:

```rust
let session_id = SessionId(hs.get_handshake_hash());
```

This is a 32-byte value unique to each completed handshake. It changes on every new handshake, even between the same parties.

**Important**: Do NOT use `DH(static_a, static_b)` as a session tag. That produces a peer-pair tag which is static across sessions.

### 6.6 Transport Encryption

Post-handshake messages use the Noise transport mode with ChaCha20-Poly1305. The library handles nonce management internally.

**Transport Nonce Handling (Normative)**:

Noise uses a 64-bit little-endian counter as the nonce, encoded into a 96-bit (12-byte) nonce as per the Noise specification. The `snow` library manages this counter internally. Implementations **MUST NOT** manually manage Noise nonces. Attempting to set or export nonces breaks the security model.

### 6.9 Protocol Symmetry Considerations

**Current Architecture**: pubky-noise uses client-server model (`client.rs`, `server.rs`). One peer initiates (client), one responds (server).

**Implication for P2P**: Two peers must decide out-of-band who initiates. For stored delivery, this is less relevant (either can write to their inbox, other polls).

**pubky-data Approach**: Fully symmetric `PubkyDataEncryptor`. Either peer can encrypt/decrypt without role assignment.

**Decision Point for Implementation**:

- **Option A**: Keep client-server architecture. Define convention for role selection (e.g., lexicographically smaller PeerId initiates).
- **Option B**: Refactor pubky-noise toward symmetric peer API. Either side can initiate, both poll inbox.

This decision should be made before significant new development on pubky-noise.

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
    peerid: [u8; 32],                // Ed25519 identity (PeerId)
    inbox_keys: Vec<InboxKeyEntry>,  // For Sealed Blob encryption
    transport_keys: Vec<TransportKeyEntry>, // For Noise sessions (optional)
    published_at: Option<u64>,       // OPTIONAL: coarse timestamp (day granularity preferred)
    signature: [u8; 64],             // Ed25519 signature by peerid
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

**Timestamp Privacy**:

- `published_at` is **OPTIONAL** and **default off** for publication
- Fine-grained timestamps leak key creation timing and correlate communication windows
- Use `key_version` as the primary ordering mechanism
- If staleness heuristic is needed, use PKARR record TTL/update metadata or coarse-grained day granularity
- Implementations SHOULD NOT publish fine-grained timestamps by default

#### 6.8.2 Pinning Rules (Normative)

| Condition | Required Pattern | Rationale |
|-----------|------------------|-----------|
| No verified KeyBinding for target PeerId | MUST use XX | No trusted key to encrypt initiator static |
| Verified KeyBinding exists | MAY use IK | Initiator can encrypt static to known responder key |
| KeyBinding expired or revoked | MUST use XX | Treat as unknown |

**MVP Policy (Normative)**:

For MVP, implementations MUST follow these conservative defaults:

| Rule | Description |
|------|-------------|
| XX by default | Use Noise_XX for all arbitrary/unknown peers |
| No automatic IK promotion | MUST NOT automatically upgrade XX -> IK for arbitrary peers |
| Explicit opt-in only | IK allowed only for: (1) explicit service peers, or (2) peers with verified KeyBinding AND explicit user/app policy acceptance |
| Rate limiting | Any IK promotion MUST be rate-limited to prevent sybil injection |

**Rationale**: Automatic XX -> IK upgrade can be abused for resource exhaustion (forcing implementations to store many pinned keys) and sybil injection (attacker creates many peer identities). MVP restricts IK to controlled scenarios.

**Upgrade to IK** (when explicitly allowed):

Implementations MUST NOT upgrade to IK until:
1. A KeyBinding for the target PeerId has been fetched and verified
2. The TransportKey in the KeyBinding has been pinned locally
3. The PeerId has been associated with the pinned TransportKey
4. The upgrade has been explicitly approved by user action or allowlisted policy

**Pin Storage**:

Implementations SHOULD persist pinned keys with:
- `peerid`: The Ed25519 public key
- `transport_x25519_pub`: The pinned Noise static key
- `key_version`: The version from KeyBinding
- `pinned_at`: Timestamp of pinning
- `last_verified`: Last time KeyBinding was re-verified

#### 6.8.3 XX to IK Upgrade Rules

**What is Pinned**:
- Peer Ed25519 identity key (PeerId)
- Optionally: peer TransportKey X25519 static (if verified via PKARR KeyBinding)

**XX to IK Upgrade Rules (Normative)**:

1. First contact MUST use XX pattern (TOFU)
2. After successful XX handshake, MAY pin the peer's TransportKey
3. Upgrade to IK pattern is allowed ONLY if:
   - A verified KeyBinding for the peer exists (from PKARR), AND
   - The TransportKey in KeyBinding matches the pinned key, AND
   - The upgrade is explicitly approved by app policy or user action
4. In MVP, automatic XX→IK upgrade for arbitrary peers is **PROHIBITED**

**Downgrade Prevention**:
- Once IK is established with a peer, downgrade to XX MUST require explicit user action or key rotation event
- If peer's PKARR KeyBinding rotates TransportKey, require re-verification before accepting new key

**PKARR Key Rotation**:
- When peer publishes new TransportKey via PKARR, the old pinned key becomes stale
- Receiver SHOULD fetch updated KeyBinding before next connection
- If new key differs from pinned key, treat as new TOFU event (XX pattern)

#### 6.8.4 TOFU Security Considerations

The XX pattern authenticates both parties to each other during the handshake, but is vulnerable to active MITM on first contact:

1. Attacker intercepts XX handshake
2. Attacker completes separate XX handshakes with both parties
3. Both parties believe they are talking to each other

**Detection**: Compare PeerPairFingerprints (Section 8.5) out-of-band. If fingerprints differ, MITM is present.

**Prevention**: Once IK pattern is used with a pinned key, active MITM requires key compromise.

---

## 7. Async Messaging (Async Envelopes)

### 7.1 Purpose and Layering

When both parties are not online simultaneously, messages are stored encrypted on the homeserver. The recipient decrypts without the sender being online.

**Explicit Layering Rules**:

| Rule | Description |
|------|-------------|
| Sealed Blob = stored delivery | Sealed Blob envelopes are written to homeserver storage and fetched by the recipient |
| Noise = live transport | Noise transport frames are NEVER written to homeserver for later decryption |
| No Noise storage | Queuing Noise ciphertext for offline delivery is PROHIBITED |
| Backup transport allowed | Apps may send already-encrypted backup blobs over live Noise channels (see Section 1.4) |

**Envelope vs Transport**:

- "Envelope" in this spec means a Sealed Blob stored on the homeserver for async retrieval
- "Transport" means a live Noise channel for real-time bidirectional communication
- These are distinct primitives with different security properties and use cases

### 7.2 Sealed Blob v2 Wire Format

Sealed Blob v2 uses a binary framing with deterministic CBOR headers:

```
Wire Format:
  magic: 0x53 0x42 0x32 ("SB2", 3 bytes)
  version: u8 (2)
  header_len: u16 (big-endian, MUST be <= 2048 bytes)
  header_bytes: [u8; header_len] (deterministic CBOR, see 7.12)
  ciphertext: [u8] (remainder, includes 16-byte Poly1305 tag)
```

**Resource Bounds (DoS Prevention)**:

| Limit | Value | Rationale |
|-------|-------|-----------|
| `header_len` | MUST be <= 2048 bytes | Prevents memory exhaustion |
| `msg_id` length | MUST be <= 128 characters | Bounds path lengths |
| CBOR nesting depth | MUST be <= 2 | Prevents parsing complexity |
| CBOR top-level keys | MUST be <= 16 | Bounds field count |
| Indefinite-length CBOR | PROHIBITED | Determinism requirement |

Implementations MUST reject messages that exceed these bounds immediately, before any cryptographic operations.

**Header Fields (Deterministic CBOR map with integer keys)**:

The header is a CBOR map using **integer keys** for compactness (see Section 7.12.3 for encoding rules).

| Key | Field Name | Type | Required | Description |
|-----|------------|------|----------|-------------|
| 0 | `context_id` | bytes(32) | REQUIRED (Paykit) | Thread identifier, raw bytes (see 7.7) |
| 1 | `created_at` | uint | RECOMMENDED | Unix timestamp (seconds) |
| 2 | `expires_at` | uint | REQUIRED (Paykit) | Expiration for requests/proposals |
| 3 | `inbox_kid` | bytes(16) | **REQUIRED** | Key identifier for recipient InboxKey |
| 4 | `msg_id` | text | REQUIRED (Paykit) | Idempotency key, ASCII, max 128 chars |
| 5 | `nonce` | bytes(24) | **REQUIRED** | XChaCha20-Poly1305 nonce (random per message) |
| 6 | `purpose` | text | Optional | Hint: `"request"`, `"proposal"`, `"ack"` |
| 7 | `recipient_peerid` | bytes(32) | **REQUIRED** | Recipient's Ed25519 public key (PeerId) |
| 8 | `sender_ephemeral_pub` | bytes(32) | **REQUIRED** | Sender's ephemeral X25519 public key for DH |
| 9 | `sender_peerid` | bytes(32) | **REQUIRED** | Sender's Ed25519 public key (for routing) |
| 10 | `sig` | bytes(64) | REQUIRED (Paykit) | Ed25519 signature for sender authenticity |

**msg_id Type (Normative)**:

`msg_id` is **text** (not bytes) with strict constraints:
- ASCII characters only (0x20-0x7E)
- Maximum length 128 characters
- When used in storage paths, use as-is (already path-safe if ASCII)
- This maintains compatibility with v2.4 and avoids encoding ambiguity

**sig Field Requirement**:

For Paykit purposes (`purpose` in {"request", "proposal", "ack"}), the `sig` field is **REQUIRED** to prove sender identity. For non-Paykit or anonymous messaging use cases, `sig` MAY be omitted.

**inbox_kid Derivation (Normative)**:

```
inbox_kid = first_16_bytes(SHA256(recipient_inbox_x25519_pub))
```

The `inbox_kid` identifies the recipient's **InboxKey** (not TransportKey) for O(1) key selection. Unknown `inbox_kid` MUST be rejected immediately WITHOUT calling Ring derivation. This prevents attackers from grinding the Ring API with arbitrary kid values.

### 7.2.1 Signature Construction

The `sig` field (key 10) is an Ed25519 signature that proves sender authenticity. Because the signature cannot include itself, the signing process uses a modified header.

**Signature Input Construction**:

```
header_no_sig = CBOR_encode(header_map with key 10 omitted)
sig_input = BLAKE3("pubky-envelope-sig/v2" || aad || header_no_sig || ciphertext)
sig = Ed25519_Sign(sender_peerid_sk, sig_input)
```

Where:
- `header_no_sig`: Deterministic CBOR encoding of header map WITHOUT key 10
- `aad`: The full AAD bytes computed using `header_no_sig` (see 7.5)
- `ciphertext`: The encrypted payload bytes (after header in wire format)
- `sender_peerid_sk`: The sender's Ed25519 private key corresponding to `sender_peerid`

**Important**: When computing AAD for signature purposes, use `header_no_sig` (without signature), not the full header.

**Signature Verification**:

1. Extract `sig` (key 10) from received header
2. Re-encode header without key 10 to produce `header_no_sig`
3. Compute `aad` using `header_no_sig`: `aad = aad_prefix || owner || path || header_no_sig`
4. Compute `sig_input = BLAKE3("pubky-envelope-sig/v2" || aad || header_no_sig || ciphertext)`
5. Verify `sig` against `sender_peerid` (key 9) using Ed25519

**Trust Rule**: Without a valid signature, treat `sender_peerid` as routing metadata only, not proven identity. For Paykit purposes (request, proposal, ack), missing or invalid `sig` MUST cause message rejection.

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
- 24 bytes (192 bits) cryptographically random, generated fresh for each envelope
- Uses XChaCha20-Poly1305 (extended nonce variant)
- No counters, no state required
- Safe for random generation due to 192-bit nonce space (collision-resistant)

**Noise Transport (Live Delivery)**:
- 64-bit little-endian counter, zero-padded to 96 bits (12 bytes) per Noise specification
- Uses ChaCha20-Poly1305
- Library (`snow`) manages counter internally
- Nonces are never exposed or persisted

**Nonce Size Clarification**:

| Protocol | Nonce Size | Construction |
|----------|------------|--------------|
| Noise Transport | 12 bytes | 64-bit LE counter, zero-padded |
| Sealed Blob v2 | 24 bytes | Random per message |

These are different constructions with different nonce management. Do not conflate them.

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
- `aad_prefix`: ASCII bytes `"pubky-envelope/v2:"` (18 bytes, includes colon)
- `owner_peerid_bytes`: Raw 32-byte Ed25519 public key of storage owner
- `canonical_path_bytes`: UTF-8 bytes of canonical storage path (see 7.12)
- `header_bytes`: Deterministic CBOR serialization of header (see 7.12)

**No delimiters between components**. The fields are concatenated directly:
- aad_prefix: 18 bytes (fixed length)
- owner_peerid_bytes: 32 bytes (fixed length)
- canonical_path_bytes: variable length
- header_bytes: variable length (self-delimiting CBOR)

**AAD is never parsed.** Both sender and receiver compute the exact same byte concatenation from known values. The "self-delimiting" property of CBOR is not used for parsing; it merely means no explicit length prefix is needed.

This construction guarantees that ALL header fields (`sender_ephemeral_pub`, `recipient_peerid`, `sender_peerid`, `inbox_kid`, `nonce`, `msg_id`, `context_id`, `created_at`, `expires_at`, `purpose`) are cryptographically authenticated.

**Storage Owner**: The peer who writes the object to their homeserver storage:
- Payment requests: sender is owner
- ACKs: receiver is owner (writes to their storage)
- Handoff: Ring user is owner

**Why header_bytes in AAD?**

Including the entire serialized header in AAD ensures:
1. No header field can be modified without detection
2. No ambiguity about which fields are authenticated
3. Future header extensions are automatically authenticated

**AAD Construction Rationale**:

AAD binds ciphertext to storage context and prevents relocation attacks. The construction uses cryptographic primitives (not SipHash or other non-cryptographic hashes). SipHash is designed for hash table collision resistance, not cryptographic binding.

This AAD construction is **complementary to** (not replacing) Noise's transport authentication:
- Noise AAD applies to live transport frames
- Sealed Blob AAD applies to stored ciphertext and binds it to the storage owner and path

They serve different purposes and are not redundant.

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

### 7.6 Sender Signature and Identity

For messages requiring strong sender authenticity, the sender MUST include an Ed25519 signature in the header (key 10). For Paykit purposes (`purpose` in {"request", "proposal", "ack"}), signature is **REQUIRED**.

**sender_peerid Definition**:

The `sender_peerid` (header key 9) is the **PKARR Ed25519 public key** of the sending identity. In Pubky's P2P model, this is the root identity (no external PKI hierarchy). The signature in key 10, when present, proves the sender controls the corresponding private key.

**Web-of-Trust / Identity Federation**: External trust models (PGP web-of-trust, X.509 hierarchies, DID verification) are out of scope for PUBKY_CRYPTO_SPEC v2.x. The Ed25519 key is self-certifying; trust establishment is an application-layer concern.

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

**Trust Rule**: The `sender_peerid` field is authenticated via AAD (tamper-evident), but the sender identity is **trusted** only if `sig` verifies. Without a valid signature, treat `sender_peerid` as routing metadata, not proven identity. For Paykit purposes (request, proposal, ack), missing or invalid `sig` MUST cause message rejection.

**Legacy JSON Format**:

For backward compatibility with JSON envelopes:

```
sig = Ed25519_Sign(
  sender_ed25519_sk,
  BLAKE3("pubky-envelope-sig/v2" || v || epk || sender || nonce || ct)
)
```

### 7.7 Terminology and ContextId Definition

This section defines core terminology used throughout the spec.

#### 7.7.0 Core Terminology

| Term | Definition |
|------|------------|
| **Thread** | A logical conversation between two peers about a specific topic (e.g., payment negotiation). May span multiple messages and Noise sessions. |
| **Session** | A live Noise transport connection. Unique per handshake. Identified by `session_id` (handshake hash). |
| **ContextId** | Opaque 32-byte identifier chosen by the application for a specific thread. RECOMMENDED to be random. NOT derived from peer keys. Used for thread routing. |
| **PairContextId** | Optional deterministic identifier derived from peer public keys. For diagnostics, correlation, and rate-limiting. NOT for thread routing. |
| **InboxKey** | X25519 key used for Sealed Blob stored delivery. |
| **TransportKey** | X25519 key used for Noise static in live transport. |
| **inbox_kid** | 16-byte identifier derived from InboxKey public key for O(1) key lookup. |

**ContextId vs PairContextId Distinction**:
- **ContextId**: Application-chosen, typically random, identifies a specific thread. Used in storage paths and message routing. Different threads between the same peers have different ContextIds.
- **PairContextId**: Deterministic, derived from sorted peer public keys. Same value for all threads between the same peer pair. Used ONLY for diagnostics, logging, rate-limiting, and cross-thread correlation. **NEVER** used for thread routing or storage paths.

**Important**: Thread routing uses `context_id`. Pair-level correlation uses `pair_context_id`. Never the other way around. Confusing these causes ambiguity.

**Thread != Session**: A single thread may span multiple sessions (e.g., reconnections). A single session may carry messages for multiple threads.

#### 7.7.1 ContextId (Normative for Paykit)

For Paykit threads, ContextId:

| Requirement | Description |
|-------------|-------------|
| Format | 32 random bytes (or 16 if constrained) |
| Generation | Random per thread, generated by the thread initiator |
| Lifetime | Stable for the lifetime of that thread |
| Uniqueness | MUST be unique per thread |
| Derivation | MUST NOT be derived from peer pubkeys |

**Canonical Form**: The canonical `context_id` is always **32 raw bytes**. All cryptographic operations (AAD computation, CBOR serialization, header encoding) use the raw bytes.

**Display Encodings** (for JSON, URLs, human display):

| Encoding | Format | Example Use |
|----------|--------|-------------|
| `context_id_hex` | `hex(context_id)` (64 lowercase chars) | JSON payloads, logs |
| `context_id_z32` | `z-base-32(context_id)` (52 chars) | Storage paths (preferred) |

**Implementation Rule**: When decoding `context_id` from JSON or display format, implementations MUST decode to 32 raw bytes before computing AAD or performing any cryptographic operation.

#### 7.7.2 PairContextId (Optional, Diagnostic Only)

For diagnostics and correlation across threads, implementations MAY compute a deterministic peer-pair identifier:

**PairContextId Derivation**:

```
sorted_keys = sort([local_peerid_z32, remote_peerid_z32])
pair_context_id = SHA256("paykit:v0:pair-context:" || sorted_keys[0] || ":" || sorted_keys[1])
```

Where:
- `first_z32` and `second_z32` are normalized z-base-32 pubkeys sorted lexicographically
- Result is 32 raw bytes
- Symmetric: same value regardless of which party computes it

**Usage Restrictions**:

| Rule | Description |
|------|-------------|
| NOT for thread identity | PairContextId MUST NOT be used as the primary thread identifier |
| NOT in storage paths | Use random ContextId in storage paths, not PairContextId |
| Diagnostics only | PairContextId is for logging, debugging, and cross-thread correlation |
| Unlinkability | Random ContextId per thread provides unlinkability; PairContextId defeats this |

**Note**: For out-of-band stable peer verification, use `PeerPairFingerprint` (Section 8.5) instead of PairContextId.

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

**Secure Handoff Definition**:

Secure Handoff is the process by which Ring transfers derived key material to an app (e.g., Bitkit) for local use. The handoff blob is a Sealed Blob encrypted to an app-generated ephemeral X25519 public key. Ring does not access the homeserver directly; the app writes the handoff blob to its storage path.

### 7.9 Encrypted ACK Protocol

ACKs confirm receipt of async messages, enabling reliable delivery without active connections.

**ACK objects are stored delivery messages and MUST be Sealed Blob v2 encrypted.**

**Encryption Target (Normative)**:

ACKs are encrypted to the **original sender's InboxKey**. The InboxKey MUST be discovered from the sender's **PKARR KeyBinding** (which publishes InboxKeys). Do NOT use the Noise transport endpoint as an InboxKey source—that endpoint publishes TransportKeys, not InboxKeys.

**Key Discovery for ACKs**:
1. Fetch sender's PKARR KeyBinding
2. Extract the InboxKey entry (not TransportKey)
3. Derive `inbox_kid` from that InboxKey
4. Encrypt ACK to that InboxKey

**ACK Header Fields**:
- `purpose`: "ack"
- `context_id`: Same as original message (32 raw bytes)
- `inbox_kid`: Derived from original sender's InboxKey
- `sender_ephemeral_pub`: Fresh ephemeral X25519 for this ACK
- `sender_peerid`: ACK sender's Ed25519 public key
- `recipient_peerid`: Original message sender's Ed25519 public key
- `sig`: REQUIRED (ACK is a Paykit object)

**ACK Plaintext Payload (Normative)**:

```json
{
  "acked_msg_id": "req_001",
  "error_code": 0,
  "error_text": null
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `acked_msg_id` | REQUIRED | ID of message being acknowledged (text, matches original msg_id) |
| `error_code` | OPTIONAL | Machine-readable error (0 = success, nonzero = error) |
| `error_text` | OPTIONAL | Human-readable error description |

**Removed from normative spec**: `msg_id`, `status`, `created_at` in the plaintext payload. These are app-layer concerns. The header already contains `msg_id` for the ACK itself.

**Note on context_id in payload**: The authenticated header carries `context_id` as 32 raw bytes (key 0). If the plaintext payload includes `context_id` for app convenience, it is display encoding (hex) only and MUST match the header value when decoded.

**ACK Storage Path**:

```
/pub/paykit.app/v0/acks/{object_type}/{context_id_z32}/{acked_msg_id}
```

Where `context_id_z32` is z-base-32 encoding for path compatibility.

**Round-Trip Trade-off**: The ACK protocol requires multiple round-trips (sender polls receiver's storage). This overhead is an inherent trade-off for async stored delivery—there is no persistent connection to push acknowledgments. For latency-critical applications, use live Noise transport with in-session acknowledgment instead.

**ACK Lifecycle**:

1. Receiver decrypts and processes message (payment request, subscription proposal, etc.)
2. Receiver fetches sender's **InboxKey from their PKARR KeyBinding** (NOT from Noise transport endpoint)
3. Receiver creates ACK with fresh ephemeral X25519 key
4. Receiver encrypts ACK as Sealed Blob v2 to sender's InboxKey
5. Receiver writes encrypted ACK to their own storage
6. Sender polls receiver's ACK directory until found or `expires_at` elapsed
7. Sender decrypts ACK with their InboxKey
8. Sender stops resending after ACK or expiration
9. ACKs are cleaned up after 7 days (configurable)

**ACK Mitigations**:

| Mitigation | Requirement |
|------------|-------------|
| Jitter | Apply +/- 20% random jitter to polling intervals |
| Batching | MAY batch multiple ACK writes into single storage operation |
| Polling cadence | Default: poll every 30 seconds, backoff to 5 minutes if idle |
| Retry caps | MAX 5 retries per message (6 total attempts) |
| Backoff | Exponential: 1m, 2m, 4m, 8m, 16m (per Section 7.13) |

**ACK AAD Construction**:

Uses standard Sealed Blob v2 AAD format (Section 7.5). The path includes `acked_msg_id`:

```
/pub/paykit.app/v0/acks/request/{context_id_z32}/{acked_msg_id}
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

#### 7.12.1 PeerId Canonical Bytes

| Context | Encoding |
|---------|----------|
| Crypto operations (DH, signatures) | Raw 32-byte Ed25519 public key |
| AAD owner/recipient/sender fields | Raw 32 bytes |
| CBOR headers (keys 7, 9) | Raw 32 bytes (bstr) |
| Storage paths | z-base-32 (52 characters, lowercase) |
| URIs | `pubky://{z32}` |

**Normalization for z-base-32**:
1. Trim whitespace
2. Strip `pubky://` prefix if present
3. Strip `pk:` prefix if present
4. Lowercase
5. Validate length (52 chars) and z-base-32 alphabet

Implementations MUST use raw bytes for any cryptographic operation. z-base-32 is for display/URIs only.

#### 7.12.2 ContextId Canonical Bytes

| Context | Encoding |
|---------|----------|
| CBOR headers (key 0) | Raw 32 bytes (bstr) |
| AAD computation | Raw 32 bytes |
| Storage paths | z-base-32 (52 chars) or hex (64 lowercase chars) |
| JSON payloads | hex (64 lowercase chars) |

Implementations MUST decode to 32 raw bytes before computing AAD or any cryptographic operation.

**ContextId is application-chosen**, typically random (see Section 7.7). It is NOT derived from peer keys.

#### 7.12.3 inbox_kid Canonical Bytes

| Context | Encoding |
|---------|----------|
| CBOR headers (key 3) | Raw 16 bytes (bstr) |
| JSON/display | hex (32 lowercase chars) |

#### 7.12.4 msg_id Encoding

| Context | Encoding |
|---------|----------|
| CBOR headers (key 4) | text (ASCII, max 128 chars) |
| Storage paths | as-is (ASCII is path-safe) |
| JSON | as-is (already text) |

#### 7.12.5 Path Canonicalization

Canonical path bytes for AAD construction:

| Rule | Description |
|------|-------------|
| Encoding | UTF-8 bytes, no BOM |
| Leading slash | REQUIRED (must start with `/`) |
| Trailing slash | PROHIBITED (except root `"/"`) |
| Duplicate slashes | PROHIBITED (no `//`) |
| Dot segments | PROHIBITED (no `.` or `..` segments) |
| Percent encoding | PROHIBITED (paths are literal bytes) |
| Unicode normalization | PROHIBITED (treat bytes as-is) |
| Character set | ASCII alphanumeric + `/-_.` only |
| Max length | 1024 bytes |

**Path Canonicalization is NORMATIVE**: Implementations that produce different byte sequences for the same logical path will fail AAD verification.

**Valid path examples**:
```
/pub/paykit.app/v0/requests/abc123/req_001
/pub/paykit.app/v0/acks/request/abc123/req_001
```

**Invalid path examples**:
```
/pub/paykit.app/v0/requests/abc123/req_001/   (trailing slash)
/pub/paykit.app/v0//requests/abc123/req_001   (duplicate slash)
/pub/paykit.app/v0/./requests/abc123/req_001  (dot segment)
pub/paykit.app/v0/requests/abc123/req_001     (no leading slash)
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
- Provides unique session identification

**Session Binding Threat Model (Clarification)**:

Session binding provides a unique session label via the Noise handshake hash. **Cryptographic protection against message injection comes from AEAD authentication under session keys**, not from the hash itself.

The handshake hash enables:
- Unique identification of a session instance
- Detection of handshake transcript tampering (when verified)

**Replay protection for stored messages** belongs in `msg_id` and app-layer idempotency, not session binding. The session hash is useful for logging and debugging, not security enforcement.

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

### 8.4 ContextId vs SessionId vs PairContextId

| Identifier | Generation | Stability | Purpose |
|------------|------------|-----------|---------|
| **SessionId** | Derived from Noise handshake transcript hash | Changes every handshake | Live session binding |
| **ContextId** | Random per thread (app-chosen) | Stable for thread lifetime | Storage paths, ACK routing |
| **PairContextId** | Derived from peer pubkey pair | Stable across all threads | Diagnostics only (optional) |

**Key Distinctions**:

- **SessionId**: Only available after handshake completes. Used for live transport binding. Changes on every new handshake, even between the same parties.

- **ContextId**: Application-chosen (typically random). Used for storage path routing and ACK bookkeeping. Each thread gets its own ContextId, providing unlinkability between threads.

- **PairContextId**: Deterministic per peer pair (Section 7.7.2). For diagnostics and cross-thread correlation only. MUST NOT be used in storage paths or as primary thread identifier.

**Important**: Neither ContextId nor PairContextId may be used to resume half-complete Noise handshakes. Noise provides no built-in handshake resume; these identifiers are strictly for app-layer routing and correlation.

### 8.5 PeerPairFingerprint

PeerPairFingerprint provides a stable, human-comparable identifier for out-of-band verification of a peer relationship.

**Purpose**: Enable users to detect TOFU (Trust On First Use) MITM attacks by comparing fingerprints out-of-band (e.g., verbally, via QR code, or secure channel).

**Derivation (Normative)**:

```
sorted_keys = sort([local_peerid_bytes, remote_peerid_bytes])  // 32-byte raw keys
fingerprint_full = BLAKE3("pubky-fingerprint/v1:" || sorted_keys[0] || sorted_keys[1])
peer_pair_fingerprint = first_8_bytes(fingerprint_full)
```

Where:
- `peerid` values: Raw 32-byte Ed25519 public keys
- `sort`: Lexicographic comparison of raw bytes
- Result: 8 bytes, displayed as 16 hex characters

**Display Format**:

```
display = hex(peer_pair_fingerprint)  // 16 lowercase hex characters
formatted = "a1b2c3d4e5f67890"         // For display
```

**Properties**:
- **Symmetric**: Same value regardless of which party computes it
- **Stable**: Does not change across handshakes or key rotations (derived from PeerIds only)
- **Deterministic**: Same inputs always produce same output

#### 8.5.1 ContextId vs PairContextId vs PeerPairFingerprint

| Identifier | Purpose | Derivation | User-Facing | Used in Paths |
|------------|---------|------------|-------------|---------------|
| ContextId | Thread routing, storage paths | App-chosen, random | No | Yes |
| PairContextId | Diagnostics, correlation, rate limits | SHA256 of sorted peer pubkeys (z32) | No | No |
| PeerPairFingerprint | TOFU verification, out-of-band comparison | BLAKE3 of sorted peer pubkeys (raw bytes) | Yes (displayed) | No |

These serve different purposes and **MUST NOT** be conflated.

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
4. Retain old keys for decryption as needed

**Key Retention Policy** (replaces "grace period"):

Key rotation uses `inbox_kid`-based lookup. Receivers maintain a keyring of InboxKeys and retain old keys for decryption as needed. This is key retention policy, not a protocol-level "grace period" mechanism.

**Recommendation**: Retain old InboxKeys for at least 7 days after rotation to handle in-flight messages encrypted to old keys.

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
| ContextId prefix (legacy) | `"paykit:v0:context:"` |
| PairContextId prefix | `"paykit:v0:pair-context:"` |
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

### C.2 Specified in v2.4 (Pending Implementation)

| Feature | Status | Notes |
|---------|--------|-------|
| ContextId app-chosen (random per thread) | 📋 Specified | Section 7.7; replaces peer-pair derivation |
| PairContextId for diagnostics | 📋 Specified | Section 7.7.2; optional, for correlation only |
| Header-bytes AAD construction | 📋 Specified | Section 7.5; replaces legacy string AAD |
| Encrypted ACK protocol with status | 📋 Specified | Section 7.9; ACKs now have own `msg_id` and `status` |
| PeerPairFingerprint | 📋 Specified | Section 8.5; BLAKE3-based, frozen |
| KeyBinding with optional timestamps | 📋 Specified | Section 6.8.1; `published_at` optional, default off |
| MVP Policy (XX only by default) | 📋 Specified | Section 6.8.2; no automatic IK promotion |
| Resend defaults | 📋 Specified | Section 7.13; 1m/2m/4m/8m/16m schedule |
| Ring FFI bounded version counters | 📋 Specified | Section 5.3; `derive_inbox_handle(app_id, key_version)` |
| Canonical encoding (CBOR headers) | 📋 Specified | Section 7.12; deterministic CBOR per RFC 8949 |
| kid 16-byte derivation | 📋 Specified | Section 7.2; `first_16_bytes(SHA256(pk))` |
| Backup transport allowance | 📋 Specified | Section 1.4; Noise may carry encrypted backup blobs |

### C.3 Not Yet Implemented

| Feature | Status | Notes |
|---------|--------|-------|
| APP_SEED derivation layer | ❌ Not implemented | Currently uses ed25519 seed directly |
| Role parameter in X25519 derivation | ❌ Not implemented | Info is `device_id \|\| epoch` only |
| LOCAL_ARCHIVE_KEY derivation | ❌ Not implemented | Needs new function in kdf.rs |
| Version-based key selection | ❌ Not implemented | App caches `{kid -> key_version}`; Ring derives by version |
| Binary wire format for Sealed Blob | ❌ Not implemented | JSON format still in use |
| Deterministic CBOR headers | ❌ Not implemented | Requires header serialization update |
| PeerPairFingerprint computation | ❌ Not implemented | Needs BLAKE3 integration |
| KeyBinding via PKARR | ❌ Not implemented | Requires PKARR metadata extension |
| IdentityPayload without epoch | ❌ Not implemented | Current impl includes epoch; needs removal |
| Ring FFI rate limiting | ❌ Not implemented | Derivation calls need rate limits |

### C.4 Breaking Changes in v2.4

| Change | Migration |
|--------|-----------|
| IdentityPayload removes `epoch` and `noise_x25519_pub` | Update `identity_payload.rs`; noise keys from handshake |
| `expires_at` renamed to `hint_expires_at` | Scope to `server_hint` only |
| ContextId now app-chosen (random) | Generate random 32-byte IDs per thread |
| Ring FFI uses `key_version` not `kid` | App caches `{kid -> key_version}` mapping |
| KeyBinding `created_at` → `published_at` (optional) | Default off; use `key_version` for ordering |

---

## Appendix D: Specification Organization

### D.1 Current Structure Assessment

This specification currently covers:
- **Core Cryptography** (Sections 1-4): ~165 lines - primitives, identity, key hierarchy
- **Device Layer** (Section 5): ~186 lines - Ring FFI, platform integration
- **Live Transport** (Section 6): ~293 lines - Noise protocol, handshakes
- **Async Messaging** (Section 7): ~703 lines - Sealed Blob, ACK, storage
- **Binding & Security** (Sections 8-11): ~225 lines - session binding, rotation, backup
- **Implementation** (Section 12, Appendices): ~250 lines - reference, domain strings

Total: ~1900 lines

### D.2 Split Recommendation

**Recommendation: Do NOT split at this time.**

Reasons to keep unified:
1. **Semantic cohesion**: Sections cross-reference heavily (e.g., Section 7 relies on Section 4 key derivation)
2. **Single source of truth**: Avoids version drift between separate documents
3. **Implementer clarity**: One document to read for complete picture
4. **Search efficiency**: `grep` and semantic search work across full context

Reasons to consider future split:
1. **Section 7 dominance**: At 703 lines, async messaging is 37% of the spec
2. **Distinct audiences**: Live transport (SDK devs) vs storage format (server implementers)
3. **Change velocity**: Async messaging evolves faster than core crypto

### D.3 If Splitting Becomes Necessary

If the spec exceeds ~3000 lines or async messaging exceeds ~1200 lines, consider:

| Document | Sections | Audience |
|----------|----------|----------|
| `PUBKY_CRYPTO_CORE.md` | 1-5, 9-11, Appendix A | Core crypto, Ring, key derivation |
| `PUBKY_TRANSPORT.md` | 6, 8 | Noise handshake, session binding |
| `PUBKY_MESSAGING.md` | 7, Appendix B-C | Sealed Blob, ACK, storage format |

Each document would include a "Related Documents" section with version compatibility matrix.

---

*This specification is maintained in the Pubky ecosystem repositories.*

