# Pubky Unified Key Delegation Spec (v0.2)

Version: v0.2
Status: Draft
Last updated: 2026-01-19

### Related Specifications

| Specification | Relationship |
|---------------|--------------|
| [PUBKY_CRYPTO_SPEC](PUBKY_CRYPTO_SPEC.md) | **Root spec**: This document extends the root crypto spec |
| [Atomicity Specification](../../atomicity-research/Atomicity%20Specification.md) | Application spec that uses AppKey for covenant signing |

## 1. Goals

This spec defines a single, coherent key model for a PKARR identity that supports:

1. Live encrypted transport (Noise)
2. Stored delivery (sealed blob) for async messaging
3. Paykit (requests, proposals, ACKs, receipts)
4. Atomicity (messages, artifacts)
5. Optional public proof of authorship for Pubky App content

The design MUST avoid:

- Root key signing prompts for routine activity
- "sign any payload" APIs that enable phishing patterns
- Unbounded key state, unbounded caches, or attacker-driven key derivation
- Mixing key roles in ways that enlarge compromise blast radius

## 2. Non-goals

- Defining the full Pubky App post format
- Replacing Noise
- Replacing sealed blob stored delivery
- Providing a generic public PKI hierarchy beyond PKARR

## 3. Design summary

Use a root PKARR identity key only to issue and revoke *delegated application certificates*.

Each delegated certificate binds, under the PKARR identity:

- An App signing key (Ed25519) for proof-of-authorship and request signing
- A TransportKey (X25519) for Noise static identity
- An InboxKey (X25519) for stored delivery encryption

Apps use delegated keys day-to-day. The root key is used rarely (issuance, rotation, revocation).

This directly addresses:

- Proof of authorship: content signed by AppKey, verifiable back to PKARR identity
- Noise: TransportKey is bound to identity via the certificate
- Stored delivery: InboxKey is discoverable and bound via the certificate
- UX: once-per-app approval, then silent signing with delegated keys


## 3.1 Design priorities and staged adoption

This spec intentionally tries to solve the "one hard problem" (delegation) without turning Pubky into a key maze.

Design priorities, in order:

1. Keep the root PKARR key rare and boring. It signs only delegation certificates and (optionally) high value recovery actions.
2. Make day to day operations use app keys (AppKey) and session keys (Noise), not the root.
3. Avoid generic sign anything or decrypt anything user prompts. Those are phishing magnets and become Nostr style UX.
4. Keep storage and transport separate. Noise is live transport. Stored delivery uses sealed blobs encrypted to an InboxKey.
5. Bound state and avoid remote input driven work. No unbounded key_id maps, no forcing Ring calls on attacker supplied ids.

MVP boundary for this document:

- Root signed AppKey certificates (AppKeyCert).
- Optional proof of authorship by signing content with AppKey.
- Optional homeserver request proof of possession (DPoP like) using AppKey.
- Explicit non goals: delegated readers for /priv, multi hop delegation chains, and per scope quota or policy systems.

## 3.2 How This Extends PUBKY_CRYPTO_SPEC

This spec is an **optional extension** to [PUBKY_CRYPTO_SPEC](PUBKY_CRYPTO_SPEC.md). It does not redefine primitives, key derivation, or wire formats already specified there.

**What PUBKY_CRYPTO_SPEC defines (root spec)**:
- Sealed Blob v2 format and encryption (Section 7)
- KeyBinding structure, CBOR encoding, and publication (Section 6.8.1)
- InboxKey/TransportKey separation (Section 4.7, normative)
- Signing hierarchy and policy (Section 7.6.1)
- Ring FFI surface and typed signing (Section 5.3)

**What this spec adds**:
- **AppCert**: A root-signed certificate binding AppKey, TransportKey, and InboxKey for delegation
- **AppKey discovery**: Via `app_keys[]` entries in KeyBinding (see CRYPTO_SPEC 6.8.5)
- **Delegated Sealed Blob signatures**: Via `cert_id` header field (see CRYPTO_SPEC 7.2.2)
- **SignedContent envelope**: For proof-of-authorship on public content
- **DPoP-like request proofs**: For homeserver API authentication

**Terminology alignment**:
- `inbox_x25519_pub` / `transport_x25519_pub`: Preferred terminology for X25519 public keys (not `inbox_enc_pub` or `transport_static_pub`)
- `cert_id`: First 16 bytes of SHA256(cert_body), used in KeyBinding and Sealed Blob headers
- `app_ed25519_pub`: The delegated Ed25519 public key in an AppCert

**Discovery**: AppCerts are discovered via KeyBinding `app_keys[]` entries (single root mechanism), not via a parallel discovery system.

## 3.2.1 Relationship to Noise, Paykit outbox, and Locks

This spec is not a replacement for Noise or Paykit.

- Noise: live transport encryption and authentication between peers when both are online.
- Paykit outbox and inbox: stored delivery of application messages (payment requests, proposals, ACKs) using sealed blobs encrypted to a recipient InboxKey. This works even when peers are offline.
- This delegation spec: who is allowed to sign and who is allowed to act as an authenticated caller to a homeserver API.

Outbox and inbox are not additional crypto protocols. They are a storage convention used by apps (for example Paykit) that relies on sealed blob encryption and idempotent message logic.

Locks overlap is mostly conceptual, not technical:

- Locks is an application level commerce and authorization scheme (receipts, subscriptions, unlock conditions, policy).
- Delegation keys are a crypto primitive that Locks can use to sign receipts, identify apps, and to avoid overusing the root key.
- This spec does not define how locked content is priced, sold, or verified. It only defines keys and signatures that Locks can reuse.

## 3.3 Deferred design space (explicitly acknowledged)

The following ideas are valuable but are deferred until the complexity is justified by real usage:

- Delegation chains (sub delegation) where an AppKey delegates a narrower key to another party.
- Delegated readers for /priv paths (capability grants for third party reads).
- Per app or per scope quotas, tiered access, and policy engines at the homeserver.
- Generic pubkyauth sign or decrypt deep links.

When we return to these, the guiding question is: can we express it as a narrow extension of AppKeyCert without introducing new global key types.

## 4. Key roles and identifiers

### 4.1 Root identity key (PKARR)

- Algorithm: Ed25519 (RFC 8032)
- Purpose: long-lived identity and certificate issuer
- Storage: Ring (or equivalent secure component)
- Rule: the root key MUST NOT sign arbitrary application payloads.

### 4.2 Delegated keys (per app, optionally per device)

Each delegated certificate (Section 5) binds three public keys:

1. **AppKey**: Ed25519
   - Purpose: signing typed application payloads (proof-of-authorship) and optionally signing HTTP requests (DPoP-like)
2. **TransportKey**: X25519 (RFC 7748)
   - Purpose: Noise static key for live sessions
3. **InboxKey**: X25519
   - Purpose: encrypting sealed blobs for stored delivery

Rules:

- Key role reuse is PROHIBITED for MVP.
  - AppKey, TransportKey, InboxKey MUST be distinct keys.
- Implementations MUST use domain separation strings in derivations.
- The delegated private keys SHOULD be stored in platform keystores (iOS Keychain / Android Keystore) when possible.

### 4.3 Key identifiers

To avoid brute force key selection and to harden against DoS:

- **inbox_kid**: 16 bytes
  - Derivation: `first_16_bytes(SHA256(inbox_x25519_pub))`
  - Used in sealed blob headers to select the correct InboxKey in O(1)
- **transport_kid**: 16 bytes
  - Derivation: `first_16_bytes(SHA256(transport_x25519_pub))`
  - Optional hint for selecting/pinning TransportKeys
- **cert_id**: 16 bytes
  - Derivation: `first_16_bytes(SHA256(cert_body_bytes))`

Receivers MUST reject unknown kids immediately without calling Ring or any derivation API.

## 5. Delegated application certificate

### 5.1 Certificate purpose

A delegated application certificate ("AppCert") is a root-signed statement that binds delegated keys and optional capability scope to a PKARR identity.

### 5.2 Certificate encoding

Wire encoding MUST be Deterministic CBOR (RFC 8949 deterministic encoding).

- Map keys MUST be unsigned integers.
- No floats.
- Definite length only.
- Keys sorted by numeric value.

### 5.3 AppCert schema (CBOR map)

All byte fields are raw bytes.

| Key | Field | Type | Required | Notes |
|---:|---|---|---|---|
| 0 | v | uint | REQUIRED | Version = 1 |
| 1 | issuer_peerid | bytes(32) | REQUIRED | Root PKARR Ed25519 pubkey |
| 2 | app_id | text | REQUIRED | e.g. `pubky.app`, `paykit`, `bitkit` |
| 3 | device_id | bytes | OPTIONAL | Stable per device if used |
| 4 | app_ed25519_pub | bytes(32) | REQUIRED | Delegated signing key |
| 5 | transport_x25519_pub | bytes(32) | REQUIRED | Delegated Noise static |
| 6 | inbox_x25519_pub | bytes(32) | REQUIRED | Delegated inbox encryption key |
| 7 | scopes | array(text) | OPTIONAL | Capability hints (Section 5.5) |
| 8 | not_before | uint | OPTIONAL | Unix seconds |
| 9 | expires_at | uint | OPTIONAL | Unix seconds |
| 10 | flags | uint | OPTIONAL | Bitfield, reserved |
| 11 | sig | bytes(64) | REQUIRED | Ed25519 over cert_body |

`cert_body` is the deterministic CBOR encoding of the same map excluding key 11.

Signature:

- `sig = Ed25519_Sign(root_sk, SHA256(cert_body_bytes))`
- Verification uses `issuer_peerid`.

### 5.4 Publication and discovery

AppCerts MUST be discoverable by peers via KeyBinding (see [PUBKY_CRYPTO_SPEC Section 6.8.5](PUBKY_CRYPTO_SPEC.md)).

**Preferred mechanism (KeyBinding `app_keys[]`)**:

1. Publish KeyBinding for `(peerid, app_id)` with `app_keys[]` entries containing:
   - `ed25519_pub`: The AppKey public key
   - `cert_id`: First 16 bytes of SHA256(cert_body)
   - `expires_at` (optional): When the cert expires

2. Store full AppCert at homeserver path: `/pub/{app_id}/v0/certs/{cert_id_hex}`

3. Peer discovers AppKey via KeyBinding, fetches full AppCert via `cert_id`, verifies signature against `issuer_peerid`

**Inline in PKARR metadata**:

- Allowed only if size constraints permit (not recommended for production)

A peer MUST treat a certificate as valid only if:

- The AppCert signature verifies under `issuer_peerid`, and
- `issuer_peerid` equals the sender's PKARR identity key, and
- The certificate is not expired (if `expires_at` present), and
- The certificate is not revoked (Section 10).

### 5.5 Scopes

Scopes are capability hints that verifiers and homeservers MAY enforce.

Examples:

- `pubky.post.sign`
- `paykit.message.sign`
- `homeserver.request.sign`
- `locks.grant.sign`

MVP rule: applications MUST NOT rely on scopes for core safety. Scopes are for policy and UX.
## 6. Publishing and discovery

The verifier needs a way to obtain a certificate (AKC) for a given `cert_id`.

This spec supports two discovery methods:

### 6.1 Inline certificate in PKARR metadata

- PKARR metadata MAY include one or more AKC blobs directly.
- This is preferred when size allows.

### 6.2 PKARR pointer to certificate object

- PKARR metadata MAY include pointers to certificate objects stored elsewhere.
- Recommended pattern: store each AKC at a stable public path on the identity's homeserver and publish a pointer.

Example pointer record (conceptual):

- `cert_id`: bytes(16)
- `url`: text (homeserver HTTPS URL) OR `pubky://` style path
- `hash`: bytes(32) = SHA256(AKC bytes)

Rules:

- The pointer record MUST be covered by the PKARR signature.
- Clients MUST verify `hash` before using the fetched AKC.
- Clients SHOULD cache AKCs by `cert_id`.

## 7. Signed content and proof of authorship

### 7.1 Problem statement

An untrusted homeserver or indexer can forge or alter unsigned content.

Goal: allow any observer to verify that a piece of content was signed by a delegated key that is authorized by the PKARR root identity.

### 7.2 SignedContent envelope

A content object is considered to have proof of authorship if it includes:

- `cert_id`: AKC identifier (bytes(16), or 32 hex for display)
- `sig`: Ed25519 signature by `app_sign_pub` from the AKC
- `payload`: the unsigned content payload (canonical bytes)
- `content_type`: an ASCII label describing what is being signed

Normative signing input:

```
sign_input = prefix || issuer_peerid || cert_id || content_type || payload_hash

prefix      = ASCII("pubky-signed-content/v1:")
issuer_peerid = 32 bytes (Ed25519 PKARR pubkey)
cert_id     = 16 bytes
content_type = UTF-8 bytes
payload_hash = 32 bytes = SHA256(payload_bytes)
```

Rules:

- `payload_bytes` MUST be canonical (deterministic CBOR recommended).
- Verifiers MUST reject if the AKC is invalid, revoked, expired, or scope-disallowed.
- Verifiers MUST reject if `issuer_peerid` does not match the expected identity.

### 7.3 Scopes

Scopes are optional but recommended.

Example scope labels:

- `pubky.post.sign`
- `paykit.request.sign`
- `atomicity.message.sign`
- `homeserver.auth.dpop`

A verifier MUST enforce scope if present.

## 8. Homeserver request authentication (optional, recommended)

This section describes an optional, DPoP-like request signing mechanism for homeserver APIs.

### 8.1 Motivation

Bearer sessions alone allow replay if the token is stolen.

Request signing binds a request to possession of an AppKey delegated by the root identity.

### 8.2 DPoP request proof

Define a deterministic request proof (JSON or CBOR) with fields:

- `method`: ASCII uppercase (e.g. "GET", "POST")
- `path`: canonical API path bytes (leading `/`, no `..`, no `//`)
- `ts`: uint, Unix timestamp seconds
- `nonce`: bytes(16), random per request
- `body_hash`: bytes(32), SHA256(body) or SHA256(empty) for no body
- `cert_id`: bytes(16)

Signing input:

```
proof_input = prefix || issuer_peerid || cert_id || method || path || ts_be || nonce || body_hash
prefix = ASCII("pubky-hs-dpop/v1:")
ts_be = u64 big-endian
```

The client sends:

- `X-Pubky-CertId: <cert_id>`
- `X-Pubky-DPoP: <sig>` where `sig` is Ed25519(AppKey) over `proof_input`

Homeserver verification rules:

- MUST validate the certificate (Section 5) and ensure it is not revoked.
- MUST validate time window, recommended +/- 120 seconds.
- MUST reject reused `(cert_id, nonce)` within the time window.
- SHOULD bind the proof to an existing session token if sessions are still used.

Notes:

- This spec does not require the homeserver to be trusted.
- This only hardens API writes and reads against token replay.

### 8.3 Replay protection and bounded state (normative)

The request signature mechanism must not create unbounded state.

**Required:**
- The homeserver MUST enforce a bounded replay cache. The cache key MUST include at least `(app_pub, nonce)`.
- The cache MUST be bounded (e.g., LRU) and entries MUST expire (e.g., after `replay_window_secs`).
- The homeserver MUST reject requests where `abs(now - timestamp) > max_clock_skew_secs`.

**Recommended defaults (non-normative):**
- `max_clock_skew_secs = 300` (5 minutes)
- `replay_window_secs = 600` (10 minutes)
- Replay cache capacity: 1024 entries per `app_pub` (or a global cap with LRU)

**Failure mode:** if the replay cache is evicted early due to pressure, a replay might be accepted within the timestamp window. This is acceptable only if the endpoint is idempotent or otherwise safe against replay. High-risk endpoints MUST either be idempotent (preferred) or maintain stronger replay defenses.

**MVP guidance:** Only require request signatures for endpoints where replay is naturally harmless (idempotent writes with `msg_id`, or reads that do not mutate server state). Defer request-signing requirements for non-idempotent mutations until the server replay story is fully hardened.

## 9. Integration with Noise and stored delivery

### 9.1 Noise transport

- Noise static key MUST be `transport_x25519_pub` from a valid AKC.
- First contact MUST use Noise XX (TOFU) unless a verified binding already exists.
- IK upgrade is OPTIONAL and MUST follow a conservative pinning policy.

Suggested role selection (to avoid out-of-band coordination):

- Initiator = peer with smaller `issuer_peerid` bytewise lexicographic ordering.
- Responder = other peer.

### 9.2 Stored delivery

- Stored delivery MUST use sealed blob encryption to `inbox_x25519_pub` from a valid AKC.
- Stored delivery MUST NOT store Noise transport ciphertext.

### 9.3 Double encryption guidance

- Stored delivery MUST NOT wrap Noise ciphertext inside a sealed blob.
- Live transport MAY carry any application payload, including already-signed content, but there is no requirement to wrap sealed blobs inside Noise for storage.

Rationale:

- Noise is a live session with non-exported state.
- Sealed blob is stateless at-rest encryption.

## 10. UX requirements

### 10.1 One-time delegation

A typical flow:

1. App requests a new AKC from Ring.
2. Ring displays the app name, scopes, and expiry.
3. User approves once.
4. Ring returns AKC + AppKey private handle to the app.

After this, the app can sign content without repeated prompts.

### 10.2 Proof of authorship display

- If a post includes a valid `SignedContent` envelope, the UI MAY show a "verified author" indicator.
- Unsigned posts are permitted but MUST NOT display the verified indicator.

## 11. Security and privacy considerations

### 11.1 Ring network isolation (normative)

Ring (or any secure element / key manager fulfilling the Ring role) MUST be a local cryptographic component only. It MUST NOT perform network I/O, fetch remote payloads, or accept remote-triggered long-running operations. All network access (homeserver, DHT, PKARR) occurs in the app or SDK layer, which then calls Ring with well-typed local inputs.

### 11.2 Bounded state and DoS resilience

- Implementations MUST NOT maintain unbounded mappings keyed by attacker-controlled inputs (e.g., arbitrary `kid` or arbitrary `key_id` values).
- Any caches keyed by remote inputs MUST be size-bounded and evict (e.g., LRU).
- Where possible, unknown identifiers SHOULD be rejected without invoking expensive derivations in Ring or the secure element.


### 11.3 Preventing "sign-anything" abuse

- Root key MUST only sign AKCs.
- Generic "sign arbitrary payload" APIs SHOULD NOT be shipped as deep links.
- If a cross-app signing API is ever added, it MUST be typed, scoped, and require an explicit confirmation UI.

### 11.4 Linkability

A stable AppKey makes all signed content linkable.

Mitigations (optional):

- Issue different AKCs per app.
- Issue different AKCs per profile or persona.
- Rotate AKCs periodically (short expiries) while keeping root identity stable.

### 11.5 Revocation

Recommended strategy:

- Use short-lived AKCs (e.g. 30-90 days) and rotate.
- For urgent revocation, publish a revoked `cert_id` list in PKARR metadata.
- Clients SHOULD also maintain a local denylist.

### 11.6 Key sprawl control

- Prefer one AKC per (app_id, device_id).
- Keep a small number of active certs and rely on rotation.

## 12. Implementation checklist

Minimum to ship a clean system:

1. Implement AKC issuance in Ring (root signs AKC).
2. Publish AKC pointers in PKARR metadata.
3. Implement verifier: fetch AKC, verify root sig, enforce expiry and optional scopes.
4. Implement SignedContent envelope and show verified indicator in UI.
5. Bind Noise transport and sealed blob to keys from AKC.
6. Prohibit root signing of arbitrary payloads.

Optional but useful:

- Homeserver DPoP-like request signing (Section 8).
- Revocation list publication in PKARR.
- Conservative IK upgrade with pinning.


## 13. Deferred features and explicit acknowledgements

This spec intentionally acknowledges several valuable ideas (some raised in Chris'
"New Auth ideas and Proof of Authorship" notes) but defers them until the
complexity is justified.

### 13.1 Delegation chains and sub-delegation (deferred)

Idea: allow an AppKey (or another delegated key) to delegate narrower capabilities
to third parties (e.g., a read-only key for a specific /priv subtree, or a write-only
key for a specific inbox-like endpoint). This resembles capability-certificate chains
that the homeserver can verify back to the root.

Deferral rationale:

- Chain validation, revocation, and UI/UX around trust boundaries are easy to get wrong.
- Many desired outcomes can be achieved in MVP by using (a) per-app AppKey certs, and
  (b) explicit app-mediated sharing flows (e.g., encrypting data for specific peers).

If/when adopted, it should be introduced as a separate certificate type with:

- Clear chain semantics (issuer, subject, scope, expiry)
- Canonical chain encoding
- Explicit revocation strategy
- Hard bounds on chain length

### 13.2 Delegated readers for /priv paths (deferred)

Idea: homeserver enforces read access to /priv based on a delegated certificate
presented by the client (proof-of-possession).

Deferral rationale:

- This overlaps with higher-level product policy (what /priv means, what is shareable).
- It changes the threat model of the homeserver API and introduces new UX questions.

In MVP, treat /priv as a homeserver policy boundary. If an app wants to share /priv
content, it should do so explicitly using end-to-end encryption to the intended peer(s).

### 13.3 Stateless auth for offline/queued writes (deferred)

Idea: allow writes without a bearer session by relying solely on request signing
and certificate validation.

Deferral rationale:

- Requires careful replay controls, quotas, and anti-abuse measures.

MVP can continue to use bearer sessions plus request signing for defense-in-depth.

### 13.4 Per-scope quotas, tiered access, and policy controls (deferred)

Idea: embed or attach policy attributes (quota, rate limits, tiers) to certificates.

Deferral rationale:

- This is primarily an operator/business concern and can be implemented as server policy
  without being a protocol primitive.

### 13.5 Generic signer and decryptor deep links (deferred)

Idea: expose generic `pubkyauth://sign?payload=...` or `pubkyauth://decrypt?...`.

Deferral rationale:

- High phishing risk.
- Hard to explain and easy to misuse.
- Encourages signing arbitrary blobs with high-value keys.

If any such feature is introduced, it should be strongly typed, scope-limited, and
app-key based (not root), with explicit user intent and clear UI.
