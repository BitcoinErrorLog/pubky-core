# PUBKY_CRYPTO_SPEC.md Review Plan - Antoine's Feedback (January 2026)

**Created**: 2026-01-16  
**Reviewer**: Antoine  
**Spec Version**: 2.4  
**Code Commit Reviewed**: b8c0246be56c (pubky-noise)

---

## Executive Summary

Antoine conducted a comprehensive review of both the `pubky-noise` codebase and `PUBKY_CRYPTO_SPEC.md`. His feedback identifies several categories of issues:

1. **Code-implementation gaps** between spec and code
2. **Architectural concerns** about client-server vs symmetric models
3. **Specification clarity** issues requiring better definitions
4. **Potential redundancy** with Noise protocol's built-in security properties
5. **High-level structural recommendation** to split spec into crypto primitives vs app protocols

This plan organizes all feedback items with severity, my assessment (agree/disagree/nuance), and proposed actions.

---

## Part 1: Code-Level Issues (pubky-noise)

These are implementation issues Antoine found in the codebase, not spec issues per se, but several have spec implications.

### 1.1 identity_payload.rs - CRITICAL

| Issue | Details |
|-------|---------|
| **`epoch` field leakage** | Per spec, epoch is Ring-internal derivation parameter. Leaking it reveals entropy space of secret key derivation. |
| **`role` field redundancy** | Noise state machine knows which side it is. Field seems redundant unless > 2 parties. |

**Assessment**: AGREE. The spec already says epoch should not appear in IdentityPayload (Section 6.3), but code still has it.

**Action Items**:
- [ ] **CODE**: Remove `epoch` from `IdentityPayload` struct
- [ ] **CODE**: Evaluate removing `role` field or document why it's needed
- [ ] **SPEC**: Add explicit note in Section 6.3 that role field is for application-layer disambiguation only

### 1.2 kdf.rs - HIGH

| Issue | Details |
|-------|---------|
| **LE vs BE bytes for epoch** | Antoine suggests network convention is BE. |
| **No min length for device_id** | No entropy enforcement. |
| **No doc on clamping entropy** | Whether fixed bits reduce entropy. |
| **`shared_secret_nonzero()` error naming** | Error says "invalid peer key" but it's the shared secret that failed. |
| **Only verifies 1st DH step** | Multi-step handshakes may need verification at each step. |

**Assessment**: 
- LE vs BE: NEUTRAL. HKDF info is not a wire protocol. LE is fine for internal construction.
- Min length: AGREE. Should enforce minimum device_id length.
- Clamping doc: AGREE. Should document entropy implications.
- Error naming: AGREE. Should be `InvalidSharedSecret` or similar.
- Multi-step verification: PARTIALLY AGREE. Snow handles this, but spec should clarify.

**Action Items**:
- [ ] **CODE**: Add minimum length check for `device_id` (suggest 16 bytes)
- [ ] **CODE**: Rename `InvalidPeerKey` error or create `InvalidSharedSecret` variant
- [ ] **SPEC**: Add note in Section 4.5 about clamping entropy implications
- [ ] **SPEC**: Clarify in Section 6.2 that snow handles DH verification at each handshake step

### 1.3 errors.rs - LOW

| Issue | Details |
|-------|---------|
| **No classification by subsystem** | Ring, Pkarr, Snow mixed with Policy, InvalidPeerKey |
| **Unclear target audience** | Human-readable vs machine-processable |

**Assessment**: PARTIALLY AGREE. Current error codes (1000, 2000, etc.) do provide some classification.

**Action Items**:
- [ ] **CODE**: Add documentation clarifying error classification scheme
- [ ] **CODE**: Add `is_internal()` vs `is_user_facing()` methods to error enum

### 1.4 client.rs - MEDIUM

| Issue | Details |
|-------|---------|
| **Prologue inflexibility** | Static field at client creation reduces flexibility. Should be method argument. |
| **`server_hint` undocumented** | Field unused in `build_initiator_xx_tofu()`. |

**Assessment**: AGREE.

**Action Items**:
- [ ] **CODE**: Make prologue a method parameter instead of struct field
- [ ] **CODE**: Document `server_hint` field purpose or remove if unused
- [ ] **SPEC**: Add definition of `server_hint` in Section 6.3

### 1.5 pubky_ring.rs - CRITICAL

| Issue | Details |
|-------|---------|
| **Keypair in hot memory** | Should use mobile's secure enclave. Derivation must happen app-side. |

**Assessment**: AGREE. This is a fundamental security concern.

**Action Items**:
- [ ] **SPEC**: Add Section 5.4 "Platform Secure Element Integration" discussing iOS Keychain / Android Keystore requirements
- [ ] **CODE**: Document `DummyRing` is for testing only; production must use platform keystore

### 1.6 server.rs - MEDIUM

| Issue | Details |
|-------|---------|
| **`seen_client_epoch` vulnerable** | Server can be flooded by UDP packets impersonating client epochs. |

**Assessment**: AGREE. This is a DoS vector.

**Action Items**:
- [ ] **CODE**: Document this limitation in server.rs
- [ ] **SPEC**: Add to Section 1.2 Threat Model that epoch-tracking is vulnerable to spoofing

### 1.7 Other Code Issues - LOW

| File | Issue | Action |
|------|-------|--------|
| `mobile_manager.rs` | ConnectionStatus persistence; exponential backoff UX | Consider laddered backoff |
| `storage_queue.rs` | `tokio::time::sleep` blocking | Refactor to non-blocking |
| `streaming.rs` | Not integrated with mobile_manager | Document or integrate |

---

## Part 2: Architectural Concerns

### 2.1 Client-Server vs Symmetric Model - HIGH

**Antoine's Point**: pubky-noise follows client-server model while pubky-data is fully symmetric. For P2P, symmetric is better - avoids out-of-band negotiation of roles.

**Assessment**: AGREE. This is a fundamental design decision that affects protocol flexibility.

**Action Items**:
- [ ] **SPEC**: Add Section 6.9 "Protocol Symmetry Considerations" discussing:
  - Current client-server model and its implications
  - Future consideration for symmetric operation
  - How inbox polling provides symmetry for stored delivery

### 2.2 Ring/Noise Coupling - MEDIUM

**Antoine's Point**: Code accessing Ring should be logically separated from network access.

**Assessment**: AGREE. Separation of concerns is good security practice.

**Action Items**:
- [ ] **SPEC**: Strengthen Section 1.1 Goal 5 (clean separation) to explicitly state Ring MUST NOT have network access

### 2.3 DoS Hardness - MEDIUM

**Antoine's Point**: Only bounds handshakes per IP; can be gamed. pubky-data defers to homeserver.

**Assessment**: AGREE. Spec should document DoS assumptions more clearly.

**Action Items**:
- [ ] **SPEC**: Expand Section 1.2 Threat Model with explicit DoS assumptions and mitigations

### 2.4 Testing Coverage - INFO

**Antoine's Point**: Cannot verify XX pattern correctness from tests; streaming.rs unused.

**Assessment**: AGREE. Testing gaps should be tracked separately.

**Action Items**:
- [ ] **CODE**: Add XX pattern interoperability tests
- [ ] **CODE**: Either integrate or remove streaming.rs

---

## Part 3: Specification Issues

### 3.1 Section 7.4 - Nonce Generation - HIGH

**Antoine's Points**:
1. XChaCha20-Poly1305 never standardized (IETF draft only)
2. Spec says 12-byte Noise nonces but Noise uses 8-byte nonces internally
3. Design meddling between 2-party encryption and 1-party backup storage

**Assessment**: 
1. AGREE - should acknowledge non-standardized status
2. AGREE - clarify that ChaCha20-Poly1305 uses 12-byte nonce for AEAD but Noise counter is 8 bytes
3. AGREE - clarify this is intentional domain separation

**Action Items**:
- [ ] **SPEC**: Add note in Section 2.1 that XChaCha20-Poly1305 is based on IETF draft-irtf-cfrg-xchacha (widely implemented, considered safe)
- [ ] **SPEC**: Clarify Section 7.4 that Noise's internal 8-byte counter + 4-byte padding produces 12-byte nonce for ChaCha20-Poly1305
- [ ] **SPEC**: Add explicit note in Section 1.4 distinguishing stored delivery (async, random nonce) from backup (local archive, different key)

### 3.2 Section 7.5 - AAD Construction - MEDIUM

**Antoine's Point**: Path should be bound in AAD; suggests SipHash for performance.

**Assessment**: 
- Path binding: ALREADY DONE in spec (path is in AAD)
- SipHash: DISAGREE. SipHash provides hash table collision resistance, not cryptographic binding. BLAKE3 or AAD inclusion is correct.

**Action Items**:
- [ ] **SPEC**: Add rationale paragraph in 7.5 explaining why cryptographic hash (not SipHash) is used for AAD construction

### 3.3 Section 7.6 - Sender Signature - MEDIUM

**Antoine's Points**:
1. Signature verification doesn't demonstrate much
2. No higher hierarchy key committed in AAD
3. Should be a signature of the PKARR pubkey
4. Missing web-of-trust discussion (PGP, X509)

**Assessment**: PARTIALLY AGREE.
- For P2P systems, the Ed25519 key IS the root identity (no hierarchy)
- Web-of-trust is future scope
- Should clarify what `sender_peerid` represents

**Action Items**:
- [ ] **SPEC**: Add paragraph in 7.6 explaining that in Pubky's P2P model, the Ed25519 key is the root identity (no external PKI)
- [ ] **SPEC**: Add note that web-of-trust / identity federation is out of scope for v2.x
- [ ] **SPEC**: Define `sender_peerid` explicitly as "the PKARR Ed25519 public key that owns the sending identity"

### 3.4 Section 7.7 - ContextId Definition - HIGH

**Antoine's Points**:
1. "Paykit thread" is not defined
2. No information if equivalent to a Noise session

**Assessment**: AGREE. These terms need explicit definitions.

**Action Items**:
- [ ] **SPEC**: Add definitions subsection at start of 7.7:
  - **Thread**: A logical conversation between two peers about a specific topic (e.g., a payment negotiation). May span multiple messages.
  - **Session**: A live Noise transport connection. Changes on each handshake.
  - Explicitly state: Thread ≠ Session. Multiple sessions may carry messages for the same thread.

### 3.5 Section 7.7.2 - PairContextId vs PeerPairFingerprint - LOW

**Antoine's Point**: Is it valuable to have PairContextId distinct from PeerPairFingerprint?

**Assessment**: YES, they serve different purposes:
- **PairContextId**: For internal diagnostics/correlation (not user-facing)
- **PeerPairFingerprint**: For user-facing TOFU verification (displayed, compared out-of-band)

**Action Items**:
- [ ] **SPEC**: Add cross-reference between 7.7.2 and 8.5 clarifying the distinction

### 3.6 Section 7.8 - Secure Handoff - MEDIUM

**Antoine's Point**: "Secure handoff" not well defined. Ring shouldn't have homeserver network paths.

**Assessment**: AGREE.

**Action Items**:
- [ ] **SPEC**: Add definition in 7.8: "Secure Handoff is the process by which Ring transfers derived key material to an app (e.g., Bitkit) for local use"
- [ ] **SPEC**: Clarify that Ring does not directly access homeserver; app writes handoff blob to homeserver

### 3.7 Section 7.9 - ACK Protocol - MEDIUM

**Antoine's Points**:
1. Rejected messages should have explicit error codes
2. `status` field is unnecessary (managed by app state machine)
3. `created_at` is redundant (timestamp in ACKed message)
4. ACK lifecycle has too many round-trips
5. Very vulnerable to traffic/timing analysis

**Assessment**: PARTIALLY AGREE.
- Error codes: AGREE, useful for debugging
- `status` field: DISAGREE, status is ACK-specific (message may be delivered but rejected)
- `created_at`: DISAGREE, provides audit trail independent of original message
- Round-trips: AGREE, but this is inherent to async stored delivery
- Traffic analysis: AGREE, acknowledged as out of scope in 1.2

**Action Items**:
- [ ] **SPEC**: Add `error_code` optional field to ACK payload for rejected status
- [ ] **SPEC**: Add note in 7.9 explaining why `status` and `created_at` are included
- [ ] **SPEC**: Add note acknowledging round-trip overhead is trade-off for async delivery

### 3.8 Section 7.10 - AAD "Reinventing Noise" - LOW

**Antoine's Point**: This is reinventing Noise where there's already data authentication.

**Assessment**: DISAGREE. These are different contexts:
- Noise AAD: For live transport frames
- Sealed Blob AAD: For stored ciphertext location binding

**Action Items**:
- [ ] **SPEC**: Add explicit clarification in 7.5 that Sealed Blob AAD is complementary to (not replacing) Noise's transport authentication

### 3.9 Section 8.1 - Live Session Binding - LOW

**Antoine's Point**: Security model uncertain. If handshake tampered, hash is garbage. If not, hash is redundant. "Prevents message injection" claim unclear.

**Assessment**: DISAGREE. The handshake hash prevents:
- Replaying messages from Session A in Session B (same parties, different sessions)
- Message injection by party who observed but didn't complete handshake

**Action Items**:
- [ ] **SPEC**: Expand Section 8.1 with explicit threat model:
  - What attack session binding prevents
  - Why it's not redundant with Noise's built-in protection

### 3.10 Section 9.1 - Key Rotation / Grace Period - LOW

**Antoine's Point**: Noise already has re-key mechanism. Grace period unnecessary if msg_id used.

**Assessment**: PARTIALLY AGREE.
- Noise re-key: For live transport sessions (Section 6)
- Grace period: For stored delivery decryption (Section 7) - sender may encrypt to old key

**Action Items**:
- [ ] **SPEC**: Clarify in 9.1 that grace period is for stored delivery only; live transport uses Noise re-key

---

## Part 4: High-Level Structural Recommendations

### 4.1 Split the Specification - HIGH

**Antoine's Recommendation**: Split PUBKY_CRYPTO_SPEC.md from app state machine (mostly after Section 7).

**Assessment**: AGREE. The spec mixes:
- Cryptographic primitives and protocols (Sections 1-6)
- Application-layer protocols (Sections 7-8, especially Paykit-specific)

**Proposed Structure**:

```
PUBKY_CRYPTO_SPEC.md (Crypto Core)
├── 1. Design Principles
├── 2. Cryptographic Primitives  
├── 3. Identity Model
├── 4. Key Hierarchy and Derivation
├── 5. Device Authorization
├── 6. Live Transport (Noise Protocol)
├── 9. Key Rotation (generic)
├── 10. Backup and Restore (generic)
├── 11. Security Considerations
└── Appendices A, B

PUBKY_MESSAGING_SPEC.md (Messaging Layer)
├── 1. Async Messaging (Sealed Blob)
├── 2. ContextId and Threading
├── 3. Storage Layout
├── 4. ACK Protocol
├── 5. Resend Defaults
├── 6. Session and Message Binding
└── Paykit-specific extensions

PAYKIT_PROTOCOL_SPEC.md (Payment Application)
├── Payment Requests
├── Subscription Proposals
├── Receipt handling
└── Paykit-specific ACK statuses
```

**Action Items**:
- [ ] **SPEC**: Evaluate splitting into 2-3 documents
- [ ] **SPEC**: At minimum, reorganize to clearly separate crypto primitives from app protocols

### 4.2 Reduce Redundancy with Noise - MEDIUM

**Antoine's Point**: There's cryptographic mechanism redundancy. Noise provides security properties we don't use and we reinvent.

**Assessment**: PARTIALLY AGREE. Some "redundancy" is intentional:
- Sealed Blob AAD is for stored delivery (Noise doesn't cover this)
- Session binding is for cross-session replay (Noise handles in-session)

But some clarification would help.

**Action Items**:
- [ ] **SPEC**: Add Section 1.5 "Relationship to Noise Protocol" explaining:
  - What Noise provides that we rely on
  - What additional mechanisms we add and why
  - What Noise features we don't use and why

---

## Part 5: Comparison with pubky-data

Antoine notes that pubky-data has some advantages over pubky-noise:

| Aspect | pubky-noise | pubky-data |
|--------|-------------|------------|
| **Model** | Client-server | Fully symmetric |
| **Ring integration** | Coupled | Decoupled |
| **Secure enclave** | DummyRing only | N/A (no derivation yet) |
| **DoS** | Bounds per IP | Defers to homeserver |
| **Thread model** | Backoff in send | Room for thread pool |
| **Testing** | Basic mobile tests | More unit tests for Noise correctness |

And pubky-noise has advantages:
- Identity binding
- High-level mobile_manager interface

**Action Items**:
- [ ] **ARCH**: Document comparison for future consolidation discussion
- [ ] **ARCH**: Consider best-of-both approach in future architecture

---

## Implementation Priority

### Critical (Spec v2.5)
1. [ ] Define "thread" vs "session" vs "context" terminology (3.4)
2. [ ] Clarify epoch field removal from IdentityPayload (1.1)
3. [ ] Add XChaCha20 non-standardization note (3.1)
4. [ ] Clarify Noise nonce sizes (3.1)

### High (Spec v2.5 or v2.6)
5. [ ] Define `sender_peerid` explicitly (3.3)
6. [ ] Define "secure handoff" (3.6)
7. [ ] Add Platform Secure Element Integration section (1.5)
8. [ ] Expand threat model for DoS (2.3)
9. [ ] Evaluate spec splitting (4.1)

### Medium (Spec v2.6+)
10. [ ] Add AAD construction rationale (3.2)
11. [ ] Add error_code to ACK payload (3.7)
12. [ ] Add Relationship to Noise Protocol section (4.2)
13. [ ] Expand session binding threat model (3.9)
14. [ ] Clarify grace period scope (3.10)

### Low (Documentation)
15. [ ] Cross-reference PairContextId vs PeerPairFingerprint (3.5)
16. [ ] Clarify AAD is complementary to Noise (3.8)
17. [ ] Document client-server vs symmetric considerations (2.1)

---

## Code Changes (Tracked Separately)

These should be tracked in pubky-noise repository issues:

1. **CRITICAL**: Remove `epoch` from `IdentityPayload`
2. **CRITICAL**: Document DummyRing is test-only
3. **HIGH**: Add minimum device_id length check
4. **HIGH**: Rename `InvalidPeerKey` to `InvalidSharedSecret`
5. **MEDIUM**: Make prologue a method parameter
6. **MEDIUM**: Document `server_hint` or remove
7. **MEDIUM**: Add XX pattern interoperability tests
8. **LOW**: Document error classification scheme
9. **LOW**: Refactor storage_queue to non-blocking
10. **LOW**: Integrate or remove streaming.rs

---

## Notes

### Where I Disagree with Antoine

1. **SipHash for AAD**: SipHash is for hash table collision resistance, not cryptographic binding. Current approach (include in AAD) is correct.

2. **AAD reinventing Noise**: Sealed Blob AAD is for stored delivery location binding. Noise AAD is for transport frames. These are complementary, not redundant.

3. **Session binding redundancy**: Handshake hash prevents cross-session replay between same parties. This is not covered by Noise's in-session protection.

4. **Grace period unnecessary**: Noise re-key is for live sessions. Grace period is for stored delivery where sender may use old key. Different concerns.

5. **LE vs BE for epoch**: HKDF info is not a wire protocol. LE is fine for internal construction and matches Rust's natural byte order.

### Where Antoine's Feedback is Especially Valuable

1. **Terminology clarity**: "Thread" vs "session" vs "context" - spec needs clearer definitions
2. **Epoch leakage**: Code still has epoch in IdentityPayload despite spec saying otherwise
3. **Symmetric model consideration**: Valid point for P2P platform design
4. **Testing gaps**: Important for protocol correctness verification
5. **Spec structure**: Splitting crypto from app protocols would improve clarity

---

*This plan should be reviewed with Antoine and the team before implementation.*
