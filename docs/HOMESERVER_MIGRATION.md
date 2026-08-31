# Homeserver migration

An identity can move its mailbox pointer (`_pubky`) from one homeserver to
another. The identity public key does not change.

## What `migrate_homeserver` does

1. Obtains a session on the **new** host:
   - `POST /signup` when the user does not exist there.
   - On HTTP 409 (`User already exists`), `POST /session` on that same host.
     This recovery is required because the homeserver creates the user
     *before* the client publishes `_pubky`. A failed first publish must not
     become a dead end.
2. Force-publishes `_pubky` to the new homeserver public key. CAS retries
   restore the previous packet in the pkarr cache, re-resolve the latest
   signed packet, and (on the last force attempt) omit If-Match so a
   phantom cache entry cannot loop forever.

Sign-in during recovery targets `https://<new-homeserver>/session`. It does
**not** follow the current `_pubky` record, which may still point at the
previous host. The hydrated session's public key is checked against the
signing identity.

On native, the session cookie is keyed by user pubkey only, not by the
issuing host. After a move, stale Pubky TLS routing can send the new
host's cookie to the old host until the packet cache expires. WASM
cookies are origin-scoped and are not affected.

## What it does not do

**Host-local data is not copied.** Files, WebDAV trees, Encrypted Link
outboxes, attachments, and sessions on the previous homeserver stay there.
A peer that already resolved `_pubky` may keep using the old mailbox until
its pkarr cache expires (packet TTL is 3600s; the pkarr client clamps cache
to 300–86400s). Native Pubky TLS can keep routing `https://<user>/…` to the
previous host for that same cache window even after `get_homeserver`
returns the new pointer. WASM clients re-select ICANN/HTTP endpoints from
the packet they resolve; they still inherit the packet cache.

After a move, the caller must re-publish anything the new host needs
(receiver markers, public documents, and so on). Ban-survival of history
depends on the peer's **local** copy, not on the old host remaining
reachable.

## API

- Rust: `PubkySigner::migrate_homeserver(homeserver, signup_token)`
- JS (`@synonymdev/pubky` bindings): `signer.migrateHomeserver(homeserver, signupToken)`
- UniFFI: `FfiSdk.migrate_homeserver(key_provider, homeserver, signup_token)`
