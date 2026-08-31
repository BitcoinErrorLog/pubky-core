# Session expiry and owner-initiated revocation

Upstreamable proposal for `pubky/pubky-core`.

## Vulnerability

Homeserver sessions were bearer secrets with no owner control:

- Sign-in set the session cookie to expire in one year (`Duration::days(365)`).
- `SessionInfo` had `created_at` and no `expires_at` (FFI hardcoded `None`).
- `SessionRepository` could create, look up by secret, and delete by secret. There was no list-by-user and no owner revoke.
- `DELETE /session` (signout) required the cookie, so only the *holder* could end that session.

If a session cookie leaked — stolen device, XSS, or a malicious app that was granted capabilities — the key owner could not revoke it for up to a year and could not even see active sessions. Rotating keys did not help: sessions are validated by secret, not re-derived from the key.

`AUTH.md` assumed an Authenticator session directory that was not implemented, and declared session expiration out of scope.

## Fix

### Expiry

- Each session row stores `expires_at`.
- `get_by_secret` rejects expired sessions and deletes them (fail closed, reap on use).
- Listing reaps expired rows for that user first.
- Cookie `max_age` / `expires` match the stored TTL.
- Default TTL is **30 days** (`session_ttl_seconds = 2592000`). `0` is treated as this default (never infinite, never expire-immediately from a missing key).
- Operators can set a different TTL in `config.toml`.

**Why 30 days, not 365:** a leaked cookie lasting a year is the bug. Thirty days is long enough for a browser/app session and short enough that a leak is time-bounded. Users who hold the key can mint a new session at any time. Operators who want the old year-long cookie can set `session_ttl_seconds = 31536000`.

### Enumeration

`POST /sessions` with a fresh root AuthToken returns the caller's active sessions:

- `id` (stable integer, used to revoke)
- `created_at` / `expires_at` (unix seconds)
- granted capabilities

The session secret is never returned. User-agent and last-seen are not stored today; they are omitted rather than faked.

### Owner-initiated revocation

- `DELETE /sessions/{id}` — revoke one session
- `DELETE /sessions` — revoke **all** sessions for the owner

**Authorization: a fresh AuthToken signed by the owner key, with root capability.** The homeserver runs the existing `AuthVerifier` (Ed25519 signature, ±45s timestamp window, replay id). The token's public key must match the tenant. A session cookie is ignored on these routes.

This cannot be satisfied by a stolen cookie: a cookie is a random 16-byte secret. It is not an Ed25519 signature over `PUBKY:AUTH`. An attacker who has only the cookie cannot produce a new AuthToken.

Root capability is required so a briefly-held scoped token (user approved a third-party QR for `/pub/app/:rw`) cannot list or revoke. Only the Authenticator signing a root token can.

**Revoke-all includes the calling session.** Safer than "except current": after a leak the owner wants every bearer dead. They sign in again with the key. An `except=` convenience would let a confused caller leave a stolen session alive if they passed the wrong id.

`DELETE /session` (cookie signout) is unchanged: the holder can still end *their own* session without the key.

### Fail-closed behaviour

- Unparseable, expired, unknown, or revoked secrets are rejected.
- Expired is treated as missing (`RowNotFound`) after reap.
- Writes with a dead cookie return 401.
- `GET /session` still returns 404 for a missing/expired cookie so `revalidate()` keeps working, and also 404 if the cookie's session user does not match the tenant key.
- Owner-proof failures return a generic 401 (no oracle for expired vs reused vs bad signature).
- Only the exact methods `GET|DELETE /session`, `POST|DELETE /sessions`, and `DELETE /sessions/{digits}` skip cookie capability checks. `PUT /sessions/1` is not a write bypass.
- `AuthToken::verify` rejects bodies shorter than 115 bytes (`Error::TooShort`) instead of indexing byte 75. Sign-in and sign-up no longer panic on a truncated body.
- `SessionSecret`'s `Debug` impl is redacted so a future `tracing::debug!(?session)` cannot leak the cookie.

## Migration

New SQL migration `m20260831_session_expiry`:

1. Add nullable `expires_at`.
2. Backfill `expires_at = created_at + INTERVAL '365 days'` so existing sessions keep the lifetime they were issued.
3. Set `NOT NULL`.
4. Index `expires_at` and `user`.

Sessions older than 365 days become expired on first use after upgrade (same as their original cookie). New sessions use the configured TTL (default 30 days).

LMDB→SQL session import writes `expires_at` from `SessionInfo` when present, otherwise `created_at + 365 days`.

## Breaking API change

`SessionInfo` wire format is now version 1 and includes `expires_at: Option<u64>`.

- Version 0 payloads still deserialize (`expires_at = None`).
- New sign-in / `GET /session` bodies serialize as version 1.
- Old clients that reject `version > 0` cannot parse new session bodies and must be updated with this crate.

`SessionInfo::new` still takes three arguments; call `set_expires_at` before sending a body to clients. FFI `FfiSessionInfo.expires_at` is populated from the homeserver instead of hardcoded `None`.

SDK additions (non-breaking):

- `PubkySigner::list_sessions()`
- `PubkySigner::revoke_session(id)`
- `PubkySigner::revoke_all_sessions()`

These live on the signer (has the key), not on `PubkySession` (has only the cookie).

## Clock skew

`expires_at` is written and compared using the homeserver clock. There is no post-expiry grace: `expires_at <= now` is expired. AuthToken verification already allows ±45 seconds; session expiry does not extend a leaked cookie.

## Concurrent revoke and replay

Deletes are ordinary SQL `DELETE`s (idempotent). A revoked or expired cookie fails on the next `get_by_secret`. Two concurrent revoke-alls both succeed.
