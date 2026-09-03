# DECISIONS — Molt wave 1c, S8 Drop relay (http-relay)

Conservative readings taken where the spec (molt_v10.plan.md §S8) is ambiguous,
with reasoning. Implementation: `src/drop.rs`, wired in `src/lib.rs` and
`src/http_relay.rs`.

1. **"Existing pubkyauth channels"** are the `/link/{id}` producer/consumer
   channels held in-memory behind `Arc<Mutex<WaitingList>>` in `AppState`.
   Drop storage is likewise in-memory: `Arc<Mutex<DropStore>>` in `AppState`.
   No persistence was added (S8 specifies TTL + LRU bounds only).

2. **"The crate's existing IP extraction" does not exist.** The `/link`
   endpoints never extracted client IPs. A `ClientIp` extractor was added in
   `drop.rs`: it uses axum's `ConnectInfo<SocketAddr>` (wired via
   `into_make_service_with_connect_info`, which does not change `/link`
   behavior) as the client identity for rate limiting. `X-Forwarded-For` is
   honored **only** when the immediate peer address is in
   `DropConfig::trusted_proxies` (default: empty, trust nobody), and then the
   rightmost hop that is not itself trusted is used, falling back to the
   leftmost hop when every listed hop is trusted; from any other peer the
   client-spoofable header is ignored entirely. Requests with no peer address
   at all (e.g. in-process tests) share a single "unknown" bucket
   (`0.0.0.0`) so they are still rate-limited as a group. (Amended in review
   round 2: previously XFF was trusted whenever `ConnectInfo` was absent,
   which let an untrusted client spoof its rate-limit identity and would
   have rate-limited the proxy IP instead of the client behind a reverse
   proxy.)

3. **Per-IP write rate limit value**: S8 mandates the limit but gives no
   number. Default: 120 writes per 60 s per IP (`DropConfig::write_rate_limit`
   / `write_rate_window`), bounded to 100k tracked IPs with LRU eviction.
   Chosen to be far above honest polling/ack traffic (writes are only `PUT`s;
   `GET`/`DELETE` are not rate-limited per S8's "write limit") and low enough
   to bound spam. Both are configurable.

4. **`limit` on GET**: absent → defaults to the configured max (50 per S8);
   values above the max are **clamped**, not rejected, so well-meaning clients
   are not broken by a hard error. Invalid (non-numeric) `since`/`limit` → 400.

5. **Content-Type on PUT is not enforced.** S8 lists the body as "SB2 ≤ 64
   KiB"; the relay treats bodies as opaque octets and enforces only the 64 KiB
   size bound (413 above it, via `DefaultBodyLimit`, applied only to `/drop`
   routes so `/link` behavior is unchanged). Rejecting other content types
   would break clients without improving anything the relay can verify.

6. **base64url channel ids**: both padded and unpadded URL-safe alphabets are
   accepted; anything that does not decode to exactly 32 bytes → 400.

7. **CBOR encoding of GET responses**: deterministic CBOR — a
   definite-length array of definite-length maps with the integer keys `0` =
   cursor (u64), `1` = ts (unix seconds, u64), `2` = body (byte string), in
   ascending key order with shortest-form integers, so the encoding of any
   given message list is unique. The plan's global "integer keys" rule gives
   no assignment for drop entries, so `0/1/2` were assigned in S8 field
   order; the schema is documented on `DropMessage`. (Amended in review
   round 2: the first implementation used serde-derived text keys, which the
   review flagged against the plan's deterministic-CBOR-with-integer-keys
   requirement.)

8. **Cursors**: per-channel, strictly increasing `u64` starting at 0, never
   reused within a channel's lifetime (deletion/expiry do not reset it).
   `since` is exclusive: messages with `cursor > since` are returned.

9. **Full channel behavior**: a `PUT` to a channel at its message-count or
   byte budget is rejected with **409 Conflict** (senders must wait for
   ack-deletes or TTL expiry); the relay never silently drops older messages,
   since only the receiver can know what was consumed.

10. **DELETE semantics**: 204 on success, 404 when the channel or cursor is
    unknown (including TTL-expired messages), 400 on a non-numeric cursor.

11. **TTL enforcement is lazy** (purged on every channel access); no
    background sweeper task was added, keeping the relay's runtime behavior
    unchanged.

12. **LRU eviction** uses a tick-stamped append-only queue with lazy skip of
    stale entries and compaction at 2× capacity, so all structures stay
    bounded without an extra dependency.

13. **Manifest** (`drop_relay_manifest()`): mirrors the S5 `Manifest`/
    `Witness` shapes as JSON. One witness, role `RelayOperator`, with
    `learns_in == learns_out = [NETWORK_LOCATION, TIME, CONTENT_SIZE,
    RELATIONSHIP_LINK]` (the relay observes writes and polls symmetrically;
    `RELATIONSHIP_LINK` is the poll-pattern linkage S8 notes). `preserves` is
    empty and `latency_bound_secs` is null — the relay preserves no correlator
    across the hop. `adapter_id` is `"http-relay.drop.v1"` (lowercase ASCII,
    dot-separated, per the plan's identifier grammar). `operator` is
    `"unknown"` with empty `domains`, since a binary cannot know its operator.

14. **Logging**: channel ids are never logged. The only drop-related log
    statement (LRU eviction) is at `debug` and carries counts only.

## Review round 2 (independent review of 64f6485d)

15. **Finding (1) — global byte cap.** `DropConfig::max_total_bytes`
    (default 256 MiB) bounds the total body bytes across all channels;
    without it, 100k channels × 4 MiB was ~400 GiB. `DropStore` tracks
    `total_bytes` precisely on insert, ack-delete, TTL purge and LRU
    eviction (exposed via `total_stored_bytes()`). When a `PUT` would exceed
    the budget, the store first purges expired messages from **all**
    channels, then evicts least-recently-used channels until the message
    fits, and only then rejects with `DropError::StorageExhausted` →
    **507 Insufficient Storage**. Purge-before-evict was chosen so stale
    data is reclaimed before live channels are destroyed; empty channels
    left by a purge are kept (and still count towards `max_channels`) so
    their cursors are not reset — they are reclaimed by ordinary LRU
    eviction.

16. **Finding (2) — X-Forwarded-For trust.** See amended entry 2. XFF is
    only honored from `DropConfig::trusted_proxies` (rightmost untrusted
    hop); otherwise the peer address is used, and with no peer at all a
    single shared "unknown" bucket is used. Default `trusted_proxies` is
    empty: a relay that is not knowingly deployed behind a reverse proxy
    trusts nothing.

17. **Finding (3) — deterministic integer-keyed CBOR.** See amended entry
    7. `DropMessage` now has a manual `Serialize` impl emitting a
    definite-length 3-entry map with ascending integer keys; a byte-exact
    unit test pins the encoding.

18. **Finding (4) — cursor overflow.** `next_cursor` now uses
    `checked_add`; at `u64::MAX` the append fails with
    `DropError::CursorExhausted` → **507** instead of silently wrapping to
    0 (which would have reused cursor 0 and broken `since` polling). The
    failed append stores nothing and leaves the channel untouched.

19. **Finding (5) — TTL sweep.** Every `PUT` runs a cheap all-channel TTL
    sweep once `total_bytes` exceeds 50% of `max_total_bytes`, so expired
    data is reclaimed before LRU eviction becomes necessary; below the
    halfway mark sweeping is skipped to keep writes O(channel). Remaining
    laziness: below 50% occupancy, expired bytes on untouched channels still
    linger until the channel is next accessed or the byte cap forces a
    purge, and no background sweeper task exists — a channel that is never
    touched again only disappears via LRU eviction. This is accepted because
    all structures remain bounded either way.

20. **Finding (6) — pre-existing `/link` timeout test.** The original
    `let mut config = Config::default(); config.request_timeout = ...`
    construction was restored literally so the pre-existing test is
    unchanged; a targeted `#[allow(clippy::field_reassign_with_default)]`
    keeps current clippy green on that legacy form.
