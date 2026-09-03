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
   `drop.rs`: it prefers axum's `ConnectInfo<SocketAddr>` (now wired via
   `into_make_service_with_connect_info`, which does not change `/link`
   behavior), falls back to the first `X-Forwarded-For` entry for
   reverse-proxy deployments, and finally to a shared "unknown" bucket
   (`0.0.0.0`) so requests without either are still rate-limited as a group.
   X-Forwarded-For is only trusted when no connection info is present, since
   it is client-spoofable.

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

7. **CBOR encoding of GET responses**: array of maps with the text keys
   `"cursor"`, `"ts"`, `"body"` exactly as named in the S8 table (`body` is a
   CBOR byte string via `serde_bytes`). The plan's global "integer keys" rule
   gives no integer key assignment for drop entries, so the literal field
   names from S8 were used. `ts` is unix seconds.

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
