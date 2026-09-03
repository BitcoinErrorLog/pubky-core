//! Molt Drop relay (plan v10, section S8): unauthenticated dead-drop channels.
//!
//! A Drop channel is an opaque 32-byte id, derived by clients from a Bond,
//! direction, purpose and epoch. This relay only ever sees the opaque id and
//! opaque ciphertext bodies; authenticity lives inside the payloads (SB2),
//! never at this layer. Everything keyed by remote input (channels, messages,
//! rate-limit entries) is bounded; see [`DropConfig`] for the bounds. Stored
//! bytes are bounded globally by [`DropConfig::max_total_bytes`]: when a
//! `PUT` would exceed that budget, expired channels are purged first, then
//! least-recently-used channels are evicted until the message fits, and a
//! message that still cannot fit is rejected with `507 Insufficient Storage`.
//!
//! `GET` responses are deterministic CBOR (see the schema documented on
//! [`DropMessage`]), and client-IP rate limiting only honors
//! `X-Forwarded-For` from [`DropConfig::trusted_proxies`].
//!
//! Channel ids are never logged above `debug` level.

use std::{
    collections::{HashMap, VecDeque},
    convert::Infallible,
    fmt,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    body::Bytes,
    extract::{ConnectInfo, DefaultBodyLimit, FromRequestParts, Path, Query, State},
    http::{header, request::Parts, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, put},
    Router,
};
use base64::{
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
    Engine as _,
};
use ipnet::IpNet;
use serde::Deserialize;

use crate::http_relay::AppState;

/// Default time-to-live for a stored drop message: 7 days (S8).
pub const DEFAULT_MESSAGE_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// Default maximum number of messages held per channel (S8).
pub const DEFAULT_MAX_MESSAGES_PER_CHANNEL: usize = 64;
/// Default maximum total body bytes held per channel: 4 MiB (S8).
pub const DEFAULT_MAX_BYTES_PER_CHANNEL: usize = 4 * 1024 * 1024;
/// Default maximum number of channels held globally before LRU eviction (S8).
pub const DEFAULT_MAX_CHANNELS: usize = 100_000;
/// Default maximum total body bytes held across all channels: 256 MiB.
pub const DEFAULT_MAX_TOTAL_BYTES: usize = 256 * 1024 * 1024;
/// Default maximum size of a single drop message body: 64 KiB (S8).
pub const DEFAULT_MAX_BODY_BYTES: usize = 64 * 1024;
/// Default maximum number of messages returned by a single poll (S8).
pub const DEFAULT_MAX_GET_LIMIT: usize = 50;
/// Default per-IP write budget within one rate window.
pub const DEFAULT_WRITE_RATE_LIMIT: u32 = 120;
/// Default per-IP write rate window length.
pub const DEFAULT_WRITE_RATE_WINDOW: Duration = Duration::from_secs(60);
/// Default maximum number of IP addresses tracked by the write rate limiter.
pub const DEFAULT_MAX_TRACKED_IPS: usize = 100_000;

/// Response header carrying the cursor of a newly appended drop message.
pub const X_DROP_CURSOR: &str = "X-Drop-Cursor";

/// Configuration bounds for the Drop relay.
///
/// All defaults are the S8 defaults; every structure keyed by remote input is
/// bounded by one of these values.
#[derive(Debug, Clone)]
pub struct DropConfig {
    /// How long a message is kept before it expires.
    pub message_ttl: Duration,
    /// Maximum number of messages held per channel.
    pub max_messages_per_channel: usize,
    /// Maximum total body bytes held per channel.
    pub max_bytes_per_channel: usize,
    /// Maximum number of channels held globally; least-recently-used channels
    /// are evicted beyond this.
    pub max_channels: usize,
    /// Maximum total message body bytes held across all channels globally.
    ///
    /// When a `PUT` would exceed this budget, expired channels are purged
    /// first, then least-recently-used channels are evicted until the message
    /// fits; a single message that still cannot fit is rejected with
    /// [`DropError::StorageExhausted`] (`507 Insufficient Storage`).
    pub max_total_bytes: usize,
    /// Proxy addresses (individual IPs or CIDR ranges) whose
    /// `X-Forwarded-For` headers are trusted for rate limiting.
    ///
    /// The header is honored (rightmost untrusted hop) only when the
    /// immediate peer address is contained in one of these networks; from any
    /// other peer the spoofable header is ignored. Default: empty (trust
    /// nobody).
    pub trusted_proxies: Vec<IpNet>,
    /// Maximum size of a single message body in bytes.
    pub max_body_bytes: usize,
    /// Maximum number of messages returned by a single `GET` poll.
    pub max_get_limit: usize,
    /// Number of writes (`PUT`) allowed per IP address per rate window.
    pub write_rate_limit: u32,
    /// Length of the per-IP write rate window.
    pub write_rate_window: Duration,
    /// Maximum number of IP addresses tracked by the rate limiter before
    /// least-recently-used entries are evicted.
    pub max_tracked_ips: usize,
}

impl Default for DropConfig {
    fn default() -> Self {
        Self {
            message_ttl: DEFAULT_MESSAGE_TTL,
            max_messages_per_channel: DEFAULT_MAX_MESSAGES_PER_CHANNEL,
            max_bytes_per_channel: DEFAULT_MAX_BYTES_PER_CHANNEL,
            max_channels: DEFAULT_MAX_CHANNELS,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            trusted_proxies: Vec::new(),
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            max_get_limit: DEFAULT_MAX_GET_LIMIT,
            write_rate_limit: DEFAULT_WRITE_RATE_LIMIT,
            write_rate_window: DEFAULT_WRITE_RATE_WINDOW,
            max_tracked_ips: DEFAULT_MAX_TRACKED_IPS,
        }
    }
}

/// An opaque Drop channel id: exactly 32 bytes, base64url-encoded on the wire.
///
/// Never logged above `debug` level anywhere in this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChannelId([u8; 32]);

impl ChannelId {
    /// Parses a base64url (padded or unpadded) channel id.
    ///
    /// Returns [`DropError::InvalidChannelId`] unless the input decodes to
    /// exactly 32 bytes.
    pub fn from_base64url(s: &str) -> Result<Self, DropError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(s)
            .or_else(|_| URL_SAFE.decode(s))
            .map_err(|_| DropError::InvalidChannelId)?;

        let id: [u8; 32] = bytes.try_into().map_err(|_| DropError::InvalidChannelId)?;

        Ok(Self(id))
    }

    /// Returns the raw 32-byte channel id.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Errors produced by the Drop relay storage and parsing layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DropError {
    /// The channel id was not base64url decoding to exactly 32 bytes.
    InvalidChannelId,
    /// A single message body exceeded the configured per-message limit.
    MessageTooLarge {
        /// The configured maximum body size in bytes.
        max: usize,
    },
    /// The channel already holds the configured maximum number of messages.
    ChannelMessageLimit {
        /// The configured maximum message count per channel.
        max: usize,
    },
    /// Storing the message would exceed the configured per-channel byte budget.
    ChannelByteLimit {
        /// The configured maximum total body bytes per channel.
        max: usize,
    },
    /// Storing the message would exceed the configured global byte budget,
    /// even after purging expired channels and evicting least-recently-used
    /// channels.
    StorageExhausted {
        /// The configured maximum total body bytes across all channels.
        max: usize,
    },
    /// The channel's cursor space (`u64`) is exhausted; no further messages
    /// can be appended without reusing a cursor.
    CursorExhausted,
    /// The per-IP write rate limit was exceeded.
    RateLimited,
    /// No message with the given cursor exists on the channel.
    MessageNotFound,
}

impl fmt::Display for DropError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DropError::InvalidChannelId => {
                write!(f, "channel id must base64url-decode to exactly 32 bytes")
            }
            DropError::MessageTooLarge { max } => {
                write!(f, "message body exceeds the {max} byte limit")
            }
            DropError::ChannelMessageLimit { max } => {
                write!(f, "channel already holds the maximum of {max} messages")
            }
            DropError::ChannelByteLimit { max } => {
                write!(f, "channel byte budget of {max} bytes would be exceeded")
            }
            DropError::StorageExhausted { max } => {
                write!(f, "global byte budget of {max} bytes is exhausted")
            }
            DropError::CursorExhausted => write!(f, "channel cursor space is exhausted"),
            DropError::RateLimited => write!(f, "per-IP write rate limit exceeded"),
            DropError::MessageNotFound => write!(f, "message not found"),
        }
    }
}

impl std::error::Error for DropError {}

/// A single stored drop message.
///
/// Wire schema for `GET /drop/{channel}` responses (deterministic CBOR): the
/// response is a definite-length CBOR array of items, and each item is a
/// definite-length CBOR map with exactly three integer keys in ascending
/// order:
///
/// | Key | Value  | CBOR type        |
/// |-----|--------|------------------|
/// | `0` | cursor | unsigned integer |
/// | `1` | ts     | unsigned integer (unix seconds) |
/// | `2` | body   | byte string      |
///
/// Integers use shortest-form encoding and all lengths are definite, so the
/// encoding of any given message list is unique.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropMessage {
    /// Per-channel, strictly monotonically increasing cursor.
    pub cursor: u64,
    /// Unix timestamp (seconds) at which the relay accepted the message.
    pub ts: u64,
    /// Opaque message body (ciphertext as far as the relay is concerned).
    pub body: Vec<u8>,
}

impl serde::Serialize for DropMessage {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry(&0u8, &self.cursor)?;
        map.serialize_entry(&1u8, &self.ts)?;
        map.serialize_entry(&2u8, &serde_bytes::Bytes::new(&self.body))?;
        map.end()
    }
}

#[derive(Debug, Default)]
struct ChannelEntry {
    messages: VecDeque<DropMessage>,
    total_bytes: usize,
    next_cursor: u64,
    lru_tick: u64,
}

#[derive(Debug)]
struct RateEntry {
    count: u32,
    window_start_secs: u64,
    lru_tick: u64,
}

/// In-memory, fully bounded storage for Drop channels.
///
/// Held behind an `Arc<Mutex>` in the relay's application state, consistent
/// with how the existing pubkyauth (`/link`) channels are held in memory.
#[derive(Debug)]
pub struct DropStore {
    config: DropConfig,
    channels: HashMap<ChannelId, ChannelEntry>,
    /// Approximate LRU order; stale entries are skipped lazily on eviction.
    channel_lru: VecDeque<(ChannelId, u64)>,
    rate_limits: HashMap<IpAddr, RateEntry>,
    /// Approximate LRU order for rate-limit entries.
    rate_lru: VecDeque<(IpAddr, u64)>,
    /// Total message body bytes currently held across all channels; tracked
    /// precisely on insert, delete, purge and eviction, and never exceeds
    /// `DropConfig::max_total_bytes`.
    total_bytes: usize,
    tick: u64,
}

impl DropStore {
    /// Creates an empty store with the given bounds.
    pub fn new(config: DropConfig) -> Self {
        Self {
            config,
            channels: HashMap::new(),
            channel_lru: VecDeque::new(),
            rate_limits: HashMap::new(),
            rate_lru: VecDeque::new(),
            total_bytes: 0,
            tick: 0,
        }
    }

    /// Appends a message to a channel and returns its cursor.
    ///
    /// Enforces the per-message size limit, the per-channel message count and
    /// byte budgets, the global channel bound, and the global byte budget
    /// (`DropConfig::max_total_bytes`). For the global byte budget, expired
    /// channels are purged first, then least-recently-used channels are
    /// evicted until the message fits; a single message that still cannot fit
    /// is rejected with [`DropError::StorageExhausted`]. Once the store is
    /// more than half full, every `PUT` first runs a cheap sweep that purges
    /// expired messages from all channels. Expired messages on the target
    /// channel are always purged before the per-channel limits are checked.
    pub fn append(
        &mut self,
        id: ChannelId,
        body: Vec<u8>,
        now: SystemTime,
    ) -> Result<u64, DropError> {
        if body.len() > self.config.max_body_bytes {
            return Err(DropError::MessageTooLarge {
                max: self.config.max_body_bytes,
            });
        }

        let now_secs = unix_secs(now);

        // Cheap TTL sweep once the store is more than half full, so expired
        // data is reclaimed before LRU eviction has to destroy live channels.
        if self.total_bytes > self.config.max_total_bytes / 2 {
            self.purge_expired_channels(now_secs);
        }

        // Global byte budget: purge expired channels first, then evict
        // least-recently-used channels until the message fits.
        if !self.fits_within_global_cap(body.len()) {
            self.purge_expired_channels(now_secs);
            while !self.fits_within_global_cap(body.len())
                && self.evict_least_recently_used_channel()
            {}
            if !self.fits_within_global_cap(body.len()) {
                return Err(DropError::StorageExhausted {
                    max: self.config.max_total_bytes,
                });
            }
        }

        if !self.channels.contains_key(&id) {
            if self.channels.len() >= self.config.max_channels {
                self.evict_channels_to(self.config.max_channels.saturating_sub(1));
            }
            self.channels.insert(id, ChannelEntry::default());
        }
        self.touch_channel(&id);
        self.purge_channel(&id, now_secs);

        let max_messages = self.config.max_messages_per_channel;
        let max_bytes = self.config.max_bytes_per_channel;

        let entry = self
            .channels
            .get_mut(&id)
            .expect("channel inserted immediately above");

        if entry.messages.len() >= max_messages {
            return Err(DropError::ChannelMessageLimit { max: max_messages });
        }
        if entry.total_bytes + body.len() > max_bytes {
            return Err(DropError::ChannelByteLimit { max: max_bytes });
        }

        let cursor = entry.next_cursor;
        entry.next_cursor = cursor.checked_add(1).ok_or(DropError::CursorExhausted)?;
        let body_len = body.len();
        entry.total_bytes += body_len;
        entry.messages.push_back(DropMessage {
            cursor,
            ts: now_secs,
            body,
        });
        self.total_bytes += body_len;

        Ok(cursor)
    }

    /// Returns up to `limit` messages with `cursor > since` (or from the
    /// beginning when `since` is `None`), oldest first.
    ///
    /// The caller is responsible for clamping `limit`; this method never
    /// returns more than `limit` messages. Polling counts as channel activity
    /// for LRU purposes. Expired messages are purged lazily and never
    /// returned. An unknown channel yields an empty vector.
    pub fn poll(
        &mut self,
        id: &ChannelId,
        since: Option<u64>,
        limit: usize,
        now: SystemTime,
    ) -> Vec<DropMessage> {
        self.touch_channel(id);
        self.purge_channel(id, unix_secs(now));

        let Some(entry) = self.channels.get(id) else {
            return Vec::new();
        };
        entry
            .messages
            .iter()
            .filter(|m| since.is_none_or(|s| m.cursor > s))
            .take(limit)
            .cloned()
            .collect()
    }

    /// Ack-deletes a single message by cursor.
    ///
    /// Returns [`DropError::MessageNotFound`] when the channel is unknown or
    /// holds no (unexpired) message with that cursor.
    pub fn delete(
        &mut self,
        id: &ChannelId,
        cursor: u64,
        now: SystemTime,
    ) -> Result<(), DropError> {
        self.touch_channel(id);
        self.purge_channel(id, unix_secs(now));

        let Some(entry) = self.channels.get_mut(id) else {
            return Err(DropError::MessageNotFound);
        };
        let Some(position) = entry.messages.iter().position(|m| m.cursor == cursor) else {
            return Err(DropError::MessageNotFound);
        };
        if let Some(message) = entry.messages.remove(position) {
            entry.total_bytes = entry.total_bytes.saturating_sub(message.body.len());
            self.total_bytes = self.total_bytes.saturating_sub(message.body.len());
        }

        Ok(())
    }

    /// Records a write attempt from `ip` and enforces the per-IP write rate
    /// limit.
    ///
    /// Returns [`DropError::RateLimited`] once `write_rate_limit` writes have
    /// been recorded within the current window. The set of tracked IPs is
    /// bounded by `max_tracked_ips` with LRU eviction.
    pub fn record_write(&mut self, ip: IpAddr, now: SystemTime) -> Result<(), DropError> {
        let now_secs = unix_secs(now);
        let window_secs = self.config.write_rate_window.as_secs().max(1);
        let limit = self.config.write_rate_limit;

        if !self.rate_limits.contains_key(&ip) {
            if self.rate_limits.len() >= self.config.max_tracked_ips {
                self.evict_rate_entries_to(self.config.max_tracked_ips.saturating_sub(1));
            }
            self.rate_limits.insert(
                ip,
                RateEntry {
                    count: 0,
                    window_start_secs: now_secs,
                    lru_tick: 0,
                },
            );
        }

        let entry = self
            .rate_limits
            .get_mut(&ip)
            .expect("rate entry inserted immediately above");
        if now_secs.saturating_sub(entry.window_start_secs) >= window_secs {
            entry.count = 0;
            entry.window_start_secs = now_secs;
        }

        if entry.count >= limit {
            self.touch_rate_entry(&ip);
            return Err(DropError::RateLimited);
        }
        entry.count += 1;
        self.touch_rate_entry(&ip);

        Ok(())
    }

    /// Returns the number of channels currently held.
    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }

    /// Returns `true` when no channels are held.
    pub fn is_empty(&self) -> bool {
        self.channels.is_empty()
    }

    /// Returns the total number of message body bytes currently held across
    /// all channels; never exceeds [`DropConfig::max_total_bytes`].
    pub fn total_stored_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Returns `true` when `additional` more body bytes can be stored without
    /// exceeding the global byte budget.
    fn fits_within_global_cap(&self, additional: usize) -> bool {
        additional <= self.config.max_total_bytes.saturating_sub(self.total_bytes)
    }

    /// Purges expired messages from a single channel, keeping the precise
    /// global byte total up to date.
    fn purge_channel(&mut self, id: &ChannelId, now_secs: u64) {
        let ttl_secs = self.config.message_ttl.as_secs();
        if let Some(entry) = self.channels.get_mut(id) {
            let freed = purge_expired(entry, now_secs, ttl_secs);
            self.total_bytes = self.total_bytes.saturating_sub(freed);
        }
    }

    /// Purges expired messages from every channel, keeping the precise
    /// global byte total up to date. Channels left empty are kept (and still
    /// count towards `max_channels`) so their cursors are not reset; they are
    /// reclaimed by ordinary LRU eviction.
    fn purge_expired_channels(&mut self, now_secs: u64) {
        let ttl_secs = self.config.message_ttl.as_secs();
        let mut freed: usize = 0;
        for entry in self.channels.values_mut() {
            freed = freed.saturating_add(purge_expired(entry, now_secs, ttl_secs));
        }
        self.total_bytes = self.total_bytes.saturating_sub(freed);
    }

    /// Evicts the least-recently-used channel and subtracts its bytes from
    /// the global total. Returns `false` when no live channel could be
    /// evicted.
    fn evict_least_recently_used_channel(&mut self) -> bool {
        while let Some((id, tick)) = self.channel_lru.pop_front() {
            let is_live = self
                .channels
                .get(&id)
                .is_some_and(|entry| entry.lru_tick == tick);
            if !is_live {
                continue;
            }
            if let Some(entry) = self.channels.remove(&id) {
                self.total_bytes = self.total_bytes.saturating_sub(entry.total_bytes);
                // Channel ids are never logged above debug level.
                tracing::debug!(
                    channels = self.channels.len(),
                    "drop store evicted least-recently-used channel"
                );
                return true;
            }
        }
        false
    }

    fn touch_channel(&mut self, id: &ChannelId) {
        self.tick = self.tick.wrapping_add(1);
        let tick = self.tick;
        if let Some(entry) = self.channels.get_mut(id) {
            entry.lru_tick = tick;
            self.channel_lru.push_back((*id, tick));
        }
        if self.channel_lru.len() > 2 * self.config.max_channels.max(1) {
            let channels = &self.channels;
            self.channel_lru
                .retain(|(id, tick)| channels.get(id).is_some_and(|e| e.lru_tick == *tick));
        }
    }

    fn touch_rate_entry(&mut self, ip: &IpAddr) {
        self.tick = self.tick.wrapping_add(1);
        let tick = self.tick;
        if let Some(entry) = self.rate_limits.get_mut(ip) {
            entry.lru_tick = tick;
            self.rate_lru.push_back((*ip, tick));
        }
        if self.rate_lru.len() > 2 * self.config.max_tracked_ips.max(1) {
            let rate_limits = &self.rate_limits;
            self.rate_lru
                .retain(|(ip, tick)| rate_limits.get(ip).is_some_and(|e| e.lru_tick == *tick));
        }
    }

    fn evict_channels_to(&mut self, target: usize) {
        while self.channels.len() > target && self.evict_least_recently_used_channel() {}
    }

    fn evict_rate_entries_to(&mut self, target: usize) {
        while self.rate_limits.len() > target {
            let Some((ip, tick)) = self.rate_lru.pop_front() else {
                break;
            };
            let is_live = self
                .rate_limits
                .get(&ip)
                .is_some_and(|entry| entry.lru_tick == tick);
            if is_live {
                self.rate_limits.remove(&ip);
            }
        }
    }
}

/// Returns the relay's Molt Manifest (plan v10, S8) so clients can embed it:
/// the `RelayOperator` witness learns `NETWORK_LOCATION`, `TIME`,
/// `CONTENT_SIZE` and `RELATIONSHIP_LINK` (poll-pattern linkage only; channel
/// ids and bodies are opaque to the relay). The relay preserves no correlator
/// across the hop.
pub fn drop_relay_manifest() -> serde_json::Value {
    serde_json::json!({
        "adapter_id": "http-relay.drop.v1",
        "witnesses": [
            {
                "role": "RelayOperator",
                "operator": "unknown",
                "domains": [],
                "learns_in": ["NETWORK_LOCATION", "TIME", "CONTENT_SIZE", "RELATIONSHIP_LINK"],
                "learns_out": ["NETWORK_LOCATION", "TIME", "CONTENT_SIZE", "RELATIONSHIP_LINK"],
            }
        ],
        "preserves": [],
        "latency_bound_secs": null,
    })
}

/// Creates the Drop relay routes (`/drop/...`) with the configured body limit.
pub(crate) fn drop_router(config: &DropConfig) -> Router<AppState> {
    Router::new()
        .route("/drop/{channel}", put(put_handler).get(get_handler))
        .route("/drop/{channel}/{cursor}", delete(delete_handler))
        .layer(DefaultBodyLimit::max(config.max_body_bytes))
}

/// Client IP extractor for rate limiting.
///
/// Uses the connection peer address ([`ConnectInfo`]). `X-Forwarded-For` is
/// honored only when the peer address is contained in
/// [`DropConfig::trusted_proxies`], in which case the rightmost hop that is
/// not itself trusted is used as the client address; from any other peer the
/// client-spoofable header is ignored. When no peer address is available at
/// all (e.g. in-process tests), all such requests share a single "unknown"
/// bucket (`0.0.0.0`). Never rejects.
pub(crate) struct ClientIp(IpAddr);

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let trusted = &state.config.drop.trusted_proxies;
        let Some(peer) = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| addr.ip())
        else {
            return Ok(Self(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        };
        if trusted.iter().any(|net| net.contains(&peer)) {
            if let Some(client) = forwarded_for(&parts.headers, trusted) {
                return Ok(Self(client));
            }
        }
        Ok(Self(peer))
    }
}

/// Returns the client address from an `X-Forwarded-For` header received from
/// a trusted proxy: the rightmost hop that is not itself a trusted proxy.
/// Falls back to the leftmost hop when every listed hop is trusted, and to
/// `None` when the header is absent or holds no parseable address.
fn forwarded_for(headers: &HeaderMap, trusted: &[IpNet]) -> Option<IpAddr> {
    let value = headers.get("x-forwarded-for")?.to_str().ok()?;
    let hops: Vec<IpAddr> = value
        .split(',')
        .filter_map(|hop| hop.trim().parse().ok())
        .collect();
    for hop in hops.iter().rev() {
        if !trusted.iter().any(|net| net.contains(hop)) {
            return Some(*hop);
        }
    }
    hops.first().copied()
}

#[derive(Debug, Deserialize)]
struct PollQuery {
    since: Option<u64>,
    limit: Option<usize>,
}

fn invalid_channel_response() -> Response {
    (
        StatusCode::BAD_REQUEST,
        DropError::InvalidChannelId.to_string(),
    )
        .into_response()
}

async fn put_handler(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(channel): Path<String>,
    body: Bytes,
) -> Response {
    let id = match ChannelId::from_base64url(&channel) {
        Ok(id) => id,
        Err(_) => return invalid_channel_response(),
    };

    let now = SystemTime::now();
    let mut store = state.drop_store.lock().await;

    if store.record_write(ip, now).is_err() {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            DropError::RateLimited.to_string(),
        )
            .into_response();
    }

    match store.append(id, body.to_vec(), now) {
        Ok(cursor) => (StatusCode::CREATED, [(X_DROP_CURSOR, cursor.to_string())]).into_response(),
        Err(error @ DropError::MessageTooLarge { .. }) => {
            (StatusCode::PAYLOAD_TOO_LARGE, error.to_string()).into_response()
        }
        Err(
            error @ (DropError::ChannelMessageLimit { .. } | DropError::ChannelByteLimit { .. }),
        ) => (StatusCode::CONFLICT, error.to_string()).into_response(),
        Err(error @ (DropError::StorageExhausted { .. } | DropError::CursorExhausted)) => {
            (StatusCode::INSUFFICIENT_STORAGE, error.to_string()).into_response()
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "failed to store message").into_response(),
    }
}

/// Encodes poll results for the wire as deterministic CBOR: a
/// definite-length array of the integer-keyed maps documented on
/// [`DropMessage`].
fn encode_messages(messages: &[DropMessage]) -> Result<Vec<u8>, serde_cbor::Error> {
    serde_cbor::to_vec(&messages)
}

async fn get_handler(
    State(state): State<AppState>,
    Path(channel): Path<String>,
    Query(query): Query<PollQuery>,
) -> Response {
    let id = match ChannelId::from_base64url(&channel) {
        Ok(id) => id,
        Err(_) => return invalid_channel_response(),
    };

    let max_limit = state.config.drop.max_get_limit;
    let limit = query.limit.unwrap_or(max_limit).min(max_limit);

    let mut store = state.drop_store.lock().await;
    let messages = store.poll(&id, query.since, limit, SystemTime::now());
    drop(store);

    match encode_messages(&messages) {
        Ok(bytes) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/cbor")],
            bytes,
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to encode response",
        )
            .into_response(),
    }
}

async fn delete_handler(
    State(state): State<AppState>,
    Path((channel, cursor)): Path<(String, String)>,
) -> Response {
    let id = match ChannelId::from_base64url(&channel) {
        Ok(id) => id,
        Err(_) => return invalid_channel_response(),
    };
    let cursor: u64 = match cursor.parse() {
        Ok(cursor) => cursor,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                "cursor must be an unsigned integer",
            )
                .into_response();
        }
    };

    let mut store = state.drop_store.lock().await;
    match store.delete(&id, cursor, SystemTime::now()) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(DropError::MessageNotFound) => (
            StatusCode::NOT_FOUND,
            DropError::MessageNotFound.to_string(),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to delete message",
        )
            .into_response(),
    }
}

fn unix_secs(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Removes expired messages from the front of a channel and returns the
/// number of body bytes freed.
fn purge_expired(entry: &mut ChannelEntry, now_secs: u64, ttl_secs: u64) -> usize {
    let mut freed: usize = 0;
    // Messages are appended in timestamp order, so scanning from the front is
    // sufficient.
    while let Some(front) = entry.messages.front() {
        if now_secs.saturating_sub(front.ts) <= ttl_secs {
            break;
        }
        if let Some(message) = entry.messages.pop_front() {
            freed = freed.saturating_add(message.body.len());
        }
    }
    entry.total_bytes = entry.total_bytes.saturating_sub(freed);
    freed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_relay::{Config, HttpRelay};

    fn encode_id(byte: u8) -> String {
        URL_SAFE_NO_PAD.encode([byte; 32])
    }

    fn test_server(config: DropConfig) -> axum_test::TestServer {
        let relay_config = Config {
            drop: config,
            ..Config::default()
        };
        let (app, _) = HttpRelay::create_app(relay_config).expect("create app");
        axum_test::TestServer::new(app).expect("test server")
    }

    /// Builds a test server whose requests all carry the given connection
    /// peer address, simulating a deployment behind a (reverse proxy) peer.
    fn test_server_with_peer(config: DropConfig, peer: IpAddr) -> axum_test::TestServer {
        use axum::{extract::Request, middleware};

        let relay_config = Config {
            drop: config,
            ..Config::default()
        };
        let (app, _) = HttpRelay::create_app(relay_config).expect("create app");
        let app = app.layer(middleware::from_fn(
            move |mut request: Request, next: middleware::Next| async move {
                request
                    .extensions_mut()
                    .insert(ConnectInfo(SocketAddr::new(peer, 4321)));
                next.run(request).await
            },
        ));
        axum_test::TestServer::new(app).expect("test server")
    }

    /// Decodes a `GET` response using the documented integer-keyed schema
    /// (`0`: cursor, `1`: ts, `2`: body); panics on any other shape.
    fn decode_wire(bytes: &[u8]) -> Vec<DropMessage> {
        use serde_cbor::Value;

        let value: Value = serde_cbor::from_slice(bytes).expect("valid cbor response");
        let Value::Array(items) = value else {
            panic!("response must be a CBOR array");
        };
        items
            .into_iter()
            .map(|item| {
                let Value::Map(entries) = item else {
                    panic!("item must be a CBOR map");
                };
                let (mut cursor, mut ts, mut body) = (None, None, None);
                for (key, value) in entries {
                    match (key, value) {
                        (Value::Integer(0), Value::Integer(v)) => {
                            cursor = Some(u64::try_from(v).expect("non-negative cursor"));
                        }
                        (Value::Integer(1), Value::Integer(v)) => {
                            ts = Some(u64::try_from(v).expect("non-negative ts"));
                        }
                        (Value::Integer(2), Value::Bytes(bytes)) => body = Some(bytes),
                        (key, value) => panic!("unexpected entry ({key:?}, {value:?})"),
                    }
                }
                DropMessage {
                    cursor: cursor.expect("cursor key present"),
                    ts: ts.expect("ts key present"),
                    body: body.expect("body key present"),
                }
            })
            .collect()
    }

    // --- ChannelId ---

    #[test]
    fn channel_id_accepts_unpadded_and_padded_base64url() {
        let raw = [42u8; 32];
        for encoded in [URL_SAFE_NO_PAD.encode(raw), URL_SAFE.encode(raw)] {
            let id = ChannelId::from_base64url(&encoded).expect("valid channel id");
            assert_eq!(id.as_bytes(), &raw);
        }
    }

    #[test]
    fn channel_id_rejects_wrong_length_and_bad_encoding() {
        assert_eq!(
            ChannelId::from_base64url(&URL_SAFE_NO_PAD.encode([1u8; 31])),
            Err(DropError::InvalidChannelId)
        );
        assert_eq!(
            ChannelId::from_base64url(&URL_SAFE_NO_PAD.encode([1u8; 33])),
            Err(DropError::InvalidChannelId)
        );
        assert_eq!(
            ChannelId::from_base64url("!!!not-base64!!!"),
            Err(DropError::InvalidChannelId)
        );
        assert_eq!(
            ChannelId::from_base64url(""),
            Err(DropError::InvalidChannelId)
        );
    }

    // --- DropStore ---

    #[test]
    fn append_and_poll_roundtrip() {
        let mut store = DropStore::new(DropConfig::default());
        let id = ChannelId([7u8; 32]);
        let now = SystemTime::now();

        let c0 = store.append(id, b"first".to_vec(), now).expect("append");
        let c1 = store.append(id, b"second".to_vec(), now).expect("append");
        assert_eq!((c0, c1), (0, 1));

        let all = store.poll(&id, None, 50, now);
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].body, b"first");
        assert_eq!(all[1].cursor, 1);

        let after_zero = store.poll(&id, Some(0), 50, now);
        assert_eq!(after_zero.len(), 1);
        assert_eq!(after_zero[0].body, b"second");

        assert!(store.poll(&id, Some(1), 50, now).is_empty());
    }

    #[test]
    fn poll_on_unknown_channel_is_empty() {
        let mut store = DropStore::new(DropConfig::default());
        let id = ChannelId([9u8; 32]);
        assert!(store.poll(&id, None, 50, SystemTime::now()).is_empty());
    }

    #[test]
    fn append_rejects_oversized_body() {
        let mut store = DropStore::new(DropConfig::default());
        let id = ChannelId([1u8; 32]);
        let err = store
            .append(id, vec![0u8; DEFAULT_MAX_BODY_BYTES + 1], SystemTime::now())
            .expect_err("oversized body must be rejected");
        assert_eq!(
            err,
            DropError::MessageTooLarge {
                max: DEFAULT_MAX_BODY_BYTES
            }
        );
    }

    #[test]
    fn append_enforces_message_count_limit() {
        let config = DropConfig {
            max_messages_per_channel: 2,
            ..DropConfig::default()
        };
        let mut store = DropStore::new(config);
        let id = ChannelId([2u8; 32]);
        let now = SystemTime::now();

        store.append(id, b"a".to_vec(), now).expect("append");
        store.append(id, b"b".to_vec(), now).expect("append");
        let err = store
            .append(id, b"c".to_vec(), now)
            .expect_err("channel is full");
        assert_eq!(err, DropError::ChannelMessageLimit { max: 2 });
    }

    #[test]
    fn append_enforces_byte_budget() {
        let config = DropConfig {
            max_bytes_per_channel: 8,
            ..DropConfig::default()
        };
        let mut store = DropStore::new(config);
        let id = ChannelId([3u8; 32]);
        let now = SystemTime::now();

        store.append(id, vec![0u8; 5], now).expect("append");
        let err = store
            .append(id, vec![0u8; 4], now)
            .expect_err("byte budget exceeded");
        assert_eq!(err, DropError::ChannelByteLimit { max: 8 });
    }

    #[test]
    fn expired_messages_are_purged_lazily() {
        let config = DropConfig {
            message_ttl: Duration::from_secs(10),
            ..DropConfig::default()
        };
        let mut store = DropStore::new(config);
        let id = ChannelId([4u8; 32]);
        let now = SystemTime::now();

        store.append(id, b"old".to_vec(), now).expect("append");
        let later = now + Duration::from_secs(11);
        assert!(store.poll(&id, None, 50, later).is_empty());

        // An expired channel frees its message-count budget again.
        let config = DropConfig {
            message_ttl: Duration::from_secs(10),
            max_messages_per_channel: 1,
            ..DropConfig::default()
        };
        let mut store = DropStore::new(config);
        store.append(id, b"old".to_vec(), now).expect("append");
        store
            .append(id, b"new".to_vec(), later)
            .expect("expired messages free budget");
    }

    #[test]
    fn global_channel_bound_evicts_least_recently_used() {
        let config = DropConfig {
            max_channels: 2,
            ..DropConfig::default()
        };
        let mut store = DropStore::new(config);
        let a = ChannelId([10u8; 32]);
        let b = ChannelId([11u8; 32]);
        let c = ChannelId([12u8; 32]);
        let now = SystemTime::now();

        store.append(a, b"a".to_vec(), now).expect("append");
        store.append(b, b"b".to_vec(), now).expect("append");
        // Touch `a` so `b` becomes the least-recently-used channel.
        store.append(a, b"a2".to_vec(), now).expect("append");
        store.append(c, b"c".to_vec(), now).expect("append");

        assert_eq!(store.channel_count(), 2);
        assert_eq!(store.poll(&a, None, 50, now).len(), 2);
        assert_eq!(store.poll(&c, None, 50, now).len(), 1);
    }

    #[test]
    fn delete_removes_one_message() {
        let mut store = DropStore::new(DropConfig::default());
        let id = ChannelId([5u8; 32]);
        let now = SystemTime::now();

        store.append(id, b"a".to_vec(), now).expect("append");
        store.append(id, b"b".to_vec(), now).expect("append");

        store.delete(&id, 0, now).expect("delete");
        let remaining = store.poll(&id, None, 50, now);
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].body, b"b");
    }

    #[test]
    fn delete_missing_message_fails() {
        let mut store = DropStore::new(DropConfig::default());
        let id = ChannelId([6u8; 32]);
        let now = SystemTime::now();

        assert_eq!(store.delete(&id, 0, now), Err(DropError::MessageNotFound));
        store.append(id, b"a".to_vec(), now).expect("append");
        assert_eq!(store.delete(&id, 99, now), Err(DropError::MessageNotFound));
    }

    #[test]
    fn record_write_enforces_and_resets_rate_limit() {
        let config = DropConfig {
            write_rate_limit: 2,
            write_rate_window: Duration::from_secs(60),
            ..DropConfig::default()
        };
        let mut store = DropStore::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        let now = SystemTime::now();

        store.record_write(ip, now).expect("first write");
        store.record_write(ip, now).expect("second write");
        assert_eq!(store.record_write(ip, now), Err(DropError::RateLimited));

        let later = now + Duration::from_secs(61);
        store.record_write(ip, later).expect("window reset");
    }

    #[test]
    fn global_byte_cap_evicts_lru_channels_and_is_never_exceeded() {
        let config = DropConfig {
            max_total_bytes: 100,
            max_bytes_per_channel: 100,
            max_body_bytes: 100,
            ..DropConfig::default()
        };
        let mut store = DropStore::new(config);
        let now = SystemTime::now();

        // Fill past the cap with many channels; the global total must never
        // exceed the cap.
        for byte in 0u8..20 {
            let id = ChannelId([byte; 32]);
            store
                .append(id, vec![byte; 30], now)
                .expect("append within global cap");
            assert!(
                store.total_stored_bytes() <= 100,
                "global byte cap exceeded"
            );
        }

        // Only the three most recent 30-byte channels fit (90 bytes); the
        // older ones were evicted least-recently-used first.
        assert_eq!(store.channel_count(), 3);
        assert_eq!(store.total_stored_bytes(), 90);
        assert!(!store.channels.contains_key(&ChannelId([0u8; 32])));
        assert!(!store.channels.contains_key(&ChannelId([16u8; 32])));
        assert!(store.channels.contains_key(&ChannelId([17u8; 32])));
        assert_eq!(store.poll(&ChannelId([19u8; 32]), None, 50, now).len(), 1);
    }

    #[test]
    fn global_byte_cap_purges_expired_before_evicting() {
        let config = DropConfig {
            message_ttl: Duration::from_secs(10),
            max_total_bytes: 100,
            max_bytes_per_channel: 100,
            max_body_bytes: 100,
            ..DropConfig::default()
        };
        let mut store = DropStore::new(config);
        let now = SystemTime::now();
        let live = ChannelId([91u8; 32]);
        let expiring = ChannelId([90u8; 32]);
        let new = ChannelId([92u8; 32]);

        store.append(expiring, vec![0u8; 40], now).expect("append");
        store
            .append(live, vec![0u8; 40], now + Duration::from_secs(2))
            .expect("append");
        // Make `live` the least-recently-used channel: without purge-first
        // the append below would evict `live` instead of the expired data.
        let mid = now + Duration::from_secs(2);
        store.poll(&live, None, 50, mid);
        store.poll(&expiring, None, 50, mid);

        let later = now + Duration::from_secs(11);
        store
            .append(new, vec![0u8; 60], later)
            .expect("expired bytes are reclaimed first");

        // The expired channel's messages were purged instead of evicting the
        // live channel.
        assert_eq!(store.poll(&live, None, 50, later).len(), 1);
        assert!(store.poll(&expiring, None, 50, later).is_empty());
        assert_eq!(store.total_stored_bytes(), 100);
    }

    #[test]
    fn append_rejects_message_larger_than_global_cap() {
        let config = DropConfig {
            max_total_bytes: 10,
            max_bytes_per_channel: 100,
            max_body_bytes: 100,
            ..DropConfig::default()
        };
        let mut store = DropStore::new(config);
        let id = ChannelId([40u8; 32]);

        let err = store
            .append(id, vec![0u8; 11], SystemTime::now())
            .expect_err("single message larger than the global cap");
        assert_eq!(err, DropError::StorageExhausted { max: 10 });
        assert_eq!(store.total_stored_bytes(), 0);
        assert!(store.is_empty());
    }

    #[test]
    fn put_sweeps_expired_channels_once_half_full() {
        let config = DropConfig {
            message_ttl: Duration::from_secs(10),
            max_total_bytes: 100,
            max_bytes_per_channel: 100,
            max_body_bytes: 100,
            ..DropConfig::default()
        };
        let a = ChannelId([60u8; 32]);
        let b = ChannelId([61u8; 32]);
        let now = SystemTime::now();
        let later = now + Duration::from_secs(11);

        // Over 50% full: the PUT sweeps expired bytes from all channels.
        let mut store = DropStore::new(config.clone());
        store.append(a, vec![0u8; 60], now).expect("append");
        store.append(b, vec![0u8; 10], later).expect("append");
        assert_eq!(store.total_stored_bytes(), 10);

        // Under 50% full: no sweep runs and expired bytes linger lazily until
        // the expired channel itself is touched.
        let mut store = DropStore::new(config);
        store.append(a, vec![0u8; 40], now).expect("append");
        store.append(b, vec![0u8; 5], later).expect("append");
        assert_eq!(store.total_stored_bytes(), 45);
        assert!(store.poll(&a, None, 50, later).is_empty());
        assert_eq!(store.total_stored_bytes(), 5);
    }

    #[test]
    fn append_at_cursor_max_fails_instead_of_wrapping() {
        let mut store = DropStore::new(DropConfig::default());
        let id = ChannelId([70u8; 32]);
        let now = SystemTime::now();

        store.append(id, b"a".to_vec(), now).expect("append");
        store
            .channels
            .get_mut(&id)
            .expect("channel exists")
            .next_cursor = u64::MAX;

        let err = store
            .append(id, b"b".to_vec(), now)
            .expect_err("cursor space is exhausted");
        assert_eq!(err, DropError::CursorExhausted);

        // The failed append did not wrap the cursor or store anything.
        let messages = store.poll(&id, None, 50, now);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].cursor, 0);
    }

    #[test]
    fn wire_encoding_is_deterministic_integer_keyed_cbor() {
        let messages = vec![
            DropMessage {
                cursor: 0,
                ts: 42,
                body: b"hi".to_vec(),
            },
            DropMessage {
                cursor: 1,
                ts: 43,
                body: Vec::new(),
            },
        ];
        let bytes = encode_messages(&messages).expect("encode");
        #[rustfmt::skip]
        let expected: Vec<u8> = vec![
            0x82, // array(2)
            0xa3, 0x00, 0x00, 0x01, 0x18, 0x2a, 0x02, 0x42, b'h', b'i',
            0xa3, 0x00, 0x01, 0x01, 0x18, 0x2b, 0x02, 0x40,
        ];
        assert_eq!(bytes, expected);
    }

    #[test]
    fn forwarded_for_selects_rightmost_untrusted_hop() {
        let trusted: Vec<IpNet> = vec!["10.0.0.0/8".parse().expect("valid ipnet")];

        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "203.0.113.1, 198.51.100.9, 10.1.2.3"
                .parse()
                .expect("header value"),
        );
        assert_eq!(
            forwarded_for(&headers, &trusted),
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)))
        );

        // Every listed hop trusted: fall back to the leftmost (original
        // client as reported by the outermost trusted proxy).
        headers.insert(
            "x-forwarded-for",
            "10.1.1.1, 10.2.2.2".parse().expect("header value"),
        );
        assert_eq!(
            forwarded_for(&headers, &trusted),
            Some(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1)))
        );

        // Absent or unparseable headers yield no address.
        assert_eq!(forwarded_for(&HeaderMap::new(), &trusted), None);
        headers.insert(
            "x-forwarded-for",
            "not-an-ip".parse().expect("header value"),
        );
        assert_eq!(forwarded_for(&headers, &trusted), None);
    }

    // --- Manifest ---

    #[test]
    fn manifest_matches_s8() {
        let manifest = drop_relay_manifest();
        let witness = &manifest["witnesses"][0];
        assert_eq!(witness["role"], "RelayOperator");
        for field in [
            "NETWORK_LOCATION",
            "TIME",
            "CONTENT_SIZE",
            "RELATIONSHIP_LINK",
        ] {
            assert!(
                witness["learns_in"]
                    .as_array()
                    .expect("array")
                    .contains(&serde_json::Value::from(field)),
                "learns_in missing {field}"
            );
            assert!(
                witness["learns_out"]
                    .as_array()
                    .expect("array")
                    .contains(&serde_json::Value::from(field)),
                "learns_out missing {field}"
            );
        }
        assert_eq!(manifest["preserves"].as_array().expect("array").len(), 0);
    }

    // --- HTTP handlers ---

    #[tokio::test]
    async fn put_then_get_roundtrip_over_http() {
        let server = test_server(DropConfig::default());
        let channel = encode_id(21);

        let response = server
            .put(&format!("/drop/{channel}"))
            .bytes(Bytes::from_static(b"ciphertext"))
            .await;
        assert_eq!(response.status_code(), 201);
        assert_eq!(response.header(X_DROP_CURSOR).to_str().unwrap(), "0");

        let response = server
            .put(&format!("/drop/{channel}"))
            .bytes(Bytes::from_static(b"more"))
            .await;
        assert_eq!(response.header(X_DROP_CURSOR).to_str().unwrap(), "1");

        let response = server.get(&format!("/drop/{channel}")).await;
        assert_eq!(response.status_code(), 200);
        assert_eq!(
            response.header(header::CONTENT_TYPE).to_str().unwrap(),
            "application/cbor"
        );
        let messages = decode_wire(response.as_bytes());
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].cursor, 0);
        assert_eq!(messages[0].body, b"ciphertext");
        assert!(messages[0].ts > 0);

        let response = server.get(&format!("/drop/{channel}?since=0")).await;
        let messages = decode_wire(response.as_bytes());
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].body, b"more");

        let response = server.get(&format!("/drop/{channel}?since=1")).await;
        assert!(decode_wire(response.as_bytes()).is_empty());
    }

    #[tokio::test]
    async fn put_rejects_invalid_channel_id() {
        let server = test_server(DropConfig::default());
        let response = server
            .put("/drop/too-short")
            .bytes(Bytes::from_static(b"x"))
            .await;
        assert_eq!(response.status_code(), 400);
    }

    #[tokio::test]
    async fn put_enforces_body_size_limit() {
        let server = test_server(DropConfig::default());
        let channel = encode_id(22);

        let response = server
            .put(&format!("/drop/{channel}"))
            .bytes(vec![0u8; DEFAULT_MAX_BODY_BYTES].into())
            .await;
        assert_eq!(response.status_code(), 201);

        let response = server
            .put(&format!("/drop/{channel}"))
            .bytes(vec![0u8; DEFAULT_MAX_BODY_BYTES + 1].into())
            .await;
        assert_eq!(response.status_code(), 413);
    }

    #[tokio::test]
    async fn put_is_rate_limited_per_ip() {
        let config = DropConfig {
            write_rate_limit: 2,
            write_rate_window: Duration::from_secs(60),
            ..DropConfig::default()
        };
        let server = test_server(config);
        let channel = encode_id(23);

        for expected in [201, 201, 429] {
            let response = server
                .put(&format!("/drop/{channel}"))
                .bytes(Bytes::from_static(b"x"))
                .await;
            assert_eq!(response.status_code(), expected);
        }
    }

    #[tokio::test]
    async fn put_returns_507_when_message_exceeds_global_byte_cap() {
        let config = DropConfig {
            max_total_bytes: 10,
            max_bytes_per_channel: 100,
            max_body_bytes: 100,
            ..DropConfig::default()
        };
        let server = test_server(config);
        let channel = encode_id(50);

        let response = server
            .put(&format!("/drop/{channel}"))
            .bytes(vec![0u8; 11].into())
            .await;
        assert_eq!(response.status_code(), 507);

        // A message that fits is still accepted.
        let response = server
            .put(&format!("/drop/{channel}"))
            .bytes(vec![0u8; 10].into())
            .await;
        assert_eq!(response.status_code(), 201);
    }

    #[tokio::test]
    async fn spoofed_xff_from_untrusted_peer_is_ignored() {
        let config = DropConfig {
            write_rate_limit: 2,
            write_rate_window: Duration::from_secs(60),
            ..DropConfig::default()
        };
        let server = test_server_with_peer(config, IpAddr::V4(Ipv4Addr::new(10, 9, 9, 9)));
        let channel = encode_id(80);

        // Three requests with different spoofed XFF values: if the header
        // were honored each would get its own rate bucket and all would
        // succeed. The untrusted peer address is used instead, so the third
        // write is rate limited.
        for (xff, expected) in [("1.1.1.1", 201), ("2.2.2.2", 201), ("3.3.3.3", 429)] {
            let response = server
                .put(&format!("/drop/{channel}"))
                .add_header("x-forwarded-for", xff)
                .bytes(Bytes::from_static(b"x"))
                .await;
            assert_eq!(response.status_code(), expected, "xff {xff}");
        }
    }

    #[tokio::test]
    async fn xff_from_trusted_proxy_is_honored() {
        let config = DropConfig {
            write_rate_limit: 1,
            write_rate_window: Duration::from_secs(60),
            trusted_proxies: vec!["10.0.0.0/8".parse().expect("valid ipnet")],
            ..DropConfig::default()
        };
        let server = test_server_with_peer(config, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let channel = encode_id(81);

        // Two different client addresses behind the trusted proxy get
        // separate rate buckets: both succeed despite write_rate_limit = 1.
        for xff in ["198.51.100.1", "198.51.100.2"] {
            let response = server
                .put(&format!("/drop/{channel}"))
                .add_header("x-forwarded-for", xff)
                .bytes(Bytes::from_static(b"x"))
                .await;
            assert_eq!(response.status_code(), 201, "xff {xff}");
        }

        // A second write from the same forwarded client is rate limited.
        let response = server
            .put(&format!("/drop/{channel}"))
            .add_header("x-forwarded-for", "198.51.100.1")
            .bytes(Bytes::from_static(b"x"))
            .await;
        assert_eq!(response.status_code(), 429);
    }

    #[tokio::test]
    async fn put_on_full_channel_conflicts() {
        let config = DropConfig {
            max_messages_per_channel: 1,
            ..DropConfig::default()
        };
        let server = test_server(config);
        let channel = encode_id(24);

        let response = server
            .put(&format!("/drop/{channel}"))
            .bytes(Bytes::from_static(b"x"))
            .await;
        assert_eq!(response.status_code(), 201);
        let response = server
            .put(&format!("/drop/{channel}"))
            .bytes(Bytes::from_static(b"y"))
            .await;
        assert_eq!(response.status_code(), 409);
    }

    #[tokio::test]
    async fn get_rejects_invalid_channel_and_query() {
        let server = test_server(DropConfig::default());
        assert_eq!(server.get("/drop/nope").await.status_code(), 400);
        let channel = encode_id(25);
        assert_eq!(
            server
                .get(&format!("/drop/{channel}?since=abc"))
                .await
                .status_code(),
            400
        );
    }

    #[tokio::test]
    async fn get_on_unknown_channel_returns_empty_array() {
        let server = test_server(DropConfig::default());
        let response = server.get(&format!("/drop/{}", encode_id(26))).await;
        assert_eq!(response.status_code(), 200);
        assert!(decode_wire(response.as_bytes()).is_empty());
    }

    #[tokio::test]
    async fn get_limit_is_clamped_to_configured_maximum() {
        let config = DropConfig {
            max_get_limit: 2,
            ..DropConfig::default()
        };
        let server = test_server(config);
        let channel = encode_id(27);

        for _ in 0..3 {
            server
                .put(&format!("/drop/{channel}"))
                .bytes(Bytes::from_static(b"x"))
                .await;
        }

        let response = server.get(&format!("/drop/{channel}?limit=50")).await;
        assert_eq!(decode_wire(response.as_bytes()).len(), 2);
        let response = server.get(&format!("/drop/{channel}?limit=1")).await;
        assert_eq!(decode_wire(response.as_bytes()).len(), 1);
        let response = server.get(&format!("/drop/{channel}")).await;
        assert_eq!(decode_wire(response.as_bytes()).len(), 2);
    }

    #[tokio::test]
    async fn delete_acks_one_message() {
        let server = test_server(DropConfig::default());
        let channel = encode_id(28);

        let response = server
            .put(&format!("/drop/{channel}"))
            .bytes(Bytes::from_static(b"x"))
            .await;
        let cursor = response.header(X_DROP_CURSOR).to_str().unwrap().to_owned();

        let response = server.delete(&format!("/drop/{channel}/{cursor}")).await;
        assert_eq!(response.status_code(), 204);

        let response = server.get(&format!("/drop/{channel}")).await;
        assert!(decode_wire(response.as_bytes()).is_empty());

        // Second delete of the same cursor is a failure path.
        let response = server.delete(&format!("/drop/{channel}/{cursor}")).await;
        assert_eq!(response.status_code(), 404);

        // Non-numeric cursor is rejected.
        let response = server.delete(&format!("/drop/{channel}/abc")).await;
        assert_eq!(response.status_code(), 400);

        // Invalid channel id is rejected.
        let response = server.delete("/drop/short/0").await;
        assert_eq!(response.status_code(), 400);
    }
}
