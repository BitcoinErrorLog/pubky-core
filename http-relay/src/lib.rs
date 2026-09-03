//! A Rust implementation of _some_ of [Http relay spec](https://httprelay.io/).
//!

#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![cfg_attr(any(), deny(clippy::unwrap_used))]

mod drop;
mod http_relay;
mod waiting_list;

pub use drop::{
    drop_relay_manifest, ChannelId, DropConfig, DropError, DropMessage, DropStore, X_DROP_CURSOR,
};
pub use http_relay::*;
