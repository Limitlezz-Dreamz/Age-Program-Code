#![deny(unsafe_code)]

//! EVTX JSON → flat `NormalizedEvent` (Section 6).

mod aliases;
mod extract;
mod flatten;

pub use aliases::{default_4688_aliases, load_field_aliases, FieldAliasRule};
pub use flatten::normalize_record;

use lw_core::NormalizedEvent;
use serde_json::Value;

/// Normalize a raw `evtx` JSON value into a `NormalizedEvent`.
///
/// `file_id` is stamped onto the result; `raw_json` is the original serialized JSON bytes
/// (uncompressed — the store may zstd-compress later).
pub fn normalize(
    value: &Value,
    file_id: i64,
    raw_json: Option<Vec<u8>>,
    aliases: &[FieldAliasRule],
) -> NormalizedEvent {
    flatten::normalize_record(value, file_id, raw_json, aliases)
}

pub fn crate_name() -> &'static str {
    env!("CARGO_PKG_NAME")
}
