#![deny(unsafe_code)]

//! Shared types and constants for Logwarden.

mod error;
mod paths;
mod time_util;
mod types;

pub use error::{Error, Result};
pub use paths::{
    data_dir, install_data_dir, install_resource_root, resource_file, resource_root, APP_VERSION,
    DATA_DIR_ENV, RESOURCES_ENV,
};
pub use time_util::{format_rfc3339_micros, parse_rfc3339_to_micros};
pub use types::*;

/// Product name constant — rename in one place.
pub const APP_NAME: &str = "Logwarden";

/// UTC microseconds since the Unix epoch.
pub type TsMicros = i64;

/// EVTX file magic (`ElfFile\0`).
pub const EVTX_MAGIC: &[u8; 8] = b"ElfFile\0";

/// Default case directory extension.
pub const CASE_EXT: &str = "lwcase";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_name_is_logwarden() {
        assert_eq!(APP_NAME, "Logwarden");
    }

    #[test]
    fn app_version_is_semverish() {
        assert!(!APP_VERSION.is_empty());
        assert!(APP_VERSION.contains('.'));
    }
}
