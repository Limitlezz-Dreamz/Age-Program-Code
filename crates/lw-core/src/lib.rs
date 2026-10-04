#![deny(unsafe_code)]

//! Shared types and constants for Logwarden.

/// Product name constant — rename in one place.
pub const APP_NAME: &str = "Logwarden";

/// UTC microseconds since the Unix epoch.
pub type TsMicros = i64;

/// Placeholder until M1 introduces the full type model.
pub fn crate_name() -> &'static str {
    env!("CARGO_PKG_NAME")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_name_is_logwarden() {
        assert_eq!(APP_NAME, "Logwarden");
    }
}
