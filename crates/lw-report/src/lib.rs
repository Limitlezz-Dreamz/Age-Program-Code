#![deny(unsafe_code)]

//! lw-report — Logwarden workspace crate (M0 stub).

pub fn crate_name() -> &'static str {
    env!("CARGO_PKG_NAME")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crate_name_is_set() {
        assert!(!crate_name().is_empty());
    }
}
