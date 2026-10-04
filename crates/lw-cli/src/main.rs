//! Headless Logwarden CLI (`lw`). Shared crates power both CLI and GUI.
#![deny(unsafe_code)]

fn main() {
    println!("{} CLI (scaffold)", lw_core::APP_NAME);
}
