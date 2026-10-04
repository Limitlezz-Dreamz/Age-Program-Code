//! Locate bundled / workspace `resources/` for GUI and CLI.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// App version from the crate (keep in sync with `package.json` / `tauri.conf.json`).
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Environment variable set by the parent process to the bundled `resources` directory.
pub const RESOURCES_ENV: &str = "LOGWARDEN_RESOURCES";

/// Environment variable set by the parent process to the writable app data directory.
pub const DATA_DIR_ENV: &str = "LOGWARDEN_DATA_DIR";

static RESOURCE_OVERRIDE: OnceLock<PathBuf> = OnceLock::new();
static DATA_OVERRIDE: OnceLock<PathBuf> = OnceLock::new();

/// Install a process-wide resource root (called once from the Tauri shell).
pub fn install_resource_root(path: PathBuf) {
    let _ = RESOURCE_OVERRIDE.set(path);
}

/// Install a process-wide data directory (called once from the Tauri shell).
pub fn install_data_dir(path: PathBuf) {
    let _ = DATA_OVERRIDE.set(path);
}

/// Root directory containing `builtin-rules/`, `mappings/`, `mitre/`, etc.
///
/// Resolution order:
/// 1. `install_resource_root` (packaged GUI)
/// 2. `LOGWARDEN_RESOURCES` (explicit process env)
/// 3. CWD-relative `resources` (dev / CLI from repo root)
/// 4. Paths relative to `CARGO_MANIFEST_DIR` (tests)
pub fn resource_root() -> Option<PathBuf> {
    if let Some(p) = RESOURCE_OVERRIDE.get() {
        return Some(p.clone());
    }
    if let Ok(p) = std::env::var(RESOURCES_ENV) {
        let p = PathBuf::from(p);
        if p.is_dir() {
            return Some(p);
        }
    }
    let mut candidates = vec![
        PathBuf::from("resources"),
        PathBuf::from("../resources"),
        PathBuf::from("../../resources"),
    ];
    if let Ok(manifest) = std::env::var("CARGO_MANIFEST_DIR") {
        let m = PathBuf::from(manifest);
        candidates.push(m.join("../../resources"));
        candidates.push(m.join("../resources"));
        candidates.push(m.join("../../../resources"));
    }
    candidates.into_iter().find(|p| p.is_dir())
}

/// Resolve a file under the resource root (e.g. `mappings/logsource-windows.yml`).
pub fn resource_file(rel: impl AsRef<Path>) -> Option<PathBuf> {
    let root = resource_root()?;
    let p = root.join(rel);
    p.is_file().then_some(p)
}

/// Writable application data directory (settings, recent cases, installed packs).
pub fn data_dir() -> PathBuf {
    if let Some(p) = DATA_OVERRIDE.get() {
        return p.clone();
    }
    if let Ok(p) = std::env::var(DATA_DIR_ENV) {
        let p = PathBuf::from(p);
        if !p.as_os_str().is_empty() {
            return p;
        }
    }
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        return PathBuf::from(xdg).join("logwarden");
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("logwarden");
    }
    // Windows / fallback when HOME is unset — prefer LOCALAPPDATA.
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        return PathBuf::from(local).join("logwarden");
    }
    PathBuf::from("data").join("logwarden")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_root_finds_workspace_resources() {
        let root = resource_root().expect("workspace resources");
        assert!(root.join("builtin-rules").is_dir());
        assert!(resource_file("mappings/logsource-windows.yml").is_some());
    }
}
