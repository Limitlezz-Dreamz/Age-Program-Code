use crate::dto::{RecentCase, Settings};
use crate::error::ApiError;
use std::fs;
use std::path::PathBuf;

pub fn app_data_dir() -> PathBuf {
    lw_core::data_dir()
}

pub fn ensure_app_dirs() -> Result<PathBuf, ApiError> {
    let dir = app_data_dir();
    fs::create_dir_all(&dir)?;
    fs::create_dir_all(dir.join("cases"))?;
    Ok(dir)
}

pub fn settings_path() -> PathBuf {
    app_data_dir().join("settings.json")
}

pub fn recent_path() -> PathBuf {
    app_data_dir().join("recent_cases.json")
}

pub fn load_settings() -> Settings {
    let _ = ensure_app_dirs();
    match fs::read_to_string(settings_path()) {
        Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
        Err(_) => Settings::default(),
    }
}

pub fn save_settings(s: &Settings) -> Result<(), ApiError> {
    ensure_app_dirs()?;
    fs::write(settings_path(), serde_json::to_string_pretty(s)?)?;
    Ok(())
}

pub fn load_recent() -> Vec<RecentCase> {
    let _ = ensure_app_dirs();
    match fs::read_to_string(recent_path()) {
        Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

pub fn save_recent(items: &[RecentCase]) -> Result<(), ApiError> {
    ensure_app_dirs()?;
    fs::write(recent_path(), serde_json::to_string_pretty(items)?)?;
    Ok(())
}

pub fn push_recent(info: &lw_core::CaseInfo) -> Result<Vec<RecentCase>, ApiError> {
    let mut items = load_recent();
    items.retain(|r| r.path != info.path);
    items.insert(
        0,
        RecentCase {
            name: info.name.clone(),
            path: info.path.clone(),
            opened_at: time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| info.created_at.clone()),
        },
    );
    items.truncate(20);
    save_recent(&items)?;
    Ok(items)
}
