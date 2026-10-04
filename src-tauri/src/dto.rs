use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct CaseInfoDto {
    pub name: String,
    pub path: String,
    pub created_at: String,
    pub app_version: String,
    pub input_paths: Vec<String>,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct RecentCase {
    pub name: String,
    pub path: String,
    pub opened_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct DiscoveredFileDto {
    pub path: String,
    pub size: u64,
    pub mtime: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct DiscoveryResult {
    pub files: Vec<DiscoveredFileDto>,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct SourceFileDto {
    pub id: i64,
    pub path: String,
    pub size: u64,
    pub sha256: Option<String>,
    pub records_ok: u64,
    pub records_err: u64,
    pub is_dirty: Option<bool>,
    pub first_ts: Option<i64>,
    pub last_ts: Option<i64>,
    pub error: Option<String>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct AnalysisOptions {
    pub profile: String,
    pub builtins: bool,
    pub build_fts: bool,
    pub hash_files: bool,
    pub run_detection: bool,
    pub threads: Option<usize>,
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            profile: "default".into(),
            builtins: true,
            build_fts: true,
            hash_files: true,
            run_detection: true,
            threads: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum IngestProgressMsg {
    #[serde(rename_all = "camelCase")]
    Discovered {
        files: u64,
        bytes: u64,
    },
    #[serde(rename_all = "camelCase")]
    Progress {
        files_done: u64,
        files_total: u64,
        bytes_done: u64,
        events: u64,
        events_per_sec: f64,
        detections: u64,
        errors: u64,
        current_file: Option<String>,
    },
    #[serde(rename_all = "camelCase")]
    Phase {
        phase: String,
    },
    #[serde(rename_all = "camelCase")]
    FileError {
        path: String,
        message: String,
    },
    #[serde(rename_all = "camelCase")]
    FileStatus {
        path: String,
        status: String,
        records_ok: u64,
        records_err: u64,
        error: Option<String>,
    },
    #[serde(rename_all = "camelCase")]
    Finished {
        run_id: i64,
        events: u64,
        detections: u64,
        elapsed_ms: u64,
    },
    Cancelled,
    #[serde(rename_all = "camelCase")]
    Failed {
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct Settings {
    pub display_timezone: String,
    pub use_utc: bool,
    pub threads: usize,
    pub fts_default: bool,
    pub hash_default: bool,
    pub rule_profile: String,
    pub builtins_default: bool,
    pub run_detection_default: bool,
    pub log_level: String,
    /// Kerberoast volume threshold (B009)
    pub thresh_kerberoast: u64,
    /// Brute force event_count (B010)
    pub thresh_bruteforce: u64,
    /// Password spray value_count (B011)
    pub thresh_spray: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            display_timezone: "UTC".into(),
            use_utc: true,
            threads: num_cpus::get().max(1),
            fts_default: true,
            hash_default: true,
            rule_profile: "default".into(),
            builtins_default: true,
            run_detection_default: true,
            log_level: "info".into(),
            thresh_kerberoast: 10,
            thresh_bruteforce: 10,
            thresh_spray: 5,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct CaseStatsDto {
    pub files: u64,
    pub files_with_errors: u64,
    pub events: u64,
    pub detections: u64,
    pub first_ts: Option<i64>,
    pub last_ts: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
#[allow(dead_code)] // reserved for M4 query IPC
pub struct GlobalFilter {
    pub time_from: Option<i64>,
    pub time_to: Option<i64>,
    pub severities: Vec<String>,
    pub computers: Vec<String>,
    pub users: Vec<String>,
    pub channels: Vec<String>,
    pub event_ids: Vec<u32>,
    pub text: Option<String>,
}
