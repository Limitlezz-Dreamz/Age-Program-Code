use crate::TsMicros;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[repr(u8)]
pub enum Severity {
    Informational = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceType {
    Evtx,
    UnifiedLog,
    Jsonl,
}

impl SourceType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Evtx => "evtx",
            Self::UnifiedLog => "unifiedlog",
            Self::Jsonl => "jsonl",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceFile {
    pub id: i64,
    pub path: String,
    pub size: u64,
    pub sha256: Option<String>,
    pub mtime: Option<TsMicros>,
    pub channel_hint: Option<String>,
    pub records_ok: u64,
    pub records_err: u64,
    pub is_dirty: Option<bool>,
    pub first_ts: Option<TsMicros>,
    pub last_ts: Option<TsMicros>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedEvent {
    pub id: i64,
    pub file_id: i64,
    pub source_type: SourceType,
    pub record_id: u64,
    pub ts: TsMicros,
    pub event_id: u32,
    pub channel: String,
    pub provider: String,
    pub computer: String,
    pub level: Option<u8>,
    pub user_sid: Option<String>,
    pub user_name: Option<String>,
    pub src_ip: Option<String>,
    pub logon_type: Option<i64>,
    pub fields: Map<String, Value>,
    /// Original evtx JSON (optionally zstd-compressed later by the store).
    pub raw_json: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Default)]
pub struct CancellationToken {
    flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.flag.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.flag.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn check(&self) -> crate::Result<()> {
        if self.is_cancelled() {
            Err(crate::Error::Cancelled)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseInfo {
    pub name: String,
    pub path: String,
    pub created_at: String,
    pub app_version: String,
    pub input_paths: Vec<String>,
    pub notes: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IngestStats {
    pub files_ok: u64,
    pub files_err: u64,
    pub records_ok: u64,
    pub records_err: u64,
    pub bytes: u64,
    pub elapsed_ms: u64,
    pub events_per_sec: f64,
}

#[derive(Debug, Clone)]
pub struct DiscoveredFile {
    pub path: std::path::PathBuf,
    pub size: u64,
    pub mtime: Option<TsMicros>,
}
