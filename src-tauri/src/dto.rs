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
pub struct GlobalFilter {
    pub time_from: Option<i64>,
    pub time_to: Option<i64>,
    pub severities: Vec<String>,
    pub computers: Vec<String>,
    pub users: Vec<String>,
    pub channels: Vec<String>,
    pub event_ids: Vec<u32>,
    pub triage: Vec<String>,
    pub mitre_tactic: Option<String>,
    pub text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct SeverityCountsDto {
    pub critical: u64,
    pub high: u64,
    pub medium: u64,
    pub low: u64,
    pub informational: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct NamedCountDto {
    pub name: String,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct CoverageWarningDto {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct TimeBucketDto {
    pub ts: i64,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct DashboardSummaryDto {
    pub severity: SeverityCountsDto,
    pub total_detections: u64,
    pub top_rules: Vec<NamedCountDto>,
    pub top_hosts: Vec<NamedCountDto>,
    pub top_users: Vec<NamedCountDto>,
    pub top_tactics: Vec<NamedCountDto>,
    pub files: u64,
    pub files_with_errors: u64,
    pub events: u64,
    pub first_ts: Option<i64>,
    pub last_ts: Option<i64>,
    pub channels: Vec<NamedCountDto>,
    pub coverage: Vec<CoverageWarningDto>,
    pub detections_over_time: Vec<TimeBucketDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct MitreRefDto {
    pub technique: Option<String>,
    pub tactic: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct RuleSourceDto {
    pub kind: String,
    pub pack: Option<String>,
    pub version: Option<String>,
    pub path: Option<String>,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct DetectionRowDto {
    pub id: i64,
    pub run_id: i64,
    pub rule_uid: String,
    pub rule_title: String,
    pub rule_author: Option<String>,
    pub rule_source: RuleSourceDto,
    pub severity: String,
    pub status: Option<String>,
    pub mitre: Vec<MitreRefDto>,
    pub ts: i64,
    pub computer: String,
    pub user: Option<String>,
    pub kind: String,
    pub event_count: u64,
    pub summary: String,
    pub fp_hint: Option<String>,
    pub triage: String,
    pub triage_note: Option<String>,
    pub event_ids: Vec<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct LinkedEventRefDto {
    pub id: i64,
    pub ts: i64,
    pub event_id: u32,
    pub channel: String,
    pub computer: String,
    pub user_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct DetectionDetailDto {
    pub detection: DetectionRowDto,
    pub group_json: Option<String>,
    pub linked_events: Vec<LinkedEventRefDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct DetectionQueryDto {
    pub offset: u64,
    pub limit: u64,
    pub sort_col: String,
    pub sort_dir: String,
    pub severities: Vec<String>,
    pub rule_uid: Option<String>,
    pub text: Option<String>,
    pub time_from: Option<i64>,
    pub time_to: Option<i64>,
    pub computers: Vec<String>,
    pub users: Vec<String>,
    pub triage: Vec<String>,
    pub mitre_tactic: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct DetectionPageDto {
    pub rows: Vec<DetectionRowDto>,
    pub total: u64,
    pub offset: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct DecodedPayloadDto {
    pub field: String,
    pub encoding: String,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct EventDetailDto {
    pub id: i64,
    pub file_id: i64,
    pub record_id: u64,
    pub ts: i64,
    pub event_id: u32,
    pub channel: String,
    pub provider: String,
    pub computer: String,
    pub level: Option<u8>,
    pub user_name: Option<String>,
    pub src_ip: Option<String>,
    pub logon_type: Option<i64>,
    pub source_path: Option<String>,
    pub description: Option<String>,
    pub fields: serde_json::Map<String, serde_json::Value>,
    pub raw_json: Option<String>,
    pub xml: Option<String>,
    pub decoded: Option<DecodedPayloadDto>,
    pub related_detection_ids: Vec<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct SetTriageRequest {
    pub detection_ids: Vec<i64>,
    pub state: String,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct HistogramQueryDto {
    pub time_from: Option<i64>,
    pub time_to: Option<i64>,
    pub computers: Vec<String>,
    pub channels: Vec<String>,
    pub series: String,
    pub bucket_micros: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct HistogramBucketDto {
    pub ts: i64,
    pub series: String,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct TimelineListQueryDto {
    pub offset: u64,
    pub limit: u64,
    pub time_from: Option<i64>,
    pub time_to: Option<i64>,
    pub computers: Vec<String>,
    pub include_events: bool,
    pub text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct TimelineItemDto {
    pub kind: String,
    pub id: i64,
    pub ts: i64,
    pub computer: String,
    pub label: String,
    pub severity: Option<String>,
    pub event_id: Option<u32>,
    pub channel: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct TimelinePageDto {
    pub rows: Vec<TimelineItemDto>,
    pub total: u64,
    pub offset: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct FieldFilterDto {
    pub field: String,
    pub op: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct EventQueryDto {
    pub offset: u64,
    pub limit: u64,
    pub sort_col: String,
    pub sort_dir: String,
    pub time_from: Option<i64>,
    pub time_to: Option<i64>,
    pub event_ids: Vec<u32>,
    pub computers: Vec<String>,
    pub channels: Vec<String>,
    pub users: Vec<String>,
    pub src_ips: Vec<String>,
    pub text: Option<String>,
    pub field_filters: Vec<FieldFilterDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct EventRowDto {
    pub id: i64,
    pub file_id: i64,
    pub record_id: u64,
    pub ts: i64,
    pub event_id: u32,
    pub channel: String,
    pub provider: String,
    pub computer: String,
    pub user_name: Option<String>,
    pub src_ip: Option<String>,
    pub logon_type: Option<i64>,
    pub summary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct EventPageDto {
    pub rows: Vec<EventRowDto>,
    pub total: u64,
    pub offset: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct PivotQueryDto {
    pub dimension: String,
    pub offset: u64,
    pub limit: u64,
    pub time_from: Option<i64>,
    pub time_to: Option<i64>,
    pub text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct PivotRowDto {
    pub key: String,
    pub event_count: u64,
    pub detection_count: u64,
    pub critical: u64,
    pub high: u64,
    pub medium: u64,
    pub low: u64,
    pub informational: u64,
    pub first_ts: Option<i64>,
    pub last_ts: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct PivotPageDto {
    pub rows: Vec<PivotRowDto>,
    pub total: u64,
    pub offset: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct LogonSummaryRowDto {
    pub user_name: String,
    pub src_ip: String,
    pub logon_type: i64,
    pub logon_type_name: String,
    pub computer: String,
    pub success_count: u64,
    pub fail_count: u64,
    pub first_ts: Option<i64>,
    pub last_ts: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct LogonPageDto {
    pub rows: Vec<LogonSummaryRowDto>,
    pub total: u64,
    pub offset: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct SavedSearchDto {
    pub id: i64,
    pub name: String,
    pub query_json: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct RulePackDto {
    pub id: String,
    pub version: String,
    pub kind: String,
    pub source_url: Option<String>,
    pub downloaded_at: String,
    pub blake3: String,
    pub rule_count: u64,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct RuleRowDto {
    pub rule_uid: String,
    pub title: String,
    pub author: Option<String>,
    pub level: Option<String>,
    pub status: Option<String>,
    pub tags: Vec<String>,
    pub source_json: String,
    pub enabled: bool,
    pub hit_count: u64,
    pub unmapped: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct RuleQueryDto {
    pub offset: u64,
    pub limit: u64,
    pub text: Option<String>,
    pub enabled_only: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct RulePageDto {
    pub rows: Vec<RuleRowDto>,
    pub total: u64,
    pub offset: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct RuleDetailDto {
    pub rule: RuleRowDto,
    pub yaml: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct SuppressionDto {
    pub id: i64,
    pub rule_uid: Option<String>,
    pub field: String,
    pub value: String,
    pub note: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct SuppressionInputDto {
    pub rule_uid: Option<String>,
    pub field: String,
    pub value: String,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct ExportRequestDto {
    pub path: String,
    pub format: String,
    pub limit: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct ExportResultDto {
    pub path: String,
    pub rows: u64,
    pub format: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-rs", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-rs", ts(export))]
pub struct HuntReportDto {
    pub run_id: i64,
    pub detections: u64,
    pub events_scanned: u64,
    pub elapsed_ms: u64,
    pub profile: String,
}
