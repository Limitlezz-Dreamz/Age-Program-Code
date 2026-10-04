/** Generated-by-hand DTOs mirroring src-tauri/src/dto.rs (ts-rs export available via --features ts-rs). */

export type ApiError = {
  code: string;
  message: string;
};

export type CaseInfoDto = {
  name: string;
  path: string;
  created_at: string;
  app_version: string;
  input_paths: string[];
  notes: string;
};

export type RecentCase = {
  name: string;
  path: string;
  opened_at: string;
};

export type DiscoveredFileDto = {
  path: string;
  size: number;
  mtime: number | null;
};

export type DiscoveryResult = {
  files: DiscoveredFileDto[];
  bytes: number;
};

export type SourceFileDto = {
  id: number;
  path: string;
  size: number;
  sha256: string | null;
  records_ok: number;
  records_err: number;
  is_dirty: boolean | null;
  first_ts: number | null;
  last_ts: number | null;
  error: string | null;
  status: string;
};

export type AnalysisOptions = {
  profile: string;
  builtins: boolean;
  build_fts: boolean;
  hash_files: boolean;
  run_detection: boolean;
  threads: number | null;
};

export type IngestProgressMsg =
  | { kind: "discovered"; files: number; bytes: number }
  | {
      kind: "progress";
      filesDone: number;
      filesTotal: number;
      bytesDone: number;
      events: number;
      eventsPerSec: number;
      detections: number;
      errors: number;
      currentFile?: string | null;
    }
  | { kind: "phase"; phase: string }
  | { kind: "fileError"; path: string; message: string }
  | {
      kind: "fileStatus";
      path: string;
      status: string;
      recordsOk: number;
      recordsErr: number;
      error?: string | null;
    }
  | {
      kind: "finished";
      runId: number;
      events: number;
      detections: number;
      elapsedMs: number;
    }
  | { kind: "cancelled" }
  | { kind: "failed"; message: string };

export type Settings = {
  display_timezone: string;
  use_utc: boolean;
  threads: number;
  fts_default: boolean;
  hash_default: boolean;
  rule_profile: string;
  builtins_default: boolean;
  run_detection_default: boolean;
  log_level: string;
  thresh_kerberoast: number;
  thresh_bruteforce: number;
  thresh_spray: number;
};

export type CaseStatsDto = {
  files: number;
  files_with_errors: number;
  events: number;
  detections: number;
  first_ts: number | null;
  last_ts: number | null;
};

export type GlobalFilter = {
  time_from?: number | null;
  time_to?: number | null;
  severities: string[];
  computers: string[];
  users: string[];
  channels: string[];
  event_ids: number[];
  triage: string[];
  mitre_tactic?: string | null;
  text?: string | null;
};

export type SeverityCountsDto = {
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
};

export type NamedCountDto = { name: string; count: number };
export type CoverageWarningDto = { code: string; message: string };
export type TimeBucketDto = { ts: number; count: number };

export type DashboardSummaryDto = {
  severity: SeverityCountsDto;
  total_detections: number;
  top_rules: NamedCountDto[];
  top_hosts: NamedCountDto[];
  top_users: NamedCountDto[];
  top_tactics: NamedCountDto[];
  files: number;
  files_with_errors: number;
  events: number;
  first_ts: number | null;
  last_ts: number | null;
  channels: NamedCountDto[];
  coverage: CoverageWarningDto[];
  detections_over_time: TimeBucketDto[];
};

export type MitreRefDto = {
  technique: string | null;
  tactic: string | null;
  name: string | null;
};

export type RuleSourceDto = {
  kind: string;
  pack?: string | null;
  version?: string | null;
  path?: string | null;
  url?: string | null;
};

export type DetectionRowDto = {
  id: number;
  run_id: number;
  rule_uid: string;
  rule_title: string;
  rule_author: string | null;
  rule_source: RuleSourceDto;
  severity: string;
  status: string | null;
  mitre: MitreRefDto[];
  ts: number;
  computer: string;
  user: string | null;
  kind: string;
  event_count: number;
  summary: string;
  fp_hint: string | null;
  triage: string;
  triage_note: string | null;
  event_ids: number[];
};

export type LinkedEventRefDto = {
  id: number;
  ts: number;
  event_id: number;
  channel: string;
  computer: string;
  user_name: string | null;
};

export type DetectionDetailDto = {
  detection: DetectionRowDto;
  group_json: string | null;
  linked_events: LinkedEventRefDto[];
};

export type DetectionQueryDto = {
  offset: number;
  limit: number;
  sort_col: string;
  sort_dir: string;
  severities: string[];
  rule_uid?: string | null;
  text?: string | null;
  time_from?: number | null;
  time_to?: number | null;
  computers: string[];
  users: string[];
  triage: string[];
  mitre_tactic?: string | null;
};

export type DetectionPageDto = {
  rows: DetectionRowDto[];
  total: number;
  offset: number;
};

export type DecodedPayloadDto = {
  field: string;
  encoding: string;
  text: string;
};

export type EventDetailDto = {
  id: number;
  file_id: number;
  record_id: number;
  ts: number;
  event_id: number;
  channel: string;
  provider: string;
  computer: string;
  level: number | null;
  user_name: string | null;
  src_ip: string | null;
  logon_type: number | null;
  source_path: string | null;
  description: string | null;
  fields: Record<string, unknown>;
  raw_json: string | null;
  xml: string | null;
  decoded: DecodedPayloadDto | null;
  related_detection_ids: number[];
};

export type SetTriageRequest = {
  detection_ids: number[];
  state: string;
  note?: string | null;
};

export type NavId =
  | "case"
  | "dashboard"
  | "detections"
  | "timeline"
  | "explorer"
  | "pivots"
  | "rules"
  | "export"
  | "settings";
