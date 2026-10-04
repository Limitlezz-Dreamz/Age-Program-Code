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
  text?: string | null;
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
