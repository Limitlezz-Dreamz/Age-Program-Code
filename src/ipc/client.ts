import { Channel, invoke } from "@tauri-apps/api/core";
import type {
  AnalysisOptions,
  ApiError,
  CaseInfoDto,
  CaseStatsDto,
  DashboardSummaryDto,
  DetectionDetailDto,
  DetectionPageDto,
  DetectionQueryDto,
  DiscoveryResult,
  EventDetailDto,
  EventPageDto,
  EventQueryDto,
  ExportRequestDto,
  ExportResultDto,
  GlobalFilter,
  HistogramBucketDto,
  HistogramQueryDto,
  HuntReportDto,
  IngestProgressMsg,
  LogonPageDto,
  PivotPageDto,
  PivotQueryDto,
  RecentCase,
  RuleDetailDto,
  RulePackDto,
  RulePageDto,
  RuleQueryDto,
  SavedSearchDto,
  SetTriageRequest,
  Settings,
  SourceFileDto,
  SuppressionDto,
  SuppressionInputDto,
  TimelineListQueryDto,
  TimelinePageDto,
} from "./types";

async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(cmd, args);
  } catch (e) {
    const err = e as ApiError | string;
    if (typeof err === "object" && err && "message" in err) {
      throw new Error(`${err.code}: ${err.message}`);
    }
    throw new Error(String(e));
  }
}

export const ipc = {
  appName: () => call<string>("app_name"),
  appVersion: () => call<string>("app_version"),
  getSettings: () => call<Settings>("get_settings"),
  setSettings: (settings: Settings) => call<void>("set_settings", { settings }),
  recentCases: () => call<RecentCase[]>("recent_cases"),
  createCase: (dir: string, name: string) =>
    call<CaseInfoDto>("create_case_cmd", { dir, name }),
  openCase: (path: string) => call<CaseInfoDto>("open_case_cmd", { path }),
  closeCase: () => call<void>("close_case"),
  currentCase: () => call<CaseInfoDto | null>("current_case"),
  addInputs: (paths: string[]) => call<DiscoveryResult>("add_inputs", { paths }),
  listFiles: () => call<SourceFileDto[]>("list_files_cmd"),
  caseStats: () => call<CaseStatsDto>("case_stats"),
  cancelAnalysis: () => call<void>("cancel_analysis"),
  defaultCasesDir: () => call<string>("default_cases_dir"),
  startAnalysis: async (
    opts: AnalysisOptions,
    onProgress: (msg: IngestProgressMsg) => void,
  ) => {
    const channel = new Channel<IngestProgressMsg>();
    channel.onmessage = onProgress;
    return call<number>("start_analysis", { opts, onProgress: channel });
  },
  dashboardSummary: (filter?: GlobalFilter | null) =>
    call<DashboardSummaryDto>("dashboard_summary_cmd", { filter: filter ?? null }),
  queryDetections: (q: DetectionQueryDto, filter?: GlobalFilter | null) =>
    call<DetectionPageDto>("query_detections_cmd", {
      q,
      filter: filter ?? null,
    }),
  getDetection: (id: number) => call<DetectionDetailDto>("get_detection_cmd", { id }),
  getEvent: (id: number) => call<EventDetailDto>("get_event_cmd", { id }),
  setTriage: (req: SetTriageRequest) => call<number>("set_triage_cmd", { req }),
  timelineHistogram: (q: HistogramQueryDto, filter?: GlobalFilter | null) =>
    call<HistogramBucketDto[]>("timeline_histogram_cmd", {
      q,
      filter: filter ?? null,
    }),
  timelineList: (q: TimelineListQueryDto, filter?: GlobalFilter | null) =>
    call<TimelinePageDto>("timeline_list_cmd", { q, filter: filter ?? null }),
  queryEvents: (q: EventQueryDto, filter?: GlobalFilter | null) =>
    call<EventPageDto>("query_events_cmd", { q, filter: filter ?? null }),
  queryPivots: (q: PivotQueryDto, filter?: GlobalFilter | null) =>
    call<PivotPageDto>("query_pivots_cmd", { q, filter: filter ?? null }),
  logonSummary: (q: PivotQueryDto, filter?: GlobalFilter | null) =>
    call<LogonPageDto>("logon_summary_cmd", { q, filter: filter ?? null }),
  listSavedSearches: () => call<SavedSearchDto[]>("list_saved_searches_cmd"),
  saveSearch: (name: string, queryJson: string) =>
    call<number>("save_search_cmd", { name, queryJson }),
  deleteSavedSearch: (id: number) => call<void>("delete_saved_search_cmd", { id }),
  listRulePacks: () => call<RulePackDto[]>("list_rule_packs_cmd"),
  importRulePack: (path: string, packId: string) =>
    call<RulePackDto>("import_rule_pack_cmd", { path, packId }),
  downloadRulePack: (kind: string) =>
    call<RulePackDto>("download_rule_pack_cmd", { kind }),
  drlNotice: () => call<string>("drl_notice_cmd"),
  listRules: (q: RuleQueryDto) => call<RulePageDto>("list_rules_cmd", { q }),
  getRule: (uid: string) => call<RuleDetailDto>("get_rule_cmd", { uid }),
  setRuleEnabled: (uid: string, enabled: boolean) =>
    call<void>("set_rule_enabled_cmd", { uid, enabled }),
  listSuppressions: () => call<SuppressionDto[]>("list_suppressions_cmd"),
  addSuppression: (s: SuppressionInputDto) =>
    call<number>("add_suppression_cmd", { s }),
  deleteSuppression: (id: number) => call<void>("delete_suppression_cmd", { id }),
  rerunDetection: (profile: string, builtins: boolean, rulesPath?: string | null) =>
    call<HuntReportDto>("rerun_detection_cmd", {
      profile,
      builtins,
      rulesPath: rulesPath ?? null,
    }),
  exportDetections: (req: ExportRequestDto) =>
    call<ExportResultDto>("export_detections_cmd", { req }),
};
