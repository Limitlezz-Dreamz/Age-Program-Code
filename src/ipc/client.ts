import { Channel, invoke } from "@tauri-apps/api/core";
import type {
  AnalysisOptions,
  ApiError,
  CaseInfoDto,
  CaseStatsDto,
  DiscoveryResult,
  IngestProgressMsg,
  RecentCase,
  Settings,
  SourceFileDto,
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
};
