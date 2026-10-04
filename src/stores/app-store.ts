import { create } from "zustand";
import type {
  AnalysisOptions,
  CaseInfoDto,
  CaseStatsDto,
  GlobalFilter,
  IngestProgressMsg,
  NavId,
  RecentCase,
  Settings,
  SourceFileDto,
} from "@/ipc/types";

export type FileRow = SourceFileDto & { status: string };

type AnalysisState = {
  running: boolean;
  runId: number | null;
  phase: string;
  filesDone: number;
  filesTotal: number;
  events: number;
  eventsPerSec: number;
  detections: number;
  errors: number;
  lastError: string | null;
};

type AppState = {
  ready: boolean;
  backend: boolean;
  screen: NavId;
  caseInfo: CaseInfoDto | null;
  recent: RecentCase[];
  settings: Settings | null;
  files: FileRow[];
  stats: CaseStatsDto | null;
  filter: GlobalFilter;
  analysis: AnalysisState;
  dropActive: boolean;
  setScreen: (s: NavId) => void;
  setReady: (backend: boolean) => void;
  markBootstrapped: () => void;
  setCase: (c: CaseInfoDto | null) => void;
  setRecent: (r: RecentCase[]) => void;
  setSettings: (s: Settings) => void;
  setFiles: (f: FileRow[]) => void;
  upsertFileStatus: (
    path: string,
    patch: Partial<FileRow>,
  ) => void;
  setStats: (s: CaseStatsDto | null) => void;
  setFilter: (f: Partial<GlobalFilter>) => void;
  clearFilter: () => void;
  setDropActive: (v: boolean) => void;
  beginAnalysis: (runId: number) => void;
  applyProgress: (msg: IngestProgressMsg) => void;
  endAnalysis: () => void;
  defaultAnalysisOptions: () => AnalysisOptions;
};

const emptyFilter = (): GlobalFilter => ({
  severities: [],
  computers: [],
  users: [],
  channels: [],
  event_ids: [],
  text: null,
});

const idleAnalysis = (): AnalysisState => ({
  running: false,
  runId: null,
  phase: "idle",
  filesDone: 0,
  filesTotal: 0,
  events: 0,
  eventsPerSec: 0,
  detections: 0,
  errors: 0,
  lastError: null,
});

export const useAppStore = create<AppState>((set, get) => ({
  ready: false,
  backend: false,
  screen: "case",
  caseInfo: null,
  recent: [],
  settings: null,
  files: [],
  stats: null,
  filter: emptyFilter(),
  analysis: idleAnalysis(),
  dropActive: false,
  setScreen: (screen) => set({ screen }),
  setReady: (backend) => set({ ready: true, backend }),
  markBootstrapped: () => set({ ready: true }),
  setCase: (caseInfo) => set({ caseInfo }),
  setRecent: (recent) => set({ recent }),
  setSettings: (settings) => set({ settings }),
  setFiles: (files) => set({ files }),
  upsertFileStatus: (path, patch) =>
    set((s) => {
      const idx = s.files.findIndex((f) => f.path === path);
      if (idx < 0) {
        return {
          files: [
            ...s.files,
            {
              id: 0,
              path,
              size: 0,
              sha256: null,
              records_ok: 0,
              records_err: 0,
              is_dirty: null,
              first_ts: null,
              last_ts: null,
              error: null,
              status: "queued",
              ...patch,
            },
          ],
        };
      }
      const next = s.files.slice();
      next[idx] = { ...next[idx], ...patch };
      return { files: next };
    }),
  setStats: (stats) => set({ stats }),
  setFilter: (f) => set((s) => ({ filter: { ...s.filter, ...f } })),
  clearFilter: () => set({ filter: emptyFilter() }),
  setDropActive: (dropActive) => set({ dropActive }),
  beginAnalysis: (runId) =>
    set({
      analysis: {
        ...idleAnalysis(),
        running: true,
        runId,
        phase: "starting",
      },
    }),
  applyProgress: (msg) => {
    const a = get().analysis;
    switch (msg.kind) {
      case "discovered":
        set({
          analysis: {
            ...a,
            filesTotal: msg.files,
            phase: "parse",
          },
        });
        break;
      case "progress":
        set({
          analysis: {
            ...a,
            filesDone: msg.filesDone,
            filesTotal: msg.filesTotal,
            events: msg.events,
            eventsPerSec: msg.eventsPerSec,
            detections: msg.detections,
            errors: msg.errors,
          },
        });
        break;
      case "phase":
        set({ analysis: { ...a, phase: msg.phase } });
        break;
      case "fileError":
        get().upsertFileStatus(msg.path, {
          status: "error",
          error: msg.message,
        });
        set({
          analysis: { ...a, lastError: msg.message, errors: a.errors + 1 },
        });
        break;
      case "fileStatus":
        get().upsertFileStatus(msg.path, {
          status: msg.status,
          records_ok: msg.recordsOk,
          records_err: msg.recordsErr,
          error: msg.error ?? null,
        });
        break;
      case "finished":
        set({
          analysis: {
            ...a,
            running: false,
            phase: "done",
            runId: msg.runId,
            events: msg.events,
            detections: msg.detections,
          },
        });
        break;
      case "cancelled":
        set({
          analysis: { ...a, running: false, phase: "cancelled" },
        });
        break;
      case "failed":
        set({
          analysis: {
            ...a,
            running: false,
            phase: "failed",
            lastError: msg.message,
          },
        });
        break;
    }
  },
  endAnalysis: () => set({ analysis: { ...get().analysis, running: false } }),
  defaultAnalysisOptions: () => {
    const s = get().settings;
    return {
      profile: s?.rule_profile ?? "default",
      builtins: s?.builtins_default ?? true,
      build_fts: s?.fts_default ?? true,
      hash_files: s?.hash_default ?? true,
      run_detection: s?.run_detection_default ?? true,
      threads: s?.threads ?? null,
    };
  },
}));
