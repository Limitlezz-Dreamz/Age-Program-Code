use crate::dto::*;
use crate::error::ApiError;
use crate::persist;
use crate::state::{AppState, OpenCase};
use lw_core::{CancellationToken, CaseInfo, APP_NAME};
use lw_detect::{hunt, HuntOptions};
use lw_ingest::{discover, ingest_paths, IngestEvent, IngestOptions};
use lw_normalize::{default_4688_aliases, load_field_aliases};
use lw_rules::RuleProfile;
use lw_store::{
    create_case, list_files, open_case, query_detections, record_inputs, stats_summary,
    write_run_stats, DetectionQuery, StoreWriteCmd,
};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tauri::ipc::Channel;
use tauri::State;

#[tauri::command]
pub fn app_name() -> &'static str {
    APP_NAME
}

#[tauri::command]
pub fn greet(name: String) -> String {
    format!("Hello, {name}! Welcome to {APP_NAME}.")
}

#[tauri::command]
pub fn get_settings(state: State<'_, AppState>) -> Result<Settings, ApiError> {
    Ok(state
        .settings
        .lock()
        .map_err(|_| ApiError::msg("lock"))?
        .clone())
}

#[tauri::command]
pub fn set_settings(state: State<'_, AppState>, settings: Settings) -> Result<(), ApiError> {
    persist::save_settings(&settings)?;
    *state.settings.lock().map_err(|_| ApiError::msg("lock"))? = settings;
    Ok(())
}

#[tauri::command]
pub fn recent_cases() -> Result<Vec<RecentCase>, ApiError> {
    Ok(persist::load_recent())
}

fn to_case_dto(info: &CaseInfo) -> CaseInfoDto {
    CaseInfoDto {
        name: info.name.clone(),
        path: info.path.clone(),
        created_at: info.created_at.clone(),
        app_version: info.app_version.clone(),
        input_paths: info.input_paths.clone(),
        notes: info.notes.clone(),
    }
}

#[tauri::command]
pub fn create_case_cmd(
    state: State<'_, AppState>,
    dir: String,
    name: String,
) -> Result<CaseInfoDto, ApiError> {
    close_case_inner(&state)?;
    let store = create_case(PathBuf::from(&dir), &name)?;
    let info = store.info()?;
    let _ = persist::push_recent(&info)?;
    let dto = to_case_dto(&info);
    *state.case.lock().map_err(|_| ApiError::msg("lock"))? = Some(OpenCase {
        store,
        pending_inputs: Vec::new(),
        file_status: Default::default(),
    });
    Ok(dto)
}

#[tauri::command]
pub fn open_case_cmd(state: State<'_, AppState>, path: String) -> Result<CaseInfoDto, ApiError> {
    close_case_inner(&state)?;
    let store = open_case(PathBuf::from(&path))?;
    let info = store.info()?;
    let _ = persist::push_recent(&info)?;
    let dto = to_case_dto(&info);
    *state.case.lock().map_err(|_| ApiError::msg("lock"))? = Some(OpenCase {
        store,
        pending_inputs: Vec::new(),
        file_status: Default::default(),
    });
    Ok(dto)
}

#[tauri::command]
pub fn close_case(state: State<'_, AppState>) -> Result<(), ApiError> {
    close_case_inner(&state)
}

fn close_case_inner(state: &AppState) -> Result<(), ApiError> {
    if let Some(token) = state
        .cancel
        .lock()
        .map_err(|_| ApiError::msg("lock"))?
        .take()
    {
        token.cancel();
    }
    if let Some(open) = state.case.lock().map_err(|_| ApiError::msg("lock"))?.take() {
        let _ = open.store.shutdown();
    }
    Ok(())
}

#[tauri::command]
pub fn current_case(state: State<'_, AppState>) -> Result<Option<CaseInfoDto>, ApiError> {
    let guard = state.case.lock().map_err(|_| ApiError::msg("lock"))?;
    match guard.as_ref() {
        Some(c) => Ok(Some(to_case_dto(&c.store.info()?))),
        None => Ok(None),
    }
}

#[tauri::command]
pub fn add_inputs(
    state: State<'_, AppState>,
    paths: Vec<String>,
) -> Result<DiscoveryResult, ApiError> {
    let path_bufs: Vec<PathBuf> = paths.iter().map(PathBuf::from).collect();
    let discovered = discover(&path_bufs)?;
    let bytes: u64 = discovered.iter().map(|f| f.size).sum();
    let files: Vec<DiscoveredFileDto> = discovered
        .into_iter()
        .map(|f| DiscoveredFileDto {
            path: f.path.display().to_string(),
            size: f.size,
            mtime: f.mtime,
        })
        .collect();

    let mut guard = state.case.lock().map_err(|_| ApiError::msg("lock"))?;
    let open = guard
        .as_mut()
        .ok_or_else(|| ApiError::new("no_case", "open or create a case first"))?;
    for f in &files {
        if !open.pending_inputs.contains(&f.path) {
            open.pending_inputs.push(f.path.clone());
        }
        open.file_status
            .insert(f.path.clone(), "queued".to_string());
    }
    record_inputs(&open.store.root, &paths)?;
    Ok(DiscoveryResult { files, bytes })
}

#[tauri::command]
pub fn list_files_cmd(state: State<'_, AppState>) -> Result<Vec<SourceFileDto>, ApiError> {
    let guard = state.case.lock().map_err(|_| ApiError::msg("lock"))?;
    let open = guard
        .as_ref()
        .ok_or_else(|| ApiError::new("no_case", "no case open"))?;
    let conn = open.store.open_read_only()?;
    let mut out: Vec<SourceFileDto> = list_files(&conn)?
        .into_iter()
        .map(|f| {
            let status = if f.error.is_some() {
                "error"
            } else if f.records_ok > 0 {
                "ok"
            } else {
                "pending"
            };
            SourceFileDto {
                id: f.id,
                path: f.path,
                size: f.size,
                sha256: f.sha256,
                records_ok: f.records_ok,
                records_err: f.records_err,
                is_dirty: f.is_dirty,
                first_ts: f.first_ts,
                last_ts: f.last_ts,
                error: f.error,
                status: status.into(),
            }
        })
        .collect();

    for p in &open.pending_inputs {
        if !out.iter().any(|f| &f.path == p) {
            out.push(SourceFileDto {
                id: 0,
                path: p.clone(),
                size: 0,
                sha256: None,
                records_ok: 0,
                records_err: 0,
                is_dirty: None,
                first_ts: None,
                last_ts: None,
                error: None,
                status: open
                    .file_status
                    .get(p)
                    .cloned()
                    .unwrap_or_else(|| "queued".into()),
            });
        }
    }
    Ok(out)
}

#[tauri::command]
pub fn case_stats(state: State<'_, AppState>) -> Result<CaseStatsDto, ApiError> {
    let guard = state.case.lock().map_err(|_| ApiError::msg("lock"))?;
    let open = guard
        .as_ref()
        .ok_or_else(|| ApiError::new("no_case", "no case open"))?;
    let conn = open.store.open_read_only()?;
    let summary = stats_summary(&conn)?;
    let detections = query_detections(
        &conn,
        &DetectionQuery {
            offset: 0,
            limit: 1,
            ..DetectionQuery::default()
        },
    )?
    .total;
    Ok(CaseStatsDto {
        files: summary.files,
        files_with_errors: summary.files_with_errors,
        events: summary.events,
        detections,
        first_ts: summary.first_ts,
        last_ts: summary.last_ts,
    })
}

#[tauri::command]
pub fn cancel_analysis(state: State<'_, AppState>) -> Result<(), ApiError> {
    if let Some(token) = state
        .cancel
        .lock()
        .map_err(|_| ApiError::msg("lock"))?
        .as_ref()
    {
        token.cancel();
    }
    Ok(())
}

#[tauri::command]
pub async fn start_analysis(
    state: State<'_, AppState>,
    opts: AnalysisOptions,
    on_progress: Channel<IngestProgressMsg>,
) -> Result<i64, ApiError> {
    let run_id = state.next_run_id();
    let cancel = CancellationToken::new();
    *state.cancel.lock().map_err(|_| ApiError::msg("lock"))? = Some(cancel.clone());

    let (root, writer_tx, pending) = {
        let guard = state.case.lock().map_err(|_| ApiError::msg("lock"))?;
        let open = guard
            .as_ref()
            .ok_or_else(|| ApiError::new("no_case", "no case open"))?;
        (
            open.store.root.clone(),
            open.store.writer().sender(),
            open.pending_inputs.clone(),
        )
    };

    if pending.is_empty() {
        // Allow re-run detection only
        if !opts.run_detection {
            return Err(ApiError::new(
                "no_inputs",
                "add EVTX files or enable detection re-run",
            ));
        }
    }

    let settings = state
        .settings
        .lock()
        .map_err(|_| ApiError::msg("lock"))?
        .clone();

    let on_progress = Arc::new(on_progress);
    let progress = Arc::clone(&on_progress);

    tauri::async_runtime::spawn_blocking(move || {
        let send = |msg: IngestProgressMsg| {
            let _ = progress.send(msg);
        };

        let t0 = Instant::now();
        let mut total_events = 0u64;
        let mut total_detections = 0u64;

        if !pending.is_empty() {
            send(IngestProgressMsg::Phase {
                phase: "parse".into(),
            });
            let paths: Vec<PathBuf> = pending.iter().map(PathBuf::from).collect();
            let aliases = lw_ingest::default_aliases_path()
                .and_then(|p| load_field_aliases(p).ok())
                .unwrap_or_else(default_4688_aliases);
            let mut ingest_opts = IngestOptions {
                hash_files: opts.hash_files,
                aliases,
                ..IngestOptions::default()
            };
            if let Some(t) = opts.threads.or(Some(settings.threads)) {
                ingest_opts.num_threads = t.max(1);
            }

            let started = Instant::now();
            let result = ingest_paths(&paths, &ingest_opts, &cancel, |ev| match ev {
                IngestEvent::Discovered { files, bytes } => {
                    send(IngestProgressMsg::Discovered {
                        files: files as u64,
                        bytes,
                    });
                }
                IngestEvent::FileStarted { file } => {
                    let _ = writer_tx.send(StoreWriteCmd::UpsertFile(file.clone()));
                    send(IngestProgressMsg::FileStatus {
                        path: file.path,
                        status: "parsing".into(),
                        records_ok: 0,
                        records_err: 0,
                        error: None,
                    });
                }
                IngestEvent::FileFinished { file } => {
                    let _ = writer_tx.send(StoreWriteCmd::UpsertFile(file.clone()));
                    let status = if file.error.is_some() { "error" } else { "ok" };
                    if let Some(err) = &file.error {
                        send(IngestProgressMsg::FileError {
                            path: file.path.clone(),
                            message: err.clone(),
                        });
                    }
                    send(IngestProgressMsg::FileStatus {
                        path: file.path,
                        status: status.into(),
                        records_ok: file.records_ok,
                        records_err: file.records_err,
                        error: file.error,
                    });
                }
                IngestEvent::Batch { events } => {
                    let _ = writer_tx.send(StoreWriteCmd::InsertEvents(events));
                }
                IngestEvent::Progress {
                    files_done,
                    files_total,
                    records_ok,
                    records_err,
                } => {
                    let elapsed = started.elapsed().as_secs_f64().max(0.001);
                    send(IngestProgressMsg::Progress {
                        files_done,
                        files_total,
                        bytes_done: 0,
                        events: records_ok,
                        events_per_sec: records_ok as f64 / elapsed,
                        detections: 0,
                        errors: records_err,
                        current_file: None,
                    });
                }
                IngestEvent::Finished { .. } => {}
            });

            match result {
                Ok(stats) => {
                    total_events = stats.records_ok;
                    let _ = writer_tx.send(StoreWriteCmd::Finalize {
                        build_fts: opts.build_fts,
                    });
                    // Wait for finalize before hunt opens another connection.
                    let (stx, srx) = std::sync::mpsc::channel();
                    let _ = writer_tx.send(StoreWriteCmd::Sync(stx));
                    let _ = srx.recv();
                    let _ = write_run_stats(&root, &stats);
                }
                Err(lw_core::Error::Cancelled) => {
                    let _ = writer_tx.send(StoreWriteCmd::Finalize { build_fts: false });
                    send(IngestProgressMsg::Cancelled);
                    return;
                }
                Err(e) => {
                    send(IngestProgressMsg::Failed {
                        message: e.to_string(),
                    });
                    return;
                }
            }
        }

        if opts.run_detection && !cancel.is_cancelled() {
            send(IngestProgressMsg::Phase {
                phase: "detect".into(),
            });
            let profile = RuleProfile::parse(&opts.profile).unwrap_or(RuleProfile::Default);
            let hunt_opts = HuntOptions {
                case_dir: root.clone(),
                profile,
                builtins: opts.builtins,
                ..Default::default()
            };
            match hunt(&hunt_opts, &cancel) {
                Ok((report, _)) => {
                    total_detections = report.detections;
                    if total_events == 0 {
                        total_events = report.events_scanned;
                    }
                    send(IngestProgressMsg::Phase {
                        phase: "done".into(),
                    });
                }
                Err(lw_core::Error::Cancelled) => {
                    send(IngestProgressMsg::Cancelled);
                    return;
                }
                Err(e) => {
                    send(IngestProgressMsg::Failed {
                        message: e.to_string(),
                    });
                    return;
                }
            }
        } else {
            send(IngestProgressMsg::Phase {
                phase: "done".into(),
            });
        }

        // Clear pending inputs after successful run
        send(IngestProgressMsg::Finished {
            run_id,
            events: total_events,
            detections: total_detections,
            elapsed_ms: t0.elapsed().as_millis() as u64,
        });
    });

    // Clear pending list after kickoff (best-effort); UI refreshes via list_files
    if let Ok(mut guard) = state.case.lock() {
        if let Some(open) = guard.as_mut() {
            open.pending_inputs.clear();
        }
    }

    Ok(run_id)
}

#[tauri::command]
pub fn default_cases_dir() -> Result<String, ApiError> {
    let dir = persist::ensure_app_dirs()?.join("cases");
    Ok(dir.display().to_string())
}

/// Export TS bindings via ts-rs when the `ts-rs` feature is enabled.
#[cfg(feature = "ts-rs")]
#[tauri::command]
pub fn export_bindings_hint() -> String {
    "Run: cargo test -p logwarden --features ts-rs export_ts".into()
}
