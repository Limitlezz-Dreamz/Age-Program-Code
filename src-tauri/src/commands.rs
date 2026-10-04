use crate::dto::*;
use crate::error::ApiError;
use crate::persist;
use crate::state::{AppState, OpenCase};
use lw_core::{
    CancellationToken, CaseInfo, Detection, DetectionKind, Severity, TriageState, APP_NAME,
};
use lw_detect::{hunt, HuntOptions};
use lw_ingest::{discover, ingest_paths, IngestEvent, IngestOptions};
use lw_normalize::{default_4688_aliases, load_field_aliases};
use lw_report::{
    export_detections_csv, export_detections_html, export_detections_json, export_detections_jsonl,
};
use lw_rules::{
    download_sigma_pack, find_mapping_path, import_pack_dir, list_packs, load_logsource_mapping,
    packs_dir, RuleProfile, SigmaPackKind, SIGMA_DRL_NOTICE,
};
use lw_store::{
    add_suppression, create_case, dashboard_summary, delete_saved_search, delete_suppression,
    get_detection, get_event, get_rule, list_files, list_saved_searches, list_suppressions,
    open_case, query_detections, query_events, query_logon_summary, query_pivots, query_rules,
    record_inputs, save_search, set_rule_enabled, set_triage, stats_summary, timeline_histogram,
    timeline_list, write_run_stats, DetectionQuery, DetectionRow, EventQuery, FieldFilter,
    HistogramQuery, PivotQuery, RuleQuery, SortDir, StoreWriteCmd, SuppressionInput,
    TimelineListQuery,
};
use std::fs::File;
use std::io::BufWriter;
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
pub fn app_version() -> &'static str {
    lw_core::APP_VERSION
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

fn with_open_case<T>(
    state: &AppState,
    f: impl FnOnce(&OpenCase) -> Result<T, ApiError>,
) -> Result<T, ApiError> {
    let guard = state.case.lock().map_err(|_| ApiError::msg("lock"))?;
    let open = guard
        .as_ref()
        .ok_or_else(|| ApiError::new("no_case", "no case open"))?;
    f(open)
}

fn parse_severity(s: &str) -> Option<Severity> {
    match s.to_ascii_lowercase().as_str() {
        "informational" | "info" => Some(Severity::Informational),
        "low" => Some(Severity::Low),
        "medium" | "med" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" | "crit" => Some(Severity::Critical),
        _ => None,
    }
}

fn parse_triage(s: &str) -> Result<TriageState, ApiError> {
    match s {
        "new" => Ok(TriageState::New),
        "reviewed" => Ok(TriageState::Reviewed),
        "false_positive" => Ok(TriageState::FalsePositive),
        "escalated" => Ok(TriageState::Escalated),
        other => Err(ApiError::new(
            "bad_triage",
            format!("unknown triage state: {other}"),
        )),
    }
}

fn rule_source_dto(src: &lw_core::RuleSource) -> RuleSourceDto {
    match src {
        lw_core::RuleSource::Builtin => RuleSourceDto {
            kind: "builtin".into(),
            pack: None,
            version: None,
            path: None,
            url: None,
        },
        lw_core::RuleSource::Sigma {
            pack,
            version,
            path,
            url,
        } => RuleSourceDto {
            kind: "sigma".into(),
            pack: Some(pack.clone()),
            version: Some(version.clone()),
            path: Some(path.clone()),
            url: url.clone(),
        },
    }
}

fn detection_row_dto(d: lw_store::DetectionRow) -> DetectionRowDto {
    DetectionRowDto {
        id: d.id,
        run_id: d.run_id,
        rule_uid: d.rule_uid,
        rule_title: d.rule_title,
        rule_author: d.rule_author,
        rule_source: rule_source_dto(&d.rule_source),
        severity: d.severity.as_str().into(),
        status: d.status,
        mitre: d
            .mitre
            .into_iter()
            .map(|m| MitreRefDto {
                technique: m.technique,
                tactic: m.tactic,
                name: m.name,
            })
            .collect(),
        ts: d.ts,
        computer: d.computer,
        user: d.user,
        kind: d.kind,
        event_count: d.event_count,
        summary: d.summary,
        fp_hint: d.fp_hint,
        triage: d.triage,
        triage_note: d.triage_note,
        event_ids: d.event_ids,
    }
}

fn to_detection_query(q: &DetectionQueryDto, filter: &GlobalFilter) -> DetectionQuery {
    let mut severities: Vec<Severity> = q
        .severities
        .iter()
        .filter_map(|s| parse_severity(s))
        .collect();
    if severities.is_empty() {
        severities = filter
            .severities
            .iter()
            .filter_map(|s| parse_severity(s))
            .collect();
    }
    let computers = if q.computers.is_empty() {
        filter.computers.clone()
    } else {
        q.computers.clone()
    };
    let users = if q.users.is_empty() {
        filter.users.clone()
    } else {
        q.users.clone()
    };
    let triage = if q.triage.is_empty() {
        filter.triage.clone()
    } else {
        q.triage.clone()
    };
    let text = q
        .text
        .clone()
        .or_else(|| filter.text.clone())
        .filter(|t| !t.is_empty());
    let sort_dir = match q.sort_dir.to_ascii_lowercase().as_str() {
        "asc" => SortDir::Asc,
        _ => SortDir::Desc,
    };
    DetectionQuery {
        offset: q.offset,
        limit: if q.limit == 0 { 200 } else { q.limit },
        sort_col: if q.sort_col.is_empty() {
            "severity".into()
        } else {
            q.sort_col.clone()
        },
        sort_dir,
        severity_min: None,
        severities,
        rule_uid: q.rule_uid.clone(),
        text,
        time_from: q.time_from.or(filter.time_from),
        time_to: q.time_to.or(filter.time_to),
        computers,
        users,
        triage,
        mitre_tactic: q
            .mitre_tactic
            .clone()
            .or_else(|| filter.mitre_tactic.clone()),
    }
}

#[tauri::command]
pub fn dashboard_summary_cmd(
    state: State<'_, AppState>,
    filter: Option<GlobalFilter>,
) -> Result<DashboardSummaryDto, ApiError> {
    let filter = filter.unwrap_or_default();
    let q = to_detection_query(
        &DetectionQueryDto {
            offset: 0,
            limit: 1,
            sort_col: "severity".into(),
            sort_dir: "desc".into(),
            severities: Vec::new(),
            rule_uid: None,
            text: None,
            time_from: None,
            time_to: None,
            computers: Vec::new(),
            users: Vec::new(),
            triage: Vec::new(),
            mitre_tactic: None,
        },
        &filter,
    );
    with_open_case(&state, |open| {
        let conn = open.store.open_read_only()?;
        let s = dashboard_summary(&conn, &q)?;
        Ok(DashboardSummaryDto {
            severity: SeverityCountsDto {
                critical: s.severity.critical,
                high: s.severity.high,
                medium: s.severity.medium,
                low: s.severity.low,
                informational: s.severity.informational,
            },
            total_detections: s.total_detections,
            top_rules: s
                .top_rules
                .into_iter()
                .map(|n| NamedCountDto {
                    name: n.name,
                    count: n.count,
                })
                .collect(),
            top_hosts: s
                .top_hosts
                .into_iter()
                .map(|n| NamedCountDto {
                    name: n.name,
                    count: n.count,
                })
                .collect(),
            top_users: s
                .top_users
                .into_iter()
                .map(|n| NamedCountDto {
                    name: n.name,
                    count: n.count,
                })
                .collect(),
            top_tactics: s
                .top_tactics
                .into_iter()
                .map(|n| NamedCountDto {
                    name: n.name,
                    count: n.count,
                })
                .collect(),
            files: s.files,
            files_with_errors: s.files_with_errors,
            events: s.events,
            first_ts: s.first_ts,
            last_ts: s.last_ts,
            channels: s
                .channels
                .into_iter()
                .map(|n| NamedCountDto {
                    name: n.name,
                    count: n.count,
                })
                .collect(),
            coverage: s
                .coverage
                .into_iter()
                .map(|c| CoverageWarningDto {
                    code: c.code,
                    message: c.message,
                })
                .collect(),
            detections_over_time: s
                .detections_over_time
                .into_iter()
                .map(|b| TimeBucketDto {
                    ts: b.ts,
                    count: b.count,
                })
                .collect(),
        })
    })
}

#[tauri::command]
pub fn query_detections_cmd(
    state: State<'_, AppState>,
    q: DetectionQueryDto,
    filter: Option<GlobalFilter>,
) -> Result<DetectionPageDto, ApiError> {
    let filter = filter.unwrap_or_default();
    with_open_case(&state, |open| {
        let conn = open.store.open_read_only()?;
        let page = query_detections(&conn, &to_detection_query(&q, &filter))?;
        Ok(DetectionPageDto {
            rows: page.rows.into_iter().map(detection_row_dto).collect(),
            total: page.total,
            offset: page.offset,
        })
    })
}

#[tauri::command]
pub fn get_detection_cmd(
    state: State<'_, AppState>,
    id: i64,
) -> Result<DetectionDetailDto, ApiError> {
    with_open_case(&state, |open| {
        let conn = open.store.open_read_only()?;
        let d = get_detection(&conn, id)?;
        Ok(DetectionDetailDto {
            detection: detection_row_dto(d.detection),
            group_json: d.group_json,
            linked_events: d
                .linked_events
                .into_iter()
                .map(|e| LinkedEventRefDto {
                    id: e.id,
                    ts: e.ts,
                    event_id: e.event_id,
                    channel: e.channel,
                    computer: e.computer,
                    user_name: e.user_name,
                })
                .collect(),
        })
    })
}

#[tauri::command]
pub fn get_event_cmd(state: State<'_, AppState>, id: i64) -> Result<EventDetailDto, ApiError> {
    with_open_case(&state, |open| {
        let conn = open.store.open_read_only()?;
        let e = get_event(&conn, id)?;
        Ok(EventDetailDto {
            id: e.id,
            file_id: e.file_id,
            record_id: e.record_id,
            ts: e.ts,
            event_id: e.event_id,
            channel: e.channel,
            provider: e.provider,
            computer: e.computer,
            level: e.level,
            user_name: e.user_name,
            src_ip: e.src_ip,
            logon_type: e.logon_type,
            source_path: e.source_path,
            description: e.description,
            fields: e.fields,
            raw_json: e.raw_json,
            xml: e.xml,
            decoded: e.decoded.map(|d| DecodedPayloadDto {
                field: d.field,
                encoding: d.encoding,
                text: d.text,
            }),
            related_detection_ids: e.related_detection_ids,
        })
    })
}

#[tauri::command]
pub fn set_triage_cmd(state: State<'_, AppState>, req: SetTriageRequest) -> Result<u64, ApiError> {
    let triage = parse_triage(&req.state)?;
    with_open_case(&state, |open| {
        // Need a writable connection for triage updates.
        let conn = lw_store::open_write_conn(&open.store.root)?;
        let n = set_triage(&conn, &req.detection_ids, triage, req.note.as_deref())?;
        Ok(n)
    })
}

fn merge_hist_filter(q: &HistogramQueryDto, filter: &GlobalFilter) -> HistogramQuery {
    HistogramQuery {
        time_from: q.time_from.or(filter.time_from),
        time_to: q.time_to.or(filter.time_to),
        computers: if q.computers.is_empty() {
            filter.computers.clone()
        } else {
            q.computers.clone()
        },
        channels: if q.channels.is_empty() {
            filter.channels.clone()
        } else {
            q.channels.clone()
        },
        series: if q.series.is_empty() {
            "severity".into()
        } else {
            q.series.clone()
        },
        bucket_micros: q.bucket_micros,
    }
}

fn merge_event_query(q: &EventQueryDto, filter: &GlobalFilter) -> EventQuery {
    let sort_dir = match q.sort_dir.to_ascii_lowercase().as_str() {
        "desc" => SortDir::Desc,
        _ => SortDir::Asc,
    };
    EventQuery {
        offset: q.offset,
        limit: if q.limit == 0 { 200 } else { q.limit },
        sort_col: if q.sort_col.is_empty() {
            "ts".into()
        } else {
            q.sort_col.clone()
        },
        sort_dir,
        time_from: q.time_from.or(filter.time_from),
        time_to: q.time_to.or(filter.time_to),
        event_ids: if q.event_ids.is_empty() {
            filter.event_ids.clone()
        } else {
            q.event_ids.clone()
        },
        computers: if q.computers.is_empty() {
            filter.computers.clone()
        } else {
            q.computers.clone()
        },
        channels: if q.channels.is_empty() {
            filter.channels.clone()
        } else {
            q.channels.clone()
        },
        users: if q.users.is_empty() {
            filter.users.clone()
        } else {
            q.users.clone()
        },
        src_ips: q.src_ips.clone(),
        text: q
            .text
            .clone()
            .or_else(|| filter.text.clone())
            .filter(|t| !t.is_empty()),
        field_filters: q
            .field_filters
            .iter()
            .map(|f| FieldFilter {
                field: f.field.clone(),
                op: f.op.clone(),
                value: f.value.clone(),
            })
            .collect(),
    }
}

#[tauri::command]
pub fn timeline_histogram_cmd(
    state: State<'_, AppState>,
    q: HistogramQueryDto,
    filter: Option<GlobalFilter>,
) -> Result<Vec<HistogramBucketDto>, ApiError> {
    let filter = filter.unwrap_or_default();
    with_open_case(&state, |open| {
        let conn = open.store.open_read_only()?;
        let buckets = timeline_histogram(&conn, &merge_hist_filter(&q, &filter))?;
        Ok(buckets
            .into_iter()
            .map(|b| HistogramBucketDto {
                ts: b.ts,
                series: b.series,
                count: b.count,
            })
            .collect())
    })
}

#[tauri::command]
pub fn timeline_list_cmd(
    state: State<'_, AppState>,
    q: TimelineListQueryDto,
    filter: Option<GlobalFilter>,
) -> Result<TimelinePageDto, ApiError> {
    let filter = filter.unwrap_or_default();
    let query = TimelineListQuery {
        offset: q.offset,
        limit: if q.limit == 0 { 200 } else { q.limit },
        time_from: q.time_from.or(filter.time_from),
        time_to: q.time_to.or(filter.time_to),
        computers: if q.computers.is_empty() {
            filter.computers.clone()
        } else {
            q.computers
        },
        include_events: q.include_events,
        text: q.text.or(filter.text).filter(|t| !t.is_empty()),
    };
    with_open_case(&state, |open| {
        let conn = open.store.open_read_only()?;
        let page = timeline_list(&conn, &query)?;
        Ok(TimelinePageDto {
            rows: page
                .rows
                .into_iter()
                .map(|r| TimelineItemDto {
                    kind: r.kind,
                    id: r.id,
                    ts: r.ts,
                    computer: r.computer,
                    label: r.label,
                    severity: r.severity,
                    event_id: r.event_id,
                    channel: r.channel,
                })
                .collect(),
            total: page.total,
            offset: page.offset,
        })
    })
}

#[tauri::command]
pub fn query_events_cmd(
    state: State<'_, AppState>,
    q: EventQueryDto,
    filter: Option<GlobalFilter>,
) -> Result<EventPageDto, ApiError> {
    let filter = filter.unwrap_or_default();
    with_open_case(&state, |open| {
        let conn = open.store.open_read_only()?;
        let page = query_events(&conn, &merge_event_query(&q, &filter))?;
        Ok(EventPageDto {
            rows: page
                .rows
                .into_iter()
                .map(|r| EventRowDto {
                    id: r.id,
                    file_id: r.file_id,
                    record_id: r.record_id,
                    ts: r.ts,
                    event_id: r.event_id,
                    channel: r.channel,
                    provider: r.provider,
                    computer: r.computer,
                    user_name: r.user_name,
                    src_ip: r.src_ip,
                    logon_type: r.logon_type,
                    summary: r.summary,
                })
                .collect(),
            total: page.total,
            offset: page.offset,
        })
    })
}

#[tauri::command]
pub fn query_pivots_cmd(
    state: State<'_, AppState>,
    q: PivotQueryDto,
    filter: Option<GlobalFilter>,
) -> Result<PivotPageDto, ApiError> {
    let filter = filter.unwrap_or_default();
    let query = PivotQuery {
        dimension: q.dimension,
        offset: q.offset,
        limit: if q.limit == 0 { 200 } else { q.limit },
        time_from: q.time_from.or(filter.time_from),
        time_to: q.time_to.or(filter.time_to),
        text: q.text.or(filter.text).filter(|t| !t.is_empty()),
    };
    with_open_case(&state, |open| {
        let conn = open.store.open_read_only()?;
        let page = query_pivots(&conn, &query)?;
        Ok(PivotPageDto {
            rows: page
                .rows
                .into_iter()
                .map(|r| PivotRowDto {
                    key: r.key,
                    event_count: r.event_count,
                    detection_count: r.detection_count,
                    critical: r.critical,
                    high: r.high,
                    medium: r.medium,
                    low: r.low,
                    informational: r.informational,
                    first_ts: r.first_ts,
                    last_ts: r.last_ts,
                })
                .collect(),
            total: page.total,
            offset: page.offset,
        })
    })
}

#[tauri::command]
pub fn logon_summary_cmd(
    state: State<'_, AppState>,
    q: PivotQueryDto,
    filter: Option<GlobalFilter>,
) -> Result<LogonPageDto, ApiError> {
    let filter = filter.unwrap_or_default();
    let query = PivotQuery {
        dimension: "logon".into(),
        offset: q.offset,
        limit: if q.limit == 0 { 200 } else { q.limit },
        time_from: q.time_from.or(filter.time_from),
        time_to: q.time_to.or(filter.time_to),
        text: q.text.or(filter.text).filter(|t| !t.is_empty()),
    };
    with_open_case(&state, |open| {
        let conn = open.store.open_read_only()?;
        let page = query_logon_summary(&conn, &query)?;
        Ok(LogonPageDto {
            rows: page
                .rows
                .into_iter()
                .map(|r| LogonSummaryRowDto {
                    user_name: r.user_name,
                    src_ip: r.src_ip,
                    logon_type: r.logon_type,
                    logon_type_name: r.logon_type_name,
                    computer: r.computer,
                    success_count: r.success_count,
                    fail_count: r.fail_count,
                    first_ts: r.first_ts,
                    last_ts: r.last_ts,
                })
                .collect(),
            total: page.total,
            offset: page.offset,
        })
    })
}

#[tauri::command]
pub fn list_saved_searches_cmd(
    state: State<'_, AppState>,
) -> Result<Vec<SavedSearchDto>, ApiError> {
    with_open_case(&state, |open| {
        let conn = open.store.open_read_only()?;
        let rows = list_saved_searches(&conn)?;
        Ok(rows
            .into_iter()
            .map(|s| SavedSearchDto {
                id: s.id,
                name: s.name,
                query_json: s.query_json,
                created_at: s.created_at,
            })
            .collect())
    })
}

#[tauri::command]
pub fn save_search_cmd(
    state: State<'_, AppState>,
    name: String,
    query_json: String,
) -> Result<i64, ApiError> {
    with_open_case(&state, |open| {
        let conn = lw_store::open_write_conn(&open.store.root)?;
        Ok(save_search(&conn, &name, &query_json)?)
    })
}

#[tauri::command]
pub fn delete_saved_search_cmd(state: State<'_, AppState>, id: i64) -> Result<(), ApiError> {
    with_open_case(&state, |open| {
        let conn = lw_store::open_write_conn(&open.store.root)?;
        delete_saved_search(&conn, id)?;
        Ok(())
    })
}

fn rule_row_dto(r: lw_store::RuleRow) -> RuleRowDto {
    RuleRowDto {
        rule_uid: r.rule_uid,
        title: r.title,
        author: r.author,
        level: r.level,
        status: r.status,
        tags: r.tags,
        source_json: r.source_json,
        enabled: r.enabled,
        hit_count: r.hit_count,
        unmapped: r.unmapped,
    }
}

fn detection_from_row(d: DetectionRow) -> Detection {
    let triage = match d.triage.as_str() {
        "reviewed" => TriageState::Reviewed,
        "false_positive" => TriageState::FalsePositive,
        "escalated" => TriageState::Escalated,
        _ => TriageState::New,
    };
    Detection {
        id: d.id,
        rule_uid: d.rule_uid,
        rule_title: d.rule_title,
        rule_author: d.rule_author,
        rule_source: d.rule_source,
        severity: d.severity,
        status: d.status,
        mitre: d.mitre,
        ts: d.ts,
        computer: d.computer,
        user: d.user,
        event_ids: d.event_ids,
        kind: if d.kind.starts_with("correlation") {
            DetectionKind::Correlation {
                ctype: d.kind,
                group: Default::default(),
                count: d.event_count,
            }
        } else {
            DetectionKind::Single
        },
        summary: d.summary,
        fp_hint: d.fp_hint,
        triage,
    }
}

#[tauri::command]
pub fn list_rule_packs_cmd() -> Result<Vec<RulePackDto>, ApiError> {
    let packs = list_packs(packs_dir())?;
    Ok(packs
        .into_iter()
        .map(|p| RulePackDto {
            id: p.id,
            version: p.version,
            kind: p.kind,
            source_url: p.source_url,
            downloaded_at: p.downloaded_at,
            blake3: p.blake3,
            rule_count: p.rule_count,
            path: p.path,
        })
        .collect())
}

#[tauri::command]
pub fn import_rule_pack_cmd(path: String, pack_id: String) -> Result<RulePackDto, ApiError> {
    let mapping_path =
        find_mapping_path().ok_or_else(|| ApiError::new("no_mapping", "mapping not found"))?;
    let mapping = load_logsource_mapping(mapping_path)?;
    let version = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "0.0.0".into());
    let (m, _) = import_pack_dir(path, &pack_id, &version, &mapping, None)?;
    Ok(RulePackDto {
        id: m.id,
        version: m.version,
        kind: m.kind,
        source_url: m.source_url,
        downloaded_at: m.downloaded_at,
        blake3: m.blake3,
        rule_count: m.rule_count,
        path: m.path,
    })
}

#[tauri::command]
pub fn download_rule_pack_cmd(kind: String) -> Result<RulePackDto, ApiError> {
    let k = SigmaPackKind::parse(&kind).ok_or_else(|| {
        ApiError::new(
            "bad_kind",
            format!("unknown pack kind: {kind} (try core, emerging, all)"),
        )
    })?;
    let mapping_path =
        find_mapping_path().ok_or_else(|| ApiError::new("no_mapping", "mapping not found"))?;
    let mapping = load_logsource_mapping(mapping_path)?;
    let (m, _) = download_sigma_pack(k, &mapping, None)?;
    Ok(RulePackDto {
        id: m.id,
        version: m.version,
        kind: m.kind,
        source_url: m.source_url,
        downloaded_at: m.downloaded_at,
        blake3: m.blake3,
        rule_count: m.rule_count,
        path: m.path,
    })
}

#[tauri::command]
pub fn drl_notice_cmd() -> String {
    SIGMA_DRL_NOTICE.to_string()
}

#[tauri::command]
pub fn list_rules_cmd(
    state: State<'_, AppState>,
    q: RuleQueryDto,
) -> Result<RulePageDto, ApiError> {
    with_open_case(&state, |open| {
        let conn = open.store.open_read_only()?;
        let page = query_rules(
            &conn,
            &RuleQuery {
                offset: q.offset,
                limit: if q.limit == 0 { 200 } else { q.limit },
                text: q.text,
                enabled_only: q.enabled_only,
            },
        )?;
        Ok(RulePageDto {
            rows: page.rows.into_iter().map(rule_row_dto).collect(),
            total: page.total,
            offset: page.offset,
        })
    })
}

#[tauri::command]
pub fn get_rule_cmd(state: State<'_, AppState>, uid: String) -> Result<RuleDetailDto, ApiError> {
    with_open_case(&state, |open| {
        let conn = open.store.open_read_only()?;
        let d = get_rule(&conn, &uid)?;
        Ok(RuleDetailDto {
            rule: rule_row_dto(d.rule),
            yaml: d.yaml,
        })
    })
}

#[tauri::command]
pub fn set_rule_enabled_cmd(
    state: State<'_, AppState>,
    uid: String,
    enabled: bool,
) -> Result<(), ApiError> {
    with_open_case(&state, |open| {
        let conn = lw_store::open_write_conn(&open.store.root)?;
        set_rule_enabled(&conn, &uid, enabled)?;
        Ok(())
    })
}

#[tauri::command]
pub fn list_suppressions_cmd(state: State<'_, AppState>) -> Result<Vec<SuppressionDto>, ApiError> {
    with_open_case(&state, |open| {
        let conn = open.store.open_read_only()?;
        let rows = list_suppressions(&conn)?;
        Ok(rows
            .into_iter()
            .map(|s| SuppressionDto {
                id: s.id,
                rule_uid: s.rule_uid,
                field: s.field,
                value: s.value,
                note: s.note,
                created_at: s.created_at,
            })
            .collect())
    })
}

#[tauri::command]
pub fn add_suppression_cmd(
    state: State<'_, AppState>,
    s: SuppressionInputDto,
) -> Result<i64, ApiError> {
    with_open_case(&state, |open| {
        let conn = lw_store::open_write_conn(&open.store.root)?;
        Ok(add_suppression(
            &conn,
            &SuppressionInput {
                rule_uid: s.rule_uid,
                field: s.field,
                value: s.value,
                note: s.note,
            },
        )?)
    })
}

#[tauri::command]
pub fn delete_suppression_cmd(state: State<'_, AppState>, id: i64) -> Result<(), ApiError> {
    with_open_case(&state, |open| {
        let conn = lw_store::open_write_conn(&open.store.root)?;
        delete_suppression(&conn, id)?;
        Ok(())
    })
}

#[tauri::command]
pub async fn rerun_detection_cmd(
    state: State<'_, AppState>,
    profile: String,
    builtins: bool,
    rules_path: Option<String>,
) -> Result<HuntReportDto, ApiError> {
    let root = {
        let guard = state.case.lock().map_err(|_| ApiError::msg("lock"))?;
        let open = guard
            .as_ref()
            .ok_or_else(|| ApiError::new("no_case", "no case open"))?;
        open.store.root.clone()
    };
    let cancel = CancellationToken::new();
    *state.cancel.lock().map_err(|_| ApiError::msg("lock"))? = Some(cancel.clone());
    let opts = HuntOptions {
        case_dir: root,
        profile: RuleProfile::parse(&profile).unwrap_or(RuleProfile::Default),
        builtins,
        rules_path: rules_path.map(PathBuf::from),
        ..Default::default()
    };
    let report = tauri::async_runtime::spawn_blocking(move || hunt(&opts, &cancel))
        .await
        .map_err(|e| ApiError::msg(e.to_string()))??
        .0;
    Ok(HuntReportDto {
        run_id: report.run_id,
        detections: report.detections,
        events_scanned: report.events_scanned,
        elapsed_ms: report.elapsed_ms,
        profile: report.profile,
    })
}

#[tauri::command]
pub fn export_detections_cmd(
    state: State<'_, AppState>,
    req: ExportRequestDto,
) -> Result<ExportResultDto, ApiError> {
    with_open_case(&state, |open| {
        let conn = open.store.open_read_only()?;
        let name = open.store.info()?.name;
        let page = query_detections(
            &conn,
            &DetectionQuery {
                offset: 0,
                limit: if req.limit == 0 { 100_000 } else { req.limit },
                ..DetectionQuery::default()
            },
        )?;
        let dets: Vec<Detection> = page.rows.into_iter().map(detection_from_row).collect();
        let file = File::create(&req.path).map_err(|e| ApiError::new("io", e.to_string()))?;
        let mut w = BufWriter::new(file);
        match req.format.to_ascii_lowercase().as_str() {
            "csv" => export_detections_csv(&dets, &mut w)
                .map_err(|e| ApiError::new("io", e.to_string()))?,
            "json" => export_detections_json(&dets, &mut w)
                .map_err(|e| ApiError::new("io", e.to_string()))?,
            "jsonl" => export_detections_jsonl(&dets, &mut w)
                .map_err(|e| ApiError::new("io", e.to_string()))?,
            "html" => export_detections_html(&name, &dets, &mut w)
                .map_err(|e| ApiError::new("io", e.to_string()))?,
            other => {
                return Err(ApiError::new(
                    "bad_format",
                    format!("unsupported export format: {other}"),
                ))
            }
        }
        Ok(ExportResultDto {
            path: req.path,
            rows: dets.len() as u64,
            format: req.format,
        })
    })
}

/// Export TS bindings via ts-rs when the `ts-rs` feature is enabled.
#[cfg(feature = "ts-rs")]
#[tauri::command]
pub fn export_bindings_hint() -> String {
    "Run: cargo test -p logwarden --features ts-rs export_ts".into()
}
