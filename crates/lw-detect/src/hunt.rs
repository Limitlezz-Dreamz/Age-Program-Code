use crate::analyzers::run_analyzers;
use crate::dedup::dedup_detections;
use crate::rsigma_engine::RsigmaEngine;
use lw_core::{CancellationToken, Detection, Result, RuleSource};
use lw_rules::{
    filter_rules, find_builtins_dir, find_mapping_path, load_builtins, load_logsource_mapping,
    load_rules_from_dir, load_rules_from_zip, LoadReport, RuleProfile, RuleSet,
};
use lw_store::{
    apply_suppressions_to_detections, begin_run, clear_run_detections, disabled_rule_uids,
    finish_run, insert_detections, iter_events_ordered, list_suppressions, open_write_conn,
    upsert_rules,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct HuntOptions {
    pub case_dir: PathBuf,
    pub profile: RuleProfile,
    pub builtins: bool,
    /// Optional pack directory or zip path.
    pub rules_path: Option<PathBuf>,
    pub pack_id: String,
    pub pack_version: String,
    pub batch_size: usize,
}

impl Default for HuntOptions {
    fn default() -> Self {
        Self {
            case_dir: PathBuf::new(),
            profile: RuleProfile::Default,
            builtins: true,
            rules_path: None,
            pack_id: "extra".into(),
            pack_version: "0.0.0".into(),
            batch_size: 2048,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntReport {
    pub run_id: i64,
    pub load: LoadReportDto,
    pub detections: u64,
    pub events_scanned: u64,
    pub elapsed_ms: u64,
    pub profile: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadReportDto {
    pub total_files: u64,
    pub total_rules: u64,
    pub loaded: u64,
    pub skipped_profile: u64,
    pub unmapped: u64,
    pub parse_errors: u64,
}

impl From<&LoadReport> for LoadReportDto {
    fn from(r: &LoadReport) -> Self {
        Self {
            total_files: r.total_files,
            total_rules: r.total_rules,
            loaded: r.loaded,
            skipped_profile: r.skipped_profile,
            unmapped: r.unmapped,
            parse_errors: r.parse_errors,
        }
    }
}

pub fn hunt(
    opts: &HuntOptions,
    cancel: &CancellationToken,
) -> Result<(HuntReport, Vec<Detection>)> {
    let t0 = Instant::now();
    let mapping_path = find_mapping_path()
        .ok_or_else(|| lw_core::Error::msg("logsource-windows.yml not found"))?;
    let mapping = load_logsource_mapping(&mapping_path)?;

    let mut set = RuleSet::default();
    if opts.builtins {
        let dir = find_builtins_dir()
            .ok_or_else(|| lw_core::Error::msg("builtin-rules directory not found"))?;
        set.merge(load_builtins(dir, &mapping)?);
    }
    if let Some(path) = &opts.rules_path {
        let extra = load_extra_rules(path, &opts.pack_id, &opts.pack_version, &mapping)?;
        set.merge(extra);
    }

    let mut load_report = set.report.clone();
    let (filtered, skipped) = filter_rules(std::mem::take(&mut set.rules), opts.profile);
    load_report.skipped_profile = skipped;
    set.rules = filtered;

    let conn = open_write_conn(&opts.case_dir)?;

    // Persist rule catalog (preserves prior enabled flags) then drop disabled rules.
    {
        let rows: Vec<_> = set
            .rules
            .iter()
            .map(|r| {
                (
                    r.uid.clone(),
                    r.title.clone(),
                    r.author.clone(),
                    r.severity.as_str().to_string(),
                    r.status.clone(),
                    r.tags.clone(),
                    serde_json::to_string(&r.source).unwrap_or_else(|_| "{}".into()),
                    r.yaml.clone(),
                    r.unmapped,
                )
            })
            .collect();
        let _ = upsert_rules(&conn, &rows);
    }
    let disabled = disabled_rule_uids(&conn).unwrap_or_default();
    if !disabled.is_empty() {
        let before = set.rules.len();
        set.rules.retain(|r| !disabled.contains(&r.uid));
        load_report.skipped_profile += (before - set.rules.len()) as u64;
    }
    load_report.loaded = set.rules.len() as u64;

    let mut engine = RsigmaEngine::new(mapping);
    let eng_report = engine.load(&set)?;
    load_report.errors.extend(eng_report.errors);
    load_report.parse_errors += eng_report.parse_errors;

    let profile_json = serde_json::json!({
        "profile": format!("{:?}", opts.profile).to_ascii_lowercase(),
        "builtins": opts.builtins,
        "rules": opts.rules_path.as_ref().map(|p| p.display().to_string()),
    })
    .to_string();
    let pack_name = if opts.builtins && opts.rules_path.is_none() {
        "builtin".to_string()
    } else if let Some(p) = &opts.rules_path {
        p.display().to_string()
    } else {
        "none".into()
    };
    let run_id = begin_run(&conn, &pack_name, None, &profile_json)?;
    clear_run_detections(&conn, run_id)?;

    let mut all = Vec::new();
    let mut events_scanned = 0u64;
    let mut offset = 0u64;
    loop {
        cancel.check()?;
        let batch = iter_events_ordered(&conn, offset, opts.batch_size as u64)?;
        if batch.is_empty() {
            break;
        }
        events_scanned += batch.len() as u64;
        offset += batch.len() as u64;
        let hits = engine.process_batch(&batch);
        all.extend(hits);
    }

    // Analyzers at finalize
    cancel.check()?;
    all.extend(run_analyzers(&conn)?);
    all = dedup_detections(all);
    let suppressions = list_suppressions(&conn).unwrap_or_default();
    all = apply_suppressions_to_detections(all, &suppressions);
    insert_detections(&conn, run_id, &all)?;
    finish_run(&conn, run_id, "ok")?;

    let elapsed_ms = t0.elapsed().as_millis() as u64;
    let report = HuntReport {
        run_id,
        load: LoadReportDto::from(&load_report),
        detections: all.len() as u64,
        events_scanned,
        elapsed_ms,
        profile: format!("{:?}", opts.profile).to_ascii_lowercase(),
    };
    tracing::info!(
        run_id,
        detections = report.detections,
        events = events_scanned,
        elapsed_ms,
        "hunt finished (no re-parse)"
    );
    Ok((report, all))
}

fn load_extra_rules(
    path: &Path,
    pack_id: &str,
    version: &str,
    mapping: &lw_rules::LogsourceMapping,
) -> Result<RuleSet> {
    if path.is_dir() {
        let source = RuleSource::Sigma {
            pack: pack_id.to_string(),
            version: version.to_string(),
            path: path.display().to_string(),
            url: None,
        };
        load_rules_from_dir(path, pack_id, version, source, mapping)
    } else if path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("zip"))
    {
        load_rules_from_zip(path, pack_id, version, None, mapping)
    } else {
        Err(lw_core::Error::msg(format!(
            "rules path must be a directory or zip: {}",
            path.display()
        )))
    }
}
