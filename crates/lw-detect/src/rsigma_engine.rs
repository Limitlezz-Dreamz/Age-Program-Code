use crate::engine::{CorrelationHit, Explanation, RawHit};
use crate::event_view::event_to_json;
use crate::summary::summarize_event;
use lw_core::{DetectionKind, Error, NormalizedEvent, Result, RuleSource, Severity};
use lw_rules::{LoadReport, LogsourceMapping, RuleBody, RuleSet};
use rsigma_eval::correlation_engine::{
    CorrelationConfig, CorrelationEngine, CorrelationEventMode, TimestampFallback,
};
use rsigma_eval::event::JsonEvent;
use rsigma_eval::pipeline::{parse_pipeline_file, Pipeline};
use rsigma_eval::{EvaluationResult, LogSourceExtractor, MatchDetailLevel};
use rsigma_parser::Level;
use std::collections::{BTreeMap, HashMap};
use std::path::Path;

pub struct RsigmaEngine {
    mapping: LogsourceMapping,
    pipelines: Vec<Pipeline>,
    corr: Option<CorrelationEngine>,
    /// rule_id / title / uid -> metadata for attribution
    meta: HashMap<String, RuleMeta>,
    /// sigma ids that are correlation bases (hidden from detection list)
    hidden_ids: std::collections::HashSet<String>,
}

#[derive(Debug, Clone)]
struct RuleMeta {
    uid: String,
    title: String,
    author: Option<String>,
    severity: Severity,
    status: Option<String>,
    tags: Vec<String>,
    source: RuleSource,
    fields: Vec<String>,
}

impl RsigmaEngine {
    pub fn new(mapping: LogsourceMapping) -> Self {
        Self {
            mapping,
            pipelines: Vec::new(),
            corr: None,
            meta: HashMap::new(),
            hidden_ids: std::collections::HashSet::new(),
        }
    }

    pub fn add_pipeline_file(&mut self, path: impl AsRef<Path>) -> Result<()> {
        let p = parse_pipeline_file(path.as_ref())
            .map_err(|e| Error::msg(format!("pipeline {}: {e}", path.as_ref().display())))?;
        self.pipelines.push(p);
        Ok(())
    }

    pub fn load(&mut self, rules: &RuleSet) -> Result<LoadReport> {
        let config = CorrelationConfig {
            timestamp_fallback: TimestampFallback::Skip,
            emit_detections: true,
            correlation_event_mode: CorrelationEventMode::Refs,
            max_correlation_events: 1000,
            timestamp_fields: vec![
                "@timestamp".into(),
                "timestamp".into(),
                "TimeCreated".into(),
            ],
            ..Default::default()
        };

        let mut corr = CorrelationEngine::new(config);
        corr.set_logsource_extractor(Some(LogSourceExtractor::new().with_defaults(
            rsigma_parser::LogSource {
                product: Some("windows".into()),
                ..Default::default()
            },
        )));
        corr.set_match_detail(MatchDetailLevel::Off);
        for p in &self.pipelines {
            corr.add_pipeline(p.clone());
        }

        self.meta.clear();
        self.hidden_ids.clear();

        let mut corr_refs: std::collections::HashSet<String> = std::collections::HashSet::new();
        for r in &rules.rules {
            if let RuleBody::Correlation(c) = &r.body {
                for ref_id in &c.rules {
                    corr_refs.insert(ref_id.clone());
                }
            }
        }

        let mut report = rules.report.clone();
        let mut add_errors = 0u64;
        let mut collection = rsigma_parser::SigmaCollection::new();

        for r in &rules.rules {
            let meta = RuleMeta {
                uid: r.uid.clone(),
                title: r.title.clone(),
                author: r.author.clone(),
                severity: r.severity,
                status: r.status.clone(),
                tags: r.tags.clone(),
                source: r.source.clone(),
                fields: match &r.body {
                    RuleBody::Detection(d) => d.fields.clone(),
                    RuleBody::Correlation(c) => c.fields.clone(),
                },
            };
            if let Some(id) = &r.id {
                if corr_refs.contains(id) && !r.is_correlation() {
                    // Hide pure base rules from the detections list when informational.
                    if r.severity <= Severity::Informational {
                        self.hidden_ids.insert(id.clone());
                    }
                }
                self.meta.insert(id.clone(), meta.clone());
            }
            self.meta.insert(r.title.clone(), meta.clone());
            self.meta.insert(r.uid.clone(), meta);

            match &r.body {
                RuleBody::Detection(rule) => collection.rules.push(rule.clone()),
                RuleBody::Correlation(c) => collection.correlations.push(c.clone()),
            }
        }
        collection.filters = rules.filters.clone();

        if let Err(e) = corr.add_collection(&collection) {
            add_errors += 1;
            report.errors.push(format!("engine load: {e}"));
        }

        report.parse_errors += add_errors;
        self.corr = Some(corr);
        Ok(report)
    }

    pub fn mapping(&self) -> &LogsourceMapping {
        &self.mapping
    }

    pub fn rule_source(&self, rule_uid: &str) -> RuleSource {
        self.meta
            .get(rule_uid)
            .map(|m| m.source.clone())
            .unwrap_or(RuleSource::Builtin)
    }

    /// Parallel detection only (unordered).
    pub fn evaluate_batch(&self, events: &[NormalizedEvent]) -> Vec<Vec<RawHit>> {
        let corr = match &self.corr {
            Some(c) => c,
            None => return vec![Vec::new(); events.len()],
        };
        let mapping = &self.mapping;
        let meta = &self.meta;
        let hidden = &self.hidden_ids;

        use rayon::prelude::*;
        events
            .par_iter()
            .map(|ev| {
                let json = event_to_json(ev, mapping);
                let je = JsonEvent::borrow(&json);
                let results = corr.evaluate(&je);
                results
                    .into_iter()
                    .filter_map(|r| detection_to_raw(r, ev, meta, hidden))
                    .collect()
            })
            .collect()
    }

    /// Parallel detect + sequential correlate using event `@timestamp` (not wall-clock).
    pub fn process_batch(&mut self, events: &[NormalizedEvent]) -> Vec<lw_core::Detection> {
        let mapping = self.mapping.clone();
        let jsons: Vec<_> = events
            .iter()
            .map(|ev| event_to_json(ev, &mapping))
            .collect();
        let Some(corr) = self.corr.as_mut() else {
            return Vec::new();
        };
        let views: Vec<JsonEvent<'_>> = jsons.iter().map(JsonEvent::borrow).collect();
        let refs: Vec<&JsonEvent<'_>> = views.iter().collect();
        let batch = corr.process_batch(&refs);

        let meta = &self.meta;
        let hidden = &self.hidden_ids;
        let mut out = Vec::new();
        for (ev, results) in events.iter().zip(batch) {
            for r in results {
                if r.is_correlation() {
                    if let Some(hit) = correlation_to_hit(r, ev, meta) {
                        let src = meta_source(meta, &hit.rule_uid, &hit.rule_title);
                        out.push(crate::engine::correlation_to_detection(hit, src));
                    }
                } else if let Some(raw) = detection_to_raw(r, ev, meta, hidden) {
                    if raw.hidden {
                        continue;
                    }
                    let src = meta
                        .get(&raw.rule_uid)
                        .map(|m| m.source.clone())
                        .unwrap_or(RuleSource::Builtin);
                    out.push(crate::engine::raw_to_detection(raw, src));
                }
            }
        }
        out
    }

    pub fn explain(&self, rule_uid: &str, event: &NormalizedEvent) -> Option<Explanation> {
        let corr = self.corr.as_ref()?;
        let compiled = corr.engine().rules().iter().find(|r| {
            r.id.as_deref()
                .map(|id| rule_uid == id || rule_uid.ends_with(&format!(":{id}")))
                .unwrap_or(false)
                || rule_uid.ends_with(&r.title)
        })?;
        let json = event_to_json(event, &self.mapping);
        let je = JsonEvent::borrow(&json);
        let exp = rsigma_eval::explain_rule(compiled, &je);
        Some(Explanation {
            matched: exp.matched,
            detail: format!("matched={}", exp.matched),
        })
    }
}

fn meta_source(meta: &HashMap<String, RuleMeta>, uid: &str, title: &str) -> RuleSource {
    meta.get(uid)
        .or_else(|| meta.get(title))
        .map(|m| m.source.clone())
        .unwrap_or(RuleSource::Builtin)
}

fn level_to_severity(level: Option<&Level>) -> Severity {
    match level {
        Some(Level::Informational) => Severity::Informational,
        Some(Level::Low) => Severity::Low,
        Some(Level::Medium) => Severity::Medium,
        Some(Level::High) => Severity::High,
        Some(Level::Critical) => Severity::Critical,
        None => Severity::Medium,
    }
}

fn lookup_meta<'a>(
    meta: &'a HashMap<String, RuleMeta>,
    r: &EvaluationResult,
) -> Option<&'a RuleMeta> {
    if let Some(id) = &r.header.rule_id {
        if let Some(m) = meta.get(id) {
            return Some(m);
        }
        for m in meta.values() {
            if m.uid.ends_with(&format!(":{id}")) {
                return Some(m);
            }
        }
    }
    meta.get(&r.header.rule_title)
}

fn detection_to_raw(
    r: EvaluationResult,
    ev: &NormalizedEvent,
    meta: &HashMap<String, RuleMeta>,
    hidden: &std::collections::HashSet<String>,
) -> Option<RawHit> {
    if !r.is_detection() {
        return None;
    }
    let m = lookup_meta(meta, &r);
    let rule_id = r.header.rule_id.clone().unwrap_or_default();
    let hidden_flag = hidden.contains(&rule_id);
    let uid = m
        .map(|x| x.uid.clone())
        .unwrap_or_else(|| format!("unknown:{rule_id}"));
    let title = m
        .map(|x| x.title.clone())
        .unwrap_or_else(|| r.header.rule_title.clone());
    let author = m.and_then(|x| x.author.clone());
    let severity = m
        .map(|x| x.severity)
        .unwrap_or_else(|| level_to_severity(r.header.level.as_ref()));
    let status = m.and_then(|x| x.status.clone());
    let tags = m
        .map(|x| x.tags.clone())
        .unwrap_or_else(|| r.header.tags.clone());
    let fields = m.map(|x| x.fields.as_slice()).unwrap_or(&[]);
    let summary = summarize_event(&title, ev, fields);
    Some(RawHit {
        rule_uid: uid,
        rule_title: title,
        rule_author: author,
        severity,
        status,
        tags,
        event_id: ev.id,
        ts: ev.ts,
        computer: ev.computer.clone(),
        user: ev.user_name.clone(),
        summary,
        hidden: hidden_flag,
        kind: DetectionKind::Single,
    })
}

fn correlation_to_hit(
    r: EvaluationResult,
    ev: &NormalizedEvent,
    meta: &HashMap<String, RuleMeta>,
) -> Option<CorrelationHit> {
    let body = r.as_correlation()?;
    let m = lookup_meta(meta, &r);
    let rule_id = r.header.rule_id.clone().unwrap_or_default();
    let uid = m
        .map(|x| x.uid.clone())
        .unwrap_or_else(|| format!("unknown:{rule_id}"));
    let title = m
        .map(|x| x.title.clone())
        .unwrap_or_else(|| r.header.rule_title.clone());
    let mut group = BTreeMap::new();
    for (k, v) in &body.group_key {
        group.insert(k.clone(), v.clone());
    }
    let mut event_ids: Vec<i64> = Vec::new();
    if let Some(refs) = &body.event_refs {
        for er in refs {
            if let Some(id) = &er.id {
                if let Ok(n) = id.parse::<i64>() {
                    event_ids.push(n);
                }
            }
        }
    }
    if event_ids.is_empty() {
        event_ids.push(ev.id);
    }
    event_ids.sort_unstable();
    event_ids.dedup();
    if event_ids.len() > 1000 {
        event_ids.truncate(1000);
    }
    let count = body.aggregated_value.max(0.0) as u64;
    let user = group
        .get("TargetUserName")
        .cloned()
        .or_else(|| ev.user_name.clone());
    let summary = format!(
        "{} {} count={count} group={group:?} ({})",
        body.correlation_type.as_str(),
        title,
        ev.computer
    );
    Some(CorrelationHit {
        rule_uid: uid,
        rule_title: title,
        rule_author: m.and_then(|x| x.author.clone()),
        severity: m
            .map(|x| x.severity)
            .unwrap_or_else(|| level_to_severity(r.header.level.as_ref())),
        status: m.and_then(|x| x.status.clone()),
        tags: m
            .map(|x| x.tags.clone())
            .unwrap_or_else(|| r.header.tags.clone()),
        ts: ev.ts,
        computer: ev.computer.clone(),
        user,
        summary,
        ctype: body.correlation_type.as_str().to_string(),
        group,
        count,
        event_ids,
    })
}
