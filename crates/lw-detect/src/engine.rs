use lw_core::{Detection, NormalizedEvent, Result, RuleSource};
use lw_rules::{LoadReport, RuleSet};
use std::collections::BTreeMap;

/// Intermediate hit from a single-event evaluation (before DB write).
#[derive(Debug, Clone)]
pub struct RawHit {
    pub rule_uid: String,
    pub rule_title: String,
    pub rule_author: Option<String>,
    pub severity: lw_core::Severity,
    pub status: Option<String>,
    pub tags: Vec<String>,
    pub event_id: i64,
    pub ts: lw_core::TsMicros,
    pub computer: String,
    pub user: Option<String>,
    pub summary: String,
    pub hidden: bool,
    pub kind: lw_core::DetectionKind,
}

#[derive(Debug, Clone)]
pub struct TimedHit {
    pub rule_id: String,
    pub event_id: i64,
    pub ts: lw_core::TsMicros,
}

#[derive(Debug, Clone)]
pub struct CorrelationHit {
    pub rule_uid: String,
    pub rule_title: String,
    pub rule_author: Option<String>,
    pub severity: lw_core::Severity,
    pub status: Option<String>,
    pub tags: Vec<String>,
    pub ts: lw_core::TsMicros,
    pub computer: String,
    pub user: Option<String>,
    pub summary: String,
    pub ctype: String,
    pub group: BTreeMap<String, String>,
    pub count: u64,
    pub event_ids: Vec<i64>,
}

#[derive(Debug, Clone)]
pub struct Explanation {
    pub matched: bool,
    pub detail: String,
}

/// Detection engine trait (Section 8).
pub trait DetectionEngine: Send {
    fn load(&mut self, rules: &RuleSet) -> Result<LoadReport>;
    fn evaluate_batch(&self, events: &[NormalizedEvent]) -> Vec<Vec<RawHit>>;
    fn explain(&self, rule_uid: &str, event: &NormalizedEvent) -> Option<Explanation>;
}

pub fn raw_to_detection(hit: RawHit, rule_source: RuleSource) -> Detection {
    Detection {
        id: 0,
        rule_uid: hit.rule_uid,
        rule_title: hit.rule_title,
        rule_author: hit.rule_author,
        rule_source,
        severity: hit.severity,
        status: hit.status,
        mitre: crate::mitre::parse_mitre_tags(&hit.tags),
        ts: hit.ts,
        computer: hit.computer,
        user: hit.user,
        event_ids: vec![hit.event_id],
        kind: hit.kind,
        summary: hit.summary,
        fp_hint: None,
        triage: lw_core::TriageState::New,
    }
}

pub fn correlation_to_detection(hit: CorrelationHit, rule_source: RuleSource) -> Detection {
    Detection {
        id: 0,
        rule_uid: hit.rule_uid,
        rule_title: hit.rule_title,
        rule_author: hit.rule_author,
        rule_source,
        severity: hit.severity,
        status: hit.status,
        mitre: crate::mitre::parse_mitre_tags(&hit.tags),
        ts: hit.ts,
        computer: hit.computer,
        user: hit.user,
        event_ids: hit.event_ids,
        kind: lw_core::DetectionKind::Correlation {
            ctype: hit.ctype,
            group: hit.group,
            count: hit.count,
        },
        summary: hit.summary,
        fp_hint: None,
        triage: lw_core::TriageState::New,
    }
}
