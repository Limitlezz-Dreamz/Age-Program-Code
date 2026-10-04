use lw_core::Detection;
use std::collections::HashSet;

/// Drop duplicate (rule_uid, event_id) pairs. Correlations keep first by rule+group+ts.
pub fn dedup_detections(mut dets: Vec<Detection>) -> Vec<Detection> {
    dets.sort_by(|a, b| (a.ts, &a.rule_uid, a.id).cmp(&(b.ts, &b.rule_uid, b.id)));
    let mut seen_single: HashSet<(String, i64)> = HashSet::new();
    let mut seen_corr: HashSet<(String, String, i64)> = HashSet::new();
    let mut out = Vec::with_capacity(dets.len());
    for d in dets {
        match &d.kind {
            lw_core::DetectionKind::Single => {
                let eid = d.event_ids.first().copied().unwrap_or(0);
                if seen_single.insert((d.rule_uid.clone(), eid)) {
                    out.push(d);
                }
            }
            lw_core::DetectionKind::Correlation { group, .. } => {
                let g = serde_json::to_string(group).unwrap_or_default();
                if seen_corr.insert((d.rule_uid.clone(), g, d.ts)) {
                    out.push(d);
                }
            }
        }
    }
    out
}
