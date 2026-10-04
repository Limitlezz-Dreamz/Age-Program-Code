#![deny(unsafe_code)]

//! CSV / JSON / JSONL / HTML export for detections (and optional events).

use lw_core::{format_rfc3339_micros, Detection, APP_NAME};
use lw_rules::SIGMA_DRL_NOTICE;
use serde::Serialize;
use std::io::Write;

pub fn crate_name() -> &'static str {
    env!("CARGO_PKG_NAME")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Csv,
    Json,
    Jsonl,
    Html,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExportDetection {
    pub timestamp_utc: String,
    pub severity: String,
    pub rule_title: String,
    pub rule_author: Option<String>,
    pub rule_id: String,
    pub rule_source: String,
    pub mitre_tactics: String,
    pub mitre_techniques: String,
    pub computer: String,
    pub user: Option<String>,
    pub summary: String,
    pub event_count: u64,
    pub event_record_ids: String,
    pub triage: String,
}

impl From<&Detection> for ExportDetection {
    fn from(d: &Detection) -> Self {
        let rule_source = match &d.rule_source {
            lw_core::RuleSource::Builtin => "builtin".into(),
            lw_core::RuleSource::Sigma { pack, version, .. } => {
                format!("sigma:{pack}@{version}")
            }
        };
        let tactics = d
            .mitre
            .iter()
            .filter_map(|m| m.tactic.clone())
            .collect::<Vec<_>>()
            .join("|");
        let techniques = d
            .mitre
            .iter()
            .filter_map(|m| m.technique.clone())
            .collect::<Vec<_>>()
            .join("|");
        Self {
            timestamp_utc: format_rfc3339_micros(d.ts).unwrap_or_else(|_| d.ts.to_string()),
            severity: d.severity.as_str().into(),
            rule_title: d.rule_title.clone(),
            rule_author: d.rule_author.clone(),
            rule_id: d.rule_uid.clone(),
            rule_source,
            mitre_tactics: tactics,
            mitre_techniques: techniques,
            computer: d.computer.clone(),
            user: d.user.clone(),
            summary: d.summary.clone(),
            event_count: d.event_ids.len() as u64,
            event_record_ids: d
                .event_ids
                .iter()
                .map(|id| id.to_string())
                .collect::<Vec<_>>()
                .join("|"),
            triage: d.triage.as_str().into(),
        }
    }
}

pub fn export_detections_csv(dets: &[Detection], mut w: impl Write) -> std::io::Result<()> {
    // UTF-8 BOM for Excel.
    w.write_all(&[0xEF, 0xBB, 0xBF])?;
    writeln!(
        w,
        "timestamp_utc,severity,rule_title,rule_author,rule_id,rule_source,mitre_tactics,mitre_techniques,computer,user,summary,event_count,event_record_ids,triage"
    )?;
    for d in dets {
        let row = ExportDetection::from(d);
        writeln!(
            w,
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            csv_escape(&row.timestamp_utc),
            csv_escape(&row.severity),
            csv_escape(&row.rule_title),
            csv_escape(row.rule_author.as_deref().unwrap_or("")),
            csv_escape(&row.rule_id),
            csv_escape(&row.rule_source),
            csv_escape(&row.mitre_tactics),
            csv_escape(&row.mitre_techniques),
            csv_escape(&row.computer),
            csv_escape(row.user.as_deref().unwrap_or("")),
            csv_escape(&row.summary),
            row.event_count,
            csv_escape(&row.event_record_ids),
            csv_escape(&row.triage),
        )?;
    }
    Ok(())
}

pub fn export_detections_json(dets: &[Detection], mut w: impl Write) -> std::io::Result<()> {
    let rows: Vec<ExportDetection> = dets.iter().map(ExportDetection::from).collect();
    let s = serde_json::to_string_pretty(&rows).map_err(std::io::Error::other)?;
    w.write_all(s.as_bytes())?;
    Ok(())
}

pub fn export_detections_jsonl(dets: &[Detection], mut w: impl Write) -> std::io::Result<()> {
    for d in dets {
        let row = ExportDetection::from(d);
        let s = serde_json::to_string(&row).map_err(std::io::Error::other)?;
        writeln!(w, "{s}")?;
    }
    Ok(())
}

pub fn export_detections_html(
    case_name: &str,
    dets: &[Detection],
    mut w: impl Write,
) -> std::io::Result<()> {
    let mut crit = 0u64;
    let mut high = 0u64;
    let mut medium = 0u64;
    let mut low = 0u64;
    let mut info = 0u64;
    for d in dets {
        match d.severity {
            lw_core::Severity::Critical => crit += 1,
            lw_core::Severity::High => high += 1,
            lw_core::Severity::Medium => medium += 1,
            lw_core::Severity::Low => low += 1,
            lw_core::Severity::Informational => info += 1,
        }
    }

    writeln!(w, "<!DOCTYPE html>")?;
    writeln!(w, "<html lang=\"en\"><head><meta charset=\"utf-8\">")?;
    writeln!(
        w,
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:;\">"
    )?;
    writeln!(
        w,
        "<title>{APP_NAME} report — {}</title>",
        html_escape(case_name)
    )?;
    writeln!(
        w,
        "<style>
body{{font-family:system-ui,sans-serif;margin:1.5rem;color:#111;background:#fafafa}}
h1,h2{{margin:0 0 .5rem}}
.meta{{color:#555;margin-bottom:1.5rem}}
table{{border-collapse:collapse;width:100%;font-size:13px;background:#fff}}
th,td{{border:1px solid #ddd;padding:.35rem .5rem;text-align:left;vertical-align:top}}
th{{background:#eee}}
.sev-critical{{color:#991b1b;font-weight:600}}
.sev-high{{color:#c2410c;font-weight:600}}
.sev-medium{{color:#a16207}}
.notice{{margin-top:2rem;padding:1rem;border:1px solid #ccc;background:#fff;font-size:12px;white-space:pre-wrap}}
</style></head><body>"
    )?;
    writeln!(w, "<h1>{APP_NAME} detection report</h1>")?;
    writeln!(
        w,
        "<p class=\"meta\">Case: {} · {} detections · Critical {crit} · High {high} · Medium {medium} · Low {low} · Info {info}</p>",
        html_escape(case_name),
        dets.len()
    )?;
    writeln!(w, "<h2>Detections</h2>")?;
    writeln!(
        w,
        "<table><thead><tr><th>Time (UTC)</th><th>Severity</th><th>Rule</th><th>Author</th><th>Source</th><th>Host</th><th>User</th><th>Summary</th></tr></thead><tbody>"
    )?;
    for d in dets {
        let row = ExportDetection::from(d);
        writeln!(
            w,
            "<tr><td>{}</td><td class=\"sev-{}\">{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            html_escape(&row.timestamp_utc),
            html_escape(&row.severity),
            html_escape(&row.severity),
            html_escape(&row.rule_title),
            html_escape(row.rule_author.as_deref().unwrap_or("")),
            html_escape(&row.rule_source),
            html_escape(&row.computer),
            html_escape(row.user.as_deref().unwrap_or("")),
            html_escape(&row.summary),
        )?;
    }
    writeln!(w, "</tbody></table>")?;
    writeln!(
        w,
        "<div class=\"notice\"><strong>MITRE ATT&amp;CK®</strong> — This product uses the MITRE ATT&amp;CK® knowledge base. ATT&amp;CK is a registered trademark of The MITRE Corporation.</div>"
    )?;
    writeln!(
        w,
        "<div class=\"notice\"><strong>Detection Rule License (DRL 1.1)</strong>\n{}</div>",
        html_escape(SIGMA_DRL_NOTICE.trim())
    )?;
    writeln!(w, "</body></html>")?;
    Ok(())
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use lw_core::{DetectionKind, RuleSource, Severity, TriageState};

    fn sample() -> Detection {
        Detection {
            id: 1,
            rule_uid: "B001".into(),
            rule_title: "Test".into(),
            rule_author: Some("alice".into()),
            rule_source: RuleSource::Sigma {
                pack: "sigmahq".into(),
                version: "1.0".into(),
                path: "/tmp".into(),
                url: None,
            },
            severity: Severity::High,
            status: None,
            mitre: vec![],
            ts: 1_700_000_000_000_000,
            computer: "HOST".into(),
            user: Some("bob".into()),
            event_ids: vec![1, 2],
            kind: DetectionKind::Single,
            summary: "cmd <script>".into(),
            fp_hint: None,
            triage: TriageState::New,
        }
    }

    #[test]
    fn csv_includes_author_and_source() {
        let mut buf = Vec::new();
        export_detections_csv(&[sample()], &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("alice"));
        assert!(s.contains("sigma:sigmahq@1.0"));
        assert!(s.contains("rule_author"));
    }

    #[test]
    fn json_includes_author_and_source() {
        let mut buf = Vec::new();
        export_detections_json(&[sample()], &mut buf).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(v[0]["rule_author"], "alice");
        assert!(v[0]["rule_source"].as_str().unwrap().contains("sigma"));
    }

    #[test]
    fn html_is_offline_safe_and_escaped() {
        let mut buf = Vec::new();
        export_detections_html("case1", &[sample()], &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("Content-Security-Policy"));
        assert!(s.contains("MITRE"));
        assert!(s.contains("Detection Rule License"));
        assert!(s.contains("&lt;script&gt;"));
        // Reference URLs may appear in DRL/MITRE notices; no loaded network resources.
        assert!(!s.contains("<script"));
        assert!(!s.contains("<link"));
        assert!(!s.contains("<img"));
        assert!(!s.contains("src=\"http"));
        assert!(!s.contains("href=\"http"));
    }
}
