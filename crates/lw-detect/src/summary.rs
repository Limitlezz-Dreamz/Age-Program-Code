use lw_core::NormalizedEvent;
use serde_json::Value;

const SYSTEM_KEYS: &[&str] = &[
    "Channel",
    "EventID",
    "Provider_Name",
    "Computer",
    "EventRecordID",
    "id",
    "product",
    "service",
    "category",
    "SystemTime",
    "TimeCreated",
    "@timestamp",
];

/// One-line detection summary from event fields.
pub fn summarize_event(
    rule_title: &str,
    event: &NormalizedEvent,
    field_hints: &[String],
) -> String {
    let mut parts = Vec::new();
    parts.push(format!("{} {}", event.event_id, rule_title));

    let mut used = 0usize;
    if !field_hints.is_empty() {
        for name in field_hints {
            if let Some(v) = event.fields.get(name) {
                if let Some(s) = value_preview(v) {
                    parts.push(format!("{name}={s}"));
                    used += 1;
                    if used >= 4 {
                        break;
                    }
                }
            }
        }
    }
    if used == 0 {
        for (k, v) in &event.fields {
            if SYSTEM_KEYS.iter().any(|s| s.eq_ignore_ascii_case(k)) {
                continue;
            }
            if let Some(s) = value_preview(v) {
                parts.push(format!("{k}={s}"));
                used += 1;
                if used >= 4 {
                    break;
                }
            }
        }
    }
    parts.push(format!("({})", event.computer));
    parts.join(" ")
}

fn value_preview(v: &Value) -> Option<String> {
    match v {
        Value::Null => None,
        Value::String(s) => {
            let t = s.trim();
            if t.is_empty() {
                None
            } else if t.len() > 80 {
                Some(format!("{}…", &t[..80]))
            } else {
                Some(t.to_string())
            }
        }
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Array(a) => {
            if a.is_empty() {
                None
            } else {
                value_preview(&a[0])
            }
        }
        Value::Object(_) => None,
    }
}
