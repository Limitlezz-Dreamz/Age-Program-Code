use serde_json::{Map, Value};

const USER_KEYS: &[&str] = &[
    "TargetUserName",
    "SubjectUserName",
    "User",
    "AccountName",
    "UserName",
    "Param1",
    "SamAccountName",
    "TargetUser",
];

const IP_KEYS: &[&str] = &[
    "IpAddress",
    "SourceIp",
    "SourceAddress",
    "ClientAddress",
    "Param3",
    "Address",
];

/// Best-effort principal extraction for pivots (Section 6.4).
pub fn extract_user_name(fields: &Map<String, Value>) -> Option<String> {
    for key in USER_KEYS {
        if let Some(v) = fields.get(*key) {
            let s = value_as_str(v)?;
            if s.is_empty() || s == "-" {
                continue;
            }
            // Machine accounts ending in `$` ignored for pivot purposes (configurable later).
            if s.ends_with('$') {
                continue;
            }
            if s.eq_ignore_ascii_case("SYSTEM") {
                continue;
            }
            return Some(s);
        }
    }
    None
}

pub fn extract_src_ip(fields: &Map<String, Value>) -> Option<String> {
    for key in IP_KEYS {
        if let Some(v) = fields.get(*key) {
            let s = value_as_str(v)?;
            if s.is_empty() || s == "-" || s == "::1" || s == "127.0.0.1" {
                continue;
            }
            return Some(s);
        }
    }
    None
}

pub fn extract_logon_type(fields: &Map<String, Value>) -> Option<i64> {
    let v = fields.get("LogonType")?;
    match v {
        Value::Number(n) => n.as_i64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

fn value_as_str(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}
