use crate::aliases::{apply_aliases, FieldAliasRule};
use crate::extract::{extract_logon_type, extract_src_ip, extract_user_name};
use lw_core::{
    format_rfc3339_micros, parse_rfc3339_to_micros, NormalizedEvent, SourceType, TsMicros,
};
use serde_json::{Map, Value};

/// Normalize one `evtx` JSON record (handles both attribute shapes).
pub fn normalize_record(
    value: &Value,
    file_id: i64,
    raw_json: Option<Vec<u8>>,
    aliases: &[FieldAliasRule],
) -> NormalizedEvent {
    let event = value.get("Event").cloned().unwrap_or_else(|| value.clone());
    let system = event.get("System").cloned().unwrap_or(Value::Null);

    let mut fields = Map::new();

    let (event_id, qualifiers) = parse_event_id(&system);
    fields.insert("EventID".into(), Value::from(event_id));
    if let Some(q) = qualifiers {
        fields.insert("EventID_Qualifiers".into(), Value::from(q));
    }

    let (ts, ts_raw, ts_invalid) = parse_timestamp(&system);
    if let Some(raw) = ts_raw {
        fields.insert("TimeCreated".into(), Value::String(raw));
    }
    if ts_invalid {
        fields.insert("_ts_invalid".into(), Value::Bool(true));
    }

    let channel = text_field(&system, "Channel").unwrap_or_default();
    let provider = provider_name(&system).unwrap_or_default();
    let computer = text_field(&system, "Computer").unwrap_or_default();
    let record_id = parse_u64_field(&system, "EventRecordID").unwrap_or(0);
    let level = parse_u8_field(&system, "Level");
    let user_sid = security_user_id(&system);

    fields.insert("Channel".into(), Value::String(channel.clone()));
    fields.insert("Provider_Name".into(), Value::String(provider.clone()));
    fields.insert("Computer".into(), Value::String(computer.clone()));
    fields.insert("EventRecordID".into(), Value::from(record_id));
    if let Some(l) = level {
        fields.insert("Level".into(), Value::from(l));
    }
    if let Some(sid) = &user_sid {
        fields.insert("SecurityUserID".into(), Value::String(sid.clone()));
    }
    for key in ["Task", "Opcode", "Keywords"] {
        if let Some(v) = system.get(key) {
            fields.insert(key.to_string(), coerce_scalar(v));
        }
    }

    // EventData flattening
    if let Some(ed) = event.get("EventData") {
        flatten_event_data(ed, &mut fields);
    }

    // UserData flattening
    if let Some(ud) = event.get("UserData") {
        flatten_user_data(ud, &mut fields);
    }

    apply_aliases(&mut fields, aliases);

    // ProcessId hex→decimal alias helper for 4688 when present as hex string.
    if let Some(Value::String(pid)) = fields.get("NewProcessId").cloned() {
        if let Some(dec) = parse_hex_or_dec(&pid) {
            fields
                .entry("ProcessId".to_string())
                .or_insert(Value::String(dec));
        }
    }

    let user_name = extract_user_name(&fields);
    let src_ip = extract_src_ip(&fields);
    let logon_type = extract_logon_type(&fields);

    NormalizedEvent {
        id: 0,
        file_id,
        source_type: SourceType::Evtx,
        record_id,
        ts,
        event_id,
        channel,
        provider,
        computer,
        level,
        user_sid,
        user_name,
        src_ip,
        logon_type,
        fields,
        raw_json,
    }
}

fn parse_event_id(system: &Value) -> (u32, Option<u32>) {
    let qualifiers = system
        .get("EventID_attributes")
        .and_then(|a| a.get("Qualifiers"))
        .and_then(as_u32)
        .or_else(|| {
            system
                .pointer("/EventID/#attributes/Qualifiers")
                .and_then(as_u32)
        });

    let id = match system.get("EventID") {
        Some(Value::Number(n)) => n.as_u64().unwrap_or(0) as u32,
        Some(Value::String(s)) => s.parse().unwrap_or(0),
        Some(Value::Object(obj)) => obj.get("#text").and_then(as_u32).unwrap_or(0),
        Some(other) => as_u32(other).unwrap_or(0),
        None => 0,
    };
    (id, qualifiers)
}

fn parse_timestamp(system: &Value) -> (TsMicros, Option<String>, bool) {
    let raw = system
        .pointer("/TimeCreated_attributes/SystemTime")
        .or_else(|| system.pointer("/TimeCreated/#attributes/SystemTime"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    match &raw {
        Some(s) => match parse_rfc3339_to_micros(s) {
            Ok(ts) => {
                // Normalize stored TimeCreated to our formatted form when possible.
                let display = format_rfc3339_micros(ts).unwrap_or_else(|_| s.clone());
                (ts, Some(display), false)
            }
            Err(_) => (0, raw, true),
        },
        None => (0, None, true),
    }
}

fn provider_name(system: &Value) -> Option<String> {
    system
        .pointer("/Provider_attributes/Name")
        .or_else(|| system.pointer("/Provider/#attributes/Name"))
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

fn security_user_id(system: &Value) -> Option<String> {
    system
        .pointer("/Security_attributes/UserID")
        .or_else(|| system.pointer("/Security/#attributes/UserID"))
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

fn text_field(obj: &Value, key: &str) -> Option<String> {
    obj.get(key).and_then(|v| match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Object(m) => m.get("#text").and_then(|t| match t {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            _ => None,
        }),
        _ => None,
    })
}

fn parse_u64_field(obj: &Value, key: &str) -> Option<u64> {
    obj.get(key).and_then(as_u64)
}

fn parse_u8_field(obj: &Value, key: &str) -> Option<u8> {
    obj.get(key).and_then(as_u32).map(|n| n as u8)
}

fn as_u32(v: &Value) -> Option<u32> {
    match v {
        Value::Number(n) => n.as_u64().map(|x| x as u32),
        Value::String(s) => s.parse().ok(),
        Value::Object(m) => m.get("#text").and_then(as_u32),
        _ => None,
    }
}

fn as_u64(v: &Value) -> Option<u64> {
    match v {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.parse().ok(),
        Value::Object(m) => m.get("#text").and_then(as_u64),
        _ => None,
    }
}

fn coerce_scalar(v: &Value) -> Value {
    match v {
        Value::Object(m) => m
            .get("#text")
            .cloned()
            .unwrap_or_else(|| Value::Object(m.clone())),
        other => other.clone(),
    }
}

fn flatten_event_data(ed: &Value, fields: &mut Map<String, Value>) {
    match ed {
        Value::Object(map) => {
            // Named Data children, or Data as array under key "Data"
            if let Some(Value::Array(arr)) = map.get("Data") {
                flatten_unnamed_data(arr, fields);
            }
            for (k, v) in map {
                if k == "Data" {
                    continue;
                }
                if k.ends_with("_attributes") {
                    continue;
                }
                insert_field(fields, k, coerce_data_value(v));
            }
        }
        Value::Array(arr) => flatten_unnamed_data(arr, fields),
        _ => {}
    }
}

fn flatten_unnamed_data(arr: &[Value], fields: &mut Map<String, Value>) {
    let mut parts = Vec::new();
    for (i, item) in arr.iter().enumerate() {
        let val = coerce_data_value(item);
        let key = format!("Data[{i}]");
        // Also use Name attribute if present
        if let Value::Object(m) = item {
            if let Some(name) = m
                .get("#attributes")
                .and_then(|a| a.get("Name"))
                .or_else(|| m.get("Data_attributes").and_then(|a| a.get("Name")))
                .and_then(|v| v.as_str())
            {
                insert_field(fields, name, val.clone());
            }
        }
        insert_field(fields, &key, val.clone());
        parts.push(value_to_string(&val));
    }
    if !parts.is_empty() {
        fields.insert("Data".into(), Value::String(parts.join(" ")));
    }
}

fn coerce_data_value(v: &Value) -> Value {
    match v {
        Value::Object(m) => {
            if let Some(t) = m.get("#text") {
                return t.clone();
            }
            // separate_json_attributes may leave a bare string-like object
            Value::Object(m.clone())
        }
        other => other.clone(),
    }
}

fn flatten_user_data(ud: &Value, fields: &mut Map<String, Value>) {
    let Value::Object(map) = ud else {
        return;
    };
    for (wrapper, inner) in map {
        if wrapper.ends_with("_attributes") {
            continue;
        }
        match inner {
            Value::Object(inner_map) => {
                for (k, v) in inner_map {
                    if k.ends_with("_attributes") || k == "#attributes" {
                        continue;
                    }
                    let val = coerce_scalar(v);
                    // short name
                    insert_field(fields, k, val.clone());
                    // fully qualified
                    let fq = format!("{wrapper}.{k}");
                    fields.insert(fq, val);
                }
            }
            other => {
                insert_field(fields, wrapper, other.clone());
            }
        }
    }
}

fn insert_field(fields: &mut Map<String, Value>, key: &str, value: Value) {
    if fields.contains_key(key) {
        // On collision, EventData wins for short names; keep loser under qualified path if new.
        // Spec: EventData wins; store loser under fully qualified path.
        // Here short key already present — keep existing, stash new under conflict path.
        let conflict = format!("_conflict.{key}");
        fields.entry(conflict).or_insert(value);
    } else {
        fields.insert(key.to_string(), value);
    }
}

fn value_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn parse_hex_or_dec(s: &str) -> Option<String> {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        let n = u64::from_str_radix(hex, 16).ok()?;
        return Some(n.to_string());
    }
    if t.chars().all(|c| c.is_ascii_hexdigit()) && t.chars().any(|c| c.is_ascii_alphabetic()) {
        let n = u64::from_str_radix(t, 16).ok()?;
        return Some(n.to_string());
    }
    t.parse::<u64>().ok().map(|n| n.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aliases::default_4688_aliases;
    use serde_json::json;

    #[test]
    fn event_id_with_qualifiers_object() {
        let v = json!({
            "Event": {
                "System": {
                    "EventID": {"#attributes": {"Qualifiers": 16384}, "#text": 7045},
                    "Channel": "System",
                    "Computer": "WIN-X",
                    "EventRecordID": 123,
                    "Provider": {"#attributes": {"Name": "Service Control Manager"}},
                    "TimeCreated": {"#attributes": {"SystemTime": "2019-03-19T23:34:25.000000Z"}}
                },
                "EventData": {"ServiceName": "PSEXESVC"}
            }
        });
        let ev = normalize_record(&v, 1, None, &[]);
        assert_eq!(ev.event_id, 7045);
        assert_eq!(ev.fields.get("EventID_Qualifiers"), Some(&json!(16384)));
        assert_eq!(ev.provider, "Service Control Manager");
        assert_eq!(ev.fields.get("ServiceName"), Some(&json!("PSEXESVC")));
        assert_eq!(
            format_rfc3339_micros(ev.ts).unwrap(),
            "2019-03-19T23:34:25.000000Z"
        );
    }

    #[test]
    fn separate_json_attributes_shape() {
        let v = json!({
            "Event": {
                "System": {
                    "EventID": 7045,
                    "EventID_attributes": {"Qualifiers": 16384},
                    "Channel": "System",
                    "Computer": "WIN-X",
                    "EventRecordID": 4480,
                    "Provider_attributes": {"Name": "Service Control Manager"},
                    "TimeCreated_attributes": {"SystemTime": "2019-03-03T09:20:28.621489Z"},
                    "Security_attributes": {"UserID": "S-1-5-18"}
                },
                "EventData": {
                    "ServiceName": "spoolfool",
                    "ImagePath": "cmd.exe"
                }
            }
        });
        let ev = normalize_record(&v, 1, None, &[]);
        assert_eq!(ev.event_id, 7045);
        assert_eq!(ev.fields.get("EventID_Qualifiers"), Some(&json!(16384)));
        assert_eq!(ev.user_sid.as_deref(), Some("S-1-5-18"));
        assert_eq!(
            format_rfc3339_micros(ev.ts).unwrap(),
            "2019-03-03T09:20:28.621489Z"
        );
    }

    #[test]
    fn userdata_log_cleared_104() {
        let v = json!({
            "Event": {
                "System": {
                    "EventID": 104,
                    "Channel": "System",
                    "Computer": "HOST",
                    "EventRecordID": 1,
                    "Provider_attributes": {"Name": "Microsoft-Windows-Eventlog"},
                    "TimeCreated_attributes": {"SystemTime": "2019-01-01T00:00:00.000000Z"}
                },
                "UserData": {
                    "LogFileCleared": {
                        "SubjectUserName": "Administrator",
                        "SubjectDomainName": "CORP",
                        "Channel": "System"
                    }
                }
            }
        });
        let ev = normalize_record(&v, 1, None, &[]);
        assert_eq!(
            ev.fields.get("SubjectUserName"),
            Some(&json!("Administrator"))
        );
        assert_eq!(
            ev.fields.get("LogFileCleared.SubjectUserName"),
            Some(&json!("Administrator"))
        );
        assert_eq!(ev.user_name.as_deref(), Some("Administrator"));
    }

    #[test]
    fn userdata_1149_eventxml() {
        let v = json!({
            "Event": {
                "System": {
                    "EventID": 1149,
                    "Channel": "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
                    "Computer": "HOST",
                    "EventRecordID": 9,
                    "Provider_attributes": {"Name": "Microsoft-Windows-TerminalServices-RemoteConnectionManager"},
                    "TimeCreated_attributes": {"SystemTime": "2019-01-01T00:00:00.000000Z"}
                },
                "UserData": {
                    "EventXML": {
                        "Param1": "administrator",
                        "Param2": "CORP",
                        "Param3": "10.0.2.16"
                    }
                }
            }
        });
        let ev = normalize_record(&v, 1, None, &[]);
        assert_eq!(ev.fields.get("Param1"), Some(&json!("administrator")));
        assert_eq!(ev.fields.get("Param3"), Some(&json!("10.0.2.16")));
        assert_eq!(ev.user_name.as_deref(), Some("administrator"));
        assert_eq!(ev.src_ip.as_deref(), Some("10.0.2.16"));
    }

    #[test]
    fn unnamed_data_array() {
        let v = json!({
            "Event": {
                "System": {
                    "EventID": 1,
                    "Channel": "Application",
                    "Computer": "HOST",
                    "EventRecordID": 1,
                    "Provider_attributes": {"Name": "Test"},
                    "TimeCreated_attributes": {"SystemTime": "2019-01-01T00:00:00.000000Z"}
                },
                "EventData": {
                    "Data": ["alpha", "beta", "gamma"]
                }
            }
        });
        let ev = normalize_record(&v, 1, None, &[]);
        assert_eq!(ev.fields.get("Data[0]"), Some(&json!("alpha")));
        assert_eq!(ev.fields.get("Data[2]"), Some(&json!("gamma")));
        assert_eq!(ev.fields.get("Data"), Some(&json!("alpha beta gamma")));
    }

    #[test]
    fn missing_timestamp_sets_invalid() {
        let v = json!({
            "Event": {
                "System": {
                    "EventID": 1,
                    "Channel": "System",
                    "Computer": "HOST",
                    "EventRecordID": 1,
                    "Provider_attributes": {"Name": "Test"}
                }
            }
        });
        let ev = normalize_record(&v, 1, None, &[]);
        assert_eq!(ev.ts, 0);
        assert_eq!(ev.fields.get("_ts_invalid"), Some(&json!(true)));
    }

    #[test]
    fn field_aliases_4688() {
        let v = json!({
            "Event": {
                "System": {
                    "EventID": 4688,
                    "Channel": "Security",
                    "Computer": "HOST",
                    "EventRecordID": 1,
                    "Provider_attributes": {"Name": "Microsoft-Windows-Security-Auditing"},
                    "TimeCreated_attributes": {"SystemTime": "2019-01-01T00:00:00.000000Z"}
                },
                "EventData": {
                    "NewProcessName": "C:\\\\Windows\\\\System32\\\\cmd.exe",
                    "ParentProcessName": "C:\\\\Windows\\\\explorer.exe",
                    "SubjectUserName": "bob",
                    "SubjectDomainName": "CORP",
                    "CommandLine": "cmd.exe /c whoami"
                }
            }
        });
        let ev = normalize_record(&v, 1, None, &default_4688_aliases());
        assert_eq!(
            ev.fields.get("Image"),
            Some(&json!("C:\\\\Windows\\\\System32\\\\cmd.exe"))
        );
        assert!(ev.fields.get("NewProcessName").is_some());
        assert_eq!(ev.fields.get("User"), Some(&json!("CORP\\bob")));
    }

    #[test]
    fn numeric_string_logon_type() {
        let v = json!({
            "Event": {
                "System": {
                    "EventID": 4624,
                    "Channel": "Security",
                    "Computer": "HOST",
                    "EventRecordID": 1,
                    "Provider_attributes": {"Name": "Microsoft-Windows-Security-Auditing"},
                    "TimeCreated_attributes": {"SystemTime": "2019-01-01T00:00:00.000000Z"}
                },
                "EventData": { "LogonType": "3", "TargetUserName": "alice", "IpAddress": "10.1.1.1" }
            }
        });
        let ev = normalize_record(&v, 1, None, &[]);
        assert_eq!(ev.logon_type, Some(3));
        assert_eq!(ev.user_name.as_deref(), Some("alice"));
        assert_eq!(ev.src_ip.as_deref(), Some("10.1.1.1"));
    }
}
