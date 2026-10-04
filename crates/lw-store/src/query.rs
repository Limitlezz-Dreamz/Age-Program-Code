use lw_core::{Error, Result, TsMicros};
use rusqlite::{params, params_from_iter, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldFilter {
    pub field: String,
    /// equals | contains | starts | ends | regex | in | exists
    pub op: String,
    pub value: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventQuery {
    pub offset: u64,
    pub limit: u64,
    pub sort_col: String,
    pub sort_dir: SortDir,
    pub time_from: Option<TsMicros>,
    pub time_to: Option<TsMicros>,
    pub event_ids: Vec<u32>,
    pub computers: Vec<String>,
    pub channels: Vec<String>,
    pub users: Vec<String>,
    pub src_ips: Vec<String>,
    pub text: Option<String>,
    pub field_filters: Vec<FieldFilter>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SortDir {
    #[default]
    Asc,
    Desc,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventRow {
    pub id: i64,
    pub file_id: i64,
    pub record_id: u64,
    pub ts: TsMicros,
    pub event_id: u32,
    pub channel: String,
    pub provider: String,
    pub computer: String,
    pub user_name: Option<String>,
    pub src_ip: Option<String>,
    pub logon_type: Option<i64>,
    /// Short preview from fields_json (CommandLine / Message / etc.).
    pub summary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Page<T> {
    pub rows: Vec<T>,
    pub total: u64,
    pub offset: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StatsSummary {
    pub files: u64,
    pub files_with_errors: u64,
    pub events: u64,
    pub first_ts: Option<TsMicros>,
    pub last_ts: Option<TsMicros>,
    pub channels: Vec<(String, u64)>,
    pub event_ids: Vec<(u32, u64)>,
}

fn sort_column(col: &str) -> Result<&'static str> {
    Ok(match col {
        "ts" => "e.ts",
        "event_id" => "e.event_id",
        "computer" => "h.name",
        "channel" => "c.name",
        "user" | "user_name" => "e.user_name",
        "id" => "e.id",
        "record_id" => "e.record_id",
        _ => return Err(Error::msg(format!("unsupported sort column: {col}"))),
    })
}

pub fn query_events(conn: &Connection, q: &EventQuery) -> Result<Page<EventRow>> {
    let mut where_parts = Vec::new();
    let mut params: Vec<rusqlite::types::Value> = Vec::new();

    if let Some(t) = q.time_from {
        where_parts.push("e.ts >= ?".to_string());
        params.push(t.into());
    }
    if let Some(t) = q.time_to {
        where_parts.push("e.ts <= ?".to_string());
        params.push(t.into());
    }
    if !q.event_ids.is_empty() {
        let placeholders = q
            .event_ids
            .iter()
            .map(|_| "?")
            .collect::<Vec<_>>()
            .join(",");
        where_parts.push(format!("e.event_id IN ({placeholders})"));
        for id in &q.event_ids {
            params.push(i64::from(*id).into());
        }
    }
    if !q.computers.is_empty() {
        let placeholders = q
            .computers
            .iter()
            .map(|_| "?")
            .collect::<Vec<_>>()
            .join(",");
        where_parts.push(format!("h.name IN ({placeholders})"));
        for c in &q.computers {
            params.push(c.clone().into());
        }
    }
    if !q.channels.is_empty() {
        let placeholders = q.channels.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        where_parts.push(format!("c.name IN ({placeholders})"));
        for c in &q.channels {
            params.push(c.clone().into());
        }
    }
    if !q.users.is_empty() {
        let placeholders = q.users.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        where_parts.push(format!("e.user_name IN ({placeholders})"));
        for u in &q.users {
            params.push(u.clone().into());
        }
    }
    if !q.src_ips.is_empty() {
        let placeholders = q.src_ips.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        where_parts.push(format!("e.src_ip IN ({placeholders})"));
        for ip in &q.src_ips {
            params.push(ip.clone().into());
        }
    }
    for ff in &q.field_filters {
        apply_field_filter(ff, &mut where_parts, &mut params)?;
    }
    if let Some(text) = &q.text {
        if !text.is_empty() {
            // Prefer FTS when available; fall back to fields_json LIKE.
            let fts_ok: bool = conn
                .query_row(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='events_fts' LIMIT 1",
                    [],
                    |_| Ok(true),
                )
                .unwrap_or(false);
            if fts_ok {
                where_parts
                    .push("e.id IN (SELECT rowid FROM events_fts WHERE events_fts MATCH ?)".into());
                params.push(text.clone().into());
            } else {
                where_parts.push("e.fields_json LIKE ?".into());
                params.push(format!("%{text}%").into());
            }
        }
    }

    let where_sql = if where_parts.is_empty() {
        "1=1".to_string()
    } else {
        where_parts.join(" AND ")
    };

    let count_sql = format!(
        "SELECT COUNT(*) FROM events e
         JOIN dict_channel c ON c.id = e.channel_id
         JOIN dict_provider p ON p.id = e.provider_id
         JOIN dict_computer h ON h.id = e.computer_id
         WHERE {where_sql}"
    );
    let total: u64 = conn
        .query_row(&count_sql, params_from_iter(params.iter().cloned()), |r| {
            r.get::<_, i64>(0)
        })
        .map_err(|e| Error::Sqlite(e.to_string()))? as u64;

    let sort = sort_column(&q.sort_col)?;
    let dir = match q.sort_dir {
        SortDir::Asc => "ASC",
        SortDir::Desc => "DESC",
    };
    let limit = q.limit.clamp(1, 1000);
    let sql = format!(
        "SELECT e.id, e.file_id, e.record_id, e.ts, e.event_id,
                c.name, p.name, h.name, e.user_name, e.src_ip, e.logon_type, e.fields_json
         FROM events e
         JOIN dict_channel c ON c.id = e.channel_id
         JOIN dict_provider p ON p.id = e.provider_id
         JOIN dict_computer h ON h.id = e.computer_id
         WHERE {where_sql}
         ORDER BY {sort} {dir}, e.id ASC
         LIMIT ? OFFSET ?"
    );
    let mut params2 = params;
    params2.push((limit as i64).into());
    params2.push((q.offset as i64).into());

    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    let rows = stmt
        .query_map(params_from_iter(params2), |r| {
            let fields_json: String = r.get(11)?;
            Ok(EventRow {
                id: r.get(0)?,
                file_id: r.get(1)?,
                record_id: r.get::<_, i64>(2)? as u64,
                ts: r.get(3)?,
                event_id: r.get::<_, i64>(4)? as u32,
                channel: r.get(5)?,
                provider: r.get(6)?,
                computer: r.get(7)?,
                user_name: r.get(8)?,
                src_ip: r.get(9)?,
                logon_type: r.get(10)?,
                summary: summarize_fields(&fields_json),
            })
        })
        .map_err(|e| Error::Sqlite(e.to_string()))?;

    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| Error::Sqlite(e.to_string()))?);
    }
    Ok(Page {
        rows: out,
        total,
        offset: q.offset,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodedPayload {
    pub field: String,
    pub encoding: String,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventDetail {
    pub id: i64,
    pub file_id: i64,
    pub record_id: u64,
    pub ts: TsMicros,
    pub event_id: u32,
    pub channel: String,
    pub provider: String,
    pub computer: String,
    pub level: Option<u8>,
    pub user_name: Option<String>,
    pub src_ip: Option<String>,
    pub logon_type: Option<i64>,
    pub source_path: Option<String>,
    pub description: Option<String>,
    pub fields: Map<String, Value>,
    pub raw_json: Option<String>,
    pub xml: Option<String>,
    pub decoded: Option<DecodedPayload>,
    pub related_detection_ids: Vec<i64>,
}

fn summarize_fields(fields_json: &str) -> Option<String> {
    let map: Map<String, Value> = serde_json::from_str(fields_json).ok()?;
    for key in [
        "CommandLine",
        "ScriptBlockText",
        "Message",
        "Image",
        "TargetUserName",
        "ProcessName",
    ] {
        if let Some(Value::String(s)) = map.get(key) {
            if !s.is_empty() {
                let mut t = s.clone();
                if t.len() > 160 {
                    t.truncate(160);
                    t.push('…');
                }
                return Some(format!("{key}={t}"));
            }
        }
    }
    None
}

fn apply_field_filter(
    ff: &FieldFilter,
    where_parts: &mut Vec<String>,
    params: &mut Vec<rusqlite::types::Value>,
) -> Result<()> {
    let field = ff.field.trim();
    if field.is_empty() {
        return Ok(());
    }
    let op = ff.op.to_ascii_lowercase();
    // Map common columns to SQL; everything else → fields_json.
    let col = match field.to_ascii_lowercase().as_str() {
        "event_id" | "eventid" => Some("e.event_id"),
        "computer" | "host" => Some("h.name"),
        "channel" => Some("c.name"),
        "provider" => Some("p.name"),
        "user" | "user_name" => Some("e.user_name"),
        "src_ip" | "ip" => Some("e.src_ip"),
        "logon_type" => Some("e.logon_type"),
        _ => None,
    };

    match (col, op.as_str()) {
        (Some(c), "equals" | "eq" | "=") => {
            where_parts.push(format!("{c} = ?"));
            params.push(ff.value.clone().into());
        }
        (Some(c), "contains") => {
            where_parts.push(format!("CAST({c} AS TEXT) LIKE ?"));
            params.push(format!("%{}%", ff.value).into());
        }
        (Some(c), "starts" | "startswith") => {
            where_parts.push(format!("CAST({c} AS TEXT) LIKE ?"));
            params.push(format!("{}%", ff.value).into());
        }
        (Some(c), "ends" | "endswith") => {
            where_parts.push(format!("CAST({c} AS TEXT) LIKE ?"));
            params.push(format!("%{}", ff.value).into());
        }
        (Some(c), "exists") => {
            where_parts.push(format!("{c} IS NOT NULL AND CAST({c} AS TEXT) != ''"));
        }
        (Some(c), "in") => {
            let vals: Vec<_> = ff
                .value
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if vals.is_empty() {
                return Ok(());
            }
            let ph = vals.iter().map(|_| "?").collect::<Vec<_>>().join(",");
            where_parts.push(format!("{c} IN ({ph})"));
            for v in vals {
                params.push(v.into());
            }
        }
        (None, "exists") => {
            where_parts.push("e.fields_json LIKE ?".into());
            params.push(format!("%\"{field}\"%").into());
        }
        (None, "equals" | "eq" | "=") => {
            // JSON substring match — MVP (no json1 dependency guarantee).
            where_parts.push("e.fields_json LIKE ?".into());
            params.push(format!("%\"{field}\":\"{}\"%", ff.value.replace('"', "")).into());
        }
        (None, "contains" | "starts" | "startswith" | "ends" | "endswith" | "regex") => {
            // regex treated as contains for MVP safety (no ReDoS from SQLite REGEXP).
            where_parts.push("e.fields_json LIKE ?".into());
            params.push(format!("%{}%", ff.value).into());
        }
        (None, "in") => {
            let vals: Vec<_> = ff
                .value
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if vals.is_empty() {
                return Ok(());
            }
            let mut ors = Vec::new();
            for v in vals {
                ors.push("e.fields_json LIKE ?".to_string());
                params.push(format!("%{v}%").into());
            }
            where_parts.push(format!("({})", ors.join(" OR ")));
        }
        _ => {
            return Err(Error::msg(format!("unsupported field filter op: {op}")));
        }
    }
    Ok(())
}

pub fn get_event(conn: &Connection, id: i64) -> Result<EventDetail> {
    let row = conn
        .query_row(
            "SELECT e.id, e.file_id, e.record_id, e.ts, e.event_id,
                    c.name, p.name, h.name, e.level, e.user_name, e.src_ip, e.logon_type,
                    e.fields_json, e.raw_zstd, f.path
             FROM events e
             JOIN dict_channel c ON c.id = e.channel_id
             JOIN dict_provider p ON p.id = e.provider_id
             JOIN dict_computer h ON h.id = e.computer_id
             LEFT JOIN files f ON f.id = e.file_id
             WHERE e.id=?1",
            params![id],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)? as u64,
                    r.get::<_, i64>(3)?,
                    r.get::<_, i64>(4)? as u32,
                    r.get::<_, String>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, String>(7)?,
                    r.get::<_, Option<i64>>(8)?.map(|v| v as u8),
                    r.get::<_, Option<String>>(9)?,
                    r.get::<_, Option<String>>(10)?,
                    r.get::<_, Option<i64>>(11)?,
                    r.get::<_, String>(12)?,
                    r.get::<_, Option<Vec<u8>>>(13)?,
                    r.get::<_, Option<String>>(14)?,
                ))
            },
        )
        .optional()
        .map_err(|e| Error::Sqlite(e.to_string()))?
        .ok_or_else(|| Error::msg(format!("event {id} not found")))?;

    let (
        id,
        file_id,
        record_id,
        ts,
        event_id,
        channel,
        provider,
        computer,
        level,
        user_name,
        src_ip,
        logon_type,
        fields_json,
        raw_zstd,
        source_path,
    ) = row;

    let fields: Map<String, Value> = serde_json::from_str(&fields_json).unwrap_or_default();
    let raw_json = raw_zstd.and_then(|blob| {
        zstd::decode_all(blob.as_slice())
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
    });
    let xml = Some(fields_to_xml(
        &channel, event_id, &provider, &computer, &fields,
    ));
    let decoded = try_decode_encoded(&fields);
    let description = event_description(&channel, event_id);

    let mut related_detection_ids = Vec::new();
    {
        let mut stmt = conn
            .prepare(
                "SELECT detection_id FROM detection_events WHERE event_id=?1 ORDER BY detection_id LIMIT 200",
            )
            .map_err(|e| Error::Sqlite(e.to_string()))?;
        let rows = stmt
            .query_map(params![id], |r| r.get::<_, i64>(0))
            .map_err(|e| Error::Sqlite(e.to_string()))?;
        for row in rows {
            related_detection_ids.push(row.map_err(|e| Error::Sqlite(e.to_string()))?);
        }
    }

    Ok(EventDetail {
        id,
        file_id,
        record_id,
        ts,
        event_id,
        channel,
        provider,
        computer,
        level,
        user_name,
        src_ip,
        logon_type,
        source_path,
        description,
        fields,
        raw_json,
        xml,
        decoded,
        related_detection_ids,
    })
}

fn event_description(channel: &str, event_id: u32) -> Option<String> {
    // Minimal built-in map; resources/event-descriptions.yml is the longer-term source.
    let key = (channel.to_ascii_lowercase(), event_id);
    let desc = match (key.0.as_str(), key.1) {
        ("security", 4624) => "An account was successfully logged on",
        ("security", 4625) => "An account failed to log on",
        ("security", 4688) => "A new process has been created",
        ("security", 1102) => "The audit log was cleared",
        ("system", 104) => "Event log cleared",
        ("system", 7045) => "A service was installed in the system",
        (_, 1) if channel.to_ascii_lowercase().contains("sysmon") => "Process Create",
        (_, 3) if channel.to_ascii_lowercase().contains("sysmon") => "Network connection",
        (_, 10) if channel.to_ascii_lowercase().contains("sysmon") => "Process Access",
        (_, 4104) => "PowerShell script block logging",
        _ => return None,
    };
    Some(desc.into())
}

fn fields_to_xml(
    channel: &str,
    event_id: u32,
    provider: &str,
    computer: &str,
    fields: &Map<String, Value>,
) -> String {
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<Event>\n");
    out.push_str("  <System>\n");
    out.push_str(&format!(
        "    <Provider Name=\"{}\"/>\n",
        xml_escape(provider)
    ));
    out.push_str(&format!("    <EventID>{event_id}</EventID>\n"));
    out.push_str(&format!("    <Channel>{}</Channel>\n", xml_escape(channel)));
    out.push_str(&format!(
        "    <Computer>{}</Computer>\n",
        xml_escape(computer)
    ));
    out.push_str("  </System>\n  <EventData>\n");
    let mut keys: Vec<_> = fields.keys().collect();
    keys.sort();
    for k in keys {
        let v = fields.get(k).map(value_to_plain).unwrap_or_default();
        out.push_str(&format!(
            "    <Data Name=\"{}\">{}</Data>\n",
            xml_escape(k),
            xml_escape(&v)
        ));
    }
    out.push_str("  </EventData>\n</Event>\n");
    out
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn value_to_plain(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn try_decode_encoded(fields: &Map<String, Value>) -> Option<DecodedPayload> {
    const CANDIDATES: &[&str] = &[
        "CommandLine",
        "ScriptBlockText",
        "Payload",
        "Image",
        "Command",
    ];
    for key in CANDIDATES {
        let Some(Value::String(s)) = fields.get(*key) else {
            continue;
        };
        if let Some(text) = try_b64_utf16le(s) {
            return Some(DecodedPayload {
                field: (*key).into(),
                encoding: "base64-utf16le".into(),
                text,
            });
        }
        if let Some(text) = try_b64_utf8(s) {
            return Some(DecodedPayload {
                field: (*key).into(),
                encoding: "base64-utf8".into(),
                text,
            });
        }
    }
    // Also scan all string fields for -enc / -EncodedCommand style blobs.
    for (key, val) in fields {
        let Value::String(s) = val else { continue };
        if let Some(blob) = extract_enc_blob(s) {
            if let Some(text) = try_b64_utf16le(&blob).or_else(|| try_b64_utf8(&blob)) {
                return Some(DecodedPayload {
                    field: key.clone(),
                    encoding: "powershell-enc".into(),
                    text,
                });
            }
        }
    }
    None
}

fn extract_enc_blob(s: &str) -> Option<String> {
    let lower = s.to_ascii_lowercase();
    for marker in ["-enc ", "-encodedcommand ", "-e "] {
        if let Some(idx) = lower.find(marker) {
            let rest = s[idx + marker.len()..].trim();
            let token = rest.split_whitespace().next()?;
            if token.len() >= 16 {
                return Some(token.to_string());
            }
        }
    }
    None
}

fn try_b64_utf16le(s: &str) -> Option<String> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.len() < 16 || !cleaned.len().is_multiple_of(4) {
        return None;
    }
    if !cleaned
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
    {
        return None;
    }
    let bytes = b64_decode(&cleaned)?;
    if bytes.len() < 4 || !bytes.len().is_multiple_of(2) {
        return None;
    }
    let mut u16s = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.as_chunks::<2>().0 {
        u16s.push(u16::from_le_bytes(*chunk));
    }
    let text = String::from_utf16(&u16s).ok()?;
    if text
        .chars()
        .filter(|c| c.is_control() && *c != '\n' && *c != '\r' && *c != '\t')
        .count()
        > 2
    {
        return None;
    }
    if text.trim().is_empty() {
        return None;
    }
    Some(text)
}

fn try_b64_utf8(s: &str) -> Option<String> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.len() < 16 {
        return None;
    }
    let bytes = b64_decode(&cleaned)?;
    let text = String::from_utf8(bytes).ok()?;
    if text
        .chars()
        .any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t')
    {
        return None;
    }
    if text.trim().is_empty() || !text.is_ascii() {
        return None;
    }
    Some(text)
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    // Minimal base64 decoder (no extra crate).
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            b'=' => Some(0),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.as_chunks::<4>().0 {
        let (a, b, c, d) = (
            val(chunk[0])?,
            val(chunk[1])?,
            val(chunk[2])?,
            val(chunk[3])?,
        );
        out.push((a << 2) | (b >> 4));
        if chunk[2] != b'=' {
            out.push((b << 4) | (c >> 2));
        }
        if chunk[3] != b'=' {
            out.push((c << 6) | d);
        }
    }
    Some(out)
}

pub fn stats_summary(conn: &Connection) -> Result<StatsSummary> {
    let files: u64 = conn
        .query_row("SELECT COUNT(*) FROM files", [], |r| r.get::<_, i64>(0))
        .map_err(|e| Error::Sqlite(e.to_string()))? as u64;
    let files_with_errors: u64 = conn
        .query_row(
            "SELECT COUNT(*) FROM files WHERE error IS NOT NULL OR records_err > 0",
            [],
            |r| r.get::<_, i64>(0),
        )
        .map_err(|e| Error::Sqlite(e.to_string()))? as u64;
    let events: u64 = conn
        .query_row("SELECT COUNT(*) FROM events", [], |r| r.get::<_, i64>(0))
        .map_err(|e| Error::Sqlite(e.to_string()))? as u64;
    let first_ts: Option<i64> = conn
        .query_row("SELECT MIN(ts) FROM events", [], |r| r.get(0))
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    let last_ts: Option<i64> = conn
        .query_row("SELECT MAX(ts) FROM events", [], |r| r.get(0))
        .map_err(|e| Error::Sqlite(e.to_string()))?;

    let mut channels = Vec::new();
    {
        let mut stmt = conn
            .prepare(
                "SELECT c.name, COUNT(*) FROM events e
                 JOIN dict_channel c ON c.id = e.channel_id
                 GROUP BY c.name ORDER BY COUNT(*) DESC LIMIT 50",
            )
            .map_err(|e| Error::Sqlite(e.to_string()))?;
        let rows = stmt
            .query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64))
            })
            .map_err(|e| Error::Sqlite(e.to_string()))?;
        for row in rows {
            channels.push(row.map_err(|e| Error::Sqlite(e.to_string()))?);
        }
    }

    let mut event_ids = Vec::new();
    {
        let mut stmt = conn
            .prepare(
                "SELECT event_id, COUNT(*) FROM events
                 GROUP BY event_id ORDER BY COUNT(*) DESC LIMIT 50",
            )
            .map_err(|e| Error::Sqlite(e.to_string()))?;
        let rows = stmt
            .query_map([], |r| {
                Ok((r.get::<_, i64>(0)? as u32, r.get::<_, i64>(1)? as u64))
            })
            .map_err(|e| Error::Sqlite(e.to_string()))?;
        for row in rows {
            event_ids.push(row.map_err(|e| Error::Sqlite(e.to_string()))?);
        }
    }

    Ok(StatsSummary {
        files,
        files_with_errors,
        events,
        first_ts,
        last_ts,
        channels,
        event_ids,
    })
}
