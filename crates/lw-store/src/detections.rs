use lw_core::{
    Detection, DetectionKind, Error, NormalizedEvent, Result, RuleSource, Severity, SourceType,
    TriageState, TsMicros,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{Map, Value};
use std::path::Path;

pub fn open_write_conn(case_dir: impl AsRef<Path>) -> Result<Connection> {
    let db = case_dir.as_ref().join("case.db");
    let conn = Connection::open(db).map_err(|e| Error::Sqlite(e.to_string()))?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA temp_store=MEMORY;",
    )
    .map_err(|e| Error::Sqlite(e.to_string()))?;
    // Ensure newer tables exist on older cases.
    conn.execute_batch(crate::schema::MIGRATION_0001)
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    Ok(conn)
}

pub fn begin_run(
    conn: &Connection,
    rule_pack: &str,
    rule_pack_hash: Option<&str>,
    profile_json: &str,
) -> Result<i64> {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    conn.execute(
        "INSERT INTO runs(started_at, finished_at, status, rule_pack, rule_pack_hash, profile_json)
         VALUES (?1, NULL, 'running', ?2, ?3, ?4)",
        params![now, rule_pack, rule_pack_hash, profile_json],
    )
    .map_err(|e| Error::Sqlite(e.to_string()))?;
    Ok(conn.last_insert_rowid())
}

pub fn finish_run(conn: &Connection, run_id: i64, status: &str) -> Result<()> {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    conn.execute(
        "UPDATE runs SET finished_at=?1, status=?2 WHERE id=?3",
        params![now, status, run_id],
    )
    .map_err(|e| Error::Sqlite(e.to_string()))?;
    Ok(())
}

pub fn clear_run_detections(conn: &Connection, run_id: i64) -> Result<()> {
    conn.execute(
        "DELETE FROM detection_events WHERE detection_id IN (SELECT id FROM detections WHERE run_id=?1)",
        params![run_id],
    )
    .map_err(|e| Error::Sqlite(e.to_string()))?;
    conn.execute("DELETE FROM detections WHERE run_id=?1", params![run_id])
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    Ok(())
}

pub fn insert_detections(conn: &Connection, run_id: i64, dets: &[Detection]) -> Result<()> {
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    for d in dets {
        let (kind, group_json) = match &d.kind {
            DetectionKind::Single => ("single".to_string(), None),
            DetectionKind::Correlation {
                ctype,
                group,
                count,
            } => (
                format!("correlation:{ctype}"),
                Some(serde_json::json!({"group": group, "count": count}).to_string()),
            ),
        };
        tx.execute(
            "INSERT INTO detections(
                run_id, rule_uid, rule_title, rule_author, rule_source_json, severity, status,
                mitre_json, ts, computer, user_name, kind, group_json, event_count, summary,
                fp_hint, triage
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
            params![
                run_id,
                d.rule_uid,
                d.rule_title,
                d.rule_author,
                serde_json::to_string(&d.rule_source)?,
                d.severity as u8 as i64,
                d.status,
                serde_json::to_string(&d.mitre)?,
                d.ts,
                d.computer,
                d.user,
                kind,
                group_json,
                d.event_ids.len() as i64,
                d.summary,
                d.fp_hint,
                d.triage.as_str(),
            ],
        )
        .map_err(|e| Error::Sqlite(e.to_string()))?;
        let det_id = tx.last_insert_rowid();
        for eid in d.event_ids.iter().take(1000) {
            tx.execute(
                "INSERT OR IGNORE INTO detection_events(detection_id, event_id) VALUES (?1,?2)",
                params![det_id, eid],
            )
            .map_err(|e| Error::Sqlite(e.to_string()))?;
        }
    }
    tx.commit().map_err(|e| Error::Sqlite(e.to_string()))?;
    Ok(())
}

/// Stream normalized events in ascending timestamp order (for re-detect / hunt).
pub fn iter_events_ordered(
    conn: &Connection,
    offset: u64,
    limit: u64,
) -> Result<Vec<NormalizedEvent>> {
    let mut stmt = conn
        .prepare(
            "SELECT e.id, e.file_id, e.source_type, e.record_id, e.ts, e.event_id,
                    c.name, p.name, h.name, e.level, e.user_name, e.src_ip, e.logon_type,
                    e.fields_json
             FROM events e
             JOIN dict_channel c ON c.id = e.channel_id
             JOIN dict_provider p ON p.id = e.provider_id
             JOIN dict_computer h ON h.id = e.computer_id
             ORDER BY e.ts ASC, e.id ASC
             LIMIT ?1 OFFSET ?2",
        )
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    let rows = stmt
        .query_map(params![limit as i64, offset as i64], |r| {
            let fields_json: String = r.get(13)?;
            let fields: Map<String, Value> = serde_json::from_str(&fields_json).unwrap_or_default();
            let source_type = match r.get::<_, String>(2)?.as_str() {
                "unifiedlog" => SourceType::UnifiedLog,
                "jsonl" => SourceType::Jsonl,
                _ => SourceType::Evtx,
            };
            Ok(NormalizedEvent {
                id: r.get(0)?,
                file_id: r.get(1)?,
                source_type,
                record_id: r.get::<_, i64>(3)? as u64,
                ts: r.get(4)?,
                event_id: r.get::<_, i64>(5)? as u32,
                channel: r.get(6)?,
                provider: r.get(7)?,
                computer: r.get(8)?,
                level: r.get::<_, Option<i64>>(9)?.map(|v| v as u8),
                user_sid: None,
                user_name: r.get(10)?,
                src_ip: r.get(11)?,
                logon_type: r.get(12)?,
                fields,
                raw_json: None,
            })
        })
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| Error::Sqlite(e.to_string()))?);
    }
    Ok(out)
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DetectionRow {
    pub id: i64,
    pub run_id: i64,
    pub rule_uid: String,
    pub rule_title: String,
    pub rule_author: Option<String>,
    pub rule_source: RuleSource,
    pub severity: Severity,
    pub status: Option<String>,
    pub mitre: Vec<lw_core::MitreRef>,
    pub ts: TsMicros,
    pub computer: String,
    pub user: Option<String>,
    pub kind: String,
    pub event_count: u64,
    pub summary: String,
    pub fp_hint: Option<String>,
    pub triage: String,
    pub triage_note: Option<String>,
    pub event_ids: Vec<i64>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LinkedEventRef {
    pub id: i64,
    pub ts: TsMicros,
    pub event_id: u32,
    pub channel: String,
    pub computer: String,
    pub user_name: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DetectionDetail {
    pub detection: DetectionRow,
    pub group_json: Option<String>,
    pub linked_events: Vec<LinkedEventRef>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DetectionQuery {
    pub offset: u64,
    pub limit: u64,
    pub sort_col: String,
    pub sort_dir: crate::query::SortDir,
    pub severity_min: Option<Severity>,
    pub severities: Vec<Severity>,
    pub rule_uid: Option<String>,
    pub text: Option<String>,
    pub time_from: Option<TsMicros>,
    pub time_to: Option<TsMicros>,
    pub computers: Vec<String>,
    pub users: Vec<String>,
    pub triage: Vec<String>,
    pub mitre_tactic: Option<String>,
}

impl Default for DetectionQuery {
    fn default() -> Self {
        Self {
            offset: 0,
            limit: 100,
            sort_col: "severity".into(),
            sort_dir: crate::query::SortDir::Desc,
            severity_min: None,
            severities: Vec::new(),
            rule_uid: None,
            text: None,
            time_from: None,
            time_to: None,
            computers: Vec::new(),
            users: Vec::new(),
            triage: Vec::new(),
            mitre_tactic: None,
        }
    }
}

fn detection_sort_column(col: &str) -> &'static str {
    match col {
        "ts" | "time" => "ts",
        "severity" | "sev" => "severity",
        "rule" | "rule_title" => "rule_title",
        "computer" | "host" => "computer",
        "user" | "user_name" => "user_name",
        "count" | "event_count" => "event_count",
        "triage" => "triage",
        _ => "severity",
    }
}

pub fn query_detections(
    conn: &Connection,
    q: &DetectionQuery,
) -> Result<crate::query::Page<DetectionRow>> {
    let mut where_parts = vec!["1=1".to_string()];
    let mut params: Vec<rusqlite::types::Value> = Vec::new();
    if let Some(sev) = q.severity_min {
        where_parts.push("severity >= ?".into());
        params.push((sev as u8 as i64).into());
    }
    if !q.severities.is_empty() {
        let placeholders = q
            .severities
            .iter()
            .map(|_| "?")
            .collect::<Vec<_>>()
            .join(",");
        where_parts.push(format!("severity IN ({placeholders})"));
        for s in &q.severities {
            params.push((*s as u8 as i64).into());
        }
    }
    if let Some(uid) = &q.rule_uid {
        where_parts.push("rule_uid = ?".into());
        params.push(uid.clone().into());
    }
    if let Some(t) = q.time_from {
        where_parts.push("ts >= ?".into());
        params.push(t.into());
    }
    if let Some(t) = q.time_to {
        where_parts.push("ts <= ?".into());
        params.push(t.into());
    }
    if !q.computers.is_empty() {
        let placeholders = q
            .computers
            .iter()
            .map(|_| "?")
            .collect::<Vec<_>>()
            .join(",");
        where_parts.push(format!("computer IN ({placeholders})"));
        for c in &q.computers {
            params.push(c.clone().into());
        }
    }
    if !q.users.is_empty() {
        let placeholders = q.users.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        where_parts.push(format!("user_name IN ({placeholders})"));
        for u in &q.users {
            params.push(u.clone().into());
        }
    }
    if !q.triage.is_empty() {
        let placeholders = q.triage.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        where_parts.push(format!("triage IN ({placeholders})"));
        for t in &q.triage {
            params.push(t.clone().into());
        }
    }
    if let Some(tactic) = &q.mitre_tactic {
        if !tactic.is_empty() {
            where_parts.push("mitre_json LIKE ?".into());
            params.push(format!("%{tactic}%").into());
        }
    }
    if let Some(text) = &q.text {
        if !text.is_empty() {
            where_parts.push(
                "(summary LIKE ? OR rule_title LIKE ? OR rule_uid LIKE ? OR computer LIKE ? OR IFNULL(user_name,'') LIKE ?)"
                    .into(),
            );
            let pat = format!("%{text}%");
            for _ in 0..5 {
                params.push(pat.clone().into());
            }
        }
    }
    let where_sql = where_parts.join(" AND ");
    let total: u64 = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM detections WHERE {where_sql}"),
            rusqlite::params_from_iter(params.iter().cloned()),
            |r| r.get::<_, i64>(0),
        )
        .map_err(|e| Error::Sqlite(e.to_string()))? as u64;

    let limit = q.limit.clamp(1, 1000);
    let sort = detection_sort_column(&q.sort_col);
    let dir = match q.sort_dir {
        crate::query::SortDir::Asc => "ASC",
        crate::query::SortDir::Desc => "DESC",
    };
    // Default secondary: severity DESC, ts ASC for stable hunting order.
    let sql = format!(
        "SELECT id, run_id, rule_uid, rule_title, rule_author, rule_source_json, severity, status,
                mitre_json, ts, computer, user_name, kind, event_count, summary, fp_hint, triage, triage_note
         FROM detections WHERE {where_sql}
         ORDER BY {sort} {dir}, severity DESC, ts ASC, id ASC
         LIMIT ? OFFSET ?"
    );
    let mut params2 = params;
    params2.push((limit as i64).into());
    params2.push((q.offset as i64).into());
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    let rows = stmt
        .query_map(rusqlite::params_from_iter(params2), |r| {
            let source_json: String = r.get(5)?;
            let mitre_json: Option<String> = r.get(8)?;
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, Option<String>>(4)?,
                source_json,
                r.get::<_, i64>(6)?,
                r.get::<_, Option<String>>(7)?,
                mitre_json,
                r.get::<_, i64>(9)?,
                r.get::<_, Option<String>>(10)?.unwrap_or_default(),
                r.get::<_, Option<String>>(11)?,
                r.get::<_, String>(12)?,
                r.get::<_, i64>(13)? as u64,
                r.get::<_, Option<String>>(14)?.unwrap_or_default(),
                r.get::<_, Option<String>>(15)?,
                r.get::<_, String>(16)?,
                r.get::<_, Option<String>>(17)?,
            ))
        })
        .map_err(|e| Error::Sqlite(e.to_string()))?;

    let mut out = Vec::new();
    for row in rows {
        let (
            id,
            run_id,
            rule_uid,
            rule_title,
            rule_author,
            source_json,
            severity,
            status,
            mitre_json,
            ts,
            computer,
            user,
            kind,
            event_count,
            summary,
            fp_hint,
            triage,
            triage_note,
        ) = row.map_err(|e| Error::Sqlite(e.to_string()))?;
        let event_ids = load_detection_event_ids(conn, id)?;
        out.push(DetectionRow {
            id,
            run_id,
            rule_uid,
            rule_title,
            rule_author,
            rule_source: serde_json::from_str(&source_json).unwrap_or(RuleSource::Builtin),
            severity: severity_from_i64(severity),
            status,
            mitre: mitre_json
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default(),
            ts,
            computer,
            user,
            kind,
            event_count,
            summary,
            fp_hint,
            triage,
            triage_note,
            event_ids,
        });
    }
    Ok(crate::query::Page {
        rows: out,
        total,
        offset: q.offset,
    })
}

pub fn get_detection(conn: &Connection, id: i64) -> Result<DetectionDetail> {
    let mut stmt = conn
        .prepare(
            "SELECT id, run_id, rule_uid, rule_title, rule_author, rule_source_json, severity, status,
                    mitre_json, ts, computer, user_name, kind, event_count, summary, fp_hint, triage,
                    triage_note, group_json
             FROM detections WHERE id=?1",
        )
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    let row = stmt
        .query_row(params![id], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, Option<String>>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, i64>(6)?,
                r.get::<_, Option<String>>(7)?,
                r.get::<_, Option<String>>(8)?,
                r.get::<_, i64>(9)?,
                r.get::<_, Option<String>>(10)?.unwrap_or_default(),
                r.get::<_, Option<String>>(11)?,
                r.get::<_, String>(12)?,
                r.get::<_, i64>(13)? as u64,
                r.get::<_, Option<String>>(14)?.unwrap_or_default(),
                r.get::<_, Option<String>>(15)?,
                r.get::<_, String>(16)?,
                r.get::<_, Option<String>>(17)?,
                r.get::<_, Option<String>>(18)?,
            ))
        })
        .optional()
        .map_err(|e| Error::Sqlite(e.to_string()))?
        .ok_or_else(|| Error::msg(format!("detection {id} not found")))?;

    let (
        id,
        run_id,
        rule_uid,
        rule_title,
        rule_author,
        source_json,
        severity,
        status,
        mitre_json,
        ts,
        computer,
        user,
        kind,
        event_count,
        summary,
        fp_hint,
        triage,
        triage_note,
        group_json,
    ) = row;
    let event_ids = load_detection_event_ids(conn, id)?;
    let detection = DetectionRow {
        id,
        run_id,
        rule_uid,
        rule_title,
        rule_author,
        rule_source: serde_json::from_str(&source_json).unwrap_or(RuleSource::Builtin),
        severity: severity_from_i64(severity),
        status,
        mitre: mitre_json
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default(),
        ts,
        computer,
        user,
        kind,
        event_count,
        summary,
        fp_hint,
        triage,
        triage_note,
        event_ids: event_ids.clone(),
    };
    let linked_events = load_linked_events(conn, &event_ids)?;
    Ok(DetectionDetail {
        detection,
        group_json,
        linked_events,
    })
}

fn load_linked_events(conn: &Connection, event_ids: &[i64]) -> Result<Vec<LinkedEventRef>> {
    if event_ids.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::with_capacity(event_ids.len().min(1000));
    for eid in event_ids.iter().take(1000) {
        let row = conn
            .query_row(
                "SELECT e.id, e.ts, e.event_id, c.name, h.name, e.user_name
                 FROM events e
                 JOIN dict_channel c ON c.id = e.channel_id
                 JOIN dict_computer h ON h.id = e.computer_id
                 WHERE e.id=?1",
                params![eid],
                |r| {
                    Ok(LinkedEventRef {
                        id: r.get(0)?,
                        ts: r.get(1)?,
                        event_id: r.get::<_, i64>(2)? as u32,
                        channel: r.get(3)?,
                        computer: r.get(4)?,
                        user_name: r.get(5)?,
                    })
                },
            )
            .optional()
            .map_err(|e| Error::Sqlite(e.to_string()))?;
        if let Some(r) = row {
            out.push(r);
        }
    }
    Ok(out)
}

pub fn set_triage(
    conn: &Connection,
    detection_ids: &[i64],
    state: TriageState,
    note: Option<&str>,
) -> Result<u64> {
    if detection_ids.is_empty() {
        return Ok(0);
    }
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    let mut updated = 0u64;
    for id in detection_ids {
        let n = tx
            .execute(
                "UPDATE detections SET triage=?1, triage_note=?2 WHERE id=?3",
                params![state.as_str(), note, id],
            )
            .map_err(|e| Error::Sqlite(e.to_string()))?;
        updated += n as u64;
    }
    tx.commit().map_err(|e| Error::Sqlite(e.to_string()))?;
    Ok(updated)
}

fn load_detection_event_ids(conn: &Connection, detection_id: i64) -> Result<Vec<i64>> {
    let mut stmt = conn
        .prepare(
            "SELECT event_id FROM detection_events WHERE detection_id=?1 ORDER BY event_id LIMIT 1000",
        )
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    let rows = stmt
        .query_map(params![detection_id], |r| r.get::<_, i64>(0))
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| Error::Sqlite(e.to_string()))?);
    }
    Ok(out)
}

fn severity_from_i64(v: i64) -> Severity {
    match v {
        0 => Severity::Informational,
        1 => Severity::Low,
        2 => Severity::Medium,
        3 => Severity::High,
        4 => Severity::Critical,
        _ => Severity::Informational,
    }
}

pub fn latest_run_id(conn: &Connection) -> Result<Option<i64>> {
    conn.query_row("SELECT id FROM runs ORDER BY id DESC LIMIT 1", [], |r| {
        r.get(0)
    })
    .optional()
    .map_err(|e| Error::Sqlite(e.to_string()))
}

#[allow(dead_code)]
fn _triage_parse(s: &str) -> TriageState {
    match s {
        "reviewed" => TriageState::Reviewed,
        "false_positive" => TriageState::FalsePositive,
        "escalated" => TriageState::Escalated,
        _ => TriageState::New,
    }
}
