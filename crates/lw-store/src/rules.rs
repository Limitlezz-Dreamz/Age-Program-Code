use lw_core::{Error, Result};
use rusqlite::{params, params_from_iter, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleRow {
    pub rule_uid: String,
    pub title: String,
    pub author: Option<String>,
    pub level: Option<String>,
    pub status: Option<String>,
    pub tags: Vec<String>,
    pub source_json: String,
    pub enabled: bool,
    pub hit_count: u64,
    pub unmapped: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleQuery {
    pub offset: u64,
    pub limit: u64,
    pub text: Option<String>,
    pub enabled_only: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleDetail {
    pub rule: RuleRow,
    pub yaml: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressionRow {
    pub id: i64,
    pub rule_uid: Option<String>,
    pub field: String,
    pub value: String,
    pub note: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressionInput {
    pub rule_uid: Option<String>,
    pub field: String,
    pub value: String,
    pub note: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RuleUpsert {
    pub rule_uid: String,
    pub title: String,
    pub author: Option<String>,
    pub level: String,
    pub status: Option<String>,
    pub tags: Vec<String>,
    pub source_json: String,
    pub yaml: String,
    pub unmapped: bool,
}

pub fn upsert_rules(conn: &Connection, rules: &[RuleUpsert]) -> Result<()> {
    let tx = conn
        .unchecked_transaction()
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    for r in rules {
        let enabled: i64 = tx
            .query_row(
                "SELECT enabled FROM rules WHERE rule_uid=?1",
                params![r.rule_uid],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| Error::Sqlite(e.to_string()))?
            .unwrap_or(1);
        tx.execute(
            "INSERT INTO rules(rule_uid, title, author, level, status, tags_json, logsource_json, source_json, yaml, enabled)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
             ON CONFLICT(rule_uid) DO UPDATE SET
               title=excluded.title,
               author=excluded.author,
               level=excluded.level,
               status=excluded.status,
               tags_json=excluded.tags_json,
               source_json=excluded.source_json,
               yaml=excluded.yaml",
            params![
                r.rule_uid,
                r.title,
                r.author,
                r.level,
                r.status,
                serde_json::to_string(&r.tags)?,
                if r.unmapped { "unmapped" } else { "mapped" },
                r.source_json,
                r.yaml,
                enabled,
            ],
        )
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    }
    tx.commit().map_err(|e| Error::Sqlite(e.to_string()))?;
    Ok(())
}

pub fn query_rules(conn: &Connection, q: &RuleQuery) -> Result<crate::query::Page<RuleRow>> {
    let mut where_parts = vec!["1=1".to_string()];
    let mut params: Vec<rusqlite::types::Value> = Vec::new();
    if let Some(en) = q.enabled_only {
        where_parts.push("enabled = ?".into());
        params.push(i64::from(en).into());
    }
    if let Some(text) = &q.text {
        if !text.is_empty() {
            where_parts
                .push("(title LIKE ? OR rule_uid LIKE ? OR IFNULL(author,'') LIKE ?)".into());
            let pat = format!("%{text}%");
            params.push(pat.clone().into());
            params.push(pat.clone().into());
            params.push(pat.into());
        }
    }
    let where_sql = where_parts.join(" AND ");
    let total: u64 = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM rules WHERE {where_sql}"),
            params_from_iter(params.iter().cloned()),
            |r| r.get::<_, i64>(0),
        )
        .map_err(|e| Error::Sqlite(e.to_string()))? as u64;

    let limit = q.limit.clamp(1, 1000);
    let sql = format!(
        "SELECT r.rule_uid, r.title, r.author, r.level, r.status, r.tags_json, r.source_json,
                r.enabled, r.logsource_json,
                (SELECT COUNT(*) FROM detections d WHERE d.rule_uid = r.rule_uid) AS hits
         FROM rules r WHERE {where_sql}
         ORDER BY hits DESC, r.title ASC
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
            let tags_json: Option<String> = r.get(5)?;
            let logsource: Option<String> = r.get(8)?;
            Ok(RuleRow {
                rule_uid: r.get(0)?,
                title: r.get(1)?,
                author: r.get(2)?,
                level: r.get(3)?,
                status: r.get(4)?,
                tags: tags_json
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or_default(),
                source_json: r.get(6)?,
                enabled: r.get::<_, i64>(7)? != 0,
                hit_count: r.get::<_, i64>(9)? as u64,
                unmapped: logsource.as_deref() == Some("unmapped"),
            })
        })
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| Error::Sqlite(e.to_string()))?);
    }
    Ok(crate::query::Page {
        rows: out,
        total,
        offset: q.offset,
    })
}

pub fn get_rule(conn: &Connection, uid: &str) -> Result<RuleDetail> {
    let row = conn
        .query_row(
            "SELECT rule_uid, title, author, level, status, tags_json, source_json, enabled, logsource_json, yaml,
                    (SELECT COUNT(*) FROM detections d WHERE d.rule_uid = rules.rule_uid)
             FROM rules WHERE rule_uid=?1",
            params![uid],
            |r| {
                let tags_json: Option<String> = r.get(5)?;
                let logsource: Option<String> = r.get(8)?;
                Ok((
                    RuleRow {
                        rule_uid: r.get(0)?,
                        title: r.get(1)?,
                        author: r.get(2)?,
                        level: r.get(3)?,
                        status: r.get(4)?,
                        tags: tags_json
                            .and_then(|s| serde_json::from_str(&s).ok())
                            .unwrap_or_default(),
                        source_json: r.get(6)?,
                        enabled: r.get::<_, i64>(7)? != 0,
                        hit_count: r.get::<_, i64>(10)? as u64,
                        unmapped: logsource.as_deref() == Some("unmapped"),
                    },
                    r.get::<_, Option<String>>(9)?.unwrap_or_default(),
                ))
            },
        )
        .optional()
        .map_err(|e| Error::Sqlite(e.to_string()))?
        .ok_or_else(|| Error::msg(format!("rule {uid} not found")))?;
    Ok(RuleDetail {
        rule: row.0,
        yaml: row.1,
    })
}

pub fn set_rule_enabled(conn: &Connection, uid: &str, enabled: bool) -> Result<()> {
    let n = conn
        .execute(
            "UPDATE rules SET enabled=?1 WHERE rule_uid=?2",
            params![i64::from(enabled), uid],
        )
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    if n == 0 {
        // Insert stub so disable works before sync.
        conn.execute(
            "INSERT INTO rules(rule_uid, title, author, level, status, tags_json, logsource_json, source_json, yaml, enabled)
             VALUES (?1,?1,NULL,NULL,NULL,'[]','mapped','{\"kind\":\"builtin\"}','',?2)",
            params![uid, i64::from(enabled)],
        )
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    }
    Ok(())
}

pub fn disabled_rule_uids(conn: &Connection) -> Result<std::collections::HashSet<String>> {
    let mut stmt = conn
        .prepare("SELECT rule_uid FROM rules WHERE enabled=0")
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    let rows = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    let mut out = std::collections::HashSet::new();
    for row in rows {
        out.insert(row.map_err(|e| Error::Sqlite(e.to_string()))?);
    }
    Ok(out)
}

pub fn list_suppressions(conn: &Connection) -> Result<Vec<SuppressionRow>> {
    let mut stmt = conn
        .prepare(
            "SELECT id, rule_uid, field, value, note, created_at FROM suppressions ORDER BY id DESC",
        )
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    let rows = stmt
        .query_map([], |r| {
            Ok(SuppressionRow {
                id: r.get(0)?,
                rule_uid: r.get(1)?,
                field: r.get(2)?,
                value: r.get(3)?,
                note: r.get(4)?,
                created_at: r.get(5)?,
            })
        })
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| Error::Sqlite(e.to_string()))?);
    }
    Ok(out)
}

pub fn add_suppression(conn: &Connection, s: &SuppressionInput) -> Result<i64> {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    conn.execute(
        "INSERT INTO suppressions(rule_uid, field, value, note, created_at) VALUES (?1,?2,?3,?4,?5)",
        params![s.rule_uid, s.field, s.value, s.note, now],
    )
    .map_err(|e| Error::Sqlite(e.to_string()))?;
    Ok(conn.last_insert_rowid())
}

pub fn delete_suppression(conn: &Connection, id: i64) -> Result<()> {
    conn.execute("DELETE FROM suppressions WHERE id=?1", params![id])
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    Ok(())
}

/// Drop detections that match active suppressions (rule_uid + summary/computer/user contains value).
pub fn apply_suppressions_to_detections(
    dets: Vec<lw_core::Detection>,
    suppressions: &[SuppressionRow],
) -> Vec<lw_core::Detection> {
    if suppressions.is_empty() {
        return dets;
    }
    dets.into_iter()
        .filter(|d| {
            !suppressions.iter().any(|s| {
                if let Some(uid) = &s.rule_uid {
                    if uid != &d.rule_uid {
                        return false;
                    }
                }
                let hay = match s.field.as_str() {
                    "computer" | "host" => d.computer.as_str(),
                    "user" | "user_name" => d.user.as_deref().unwrap_or(""),
                    "summary" | "*" | "" => d.summary.as_str(),
                    other => {
                        // Field name match against summary text for MVP.
                        if d.summary
                            .to_ascii_lowercase()
                            .contains(&other.to_ascii_lowercase())
                        {
                            d.summary.as_str()
                        } else {
                            return false;
                        }
                    }
                };
                hay.to_ascii_lowercase()
                    .contains(&s.value.to_ascii_lowercase())
            })
        })
        .collect()
}
