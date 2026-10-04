use lw_core::{Error, Result, TsMicros};
use rusqlite::{params_from_iter, Connection};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PivotDimension {
    Computer,
    User,
    SrcIp,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PivotQuery {
    pub dimension: String, // computer | user | src_ip
    pub offset: u64,
    pub limit: u64,
    pub time_from: Option<TsMicros>,
    pub time_to: Option<TsMicros>,
    pub text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PivotRow {
    pub key: String,
    pub event_count: u64,
    pub detection_count: u64,
    pub critical: u64,
    pub high: u64,
    pub medium: u64,
    pub low: u64,
    pub informational: u64,
    pub first_ts: Option<i64>,
    pub last_ts: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogonSummaryRow {
    pub user_name: String,
    pub src_ip: String,
    pub logon_type: i64,
    pub logon_type_name: String,
    pub computer: String,
    pub success_count: u64,
    pub fail_count: u64,
    pub first_ts: Option<i64>,
    pub last_ts: Option<i64>,
}

pub fn logon_type_name(lt: i64) -> &'static str {
    match lt {
        2 => "Interactive",
        3 => "Network",
        4 => "Batch",
        5 => "Service",
        7 => "Unlock",
        8 => "NetworkCleartext",
        9 => "NewCredentials",
        10 => "RemoteInteractive",
        11 => "CachedInteractive",
        -1 => "Unknown",
        _ => "Other",
    }
}

pub fn query_pivots(conn: &Connection, q: &PivotQuery) -> Result<crate::query::Page<PivotRow>> {
    let dim = match q.dimension.as_str() {
        "user" | "users" => PivotDimension::User,
        "src_ip" | "ip" | "ips" => PivotDimension::SrcIp,
        _ => PivotDimension::Computer,
    };

    let (event_expr, det_expr, event_null) = match dim {
        PivotDimension::Computer => ("h.name", "d.computer", "h.name"),
        PivotDimension::User => ("e.user_name", "d.user_name", "e.user_name"),
        PivotDimension::SrcIp => ("e.src_ip", "NULL", "e.src_ip"),
    };

    // Event aggregates
    let mut where_e = vec!["1=1".into()];
    let mut params_e: Vec<rusqlite::types::Value> = Vec::new();
    if let Some(t) = q.time_from {
        where_e.push("e.ts >= ?".into());
        params_e.push(t.into());
    }
    if let Some(t) = q.time_to {
        where_e.push("e.ts <= ?".into());
        params_e.push(t.into());
    }
    where_e.push(format!("{event_null} IS NOT NULL AND {event_null} != ''"));
    if let Some(text) = &q.text {
        if !text.is_empty() {
            where_e.push(format!("{event_expr} LIKE ?"));
            params_e.push(format!("%{text}%").into());
        }
    }
    let where_e_sql = where_e.join(" AND ");

    let event_sql = format!(
        "SELECT {event_expr} AS k, COUNT(*) AS n, MIN(e.ts), MAX(e.ts)
         FROM events e
         JOIN dict_computer h ON h.id = e.computer_id
         WHERE {where_e_sql}
         GROUP BY k"
    );

    let mut map = std::collections::BTreeMap::<String, PivotRow>::new();
    {
        let mut stmt = conn
            .prepare(&event_sql)
            .map_err(|e| Error::Sqlite(e.to_string()))?;
        let rows = stmt
            .query_map(params_from_iter(params_e.iter().cloned()), |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)? as u64,
                    r.get::<_, Option<i64>>(2)?,
                    r.get::<_, Option<i64>>(3)?,
                ))
            })
            .map_err(|e| Error::Sqlite(e.to_string()))?;
        for row in rows {
            let (key, n, first, last) = row.map_err(|e| Error::Sqlite(e.to_string()))?;
            map.insert(
                key.clone(),
                PivotRow {
                    key,
                    event_count: n,
                    detection_count: 0,
                    critical: 0,
                    high: 0,
                    medium: 0,
                    low: 0,
                    informational: 0,
                    first_ts: first,
                    last_ts: last,
                },
            );
        }
    }

    // Detection aggregates (skip for src_ip — not stored on detections)
    if dim != PivotDimension::SrcIp {
        let mut where_d = vec!["1=1".into()];
        let mut params_d: Vec<rusqlite::types::Value> = Vec::new();
        if let Some(t) = q.time_from {
            where_d.push("d.ts >= ?".into());
            params_d.push(t.into());
        }
        if let Some(t) = q.time_to {
            where_d.push("d.ts <= ?".into());
            params_d.push(t.into());
        }
        where_d.push(format!("{det_expr} IS NOT NULL AND {det_expr} != ''"));
        if let Some(text) = &q.text {
            if !text.is_empty() {
                where_d.push(format!("{det_expr} LIKE ?"));
                params_d.push(format!("%{text}%").into());
            }
        }
        let where_d_sql = where_d.join(" AND ");
        let det_sql = format!(
            "SELECT {det_expr} AS k, COUNT(*),
                    SUM(CASE WHEN severity=4 THEN 1 ELSE 0 END),
                    SUM(CASE WHEN severity=3 THEN 1 ELSE 0 END),
                    SUM(CASE WHEN severity=2 THEN 1 ELSE 0 END),
                    SUM(CASE WHEN severity=1 THEN 1 ELSE 0 END),
                    SUM(CASE WHEN severity=0 THEN 1 ELSE 0 END),
                    MIN(d.ts), MAX(d.ts)
             FROM detections d WHERE {where_d_sql} GROUP BY k"
        );
        let mut stmt = conn
            .prepare(&det_sql)
            .map_err(|e| Error::Sqlite(e.to_string()))?;
        let rows = stmt
            .query_map(params_from_iter(params_d), |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)? as u64,
                    r.get::<_, i64>(2)? as u64,
                    r.get::<_, i64>(3)? as u64,
                    r.get::<_, i64>(4)? as u64,
                    r.get::<_, i64>(5)? as u64,
                    r.get::<_, i64>(6)? as u64,
                    r.get::<_, Option<i64>>(7)?,
                    r.get::<_, Option<i64>>(8)?,
                ))
            })
            .map_err(|e| Error::Sqlite(e.to_string()))?;
        for row in rows {
            let (key, n, crit, high, med, low, info, first, last) =
                row.map_err(|e| Error::Sqlite(e.to_string()))?;
            let entry = map.entry(key.clone()).or_insert(PivotRow {
                key: key.clone(),
                event_count: 0,
                detection_count: 0,
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                informational: 0,
                first_ts: None,
                last_ts: None,
            });
            entry.detection_count = n;
            entry.critical = crit;
            entry.high = high;
            entry.medium = med;
            entry.low = low;
            entry.informational = info;
            entry.first_ts = match (entry.first_ts, first) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
            entry.last_ts = match (entry.last_ts, last) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (a, b) => a.or(b),
            };
        }
    }

    let mut rows: Vec<PivotRow> = map.into_values().collect();
    rows.sort_by(|a, b| {
        b.detection_count
            .cmp(&a.detection_count)
            .then(b.event_count.cmp(&a.event_count))
            .then(a.key.cmp(&b.key))
    });
    let total = rows.len() as u64;
    let start = q.offset.min(total) as usize;
    let end = (start + q.limit.clamp(1, 1000) as usize).min(rows.len());
    Ok(crate::query::Page {
        rows: rows[start..end].to_vec(),
        total,
        offset: q.offset,
    })
}

pub fn query_logon_summary(
    conn: &Connection,
    q: &PivotQuery,
) -> Result<crate::query::Page<LogonSummaryRow>> {
    let mut where_parts: Vec<String> = vec!["1=1".into()];
    let mut params: Vec<rusqlite::types::Value> = Vec::new();
    if let Some(t) = q.time_from {
        where_parts.push("last_ts >= ?".into());
        params.push(t.into());
    }
    if let Some(t) = q.time_to {
        where_parts.push("first_ts <= ?".into());
        params.push(t.into());
    }
    if let Some(text) = &q.text {
        if !text.is_empty() {
            where_parts.push("(user_name LIKE ? OR src_ip LIKE ? OR computer LIKE ?)".into());
            let pat = format!("%{text}%");
            params.push(pat.clone().into());
            params.push(pat.clone().into());
            params.push(pat.into());
        }
    }
    let where_sql = where_parts.join(" AND ");
    let total: u64 = conn
        .query_row(
            &format!("SELECT COUNT(*) FROM logon_summary WHERE {where_sql}"),
            params_from_iter(params.iter().cloned()),
            |r| r.get::<_, i64>(0),
        )
        .map_err(|e| Error::Sqlite(e.to_string()))? as u64;

    let limit = q.limit.clamp(1, 1000);
    let sql = format!(
        "SELECT user_name, src_ip, logon_type, computer, success_count, fail_count, first_ts, last_ts
         FROM logon_summary WHERE {where_sql}
         ORDER BY (success_count + fail_count) DESC, computer, user_name
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
            let lt: i64 = r.get(2)?;
            Ok(LogonSummaryRow {
                user_name: r.get(0)?,
                src_ip: r.get(1)?,
                logon_type: lt,
                logon_type_name: logon_type_name(lt).into(),
                computer: r.get(3)?,
                success_count: r.get::<_, i64>(4)? as u64,
                fail_count: r.get::<_, i64>(5)? as u64,
                first_ts: r.get(6)?,
                last_ts: r.get(7)?,
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
