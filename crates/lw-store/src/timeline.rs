use lw_core::{Error, Result, TsMicros};
use rusqlite::{params_from_iter, Connection};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HistogramQuery {
    pub time_from: Option<TsMicros>,
    pub time_to: Option<TsMicros>,
    pub computers: Vec<String>,
    pub channels: Vec<String>,
    /// "severity" (detections) or "channel" (events) stacking key.
    pub series: String,
    /// Optional fixed bucket in micros; None = auto.
    pub bucket_micros: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistogramBucket {
    pub ts: i64,
    pub series: String,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineItem {
    pub kind: String, // "detection" | "event"
    pub id: i64,
    pub ts: i64,
    pub computer: String,
    pub label: String,
    pub severity: Option<String>,
    pub event_id: Option<u32>,
    pub channel: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TimelineListQuery {
    pub offset: u64,
    pub limit: u64,
    pub time_from: Option<TsMicros>,
    pub time_to: Option<TsMicros>,
    pub computers: Vec<String>,
    pub include_events: bool,
    pub text: Option<String>,
}

fn auto_bucket(first: i64, last: i64) -> i64 {
    let span = (last - first).max(1);
    // Target ~80 buckets; clamp 1s … 1d.
    let b = span / 80;
    b.clamp(1_000_000, 86_400_000_000)
}

pub fn timeline_histogram(conn: &Connection, q: &HistogramQuery) -> Result<Vec<HistogramBucket>> {
    let first: Option<i64> = conn
        .query_row("SELECT MIN(ts) FROM events", [], |r| r.get(0))
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    let last: Option<i64> = conn
        .query_row("SELECT MAX(ts) FROM events", [], |r| r.get(0))
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    let (Some(mut first), Some(mut last)) = (first, last) else {
        return Ok(Vec::new());
    };
    if let Some(t) = q.time_from {
        first = first.max(t);
    }
    if let Some(t) = q.time_to {
        last = last.min(t);
    }
    if last <= first {
        return Ok(Vec::new());
    }
    let bucket = q.bucket_micros.unwrap_or_else(|| auto_bucket(first, last));

    if q.series.eq_ignore_ascii_case("channel") {
        histogram_events(conn, q, bucket)
    } else {
        histogram_detections(conn, q, bucket)
    }
}

fn histogram_detections(
    conn: &Connection,
    q: &HistogramQuery,
    bucket: i64,
) -> Result<Vec<HistogramBucket>> {
    let mut where_parts = vec!["1=1".into()];
    let mut params: Vec<rusqlite::types::Value> = vec![bucket.into(), bucket.into()];
    if let Some(t) = q.time_from {
        where_parts.push("ts >= ?".into());
        params.push(t.into());
    }
    if let Some(t) = q.time_to {
        where_parts.push("ts <= ?".into());
        params.push(t.into());
    }
    if !q.computers.is_empty() {
        let ph = q
            .computers
            .iter()
            .map(|_| "?")
            .collect::<Vec<_>>()
            .join(",");
        where_parts.push(format!("computer IN ({ph})"));
        for c in &q.computers {
            params.push(c.clone().into());
        }
    }
    let where_sql = where_parts.join(" AND ");
    let sql = format!(
        "SELECT (ts / ?) * ? AS bucket, severity, COUNT(*)
         FROM detections WHERE {where_sql}
         GROUP BY bucket, severity ORDER BY bucket ASC, severity ASC LIMIT 2000"
    );
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    let rows = stmt
        .query_map(params_from_iter(params), |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)? as u64,
            ))
        })
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    let mut out = Vec::new();
    for row in rows {
        let (ts, sev, count) = row.map_err(|e| Error::Sqlite(e.to_string()))?;
        out.push(HistogramBucket {
            ts,
            series: severity_name(sev).into(),
            count,
        });
    }
    Ok(out)
}

fn histogram_events(
    conn: &Connection,
    q: &HistogramQuery,
    bucket: i64,
) -> Result<Vec<HistogramBucket>> {
    let mut where_parts = vec!["1=1".into()];
    let mut params: Vec<rusqlite::types::Value> = vec![bucket.into(), bucket.into()];
    if let Some(t) = q.time_from {
        where_parts.push("e.ts >= ?".into());
        params.push(t.into());
    }
    if let Some(t) = q.time_to {
        where_parts.push("e.ts <= ?".into());
        params.push(t.into());
    }
    if !q.computers.is_empty() {
        let ph = q
            .computers
            .iter()
            .map(|_| "?")
            .collect::<Vec<_>>()
            .join(",");
        where_parts.push(format!("h.name IN ({ph})"));
        for c in &q.computers {
            params.push(c.clone().into());
        }
    }
    if !q.channels.is_empty() {
        let ph = q.channels.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        where_parts.push(format!("c.name IN ({ph})"));
        for c in &q.channels {
            params.push(c.clone().into());
        }
    }
    let where_sql = where_parts.join(" AND ");
    let sql = format!(
        "SELECT (e.ts / ?) * ? AS bucket, c.name, COUNT(*)
         FROM events e
         JOIN dict_channel c ON c.id = e.channel_id
         JOIN dict_computer h ON h.id = e.computer_id
         WHERE {where_sql}
         GROUP BY bucket, c.name ORDER BY bucket ASC LIMIT 2000"
    );
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    let rows = stmt
        .query_map(params_from_iter(params), |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)? as u64,
            ))
        })
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    let mut out = Vec::new();
    for row in rows {
        let (ts, series, count) = row.map_err(|e| Error::Sqlite(e.to_string()))?;
        out.push(HistogramBucket { ts, series, count });
    }
    Ok(out)
}

fn severity_name(v: i64) -> &'static str {
    match v {
        0 => "informational",
        1 => "low",
        2 => "medium",
        3 => "high",
        4 => "critical",
        _ => "informational",
    }
}

pub fn timeline_list(
    conn: &Connection,
    q: &TimelineListQuery,
) -> Result<crate::query::Page<TimelineItem>> {
    let mut items = Vec::new();
    // Detections
    {
        let mut where_parts = vec!["1=1".into()];
        let mut params: Vec<rusqlite::types::Value> = Vec::new();
        if let Some(t) = q.time_from {
            where_parts.push("ts >= ?".into());
            params.push(t.into());
        }
        if let Some(t) = q.time_to {
            where_parts.push("ts <= ?".into());
            params.push(t.into());
        }
        if !q.computers.is_empty() {
            let ph = q
                .computers
                .iter()
                .map(|_| "?")
                .collect::<Vec<_>>()
                .join(",");
            where_parts.push(format!("computer IN ({ph})"));
            for c in &q.computers {
                params.push(c.clone().into());
            }
        }
        if let Some(text) = &q.text {
            if !text.is_empty() {
                where_parts.push("(summary LIKE ? OR rule_title LIKE ?)".into());
                let pat = format!("%{text}%");
                params.push(pat.clone().into());
                params.push(pat.into());
            }
        }
        let where_sql = where_parts.join(" AND ");
        let sql = format!(
            "SELECT id, ts, computer, rule_title, severity FROM detections
             WHERE {where_sql} ORDER BY ts ASC, id ASC LIMIT 5000"
        );
        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| Error::Sqlite(e.to_string()))?;
        let rows = stmt
            .query_map(params_from_iter(params), |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                    r.get::<_, String>(3)?,
                    r.get::<_, i64>(4)?,
                ))
            })
            .map_err(|e| Error::Sqlite(e.to_string()))?;
        for row in rows {
            let (id, ts, computer, title, sev) = row.map_err(|e| Error::Sqlite(e.to_string()))?;
            items.push(TimelineItem {
                kind: "detection".into(),
                id,
                ts,
                computer,
                label: title,
                severity: Some(severity_name(sev).into()),
                event_id: None,
                channel: None,
            });
        }
    }

    if q.include_events {
        let mut where_parts = vec!["1=1".into()];
        let mut params: Vec<rusqlite::types::Value> = Vec::new();
        if let Some(t) = q.time_from {
            where_parts.push("e.ts >= ?".into());
            params.push(t.into());
        }
        if let Some(t) = q.time_to {
            where_parts.push("e.ts <= ?".into());
            params.push(t.into());
        }
        if !q.computers.is_empty() {
            let ph = q
                .computers
                .iter()
                .map(|_| "?")
                .collect::<Vec<_>>()
                .join(",");
            where_parts.push(format!("h.name IN ({ph})"));
            for c in &q.computers {
                params.push(c.clone().into());
            }
        }
        let where_sql = where_parts.join(" AND ");
        let sql = format!(
            "SELECT e.id, e.ts, h.name, e.event_id, c.name FROM events e
             JOIN dict_computer h ON h.id = e.computer_id
             JOIN dict_channel c ON c.id = e.channel_id
             WHERE {where_sql}
             ORDER BY e.ts ASC, e.id ASC LIMIT 5000"
        );
        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| Error::Sqlite(e.to_string()))?;
        let rows = stmt
            .query_map(params_from_iter(params), |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)? as u32,
                    r.get::<_, String>(4)?,
                ))
            })
            .map_err(|e| Error::Sqlite(e.to_string()))?;
        for row in rows {
            let (id, ts, computer, event_id, channel) =
                row.map_err(|e| Error::Sqlite(e.to_string()))?;
            items.push(TimelineItem {
                kind: "event".into(),
                id,
                ts,
                computer,
                label: format!("EID {event_id}"),
                severity: None,
                event_id: Some(event_id),
                channel: Some(channel),
            });
        }
    }

    items.sort_by(|a, b| a.ts.cmp(&b.ts).then(a.id.cmp(&b.id)));
    let total = items.len() as u64;
    let start = q.offset.min(total) as usize;
    let end = (start + q.limit.clamp(1, 1000) as usize).min(items.len());
    Ok(crate::query::Page {
        rows: items[start..end].to_vec(),
        total,
        offset: q.offset,
    })
}
