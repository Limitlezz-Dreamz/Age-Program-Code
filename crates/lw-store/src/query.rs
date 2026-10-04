use lw_core::{Error, Result, TsMicros};
use rusqlite::{params_from_iter, Connection};
use serde::{Deserialize, Serialize};

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
    pub text: Option<String>,
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
    if let Some(text) = &q.text {
        if !text.is_empty() {
            where_parts
                .push("e.id IN (SELECT rowid FROM events_fts WHERE events_fts MATCH ?)".into());
            params.push(text.clone().into());
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
                c.name, p.name, h.name, e.user_name, e.src_ip, e.logon_type
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
