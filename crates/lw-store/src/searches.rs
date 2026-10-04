use lw_core::{Error, Result};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedSearch {
    pub id: i64,
    pub name: String,
    pub query_json: String,
    pub created_at: i64,
}

pub fn list_saved_searches(conn: &Connection) -> Result<Vec<SavedSearch>> {
    let mut stmt = conn
        .prepare(
            "SELECT id, name, query_json, created_at FROM saved_searches ORDER BY created_at DESC",
        )
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    let rows = stmt
        .query_map([], |r| {
            Ok(SavedSearch {
                id: r.get(0)?,
                name: r.get(1)?,
                query_json: r.get(2)?,
                created_at: r.get(3)?,
            })
        })
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| Error::Sqlite(e.to_string()))?);
    }
    Ok(out)
}

pub fn save_search(conn: &Connection, name: &str, query_json: &str) -> Result<i64> {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    conn.execute(
        "INSERT INTO saved_searches(name, query_json, created_at) VALUES (?1,?2,?3)",
        params![name, query_json, now],
    )
    .map_err(|e| Error::Sqlite(e.to_string()))?;
    Ok(conn.last_insert_rowid())
}

pub fn delete_saved_search(conn: &Connection, id: i64) -> Result<()> {
    conn.execute("DELETE FROM saved_searches WHERE id=?1", params![id])
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    Ok(())
}
