use lw_core::{Error, Result, SourceFile};
use rusqlite::Connection;

/// List all evidence files in the case DB.
pub fn list_files(conn: &Connection) -> Result<Vec<SourceFile>> {
    let mut stmt = conn
        .prepare(
            "SELECT id, path, size, sha256, mtime, records_ok, records_err, is_dirty, first_ts, last_ts, error
             FROM files ORDER BY id",
        )
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    let rows = stmt
        .query_map([], |r| {
            Ok(SourceFile {
                id: r.get(0)?,
                path: r.get(1)?,
                size: r.get::<_, i64>(2)? as u64,
                sha256: r.get(3)?,
                mtime: r.get(4)?,
                channel_hint: None,
                records_ok: r.get::<_, i64>(5)? as u64,
                records_err: r.get::<_, i64>(6)? as u64,
                is_dirty: r.get::<_, Option<i64>>(7)?.map(|v| v != 0),
                first_ts: r.get(8)?,
                last_ts: r.get(9)?,
                error: r.get(10)?,
            })
        })
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(|e| Error::Sqlite(e.to_string()))?);
    }
    Ok(out)
}
