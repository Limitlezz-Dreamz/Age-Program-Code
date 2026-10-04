use crate::schema::MIGRATION_0001;
use crate::writer::{spawn_writer, StoreWriteCmd, WriterHandle};
use lw_core::{CaseInfo, Error, Result, APP_NAME, CASE_EXT};
use rusqlite::{Connection, OpenFlags};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

pub struct CaseStore {
    pub root: PathBuf,
    pub db_path: PathBuf,
    writer: WriterHandle,
}

impl CaseStore {
    pub fn writer(&self) -> &WriterHandle {
        &self.writer
    }

    pub fn open_read_only(&self) -> Result<Connection> {
        Connection::open_with_flags(
            &self.db_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| Error::Sqlite(e.to_string()))
    }

    pub fn info(&self) -> Result<CaseInfo> {
        let p = self.root.join("case.json");
        let text = fs::read_to_string(p)?;
        serde_json::from_str(&text).map_err(|e| Error::msg(e.to_string()))
    }

    pub fn shutdown(self) -> Result<()> {
        self.writer.send(StoreWriteCmd::Shutdown)?;
        self.writer.join()
    }
}

/// Create `<name>.lwcase` under `dir` (or use `dir` if it already ends with `.lwcase`).
pub fn create_case(dir: impl AsRef<Path>, name: &str) -> Result<CaseStore> {
    let dir = dir.as_ref();
    fs::create_dir_all(dir)?;
    let root = if dir.extension().and_then(|e| e.to_str()) == Some(CASE_EXT) {
        dir.to_path_buf()
    } else {
        dir.join(format!("{name}.{CASE_EXT}"))
    };
    fs::create_dir_all(&root)?;
    fs::create_dir_all(root.join("exports"))?;
    fs::create_dir_all(root.join("logs"))?;

    let db_path = root.join("case.db");
    {
        let conn = Connection::open(&db_path).map_err(|e| Error::Sqlite(e.to_string()))?;
        conn.execute_batch(MIGRATION_0001)
            .map_err(|e| Error::Sqlite(e.to_string()))?;
        conn.execute(
            "INSERT OR REPLACE INTO meta(key,value) VALUES ('schema_version', '1')",
            [],
        )
        .map_err(|e| Error::Sqlite(e.to_string()))?;
        conn.execute(
            "INSERT OR REPLACE INTO meta(key,value) VALUES ('app_version', ?1)",
            [env!("CARGO_PKG_VERSION")],
        )
        .map_err(|e| Error::Sqlite(e.to_string()))?;
        conn.execute(
            "INSERT OR REPLACE INTO meta(key,value) VALUES ('case_name', ?1)",
            [name],
        )
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    }

    let created = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into());
    let info = CaseInfo {
        name: name.to_string(),
        path: root.display().to_string(),
        created_at: created,
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        input_paths: vec![],
        notes: format!("Created by {APP_NAME}"),
    };
    fs::write(root.join("case.json"), serde_json::to_string_pretty(&info)?)?;

    let writer = spawn_writer(db_path.clone())?;
    Ok(CaseStore {
        root,
        db_path,
        writer,
    })
}

pub fn open_case(path: impl AsRef<Path>) -> Result<CaseStore> {
    let root = path.as_ref().to_path_buf();
    let db_path = if root.is_file() && root.extension().and_then(|e| e.to_str()) == Some("db") {
        let parent = root
            .parent()
            .ok_or_else(|| Error::InvalidCase("db has no parent".into()))?
            .to_path_buf();
        let writer = spawn_writer(root.clone())?;
        return Ok(CaseStore {
            root: parent,
            db_path: root,
            writer,
        });
    } else {
        root.join("case.db")
    };
    if !db_path.exists() {
        return Err(Error::InvalidCase(format!(
            "missing case.db under {}",
            root.display()
        )));
    }
    // Ensure schema (idempotent).
    {
        let conn = Connection::open(&db_path).map_err(|e| Error::Sqlite(e.to_string()))?;
        conn.execute_batch(MIGRATION_0001)
            .map_err(|e| Error::Sqlite(e.to_string()))?;
    }
    let writer = spawn_writer(db_path.clone())?;
    Ok(CaseStore {
        root,
        db_path,
        writer,
    })
}

/// Append input paths into case.json metadata.
pub fn record_inputs(root: &Path, paths: &[String]) -> Result<()> {
    let p = root.join("case.json");
    let mut info: CaseInfo = serde_json::from_str(&fs::read_to_string(&p)?)?;
    info.input_paths.extend(paths.iter().cloned());
    fs::write(p, serde_json::to_string_pretty(&info)?)?;
    Ok(())
}

pub fn write_run_stats(root: &Path, stats: &lw_core::IngestStats) -> Result<()> {
    let p = root.join("case.json");
    // Keep case.json lean; also stash last stats beside it.
    let stats_path = root.join("last_ingest.json");
    fs::write(stats_path, serde_json::to_string_pretty(&json!(stats))?)?;
    let _ = p;
    Ok(())
}
