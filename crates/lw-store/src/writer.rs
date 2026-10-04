use crate::schema::{FINALIZE_INDEXES, FTS_CREATE};
use lw_core::{Error, NormalizedEvent, Result, SourceFile};
use rusqlite::{params, Connection};
use std::collections::HashMap;
use std::path::PathBuf;
use std::thread::JoinHandle;

pub enum StoreWriteCmd {
    UpsertFile(SourceFile),
    InsertEvents(Vec<NormalizedEvent>),
    Finalize {
        build_fts: bool,
    },
    /// Block the sender until the writer has processed all prior commands.
    Sync(std::sync::mpsc::Sender<()>),
    Shutdown,
}

pub struct WriterHandle {
    tx: crossbeam_channel::Sender<StoreWriteCmd>,
    join: Option<JoinHandle<Result<()>>>,
}

impl WriterHandle {
    pub fn sender(&self) -> crossbeam_channel::Sender<StoreWriteCmd> {
        self.tx.clone()
    }

    pub fn send(&self, cmd: StoreWriteCmd) -> Result<()> {
        self.tx
            .send(cmd)
            .map_err(|_| Error::msg("store writer channel closed"))
    }

    /// Wait until the writer has drained commands sent before this call.
    pub fn sync(&self) -> Result<()> {
        let (tx, rx) = std::sync::mpsc::channel();
        self.send(StoreWriteCmd::Sync(tx))?;
        rx.recv()
            .map_err(|_| Error::msg("store writer sync failed"))
    }

    pub fn join(mut self) -> Result<()> {
        if let Some(j) = self.join.take() {
            j.join()
                .map_err(|_| Error::msg("store writer panicked"))??;
        }
        Ok(())
    }
}

pub fn spawn_writer(db_path: PathBuf) -> Result<WriterHandle> {
    let (tx, rx) = crossbeam_channel::bounded::<StoreWriteCmd>(8);
    let join = std::thread::Builder::new()
        .name("lw-store-writer".into())
        .spawn(move || writer_loop(db_path, rx))
        .map_err(|e| Error::msg(format!("spawn writer: {e}")))?;
    Ok(WriterHandle {
        tx,
        join: Some(join),
    })
}

fn writer_loop(db_path: PathBuf, rx: crossbeam_channel::Receiver<StoreWriteCmd>) -> Result<()> {
    let mut conn = Connection::open(db_path).map_err(|e| Error::Sqlite(e.to_string()))?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA temp_store=MEMORY;",
    )
    .map_err(|e| Error::Sqlite(e.to_string()))?;

    let mut channel_cache: HashMap<String, i64> = HashMap::new();
    let mut provider_cache: HashMap<String, i64> = HashMap::new();
    let mut computer_cache: HashMap<String, i64> = HashMap::new();

    while let Ok(cmd) = rx.recv() {
        match cmd {
            StoreWriteCmd::UpsertFile(f) => {
                upsert_file(&conn, &f)?;
            }
            StoreWriteCmd::InsertEvents(events) => {
                insert_events_batch(
                    &mut conn,
                    &events,
                    &mut channel_cache,
                    &mut provider_cache,
                    &mut computer_cache,
                )?;
            }
            StoreWriteCmd::Finalize { build_fts } => {
                finalize(&mut conn, build_fts)?;
            }
            StoreWriteCmd::Sync(done) => {
                let _ = done.send(());
            }
            StoreWriteCmd::Shutdown => break,
        }
    }
    Ok(())
}

fn upsert_file(conn: &Connection, f: &SourceFile) -> Result<()> {
    conn.execute(
        "INSERT INTO files(id, path, size, sha256, mtime, records_ok, records_err, is_dirty, first_ts, last_ts, error)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)
         ON CONFLICT(id) DO UPDATE SET
           path=excluded.path, size=excluded.size, sha256=excluded.sha256, mtime=excluded.mtime,
           records_ok=excluded.records_ok, records_err=excluded.records_err, is_dirty=excluded.is_dirty,
           first_ts=excluded.first_ts, last_ts=excluded.last_ts, error=excluded.error",
        params![
            f.id,
            f.path,
            f.size as i64,
            f.sha256,
            f.mtime,
            f.records_ok as i64,
            f.records_err as i64,
            f.is_dirty.map(i64::from),
            f.first_ts,
            f.last_ts,
            f.error,
        ],
    )
    .map_err(|e| Error::Sqlite(e.to_string()))?;
    Ok(())
}

fn dict_id(
    conn: &Connection,
    cache: &mut HashMap<String, i64>,
    table: &str,
    name: &str,
) -> Result<i64> {
    if let Some(id) = cache.get(name) {
        return Ok(*id);
    }
    conn.execute(
        &format!("INSERT OR IGNORE INTO {table}(name) VALUES (?1)"),
        params![name],
    )
    .map_err(|e| Error::Sqlite(e.to_string()))?;
    let id: i64 = conn
        .query_row(
            &format!("SELECT id FROM {table} WHERE name = ?1"),
            params![name],
            |r| r.get(0),
        )
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    cache.insert(name.to_string(), id);
    Ok(id)
}

fn insert_events_batch(
    conn: &mut Connection,
    events: &[NormalizedEvent],
    channel_cache: &mut HashMap<String, i64>,
    provider_cache: &mut HashMap<String, i64>,
    computer_cache: &mut HashMap<String, i64>,
) -> Result<()> {
    if events.is_empty() {
        return Ok(());
    }
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|e| Error::Sqlite(e.to_string()))?;

    // Resolve dictionary IDs first to avoid overlapping borrows with the insert statement.
    let mut prepared = Vec::with_capacity(events.len());
    for ev in events {
        let channel_id = dict_id(&tx, channel_cache, "dict_channel", &ev.channel)?;
        let provider_id = dict_id(&tx, provider_cache, "dict_provider", &ev.provider)?;
        let computer_id = dict_id(&tx, computer_cache, "dict_computer", &ev.computer)?;
        let fields_json = serde_json::to_string(&ev.fields)?;
        let raw_zstd = ev
            .raw_json
            .as_ref()
            .map(|b| zstd::encode_all(b.as_slice(), 1))
            .transpose()
            .map_err(|e| Error::msg(format!("zstd: {e}")))?;
        prepared.push((
            ev,
            channel_id,
            provider_id,
            computer_id,
            fields_json,
            raw_zstd,
        ));
    }

    {
        let mut stmt = tx
            .prepare_cached(
                "INSERT INTO events(
                    file_id, source_type, record_id, ts, event_id,
                    channel_id, provider_id, computer_id, level,
                    user_name, src_ip, logon_type, fields_json, raw_zstd
                 ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
            )
            .map_err(|e| Error::Sqlite(e.to_string()))?;

        for (ev, channel_id, provider_id, computer_id, fields_json, raw_zstd) in prepared {
            stmt.execute(params![
                ev.file_id,
                ev.source_type.as_str(),
                ev.record_id as i64,
                ev.ts,
                ev.event_id,
                channel_id,
                provider_id,
                computer_id,
                ev.level.map(i64::from),
                ev.user_name,
                ev.src_ip,
                ev.logon_type,
                fields_json,
                raw_zstd,
            ])
            .map_err(|e| Error::Sqlite(e.to_string()))?;
        }
    }

    tx.commit().map_err(|e| Error::Sqlite(e.to_string()))?;
    Ok(())
}

fn finalize(conn: &mut Connection, build_fts: bool) -> Result<()> {
    conn.execute_batch(FINALIZE_INDEXES)
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    if build_fts {
        conn.execute_batch(FTS_CREATE)
            .map_err(|e| Error::Sqlite(e.to_string()))?;
        conn.execute("DELETE FROM events_fts", [])
            .map_err(|e| Error::Sqlite(e.to_string()))?;

        type FtsRow = (
            i64,
            i64,
            Option<String>,
            Option<String>,
            String,
            String,
            String,
            String,
        );
        let rows: Vec<FtsRow> = {
            let mut stmt = conn
                .prepare(
                    "SELECT e.id, e.event_id, e.user_name, e.src_ip, e.fields_json,
                            c.name, p.name, h.name
                     FROM events e
                     JOIN dict_channel c ON c.id = e.channel_id
                     JOIN dict_provider p ON p.id = e.provider_id
                     JOIN dict_computer h ON h.id = e.computer_id",
                )
                .map_err(|e| Error::Sqlite(e.to_string()))?;
            let mapped = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, Option<String>>(2)?,
                        r.get::<_, Option<String>>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, String>(5)?,
                        r.get::<_, String>(6)?,
                        r.get::<_, String>(7)?,
                    ))
                })
                .map_err(|e| Error::Sqlite(e.to_string()))?;
            let mut out = Vec::new();
            for row in mapped {
                out.push(row.map_err(|e| Error::Sqlite(e.to_string()))?);
            }
            out
        };

        let tx = conn
            .transaction()
            .map_err(|e| Error::Sqlite(e.to_string()))?;
        {
            let mut ins = tx
                .prepare("INSERT INTO events_fts(rowid, text) VALUES (?1, ?2)")
                .map_err(|e| Error::Sqlite(e.to_string()))?;
            for (id, eid, user, ip, fields_json, channel, provider, computer) in rows {
                let mut text = format!("{channel} {provider} {computer} {eid} ");
                if let Some(u) = user {
                    text.push_str(&u);
                    text.push(' ');
                }
                if let Some(i) = ip {
                    text.push_str(&i);
                    text.push(' ');
                }
                if let Ok(serde_json::Value::Object(map)) =
                    serde_json::from_str::<serde_json::Value>(&fields_json)
                {
                    for (k, v) in map {
                        text.push_str(&k);
                        text.push(' ');
                        match v {
                            serde_json::Value::String(s) => {
                                text.push_str(&s);
                                text.push(' ');
                            }
                            serde_json::Value::Number(n) => {
                                text.push_str(&n.to_string());
                                text.push(' ');
                            }
                            _ => {}
                        }
                    }
                }
                ins.execute(params![id, text])
                    .map_err(|e| Error::Sqlite(e.to_string()))?;
            }
        }
        tx.commit().map_err(|e| Error::Sqlite(e.to_string()))?;
    }
    Ok(())
}
