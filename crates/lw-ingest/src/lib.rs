#![deny(unsafe_code)]

//! EVTX discovery, hashing, and parallel parsing.

mod discover;
mod hash;
mod parse;

pub use discover::{discover_evtx_paths, is_evtx_file};
pub use hash::sha256_file;
pub use parse::{parse_evtx_file, ParseFileResult, ParseOptions};

use lw_core::{
    CancellationToken, DiscoveredFile, Error, IngestStats, NormalizedEvent, Result, SourceFile,
};
use lw_normalize::{default_4688_aliases, FieldAliasRule};
use rayon::prelude::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct IngestOptions {
    pub hash_files: bool,
    pub num_threads: usize,
    pub aliases: Vec<FieldAliasRule>,
    pub batch_size: usize,
}

impl Default for IngestOptions {
    fn default() -> Self {
        Self {
            hash_files: true,
            num_threads: num_cpus::get(),
            aliases: default_4688_aliases(),
            batch_size: 5_000,
        }
    }
}

#[derive(Debug, Clone)]
pub enum IngestEvent {
    Discovered {
        files: usize,
        bytes: u64,
    },
    /// Emitted before any batches so the store can insert the `files` row (FK).
    FileStarted {
        file: SourceFile,
    },
    FileFinished {
        file: SourceFile,
    },
    Batch {
        events: Vec<NormalizedEvent>,
    },
    Progress {
        files_done: u64,
        files_total: u64,
        records_ok: u64,
        records_err: u64,
    },
    Finished {
        stats: IngestStats,
    },
}

/// Discover EVTX inputs under `paths` (files or directories).
pub fn discover(paths: &[PathBuf]) -> Result<Vec<DiscoveredFile>> {
    discover_evtx_paths(paths)
}

/// Parse discovered files in parallel, invoking `on_event` for progress and batches.
///
/// The callback must be cheap; store writes should happen on a dedicated writer.
pub fn ingest_files<F>(
    files: &[DiscoveredFile],
    opts: &IngestOptions,
    cancel: &CancellationToken,
    mut on_event: F,
) -> Result<IngestStats>
where
    F: FnMut(IngestEvent) + Send,
{
    let started = Instant::now();
    let total_bytes: u64 = files.iter().map(|f| f.size).sum();
    on_event(IngestEvent::Discovered {
        files: files.len(),
        bytes: total_bytes,
    });

    let files_total = files.len() as u64;
    let files_done = Arc::new(AtomicU64::new(0));
    let records_ok = Arc::new(AtomicU64::new(0));
    let records_err = Arc::new(AtomicU64::new(0));
    let files_ok = Arc::new(AtomicU64::new(0));
    let files_err = Arc::new(AtomicU64::new(0));

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(opts.num_threads.max(1))
        .build()
        .map_err(|e| Error::msg(format!("rayon pool: {e}")))?;

    // Cap per-file evtx threads so we don't oversubscribe.
    let per_file_threads = (opts.num_threads.max(1) / files.len().max(1)).max(1);

    let (tx, rx) = crossbeam_channel::bounded::<IngestEvent>(16);
    let aliases = opts.aliases.clone();
    let hash_files = opts.hash_files;
    let batch_size = opts.batch_size;
    let cancel = cancel.clone();

    let producer = {
        let tx = tx.clone();
        let files = files.to_vec();
        let files_done = Arc::clone(&files_done);
        let records_ok = Arc::clone(&records_ok);
        let records_err = Arc::clone(&records_err);
        let files_ok = Arc::clone(&files_ok);
        let files_err = Arc::clone(&files_err);
        std::thread::spawn(move || {
            pool.install(|| {
                files.par_iter().enumerate().try_for_each(|(idx, df)| {
                    cancel.check()?;
                    let file_id = (idx as i64) + 1;
                    let mut stub = source_file_stub(df, file_id);
                    let _ = tx.send(IngestEvent::FileStarted { file: stub.clone() });

                    let sha = if hash_files {
                        match sha256_file(&df.path) {
                            Ok(h) => Some(h),
                            Err(e) => {
                                stub.error = Some(format!("hash failed: {e}"));
                                files_err.fetch_add(1, Ordering::Relaxed);
                                files_done.fetch_add(1, Ordering::Relaxed);
                                let _ = tx.send(IngestEvent::FileFinished { file: stub });
                                return Ok(());
                            }
                        }
                    } else {
                        None
                    };

                    let parse_opts = ParseOptions {
                        file_id,
                        num_threads: per_file_threads,
                        aliases: aliases.clone(),
                        batch_size,
                    };

                    match parse_evtx_file(&df.path, &parse_opts, &cancel, |batch| {
                        let _ = tx.send(IngestEvent::Batch { events: batch });
                    }) {
                        Ok(result) => {
                            records_ok.fetch_add(result.records_ok, Ordering::Relaxed);
                            records_err.fetch_add(result.records_err, Ordering::Relaxed);
                            let mut sf = SourceFile {
                                id: file_id,
                                path: df.path.display().to_string(),
                                size: df.size,
                                sha256: sha,
                                mtime: df.mtime,
                                channel_hint: result.channel_hint,
                                records_ok: result.records_ok,
                                records_err: result.records_err,
                                is_dirty: result.is_dirty,
                                first_ts: result.first_ts,
                                last_ts: result.last_ts,
                                error: result.error,
                            };
                            if sf.records_ok == 0 && sf.error.is_some() {
                                sf.records_err = sf.records_err.max(1);
                                files_err.fetch_add(1, Ordering::Relaxed);
                            } else {
                                files_ok.fetch_add(1, Ordering::Relaxed);
                            }
                            files_done.fetch_add(1, Ordering::Relaxed);
                            let _ = tx.send(IngestEvent::FileFinished { file: sf });
                            let _ = tx.send(IngestEvent::Progress {
                                files_done: files_done.load(Ordering::Relaxed),
                                files_total,
                                records_ok: records_ok.load(Ordering::Relaxed),
                                records_err: records_err.load(Ordering::Relaxed),
                            });
                            Ok(())
                        }
                        Err(Error::Cancelled) => Err(Error::Cancelled),
                        Err(e) => {
                            let mut sf = source_file_stub(df, file_id);
                            sf.sha256 = sha;
                            sf.error = Some(e.to_string());
                            files_err.fetch_add(1, Ordering::Relaxed);
                            files_done.fetch_add(1, Ordering::Relaxed);
                            let _ = tx.send(IngestEvent::FileFinished { file: sf });
                            Ok(())
                        }
                    }
                })
            })
        })
    };

    drop(tx);

    let mut cancelled = false;
    while let Ok(ev) = rx.recv() {
        if matches!(ev, IngestEvent::Finished { .. }) {
            break;
        }
        on_event(ev);
    }

    match producer.join() {
        Ok(Ok(())) => {}
        Ok(Err(Error::Cancelled)) => cancelled = true,
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err(Error::msg("ingest worker panicked")),
    }

    if cancelled {
        return Err(Error::Cancelled);
    }

    let elapsed = started.elapsed();
    let ok = records_ok.load(Ordering::Relaxed);
    let eps = if elapsed.as_secs_f64() > 0.0 {
        ok as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };
    let stats = IngestStats {
        files_ok: files_ok.load(Ordering::Relaxed),
        files_err: files_err.load(Ordering::Relaxed),
        records_ok: ok,
        records_err: records_err.load(Ordering::Relaxed),
        bytes: total_bytes,
        elapsed_ms: elapsed.as_millis() as u64,
        events_per_sec: eps,
    };
    on_event(IngestEvent::Finished {
        stats: stats.clone(),
    });
    Ok(stats)
}

fn source_file_stub(df: &DiscoveredFile, file_id: i64) -> SourceFile {
    SourceFile {
        id: file_id,
        path: df.path.display().to_string(),
        size: df.size,
        sha256: None,
        mtime: df.mtime,
        channel_hint: None,
        records_ok: 0,
        records_err: 0,
        is_dirty: None,
        first_ts: None,
        last_ts: None,
        error: None,
    }
}

/// Convenience: discover + ingest paths.
pub fn ingest_paths<F>(
    paths: &[PathBuf],
    opts: &IngestOptions,
    cancel: &CancellationToken,
    on_event: F,
) -> Result<IngestStats>
where
    F: FnMut(IngestEvent) + Send,
{
    let files = discover(paths)?;
    if files.is_empty() {
        return Err(Error::msg("no EVTX files discovered"));
    }
    ingest_files(&files, opts, cancel, on_event)
}

pub fn crate_name() -> &'static str {
    env!("CARGO_PKG_NAME")
}

/// Resolve field-aliases YAML from bundled / workspace resources.
pub fn default_aliases_path() -> Option<PathBuf> {
    lw_core::resource_file("mappings/fields-windows.yml")
}
