//! Headless Logwarden CLI (`lw`).
#![deny(unsafe_code)]

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use lw_core::{format_rfc3339_micros, CancellationToken, APP_NAME};
use lw_ingest::{ingest_paths, IngestEvent, IngestOptions};
use lw_normalize::{default_4688_aliases, load_field_aliases};
use lw_store::{
    create_case, open_case, query_events, record_inputs, stats_summary, write_run_stats,
    EventQuery, SortDir, StoreWriteCmd,
};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "lw", version, about = "Logwarden headless CLI")]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Ingest EVTX files/folders into a case database
    Ingest {
        /// Input files or directories
        paths: Vec<PathBuf>,
        /// Case directory (created if missing)
        #[arg(long)]
        case: PathBuf,
        /// Case name when creating under a parent directory
        #[arg(long, default_value = "case")]
        name: String,
        /// Disable SHA-256 hashing
        #[arg(long)]
        no_hash: bool,
        /// Skip FTS index at finalize
        #[arg(long)]
        no_fts: bool,
        /// Worker threads
        #[arg(long)]
        threads: Option<usize>,
        /// Print events/sec benchmark summary
        #[arg(long)]
        bench: bool,
        /// Field aliases YAML (defaults to built-in 4688 aliases)
        #[arg(long)]
        aliases: Option<PathBuf>,
    },
    /// Show case statistics
    Stats {
        #[arg(long)]
        case: PathBuf,
        #[arg(long, value_enum, default_value_t = StatsFormat::Text)]
        format: StatsFormat,
    },
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum StatsFormat {
    Text,
    Json,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env()
                .add_directive("info".parse()?)
                .add_directive("evtx=warn".parse()?),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Commands::Ingest {
            paths,
            case,
            name,
            no_hash,
            no_fts,
            threads,
            bench,
            aliases,
        } => cmd_ingest(
            paths, case, name, !no_hash, !no_fts, threads, bench, aliases,
        ),
        Commands::Stats { case, format } => cmd_stats(case, format),
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_ingest(
    paths: Vec<PathBuf>,
    case: PathBuf,
    name: String,
    hash_files: bool,
    build_fts: bool,
    threads: Option<usize>,
    bench: bool,
    aliases_path: Option<PathBuf>,
) -> Result<()> {
    if paths.is_empty() {
        bail!("provide at least one input path");
    }

    let store = if case.join("case.db").exists() || case.join("case.json").exists() {
        open_case(&case).with_context(|| format!("open case {}", case.display()))?
    } else {
        create_case(&case, &name)
            .with_context(|| format!("create case under {}", case.display()))?
    };

    let input_strs: Vec<String> = paths.iter().map(|p| p.display().to_string()).collect();
    record_inputs(&store.root, &input_strs)?;

    let aliases = if let Some(p) = aliases_path {
        load_field_aliases(p)?
    } else if let Some(p) = lw_ingest::default_aliases_path() {
        load_field_aliases(p).unwrap_or_else(|_| default_4688_aliases())
    } else {
        default_4688_aliases()
    };

    let mut opts = IngestOptions {
        hash_files,
        aliases,
        ..IngestOptions::default()
    };
    if let Some(t) = threads {
        opts.num_threads = t.max(1);
    }

    let cancel = CancellationToken::new();
    let writer_tx = store.writer().sender();

    println!("{APP_NAME} ingest → {}", store.root.display());

    let stats = ingest_paths(&paths, &opts, &cancel, |ev| match ev {
        IngestEvent::Discovered { files, bytes } => {
            println!("discovered {files} files ({:.1} MB)", bytes as f64 / 1e6);
        }
        IngestEvent::FileStarted { file } => {
            let _ = writer_tx.send(StoreWriteCmd::UpsertFile(file));
        }
        IngestEvent::FileFinished { file } => {
            let _ = writer_tx.send(StoreWriteCmd::UpsertFile(file.clone()));
            if let Some(err) = &file.error {
                eprintln!("file error {}: {err}", file.path);
            }
        }
        IngestEvent::Batch { events } => {
            let _ = writer_tx.send(StoreWriteCmd::InsertEvents(events));
        }
        IngestEvent::Progress {
            files_done,
            files_total,
            records_ok,
            records_err,
        } => {
            eprint!(
                "\rprogress {files_done}/{files_total} events={records_ok} errors={records_err}"
            );
        }
        IngestEvent::Finished { .. } => {}
    });

    let stats = match stats {
        Ok(s) => s,
        Err(lw_core::Error::Cancelled) => {
            eprintln!("\ncancelled");
            let _ = writer_tx.send(StoreWriteCmd::Finalize { build_fts: false });
            store.shutdown()?;
            bail!("cancelled");
        }
        Err(e) => {
            store.shutdown()?;
            return Err(e.into());
        }
    };

    eprintln!();
    writer_tx
        .send(StoreWriteCmd::Finalize { build_fts })
        .map_err(|_| anyhow::anyhow!("store writer channel closed"))?;
    write_run_stats(&store.root, &stats)?;
    store.shutdown()?;

    println!(
        "done: files_ok={} files_err={} events={} errors={} elapsed={}ms ({:.0} ev/s)",
        stats.files_ok,
        stats.files_err,
        stats.records_ok,
        stats.records_err,
        stats.elapsed_ms,
        stats.events_per_sec
    );
    if bench {
        println!(
            "BENCH events_per_sec={:.2} bytes={} elapsed_ms={}",
            stats.events_per_sec, stats.bytes, stats.elapsed_ms
        );
    }
    Ok(())
}

fn cmd_stats(case: PathBuf, format: StatsFormat) -> Result<()> {
    let store = open_case(&case)?;
    let conn = store.open_read_only()?;
    let summary = stats_summary(&conn)?;
    match format {
        StatsFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&summary)?);
        }
        StatsFormat::Text => {
            println!("case: {}", store.root.display());
            println!(
                "files: {} (with errors: {})",
                summary.files, summary.files_with_errors
            );
            println!("events: {}", summary.events);
            if let (Some(a), Some(b)) = (summary.first_ts, summary.last_ts) {
                println!(
                    "time range (UTC): {} .. {}",
                    format_rfc3339_micros(a).unwrap_or_else(|_| a.to_string()),
                    format_rfc3339_micros(b).unwrap_or_else(|_| b.to_string())
                );
            }
            println!("top channels:");
            for (name, n) in summary.channels.iter().take(15) {
                println!("  {name}: {n}");
            }
            println!("top event IDs:");
            for (eid, n) in summary.event_ids.iter().take(15) {
                println!("  {eid}: {n}");
            }
            let page = query_events(
                &conn,
                &EventQuery {
                    offset: 0,
                    limit: 5,
                    sort_col: "ts".into(),
                    sort_dir: SortDir::Asc,
                    ..EventQuery::default()
                },
            )?;
            println!("sample events ({} total):", page.total);
            for row in page.rows {
                println!(
                    "  {} eid={} {} @ {}",
                    format_rfc3339_micros(row.ts).unwrap_or_default(),
                    row.event_id,
                    row.channel,
                    row.computer
                );
            }
        }
    }
    store.shutdown()?;
    Ok(())
}
