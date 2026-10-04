use evtx::{EvtxParser, ParserSettings};
use lw_core::{CancellationToken, Error, NormalizedEvent, Result, TsMicros};
use lw_normalize::normalize;
use lw_normalize::FieldAliasRule;
use serde_json::Value;
use std::fs::OpenOptions;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct ParseOptions {
    pub file_id: i64,
    pub num_threads: usize,
    pub aliases: Vec<FieldAliasRule>,
    pub batch_size: usize,
}

#[derive(Debug, Default)]
pub struct ParseFileResult {
    pub records_ok: u64,
    pub records_err: u64,
    pub is_dirty: Option<bool>,
    pub channel_hint: Option<String>,
    pub first_ts: Option<TsMicros>,
    pub last_ts: Option<TsMicros>,
    pub error: Option<String>,
}

/// Parse one EVTX file read-only, streaming normalized batches to `on_batch`.
pub fn parse_evtx_file<F>(
    path: &Path,
    opts: &ParseOptions,
    cancel: &CancellationToken,
    mut on_batch: F,
) -> Result<ParseFileResult>
where
    F: FnMut(Vec<NormalizedEvent>),
{
    let mut result = ParseFileResult {
        // Dirty flag from header bytes (header field is private on EvtxParser).
        is_dirty: read_dirty_flag(path).ok().flatten(),
        ..Default::default()
    };

    // Read-only open — never write/lock evidence.
    let file = OpenOptions::new()
        .read(true)
        .write(false)
        .open(path)
        .map_err(|e| Error::msg(format!("open {}: {e}", path.display())))?;

    let mut parser = match EvtxParser::from_read_seek(file) {
        Ok(p) => p,
        Err(e) => {
            result.error = Some(format!("evtx header/open: {e}"));
            result.records_err = 1;
            return Ok(result);
        }
    };

    let settings = ParserSettings::default()
        .separate_json_attributes(true)
        .validate_checksums(false)
        .num_threads(opts.num_threads.max(1));
    parser = parser.with_configuration(settings);

    let mut batch = Vec::with_capacity(opts.batch_size);

    for item in parser.records_json_value() {
        cancel.check()?;
        match item {
            Ok(rec) => {
                let value: Value = rec.data;
                let raw = serde_json::to_vec(&value).ok();
                let mut ev = normalize(&value, opts.file_id, raw, &opts.aliases);
                ev.record_id = rec.event_record_id;
                if result.channel_hint.is_none() && !ev.channel.is_empty() {
                    result.channel_hint = Some(ev.channel.clone());
                }
                result.first_ts = Some(result.first_ts.map(|t| t.min(ev.ts)).unwrap_or(ev.ts));
                result.last_ts = Some(result.last_ts.map(|t| t.max(ev.ts)).unwrap_or(ev.ts));
                result.records_ok += 1;
                batch.push(ev);
                if batch.len() >= opts.batch_size {
                    on_batch(std::mem::take(&mut batch));
                }
            }
            Err(e) => {
                result.records_err += 1;
                // Keep going — per-record/chunk errors are non-fatal.
                tracing::debug!(path = %path.display(), error = %e, "record parse error");
                if result.error.is_none() {
                    result.error = Some(format!("record/chunk errors (first): {e}"));
                }
            }
        }
    }

    if !batch.is_empty() {
        on_batch(batch);
    }

    Ok(result)
}

fn read_dirty_flag(path: &Path) -> Result<Option<bool>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = OpenOptions::new().read(true).open(path)?;
    // Flags are a u32 at offset 120 in the EVTX header.
    f.seek(SeekFrom::Start(120))?;
    let mut buf = [0u8; 4];
    f.read_exact(&mut buf)?;
    let flags = u32::from_le_bytes(buf);
    Ok(Some(flags & 0x1 != 0))
}
