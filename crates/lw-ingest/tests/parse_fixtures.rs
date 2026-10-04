//! Fixture-backed ingest tests. Heavy ones require `LW_FIXTURES=1`.

use lw_core::CancellationToken;
use lw_ingest::{discover_evtx_paths, parse_evtx_file, ParseOptions};
use lw_normalize::default_4688_aliases;
use std::path::{Path, PathBuf};

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

fn cc0_sample() -> PathBuf {
    fixtures_root().join("cc0/sample.evtx")
}

#[test]
fn parse_cc0_sample_no_panic() {
    let path = cc0_sample();
    if !path.exists() {
        eprintln!("skip: missing {}", path.display());
        return;
    }
    let cancel = CancellationToken::new();
    let mut total = 0u64;
    let result = parse_evtx_file(
        &path,
        &ParseOptions {
            file_id: 1,
            num_threads: 2,
            aliases: default_4688_aliases(),
            batch_size: 500,
        },
        &cancel,
        |batch| total += batch.len() as u64,
    )
    .expect("parse");
    assert!(result.records_ok > 0 || result.records_err > 0);
    assert_eq!(total, result.records_ok);
}

#[test]
fn truncated_file_yields_partial_or_error() {
    let path = cc0_sample();
    if !path.exists() {
        return;
    }
    let bytes = std::fs::read(&path).unwrap();
    // Cut near a chunk boundary (header 4096 + one chunk 65536) + 1000.
    let cut = (4096 + 65536 + 1000)
        .min(bytes.len().saturating_sub(1))
        .max(5000);
    let dir = tempfile::tempdir().unwrap();
    let bad = dir.path().join("truncated.evtx");
    std::fs::write(&bad, &bytes[..cut]).unwrap();

    let cancel = CancellationToken::new();
    let mut total = 0u64;
    let result = parse_evtx_file(
        &bad,
        &ParseOptions {
            file_id: 1,
            num_threads: 1,
            aliases: default_4688_aliases(),
            batch_size: 500,
        },
        &cancel,
        |batch| total += batch.len() as u64,
    )
    .expect("truncated parse must not panic");
    // Either we got some records before damage, and/or an error was recorded.
    assert!(total == result.records_ok);
    assert!(result.records_ok > 0 || result.records_err > 0 || result.error.is_some());
}

#[test]
fn timestamp_round_trip_on_sample() {
    let path = cc0_sample();
    if !path.exists() {
        return;
    }
    use evtx::{EvtxParser, ParserSettings};
    use lw_core::format_rfc3339_micros;
    use lw_normalize::normalize;

    let mut parser = EvtxParser::from_path(&path).unwrap().with_configuration(
        ParserSettings::default()
            .separate_json_attributes(true)
            .num_threads(1),
    );
    let mut checked = 0u32;
    for item in parser.records_json_value().take(50) {
        let rec = item.unwrap();
        let value = rec.data;
        let source = value
            .pointer("/Event/System/TimeCreated_attributes/SystemTime")
            .or_else(|| value.pointer("/Event/System/TimeCreated/#attributes/SystemTime"))
            .and_then(|v| v.as_str())
            .expect("SystemTime present");
        let ev = normalize(&value, 1, None, &[]);
        let formatted = format_rfc3339_micros(ev.ts).unwrap();
        // Source may have fewer than 6 fractional digits; compare parsed micros equality.
        let src_ts = lw_core::parse_rfc3339_to_micros(source).unwrap();
        assert_eq!(ev.ts, src_ts, "record {}", ev.record_id);
        assert_eq!(formatted, lw_core::format_rfc3339_micros(src_ts).unwrap());
        checked += 1;
    }
    assert!(checked > 0);
}

fn count_with_evtx_crate(path: &Path) -> u64 {
    use evtx::{EvtxParser, ParserSettings};
    let mut parser = EvtxParser::from_path(path)
        .unwrap()
        .with_configuration(ParserSettings::default().num_threads(1));
    parser.records_json_value().filter(|r| r.is_ok()).count() as u64
}

#[test]
#[ignore = "set LW_FIXTURES=1 and run with --ignored"]
fn attack_samples_counts_match_parser() {
    if std::env::var("LW_FIXTURES").ok().as_deref() != Some("1") {
        return;
    }
    let root = fixtures_root().join("ext/EVTX-ATTACK-SAMPLES");
    assert!(root.exists(), "run just fixtures first");
    let files = discover_evtx_paths(&[root]).unwrap();
    let sample: Vec<_> = files.into_iter().take(20).collect();
    assert_eq!(sample.len(), 20);
    let cancel = CancellationToken::new();
    for df in sample {
        let expected = count_with_evtx_crate(&df.path);
        let mut got = 0u64;
        let result = parse_evtx_file(
            &df.path,
            &ParseOptions {
                file_id: 1,
                num_threads: 2,
                aliases: default_4688_aliases(),
                batch_size: 1000,
            },
            &cancel,
            |batch| got += batch.len() as u64,
        )
        .unwrap();
        assert_eq!(got, expected, "count mismatch for {}", df.path.display());
        assert_eq!(result.records_ok, expected);
    }
}

#[test]
#[ignore = "set LW_FIXTURES=1 and run with --ignored"]
fn ingest_attack_samples_no_panic() {
    if std::env::var("LW_FIXTURES").ok().as_deref() != Some("1") {
        return;
    }
    let root = fixtures_root().join("ext/EVTX-ATTACK-SAMPLES");
    let files = discover_evtx_paths(&[root]).unwrap();
    assert!(files.len() > 200);
    let cancel = CancellationToken::new();
    let opts = lw_ingest::IngestOptions {
        hash_files: false,
        num_threads: num_cpus::get(),
        ..lw_ingest::IngestOptions::default()
    };
    let stats = lw_ingest::ingest_files(&files, &opts, &cancel, |_| {}).expect("ingest");
    assert!(stats.records_ok > 0);
}
