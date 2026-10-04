#![cfg(test)]

use crate::{create_case, query_events, stats_summary, EventQuery, SortDir, StoreWriteCmd};
use lw_core::{NormalizedEvent, SourceFile, SourceType};
use serde_json::{json, Map};
use tempfile::tempdir;

fn sample_event(file_id: i64, record_id: u64, ts: i64) -> NormalizedEvent {
    let mut fields = Map::new();
    fields.insert("EventID".into(), json!(4624));
    fields.insert("Channel".into(), json!("Security"));
    NormalizedEvent {
        id: 0,
        file_id,
        source_type: SourceType::Evtx,
        record_id,
        ts,
        event_id: 4624,
        channel: "Security".into(),
        provider: "Microsoft-Windows-Security-Auditing".into(),
        computer: "HOST1".into(),
        level: Some(0),
        user_sid: None,
        user_name: Some("alice".into()),
        src_ip: Some("10.0.0.1".into()),
        logon_type: Some(3),
        fields,
        raw_json: Some(br#"{"Event":{}}"#.to_vec()),
    }
}

#[test]
fn writer_insert_query_and_finalize() {
    let dir = tempdir().unwrap();
    let store = create_case(dir.path(), "t").unwrap();
    let tx = store.writer().sender();
    tx.send(StoreWriteCmd::UpsertFile(SourceFile {
        id: 1,
        path: "a.evtx".into(),
        size: 10,
        sha256: Some("abc".into()),
        mtime: None,
        channel_hint: Some("Security".into()),
        records_ok: 2,
        records_err: 0,
        is_dirty: Some(false),
        first_ts: Some(1),
        last_ts: Some(2),
        error: None,
    }))
    .unwrap();
    tx.send(StoreWriteCmd::InsertEvents(vec![
        sample_event(1, 1, 1_000_000),
        sample_event(1, 2, 2_000_000),
    ]))
    .unwrap();
    tx.send(StoreWriteCmd::Finalize { build_fts: true })
        .unwrap();
    store.shutdown().unwrap();

    let store = crate::open_case(dir.path().join("t.lwcase")).unwrap();
    let conn = store.open_read_only().unwrap();
    let summary = stats_summary(&conn).unwrap();
    assert_eq!(summary.events, 2);
    assert_eq!(summary.files, 1);

    let page = query_events(
        &conn,
        &EventQuery {
            offset: 0,
            limit: 10,
            sort_col: "ts".into(),
            sort_dir: SortDir::Asc,
            users: vec!["alice".into()],
            ..EventQuery::default()
        },
    )
    .unwrap();
    assert_eq!(page.total, 2);
    assert_eq!(page.rows[0].record_id, 1);
    store.shutdown().unwrap();
}
