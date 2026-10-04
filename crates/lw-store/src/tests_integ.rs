#![cfg(test)]

use crate::{
    begin_run, create_case, dashboard_summary, finish_run, get_event, insert_detections,
    open_write_conn, query_events, set_triage, stats_summary, EventQuery, SortDir, StoreWriteCmd,
};
use lw_core::{
    Detection, DetectionKind, NormalizedEvent, RuleSource, Severity, SourceFile, SourceType,
    TriageState,
};
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

#[test]
fn dashboard_event_detail_and_triage() {
    let dir = tempdir().unwrap();
    let store = create_case(dir.path(), "dash").unwrap();
    let root = store.root.clone();
    let tx = store.writer().sender();
    tx.send(StoreWriteCmd::UpsertFile(SourceFile {
        id: 1,
        path: "a.evtx".into(),
        size: 10,
        sha256: None,
        mtime: None,
        channel_hint: Some("Security".into()),
        records_ok: 1,
        records_err: 0,
        is_dirty: Some(false),
        first_ts: Some(1_000_000),
        last_ts: Some(1_000_000),
        error: None,
    }))
    .unwrap();
    let mut ev = sample_event(1, 1, 1_000_000);
    ev.fields.insert(
        "CommandLine".into(),
        json!("<img src=x onerror=alert(1)> whoami"),
    );
    tx.send(StoreWriteCmd::InsertEvents(vec![ev])).unwrap();
    tx.send(StoreWriteCmd::Finalize { build_fts: false })
        .unwrap();
    store.shutdown().unwrap();

    let conn = open_write_conn(&root).unwrap();
    let run_id = begin_run(&conn, "builtin", None, "{}").unwrap();
    insert_detections(
        &conn,
        run_id,
        &[Detection {
            id: 0,
            rule_uid: "B001".into(),
            rule_title: "Test rule".into(),
            rule_author: Some("logwarden".into()),
            rule_source: RuleSource::Builtin,
            severity: Severity::High,
            status: Some("stable".into()),
            mitre: vec![],
            ts: 1_000_000,
            computer: "HOST1".into(),
            user: Some("alice".into()),
            event_ids: vec![1],
            kind: DetectionKind::Single,
            summary: "xss <script>".into(),
            fp_hint: None,
            triage: TriageState::New,
        }],
    )
    .unwrap();
    finish_run(&conn, run_id, "ok").unwrap();

    let dash = dashboard_summary(&conn, &crate::DetectionQuery::default()).unwrap();
    assert_eq!(dash.total_detections, 1);
    assert_eq!(dash.severity.high, 1);
    assert!(!dash.coverage.is_empty()); // no sysmon etc.

    let filtered = dashboard_summary(
        &conn,
        &crate::DetectionQuery {
            severities: vec![Severity::Critical],
            ..crate::DetectionQuery::default()
        },
    )
    .unwrap();
    assert_eq!(filtered.total_detections, 0);

    let event = get_event(&conn, 1).unwrap();
    assert_eq!(event.event_id, 4624);
    let cmdline = event
        .fields
        .get("CommandLine")
        .and_then(|v| v.as_str())
        .unwrap();
    assert!(cmdline.contains("<img"));
    assert!(event.xml.as_ref().unwrap().contains("&lt;img"));

    let n = set_triage(&conn, &[1], TriageState::Reviewed, Some("ok")).unwrap();
    assert_eq!(n, 1);
}
