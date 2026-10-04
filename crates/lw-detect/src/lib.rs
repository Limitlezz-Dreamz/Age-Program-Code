#![deny(unsafe_code)]

//! Detection engine, built-in analyzers, and headless hunt orchestration.

mod analyzers;
mod dedup;
mod engine;
mod event_view;
mod hunt;
mod mitre;
mod rsigma_engine;
mod summary;

pub use analyzers::{
    run_analyzers, Analyzer, AnalyzerOutput, GapAnalyzer, LogonSummaryAnalyzer, LogonSummaryRow,
};
pub use dedup::dedup_detections;
pub use engine::{
    correlation_to_detection, raw_to_detection, CorrelationHit, DetectionEngine, Explanation,
    RawHit, TimedHit,
};
pub use hunt::{hunt, HuntOptions, HuntReport, LoadReportDto};
pub use mitre::{load_attack_json, parse_mitre_tags};
pub use rsigma_engine::RsigmaEngine;

pub fn crate_name() -> &'static str {
    env!("CARGO_PKG_NAME")
}

#[cfg(test)]
mod tests {
    use super::*;
    use lw_core::{CancellationToken, SourceType};
    use lw_rules::{
        filter_rules, find_builtins_dir, find_mapping_path, load_builtins, load_logsource_mapping,
        RuleProfile,
    };
    use lw_store::{create_case, open_write_conn, StoreWriteCmd};
    use serde_json::{json, Map};
    use std::sync::Arc;

    #[test]
    fn crate_name_is_set() {
        assert!(!crate_name().is_empty());
    }

    #[test]
    fn builtins_detect_security_log_cleared() {
        let mapping =
            load_logsource_mapping(find_mapping_path().expect("mapping")).expect("load mapping");
        let mut ruleset =
            load_builtins(find_builtins_dir().expect("builtins"), &mapping).expect("builtins");
        let (rules, _) = filter_rules(std::mem::take(&mut ruleset.rules), RuleProfile::All);
        ruleset.rules = rules;
        let mut engine = RsigmaEngine::new(mapping);
        engine.load(&ruleset).expect("load engine");

        let mut fields = Map::new();
        fields.insert("Channel".into(), json!("Security"));
        fields.insert("EventID".into(), json!(1102));
        fields.insert("Provider_Name".into(), json!("Microsoft-Windows-Eventlog"));
        let ev = lw_core::NormalizedEvent {
            id: 1,
            file_id: 1,
            source_type: SourceType::Evtx,
            record_id: 10,
            ts: 1_700_000_000_000_000,
            event_id: 1102,
            channel: "Security".into(),
            provider: "Microsoft-Windows-Eventlog".into(),
            computer: "DC01".into(),
            level: Some(4),
            user_sid: None,
            user_name: None,
            src_ip: None,
            logon_type: None,
            fields,
            raw_json: None,
        };
        let hits = engine.process_batch(&[ev]);
        assert!(
            hits.iter().any(|h| h.rule_uid.contains("B001")),
            "expected B001, got {:?}",
            hits.iter().map(|h| &h.rule_uid).collect::<Vec<_>>()
        );
    }

    #[test]
    fn correlation_uses_event_time_not_wall_clock() {
        let mapping =
            load_logsource_mapping(find_mapping_path().expect("mapping")).expect("load mapping");
        let mut ruleset =
            load_builtins(find_builtins_dir().expect("builtins"), &mapping).expect("builtins");
        let (rules, _) = filter_rules(std::mem::take(&mut ruleset.rules), RuleProfile::All);
        ruleset.rules = rules;
        let mut engine = RsigmaEngine::new(mapping);
        engine.load(&ruleset).expect("load");

        let base_ts = 1_600_000_000_000_000i64; // fixed historical time
        let mut events = Vec::new();
        for i in 0..10 {
            let mut fields = Map::new();
            fields.insert("Channel".into(), json!("Security"));
            fields.insert("EventID".into(), json!(4625));
            fields.insert("TargetUserName".into(), json!("alice"));
            fields.insert("IpAddress".into(), json!("10.0.0.5"));
            events.push(lw_core::NormalizedEvent {
                id: i + 1,
                file_id: 1,
                source_type: SourceType::Evtx,
                record_id: i as u64,
                ts: base_ts + i * 1_000_000,
                event_id: 4625,
                channel: "Security".into(),
                provider: "Microsoft-Windows-Security-Auditing".into(),
                computer: "DC01".into(),
                level: Some(4),
                user_sid: None,
                user_name: Some("alice".into()),
                src_ip: Some("10.0.0.5".into()),
                logon_type: Some(3),
                fields,
                raw_json: None,
            });
        }
        let hits = engine.process_batch(&events);
        assert!(
            hits.iter().any(|h| h.rule_uid.contains("B010")),
            "expected B010 brute force correlation, got {:?}",
            hits.iter().map(|h| &h.rule_uid).collect::<Vec<_>>()
        );
        let _ = Arc::new(CancellationToken::new());
    }

    #[test]
    fn hunt_on_empty_case() {
        let tmp = tempfile::tempdir().unwrap();
        let store = create_case(tmp.path(), "empty").unwrap();
        // writer idle
        store
            .writer()
            .send(StoreWriteCmd::Finalize { build_fts: false })
            .unwrap();
        let root = store.root.clone();
        store.shutdown().unwrap();

        let opts = HuntOptions {
            case_dir: root,
            profile: RuleProfile::Default,
            builtins: true,
            ..Default::default()
        };
        let (report, dets) = hunt(&opts, &CancellationToken::new()).unwrap();
        assert_eq!(report.events_scanned, 0);
        assert!(dets.is_empty());
        let _ = open_write_conn(&opts.case_dir).unwrap();
    }
}
