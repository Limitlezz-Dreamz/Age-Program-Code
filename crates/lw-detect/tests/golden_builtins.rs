//! Golden built-in detections against sample EVTX (opt-in via LW_FIXTURES=1).
use lw_core::CancellationToken;
use lw_detect::{hunt, HuntOptions};
use lw_ingest::{ingest_paths, IngestEvent, IngestOptions};
use lw_rules::RuleProfile;
use lw_store::{create_case, open_write_conn, query_detections, DetectionQuery, StoreWriteCmd};
use std::path::{Path, PathBuf};

fn fixtures_root() -> Option<PathBuf> {
    let p = PathBuf::from("tests/fixtures/ext");
    if p.is_dir() {
        Some(p)
    } else {
        None
    }
}

fn resolve_fixture(rel: &str) -> Option<PathBuf> {
    let root = fixtures_root()?;
    let candidates = [
        root.join("EVTX-ATTACK-SAMPLES").join(rel),
        root.join("hayabusa-sample-evtx").join(rel),
        root.join(rel),
    ];
    candidates.into_iter().find(|p| p.is_file())
}

fn ingest_one(evtx: &Path) -> PathBuf {
    let case = PathBuf::from(format!(
        "/tmp/lw-golden-{}.lwcase",
        evtx.file_stem().unwrap().to_string_lossy()
    ));
    let _ = std::fs::remove_dir_all(&case);
    let store = create_case(&case, "golden").unwrap();
    let tx = store.writer().sender();
    let opts = IngestOptions {
        hash_files: false,
        ..IngestOptions::default()
    };
    ingest_paths(
        &[evtx.to_path_buf()],
        &opts,
        &CancellationToken::new(),
        |ev| match ev {
            IngestEvent::FileStarted { file } | IngestEvent::FileFinished { file } => {
                let _ = tx.send(StoreWriteCmd::UpsertFile(file));
            }
            IngestEvent::Batch { events } => {
                let _ = tx.send(StoreWriteCmd::InsertEvents(events));
            }
            _ => {}
        },
    )
    .unwrap();
    tx.send(StoreWriteCmd::Finalize { build_fts: false })
        .unwrap();
    let root = store.root.clone();
    store.shutdown().unwrap();
    root
}

fn expect_rule(case: &Path, rule_id: &str) {
    let opts = HuntOptions {
        case_dir: case.to_path_buf(),
        profile: RuleProfile::All,
        builtins: true,
        ..Default::default()
    };
    let (report, _) = hunt(&opts, &CancellationToken::new()).unwrap();
    assert!(report.detections > 0, "no detections for {rule_id}");
    let conn = open_write_conn(case).unwrap();
    let page = query_detections(
        &conn,
        &DetectionQuery {
            offset: 0,
            limit: 500,
            ..DetectionQuery::default()
        },
    )
    .unwrap();
    assert!(
        page.rows.iter().any(|d| d.rule_uid.contains(rule_id)),
        "expected {rule_id} in {:?}",
        page.rows.iter().map(|d| &d.rule_uid).collect::<Vec<_>>()
    );
}

macro_rules! golden {
    ($name:ident, $rel:expr, $rule:expr) => {
        #[test]
        fn $name() {
            if std::env::var("LW_FIXTURES").ok().as_deref() != Some("1") {
                eprintln!("skip {} (set LW_FIXTURES=1)", stringify!($name));
                return;
            }
            let Some(path) = resolve_fixture($rel) else {
                eprintln!("skip {} — fixture missing: {}", stringify!($name), $rel);
                return;
            };
            let case = ingest_one(&path);
            expect_rule(&case, $rule);
        }
    };
}

golden!(
    b001_security_log_cleared,
    "Defense Evasion/DE_1102_security_log_cleared.evtx",
    "B001"
);
golden!(
    b002_system_log_cleared,
    "Defense Evasion/DE_104_system_log_cleared.evtx",
    "B002"
);
golden!(
    b004_service_installed,
    "Lateral Movement/LM_Remote_Service02_7045.evtx",
    "B004"
);
golden!(b006_new_user, "DeepBlueCLI/new-user-security.evtx", "B006");
golden!(
    b007_priv_group,
    "Persistence/Network_Service_Guest_added_to_admins_4732.evtx",
    "B007"
);
golden!(
    b018_rdp_auth,
    "Command and Control/DE_RDP_Tunneling_TerminalServices-RemoteConnectionManagerOperational_1149.evtx",
    "B018"
);
golden!(
    b020_scriptblock,
    "Credential Access/Powershell_4104_MiniDumpWriteDump_Lsass.evtx",
    "B020"
);
golden!(
    b022_defender,
    "AutomatedTestingTools/WinDefender_Events_1117_1116_AtomicRedTeam.evtx",
    "B022"
);
golden!(b025_wmi, "Persistence/wmighost_sysmon_20_21_1.evtx", "B025");
golden!(
    b026_bits,
    "Persistence/persist_bitsadmin_Microsoft-Windows-Bits-Client-Operational.evtx",
    "B026"
);
