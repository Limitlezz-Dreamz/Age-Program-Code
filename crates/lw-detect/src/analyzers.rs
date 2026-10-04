use lw_core::{Detection, DetectionKind, MitreRef, Result, RuleSource, Severity, TriageState};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub trait Analyzer: Send {
    fn id(&self) -> &'static str;
    fn run(&self, conn: &Connection) -> Result<AnalyzerOutput>;
}

#[derive(Debug, Default)]
pub struct AnalyzerOutput {
    pub detections: Vec<Detection>,
    pub logon_rows: Vec<LogonSummaryRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogonSummaryRow {
    pub user_name: String,
    pub src_ip: String,
    pub logon_type: i64,
    pub computer: String,
    pub success_count: u64,
    pub fail_count: u64,
    pub first_ts: i64,
    pub last_ts: i64,
}

/// A001: record-id gaps / time going backwards.
pub struct GapAnalyzer;

impl Analyzer for GapAnalyzer {
    fn id(&self) -> &'static str {
        "A001"
    }

    fn run(&self, conn: &Connection) -> Result<AnalyzerOutput> {
        let mut stmt = conn
            .prepare(
                "SELECT e.id, e.file_id, e.record_id, e.ts, c.name, h.name
                 FROM events e
                 JOIN dict_channel c ON c.id = e.channel_id
                 JOIN dict_computer h ON h.id = e.computer_id
                 ORDER BY e.file_id, c.name, e.record_id, e.id",
            )
            .map_err(|e| lw_core::Error::Sqlite(e.to_string()))?;

        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)? as u64,
                    r.get::<_, i64>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                ))
            })
            .map_err(|e| lw_core::Error::Sqlite(e.to_string()))?;

        let mut prev_file: Option<i64> = None;
        let mut prev_channel: Option<String> = None;
        let mut prev_record: Option<u64> = None;
        let mut prev_ts: Option<i64> = None;
        let mut seen_in_group = false;
        let mut detections = Vec::new();

        for row in rows {
            let (eid, file_id, record_id, ts, channel, computer) =
                row.map_err(|e| lw_core::Error::Sqlite(e.to_string()))?;

            let same_group =
                prev_file == Some(file_id) && prev_channel.as_deref() == Some(channel.as_str());
            if same_group {
                if seen_in_group {
                    if let (Some(prid), Some(pts)) = (prev_record, prev_ts) {
                        if record_id > prid + 1 {
                            conn.execute(
                                "INSERT INTO gaps(file_id, channel, computer, from_record, to_record, from_ts, to_ts, reason)
                                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                                params![
                                    file_id,
                                    channel,
                                    computer,
                                    prid as i64,
                                    record_id as i64,
                                    pts,
                                    ts,
                                    "record_id_gap"
                                ],
                            )
                            .map_err(|e| lw_core::Error::Sqlite(e.to_string()))?;
                            detections.push(gap_detection(
                                eid,
                                ts,
                                &computer,
                                &format!(
                                    "Possible log tampering/gap: {channel} records {prid}->{record_id} ({computer})"
                                ),
                            ));
                        }
                        // time went backwards by > 1h (ts micros)
                        if ts + 3_600_000_000 < pts {
                            conn.execute(
                                "INSERT INTO gaps(file_id, channel, computer, from_record, to_record, from_ts, to_ts, reason)
                                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                                params![
                                    file_id,
                                    channel,
                                    computer,
                                    prid as i64,
                                    record_id as i64,
                                    pts,
                                    ts,
                                    "time_backwards"
                                ],
                            )
                            .map_err(|e| lw_core::Error::Sqlite(e.to_string()))?;
                            detections.push(gap_detection(
                                eid,
                                ts,
                                &computer,
                                &format!(
                                    "Possible log tampering/gap: {channel} time went backwards ({computer})"
                                ),
                            ));
                        }
                    }
                }
                seen_in_group = true;
            } else {
                // New group: ignore gap at start of file/channel (rolled logs).
                seen_in_group = true;
            }

            prev_file = Some(file_id);
            prev_channel = Some(channel);
            prev_record = Some(record_id);
            prev_ts = Some(ts);
        }

        Ok(AnalyzerOutput {
            detections,
            logon_rows: Vec::new(),
        })
    }
}

fn gap_detection(event_id: i64, ts: i64, computer: &str, summary: &str) -> Detection {
    Detection {
        id: 0,
        rule_uid: "builtin:A001".into(),
        rule_title: "Possible log tampering/gap".into(),
        rule_author: Some("Logwarden built-in".into()),
        rule_source: RuleSource::Builtin,
        severity: Severity::Medium,
        status: Some("stable".into()),
        mitre: vec![MitreRef {
            technique: Some("T1070.001".into()),
            tactic: Some("defense-evasion".into()),
            name: Some("Clear Windows Event Logs".into()),
        }],
        ts,
        computer: computer.to_string(),
        user: None,
        event_ids: vec![event_id],
        kind: DetectionKind::Single,
        summary: summary.to_string(),
        fp_hint: Some("Log rotation at file start is ignored; mid-file gaps are suspicious".into()),
        triage: TriageState::New,
    }
}

/// A002: logon summary (4624/4625) — feeds pivots, not detections.
pub struct LogonSummaryAnalyzer;

impl Analyzer for LogonSummaryAnalyzer {
    fn id(&self) -> &'static str {
        "A002"
    }

    fn run(&self, conn: &Connection) -> Result<AnalyzerOutput> {
        let mut stmt = conn
            .prepare(
                "SELECT e.event_id, e.ts, e.user_name, e.src_ip, e.logon_type, h.name
                 FROM events e
                 JOIN dict_computer h ON h.id = e.computer_id
                 WHERE e.event_id IN (4624, 4625)",
            )
            .map_err(|e| lw_core::Error::Sqlite(e.to_string()))?;

        #[derive(Hash, Eq, PartialEq)]
        struct Key {
            user: String,
            ip: String,
            lt: i64,
            computer: String,
        }

        let mut map: HashMap<Key, (u64, u64, i64, i64)> = HashMap::new();
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)? as u32,
                    r.get::<_, i64>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, Option<i64>>(4)?,
                    r.get::<_, String>(5)?,
                ))
            })
            .map_err(|e| lw_core::Error::Sqlite(e.to_string()))?;

        for row in rows {
            let (eid, ts, user, ip, lt, computer) =
                row.map_err(|e| lw_core::Error::Sqlite(e.to_string()))?;
            let key = Key {
                user: user.unwrap_or_default(),
                ip: ip.unwrap_or_default(),
                lt: lt.unwrap_or(-1),
                computer,
            };
            let entry = map.entry(key).or_insert((0, 0, ts, ts));
            entry.2 = entry.2.min(ts);
            entry.3 = entry.3.max(ts);
            match eid {
                4624 => entry.0 += 1,
                4625 => entry.1 += 1,
                _ => {}
            }
        }

        let mut logon_rows: Vec<LogonSummaryRow> = map
            .into_iter()
            .map(|(k, (success, fail, first, last))| LogonSummaryRow {
                user_name: k.user,
                src_ip: k.ip,
                logon_type: k.lt,
                computer: k.computer,
                success_count: success,
                fail_count: fail,
                first_ts: first,
                last_ts: last,
            })
            .collect();
        logon_rows.sort_by(|a, b| {
            (&a.computer, &a.user_name, a.logon_type).cmp(&(
                &b.computer,
                &b.user_name,
                b.logon_type,
            ))
        });

        conn.execute("DELETE FROM logon_summary", [])
            .map_err(|e| lw_core::Error::Sqlite(e.to_string()))?;
        for row in &logon_rows {
            conn.execute(
                "INSERT INTO logon_summary(user_name, src_ip, logon_type, computer, success_count, fail_count, first_ts, last_ts)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    row.user_name,
                    row.src_ip,
                    row.logon_type,
                    row.computer,
                    row.success_count as i64,
                    row.fail_count as i64,
                    row.first_ts,
                    row.last_ts
                ],
            )
            .map_err(|e| lw_core::Error::Sqlite(e.to_string()))?;
        }

        Ok(AnalyzerOutput {
            detections: Vec::new(),
            logon_rows,
        })
    }
}

pub fn run_analyzers(conn: &Connection) -> Result<Vec<Detection>> {
    let analyzers: Vec<Box<dyn Analyzer>> =
        vec![Box::new(GapAnalyzer), Box::new(LogonSummaryAnalyzer)];
    let mut dets = Vec::new();
    for a in analyzers {
        let out = a.run(conn)?;
        dets.extend(out.detections);
    }
    Ok(dets)
}
