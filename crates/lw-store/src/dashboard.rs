use crate::files::list_files;
use crate::query::stats_summary;
use lw_core::{Error, Result};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SeverityCounts {
    pub critical: u64,
    pub high: u64,
    pub medium: u64,
    pub low: u64,
    pub informational: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamedCount {
    pub name: String,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageWarning {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeBucket {
    pub ts: i64,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardSummary {
    pub severity: SeverityCounts,
    pub total_detections: u64,
    pub top_rules: Vec<NamedCount>,
    pub top_hosts: Vec<NamedCount>,
    pub top_users: Vec<NamedCount>,
    pub top_tactics: Vec<NamedCount>,
    pub files: u64,
    pub files_with_errors: u64,
    pub events: u64,
    pub first_ts: Option<i64>,
    pub last_ts: Option<i64>,
    pub channels: Vec<NamedCount>,
    pub coverage: Vec<CoverageWarning>,
    pub detections_over_time: Vec<TimeBucket>,
}

pub fn dashboard_summary(conn: &Connection) -> Result<DashboardSummary> {
    let stats = stats_summary(conn)?;
    let mut severity = SeverityCounts::default();
    {
        let mut stmt = conn
            .prepare("SELECT severity, COUNT(*) FROM detections GROUP BY severity")
            .map_err(|e| Error::Sqlite(e.to_string()))?;
        let rows = stmt
            .query_map([], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)? as u64))
            })
            .map_err(|e| Error::Sqlite(e.to_string()))?;
        for row in rows {
            let (sev, n) = row.map_err(|e| Error::Sqlite(e.to_string()))?;
            match sev {
                0 => severity.informational = n,
                1 => severity.low = n,
                2 => severity.medium = n,
                3 => severity.high = n,
                4 => severity.critical = n,
                _ => {}
            }
        }
    }
    let total_detections =
        severity.critical + severity.high + severity.medium + severity.low + severity.informational;

    let top_rules = named_counts(
        conn,
        "SELECT rule_title, COUNT(*) FROM detections GROUP BY rule_title ORDER BY COUNT(*) DESC LIMIT 10",
    )?;
    let top_hosts = named_counts(
        conn,
        "SELECT computer, COUNT(*) FROM detections WHERE computer IS NOT NULL AND computer != ''
         GROUP BY computer ORDER BY COUNT(*) DESC LIMIT 10",
    )?;
    let top_users = named_counts(
        conn,
        "SELECT user_name, COUNT(*) FROM detections WHERE user_name IS NOT NULL AND user_name != ''
         GROUP BY user_name ORDER BY COUNT(*) DESC LIMIT 10",
    )?;

    // Tactic counts from mitre_json (best-effort parse for MVP).
    let top_tactics = {
        let mut stmt = conn
            .prepare("SELECT mitre_json FROM detections WHERE mitre_json IS NOT NULL")
            .map_err(|e| Error::Sqlite(e.to_string()))?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(|e| Error::Sqlite(e.to_string()))?;
        let mut map = std::collections::HashMap::<String, u64>::new();
        for row in rows {
            let json = row.map_err(|e| Error::Sqlite(e.to_string()))?;
            if let Ok(refs) = serde_json::from_str::<Vec<lw_core::MitreRef>>(&json) {
                for r in refs {
                    if let Some(t) = r.tactic {
                        *map.entry(t).or_default() += 1;
                    }
                }
            }
        }
        let mut v: Vec<_> = map.into_iter().collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v.into_iter()
            .take(10)
            .map(|(name, count)| NamedCount { name, count })
            .collect::<Vec<_>>()
    };

    let channels = stats
        .channels
        .into_iter()
        .map(|(name, count)| NamedCount { name, count })
        .collect::<Vec<_>>();

    let coverage = coverage_warnings(conn, &channels)?;
    let detections_over_time = detections_sparkline(conn, stats.first_ts, stats.last_ts)?;

    Ok(DashboardSummary {
        severity,
        total_detections,
        top_rules,
        top_hosts,
        top_users,
        top_tactics,
        files: stats.files,
        files_with_errors: stats.files_with_errors,
        events: stats.events,
        first_ts: stats.first_ts,
        last_ts: stats.last_ts,
        channels,
        coverage,
        detections_over_time,
    })
}

fn detections_sparkline(
    conn: &Connection,
    first_ts: Option<i64>,
    last_ts: Option<i64>,
) -> Result<Vec<TimeBucket>> {
    let (Some(first), Some(last)) = (first_ts, last_ts) else {
        return Ok(Vec::new());
    };
    if last <= first {
        return Ok(Vec::new());
    }
    let span = (last - first).max(1);
    // Aim for ~48 buckets.
    let bucket = ((span / 48).max(1_000_000)).max(1);
    let mut stmt = conn
        .prepare(
            "SELECT (ts / ?1) * ?1 AS bucket, COUNT(*) FROM detections
             GROUP BY bucket ORDER BY bucket ASC LIMIT 200",
        )
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    let rows = stmt
        .query_map([bucket], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)? as u64))
        })
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    let mut out = Vec::new();
    for row in rows {
        let (ts, count) = row.map_err(|e| Error::Sqlite(e.to_string()))?;
        out.push(TimeBucket { ts, count });
    }
    Ok(out)
}

fn named_counts(conn: &Connection, sql: &str) -> Result<Vec<NamedCount>> {
    let mut stmt = conn
        .prepare(sql)
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    let rows = stmt
        .query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64))
        })
        .map_err(|e| Error::Sqlite(e.to_string()))?;
    let mut out = Vec::new();
    for row in rows {
        let (name, count) = row.map_err(|e| Error::Sqlite(e.to_string()))?;
        out.push(NamedCount { name, count });
    }
    Ok(out)
}

fn coverage_warnings(conn: &Connection, channels: &[NamedCount]) -> Result<Vec<CoverageWarning>> {
    let mut out = Vec::new();
    let has = |substr: &str| {
        channels.iter().any(|c| {
            c.name
                .to_ascii_lowercase()
                .contains(&substr.to_ascii_lowercase())
        })
    };
    if !has("sysmon") {
        out.push(CoverageWarning {
            code: "no_sysmon".into(),
            message: "No Sysmon logs: Sysmon-based rules can't fire".into(),
        });
    }
    // 4688 without CommandLine
    let has_4688: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM events WHERE event_id = 4688 LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if has_4688 > 0 {
        let with_cmd: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM events WHERE event_id = 4688 AND fields_json LIKE '%CommandLine%' LIMIT 1",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if with_cmd == 0 {
            out.push(CoverageWarning {
                code: "no_cmdline_4688".into(),
                message:
                    "4688 present but no CommandLine field: command-line auditing likely disabled"
                        .into(),
            });
        }
    }
    let has_4104: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM events WHERE event_id = 4104 LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if has_4104 == 0 && (has("powershell") || has("PowerShell")) {
        out.push(CoverageWarning {
            code: "no_4104".into(),
            message: "PowerShell channel present but EventID 4104 not present".into(),
        });
    } else if has_4104 == 0 && !has("powershell") {
        out.push(CoverageWarning {
            code: "no_ps_scriptblock".into(),
            message: "PowerShell 4104 not present".into(),
        });
    }

    let files = list_files(conn)?;
    let dirty = files.iter().filter(|f| f.is_dirty == Some(true)).count();
    if dirty > 0 {
        out.push(CoverageWarning {
            code: "dirty_files".into(),
            message: format!("{dirty} EVTX file(s) marked dirty (incomplete write)"),
        });
    }
    Ok(out)
}
