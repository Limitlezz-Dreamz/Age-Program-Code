#![deny(unsafe_code)]

//! SQLite case store: schema, writer thread, queries.

mod case;
mod dashboard;
mod detections;
mod files;
mod query;
mod schema;
mod writer;

pub use case::{create_case, open_case, record_inputs, write_run_stats, CaseStore};
pub use dashboard::{
    dashboard_summary, CoverageWarning, DashboardSummary, NamedCount, SeverityCounts, TimeBucket,
};
pub use detections::{
    begin_run, clear_run_detections, detection_where, finish_run, get_detection, insert_detections,
    iter_events_ordered, latest_run_id, open_write_conn, query_detections, set_triage,
    DetectionDetail, DetectionQuery, DetectionRow, LinkedEventRef,
};
pub use files::list_files;
pub use query::{
    get_event, query_events, stats_summary, DecodedPayload, EventDetail, EventQuery, EventRow,
    Page, SortDir, StatsSummary,
};
pub use writer::{spawn_writer, StoreWriteCmd, WriterHandle};

pub fn crate_name() -> &'static str {
    env!("CARGO_PKG_NAME")
}

#[cfg(test)]
#[path = "tests_integ.rs"]
mod tests_integ;
