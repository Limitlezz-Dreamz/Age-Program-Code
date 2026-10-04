#![deny(unsafe_code)]

//! SQLite case store: schema, writer thread, queries.

mod case;
mod dashboard;
mod detections;
mod files;
mod pivots;
mod query;
mod rules;
mod schema;
mod searches;
mod timeline;
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
pub use pivots::{
    logon_type_name, query_logon_summary, query_pivots, LogonSummaryRow, PivotQuery, PivotRow,
};
pub use query::{
    get_event, query_events, stats_summary, DecodedPayload, EventDetail, EventQuery, EventRow,
    FieldFilter, Page, SortDir, StatsSummary,
};
pub use rules::{
    add_suppression, apply_suppressions_to_detections, delete_suppression, disabled_rule_uids,
    get_rule, list_suppressions, query_rules, set_rule_enabled, upsert_rules, RuleDetail,
    RuleQuery, RuleRow, RuleUpsert, SuppressionInput, SuppressionRow,
};
pub use searches::{delete_saved_search, list_saved_searches, save_search, SavedSearch};
pub use timeline::{
    timeline_histogram, timeline_list, HistogramBucket, HistogramQuery, TimelineItem,
    TimelineListQuery,
};
pub use writer::{spawn_writer, StoreWriteCmd, WriterHandle};

pub fn crate_name() -> &'static str {
    env!("CARGO_PKG_NAME")
}

#[cfg(test)]
#[path = "tests_integ.rs"]
mod tests_integ;
