#![deny(unsafe_code)]

//! SQLite case store: schema, writer thread, queries.

mod case;
mod detections;
mod files;
mod query;
mod schema;
mod writer;

pub use case::{create_case, open_case, record_inputs, write_run_stats, CaseStore};
pub use detections::{
    begin_run, clear_run_detections, finish_run, insert_detections, iter_events_ordered,
    latest_run_id, open_write_conn, query_detections, DetectionQuery, DetectionRow,
};
pub use files::list_files;
pub use query::{query_events, stats_summary, EventQuery, EventRow, Page, SortDir, StatsSummary};
pub use writer::{spawn_writer, StoreWriteCmd, WriterHandle};

pub fn crate_name() -> &'static str {
    env!("CARGO_PKG_NAME")
}

#[cfg(test)]
#[path = "tests_integ.rs"]
mod tests_integ;
