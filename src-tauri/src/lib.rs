#![deny(unsafe_code)]

mod commands;
mod dto;
mod error;
mod persist;
mod state;

use state::AppState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let _ = persist::ensure_app_dirs();

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::new())
        .invoke_handler(tauri::generate_handler![
            commands::app_name,
            commands::greet,
            commands::get_settings,
            commands::set_settings,
            commands::recent_cases,
            commands::create_case_cmd,
            commands::open_case_cmd,
            commands::close_case,
            commands::current_case,
            commands::add_inputs,
            commands::list_files_cmd,
            commands::case_stats,
            commands::cancel_analysis,
            commands::start_analysis,
            commands::default_cases_dir,
            commands::dashboard_summary_cmd,
            commands::query_detections_cmd,
            commands::get_detection_cmd,
            commands::get_event_cmd,
            commands::set_triage_cmd,
            commands::timeline_histogram_cmd,
            commands::timeline_list_cmd,
            commands::query_events_cmd,
            commands::query_pivots_cmd,
            commands::logon_summary_cmd,
            commands::list_saved_searches_cmd,
            commands::save_search_cmd,
            commands::delete_saved_search_cmd,
            commands::list_rule_packs_cmd,
            commands::import_rule_pack_cmd,
            commands::download_rule_pack_cmd,
            commands::drl_notice_cmd,
            commands::list_rules_cmd,
            commands::get_rule_cmd,
            commands::set_rule_enabled_cmd,
            commands::list_suppressions_cmd,
            commands::add_suppression_cmd,
            commands::delete_suppression_cmd,
            commands::rerun_detection_cmd,
            commands::export_detections_cmd,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod export_ts {
    #[cfg(feature = "ts-rs")]
    #[test]
    fn export_bindings() {
        use crate::dto::*;
        use crate::error::ApiError;
        use std::path::PathBuf;

        let out = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../src/ipc/generated");
        let _ = std::fs::create_dir_all(&out);
        // Force export by touching types — ts-rs exports via #[ts(export)] at compile time
        // when TS_RS_EXPORT_DIR is set.
        std::env::set_var("TS_RS_EXPORT_DIR", out.display().to_string());
        let _ = std::mem::size_of::<ApiError>();
        let _ = std::mem::size_of::<CaseInfoDto>();
        let _ = std::mem::size_of::<RecentCase>();
        let _ = std::mem::size_of::<DiscoveredFileDto>();
        let _ = std::mem::size_of::<DiscoveryResult>();
        let _ = std::mem::size_of::<SourceFileDto>();
        let _ = std::mem::size_of::<AnalysisOptions>();
        let _ = std::mem::size_of::<IngestProgressMsg>();
        let _ = std::mem::size_of::<Settings>();
        let _ = std::mem::size_of::<CaseStatsDto>();
        let _ = std::mem::size_of::<GlobalFilter>();
        let _ = std::mem::size_of::<DashboardSummaryDto>();
        let _ = std::mem::size_of::<DetectionQueryDto>();
        let _ = std::mem::size_of::<DetectionPageDto>();
        let _ = std::mem::size_of::<DetectionDetailDto>();
        let _ = std::mem::size_of::<EventDetailDto>();
        let _ = std::mem::size_of::<SetTriageRequest>();
    }
}
