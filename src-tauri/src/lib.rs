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
    }
}
