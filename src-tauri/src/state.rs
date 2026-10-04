use crate::dto::Settings;
use crate::persist;
use lw_core::CancellationToken;
use lw_store::CaseStore;
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Mutex;

pub struct OpenCase {
    pub store: CaseStore,
    pub pending_inputs: Vec<String>,
    pub file_status: HashMap<String, String>,
}

pub struct AppState {
    pub case: Mutex<Option<OpenCase>>,
    pub cancel: Mutex<Option<CancellationToken>>,
    pub settings: Mutex<Settings>,
    pub run_seq: AtomicI64,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            case: Mutex::new(None),
            cancel: Mutex::new(None),
            settings: Mutex::new(persist::load_settings()),
            run_seq: AtomicI64::new(1),
        }
    }

    pub fn next_run_id(&self) -> i64 {
        self.run_seq.fetch_add(1, Ordering::SeqCst)
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}
