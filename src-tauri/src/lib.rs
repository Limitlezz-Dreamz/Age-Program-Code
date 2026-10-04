use lw_core::APP_NAME;

#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {name}! Welcome to {APP_NAME}.")
}

#[tauri::command]
fn app_name() -> &'static str {
    APP_NAME
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![greet, app_name])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
