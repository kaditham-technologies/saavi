// Saavi's shell is deliberately thin: a window around the frontend.
// Logic lives in the frontend; this grows only for OS integration
// (keychain, file dialogs) — see docs/ROADMAP.md.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_http::init())
        .run(tauri::generate_context!())
        .expect("error while running Saavi");
}
