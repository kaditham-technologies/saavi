// Saavi's shell is deliberately thin: a window around the frontend.
// Logic lives in the frontend; this grows only for OS integration
// (keychain, file dialogs) — see ROADMAP.md.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running Saavi");
}
