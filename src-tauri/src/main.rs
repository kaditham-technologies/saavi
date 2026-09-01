// Saavi's shell is deliberately thin: a window around the frontend, plus
// one piece of OS integration — the system GnuPG keyring (gpg.rs), which
// delegates every operation to the user's own gpg binary.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod gpg;
mod keychain;
mod selfupdate;
mod store;

fn main() {
    tauri::Builder::default()
        // Registered FIRST, per the plugin's contract. Two Saavi processes
        // would race the sealed key store (each holds a full mirror; last
        // writer wins with the WHOLE store) — a second launch focuses the
        // first window instead.
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            use tauri::Manager;
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.unminimize();
                let _ = w.set_focus();
            }
        }))
        // The shell records what the user drops, so gpg.rs can tell a file
        // the user chose from a path the webview merely named.
        .manage(gpg::DroppedPaths::default())
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::DragDrop(tauri::DragDropEvent::Drop { paths, .. }) = event {
                tauri::Manager::state::<gpg::DroppedPaths>(window).remember(paths);
            }
        })
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_http::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .invoke_handler(tauri::generate_handler![
            gpg::gpg_info,
            gpg::gpg_list_keys,
            gpg::gpg_export_public,
            gpg::gpg_export_secret,
            gpg::gpg_import,
            gpg::gpg_encrypt,
            gpg::gpg_decrypt,
            gpg::gpg_delete_public,
            gpg::gpg_generate,
            gpg::gpg_clearsign,
            gpg::gpg_set_expire,
            gpg::gpg_passwd,
            gpg::gpg_add_uid,
            gpg::gpg_revoke_uid,
            gpg::gpg_set_ownertrust,
            gpg::gpg_sign_key,
            gpg::gpg_recv_key,
            gpg::gpg_gen_revoke,
            gpg::gpg_encrypt_file,
            gpg::gpg_decrypt_file,
            selfupdate::deb_capable,
            selfupdate::deb_install,
            keychain::keychain_available,
            keychain::keychain_get,
            keychain::keychain_set,
            keychain::keychain_delete,
            keychain::keychain_store_secret_get,
            keychain::keychain_store_secret_set,
            store::store_read,
            store::store_write,
            store::store_backup_write,
            store::store_backup_read,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Saavi");
}
