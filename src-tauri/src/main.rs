// Saavi's shell is deliberately thin: a window around the frontend, plus
// one piece of OS integration — the system GnuPG keyring (gpg.rs), which
// delegates every operation to the user's own gpg binary.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod gpg;
mod keychain;

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_http::init())
        .plugin(tauri_plugin_opener::init())
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
            keychain::keychain_available,
            keychain::keychain_get,
            keychain::keychain_set,
            keychain::keychain_delete,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Saavi");
}
