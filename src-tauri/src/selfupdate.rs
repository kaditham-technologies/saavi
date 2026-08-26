// The .deb self-update path. The Tauri updater cannot serve deb installs
// (it swaps AppImages); this keeps "one click, download, restart" true for
// them. The frontend downloads the release's .deb and verifies the whole
// chain first — SHA256SUMS.asc against the release key pinned in the app,
// then the file's sha256 — and stages the bytes under the temp dir (the fs
// plugin's scope allows exactly that one path). This side re-confirms
// natively and hands the staged file to dpkg through pkexec: polkit's own
// authentication dialog guards the actual install, same spirit as the
// native confirms before system-keyring changes.

use std::path::{Path, PathBuf};

fn staged() -> PathBuf {
    std::env::temp_dir().join("saavi-update").join("saavi-update.deb")
}

/// A deb-managed install we can hand to dpkg: Linux, not an AppImage run,
/// with dpkg and pkexec present.
#[tauri::command]
pub fn deb_capable() -> bool {
    cfg!(target_os = "linux")
        && std::env::var_os("APPIMAGE").is_none()
        && Path::new("/usr/bin/dpkg").exists()
        && (Path::new("/usr/bin/pkexec").exists() || Path::new("/bin/pkexec").exists())
}

#[tauri::command]
pub async fn deb_install(app: tauri::AppHandle) -> Result<(), String> {
    if !deb_capable() {
        return Err("This install cannot self-update through dpkg.".into());
    }
    let path = staged();
    if !path.is_file() {
        return Err("No downloaded update is staged.".into());
    }
    if !crate::gpg::confirm_native(
        &app,
        "Install update",
        "Install the downloaded and verified Saavi update now?\n\nYour system will ask you to authenticate, and Saavi restarts afterwards.",
    ) {
        return Err("Cancelled.".into());
    }
    let p = path.to_str().ok_or("The staging path is not valid UTF-8.")?.to_string();
    let done = tauri::async_runtime::spawn_blocking(move || {
        std::process::Command::new("pkexec")
            .args(["dpkg", "-i", "--", &p])
            .status()
            .map_err(|e| format!("Could not start pkexec: {e}"))
    })
    .await
    .map_err(|e| format!("The install task failed: {e}"))??;
    let _ = std::fs::remove_file(&path);
    if !done.success() {
        return Err("Installation was cancelled or did not finish.".into());
    }
    Ok(())
}
