//! The sealed key store's file operations (docs/KEY-AGENT.md phase 0).
//!
//! The shell moves bytes; it never sees inside them. Sealing and unsealing
//! happen in the frontend core (src/bundle.ts) under a secret the OS
//! keychain holds (keychain.rs) — the file written here is opaque
//! ciphertext, and losing a write is the failure that matters, so writes
//! are atomic: temp file, fsync, rename.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use tauri::Manager;

const STORE_FILE: &str = "ring-store.asc";

fn data_dir(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_data_dir()
        .map_err(|e| format!("No data directory: {e}"))
}

#[cfg(unix)]
fn restrict(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}
#[cfg(not(unix))]
fn restrict(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

/// Write-then-rename, fsynced, owner-only. A crash mid-write leaves the
/// previous store intact; there is never a moment with a half-written file
/// under the real name. The temp name is unique per write (two processes
/// must not interleave into one file) and `create_new` refuses to open an
/// existing path — which also refuses to write through a planted symlink.
fn write_atomic(dir: &std::path::Path, name: &str, contents: &str) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|e| format!("Could not create the data directory: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = dir.join(format!("{name}.{}.{nanos}.tmp", std::process::id()));
    let fin = dir.join(name);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .map_err(|e| format!("Could not write the key store: {e}"))?;
    restrict(&tmp).map_err(|e| format!("Could not restrict the key store: {e}"))?;
    let written = f
        .write_all(contents.as_bytes())
        .and_then(|()| f.sync_all())
        .map_err(|e| format!("Could not write the key store: {e}"));
    drop(f);
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    fs::rename(&tmp, &fin).map_err(|e| format!("Could not commit the key store: {e}"))?;
    if let Ok(d) = fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

#[tauri::command]
pub async fn store_read(app: tauri::AppHandle) -> Result<Option<String>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let path = data_dir(&app)?.join(STORE_FILE);
        match fs::read_to_string(&path) {
            Ok(s) => Ok(Some(s)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("Could not read the key store: {e}")),
        }
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn store_write(app: tauri::AppHandle, contents: String) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || write_atomic(&data_dir(&app)?, STORE_FILE, &contents))
        .await
        .map_err(|e| e.to_string())?
}

#[derive(serde::Serialize)]
pub struct BackupRef {
    name: String,
    path: String,
}

/// The pre-migration backup: the plain bundle (its private keys are still
/// passphrase-locked), named so several never collide, owner-only.
#[tauri::command]
pub async fn store_backup_write(app: tauri::AppHandle, contents: String) -> Result<BackupRef, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let dir = data_dir(&app)?;
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let name = format!("ring-backup-{ts}.json");
        write_atomic(&dir, &name, &contents)?;
        Ok(BackupRef { path: dir.join(&name).display().to_string(), name })
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Reads back a backup THIS app wrote — the name is checked to that shape,
/// so the webview cannot use it to read arbitrary files.
#[tauri::command]
pub async fn store_backup_read(app: tauri::AppHandle, name: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let ok = name.strip_prefix("ring-backup-").and_then(|r| r.strip_suffix(".json"))
            .is_some_and(|ts| !ts.is_empty() && ts.bytes().all(|b| b.is_ascii_digit()));
        if !ok {
            return Err("Not a backup name.".into());
        }
        fs::read_to_string(data_dir(&app)?.join(&name)).map_err(|e| format!("Could not read the backup: {e}"))
    })
    .await
    .map_err(|e| e.to_string())?
}

#[cfg(test)]
mod tests {
    #[test]
    fn backup_names_are_bound_to_their_shape() {
        let ok = |n: &str| {
            n.strip_prefix("ring-backup-").and_then(|r| r.strip_suffix(".json"))
                .is_some_and(|ts| !ts.is_empty() && ts.bytes().all(|b| b.is_ascii_digit()))
        };
        assert!(ok("ring-backup-1756713600.json"));
        assert!(!ok("ring-backup-.json"));
        assert!(!ok("ring-backup-../../etc/passwd.json"));
        assert!(!ok("../ring-backup-1.json"));
        assert!(!ok("ring-store.asc"));
    }
}
