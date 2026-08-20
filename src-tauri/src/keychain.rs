//! OS keychain for Saavi-store passphrases (roadmap #1).
//!
//! Opt-in: the user ticks "remember in the keychain" when unlocking or
//! creating a key. The passphrase then lives in the platform credential
//! store — macOS Keychain, Windows Credential Manager, Secret Service
//! (GNOME Keyring / KWallet) on Linux — under this app's service name, one
//! entry per key fingerprint. Saavi reads it back to unlock silently.
//!
//! What this changes in the threat model: at rest, the key's protection
//! becomes the OS login (plus whatever the platform store does), rather
//! than a passphrase only Saavi knows. That is the normal desktop trade
//! and it is the user's choice; the UI says so when offering it.

use std::sync::OnceLock;

const SERVICE: &str = "ie.kaditham.saavi";

fn account_for(fingerprint: &str) -> Result<String, String> {
    let f: String = fingerprint.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_uppercase();
    if f.len() < 16 || f.len() > 64 || !f.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Not a fingerprint.".into());
    }
    Ok(format!("ring:{f}"))
}

fn entry(fingerprint: &str) -> Result<keyring::Entry, String> {
    let account = account_for(fingerprint)?;
    keyring::Entry::new(SERVICE, &account).map_err(|e| format!("Keychain unavailable: {e}"))
}

/// Whether a usable credential store exists on this machine. Probed once:
/// on Linux without a Secret Service daemon this is false and the UI
/// simply does not offer the option.
#[tauri::command]
pub async fn keychain_available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        tauri::async_runtime::block_on(tauri::async_runtime::spawn_blocking(|| {
            match keyring::Entry::new(SERVICE, "probe") {
                Ok(e) => match e.get_password() {
                    Ok(_) | Err(keyring::Error::NoEntry) => true,
                    Err(_) => false,
                },
                Err(_) => false,
            }
        }))
        .unwrap_or(false)
    })
}

#[tauri::command]
pub async fn keychain_get(fingerprint: String) -> Result<Option<String>, String> {
    tauri::async_runtime::spawn_blocking(move || match entry(&fingerprint)?.get_password() {
        Ok(p) => Ok(Some(p)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(format!("Keychain read failed: {e}")),
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn keychain_set(fingerprint: String, passphrase: String) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || {
        entry(&fingerprint)?
            .set_password(&passphrase)
            .map_err(|e| format!("Keychain write failed: {e}"))
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn keychain_delete(fingerprint: String) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || match entry(&fingerprint)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(format!("Keychain delete failed: {e}")),
    })
    .await
    .map_err(|e| e.to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accounts_are_fingerprint_bound() {
        assert_eq!(account_for("abcd ef01 2345 6789 abcd ef01 2345 6789 abcd ef01").unwrap(), "ring:ABCDEF0123456789ABCDEF0123456789ABCDEF01");
        assert!(account_for("not a fingerprint").is_err());
        assert!(account_for("").is_err());
    }
}
