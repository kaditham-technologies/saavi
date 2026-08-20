//! System GnuPG keyring — the KGpg succession.
//!
//! Saavi does not read `~/.gnupg` and does not implement OpenPGP here. Every
//! operation is the user's own `gpg` binary, run with a fixed argument set:
//! `--with-colons` for listing, `--status-fd` for the outcome of everything
//! else. Passphrases never pass through Saavi — gpg-agent and the user's
//! pinentry handle them (and smartcards, and the agent cache). Trust is
//! gpg's trust model; an override is explicit and per operation.
//!
//! Inputs from the webview are validated before they become arguments
//! (fingerprints: hex; addresses: one `@`, no whitespace or angle brackets),
//! and all key/message material travels over stdin, never argv.

use serde::Serialize;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

// ---------------------------------------------------------------- locating

/// Candidate locations beyond PATH. Apps launched from the Dock/Finder or a
/// desktop shortcut get a minimal PATH, so these matter in practice.
fn candidates() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            v.push(dir.join(exe("gpg")));
            v.push(dir.join(exe("gpg2")));
        }
    }
    #[cfg(target_os = "windows")]
    {
        for var in ["ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA"] {
            if let Some(base) = std::env::var_os(var) {
                let base = PathBuf::from(base);
                v.push(base.join("GnuPG").join("bin").join("gpg.exe"));
                v.push(base.join("Programs").join("GnuPG").join("bin").join("gpg.exe"));
                v.push(base.join("Gpg4win").join("bin").join("gpg.exe"));
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        for p in [
            "/opt/homebrew/bin/gpg",
            "/usr/local/bin/gpg",
            "/usr/local/MacGPG2/bin/gpg2",
            "/opt/local/bin/gpg",
        ] {
            v.push(PathBuf::from(p));
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        for p in ["/usr/bin/gpg", "/usr/local/bin/gpg", "/usr/bin/gpg2"] {
            v.push(PathBuf::from(p));
        }
    }
    v
}

#[cfg(target_os = "windows")]
fn exe(name: &str) -> String {
    format!("{name}.exe")
}
#[cfg(not(target_os = "windows"))]
fn exe(name: &str) -> String {
    name.to_string()
}

fn gpg_binary() -> Option<&'static Path> {
    static BIN: OnceLock<Option<PathBuf>> = OnceLock::new();
    BIN.get_or_init(|| candidates().into_iter().find(|p| p.is_file()))
        .as_deref()
}

// ---------------------------------------------------------------- running

struct Run {
    status_ok: bool,
    stdout: Vec<u8>,
    /// `[GNUPG:] ...` lines, prefix stripped.
    status: Vec<String>,
    /// Everything else gpg wrote to stderr (human messages).
    messages: Vec<String>,
}

fn command(bin: &Path) -> Command {
    let mut c = Command::new(bin);
    c.args([
        "--batch",
        "--no-tty",
        "--status-fd",
        "2",
        "--display-charset",
        "utf-8",
        "--utf8-strings",
        "--exit-on-status-write-error",
    ]);
    c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        c.creation_flags(CREATE_NO_WINDOW);
    }
    c
}

fn run(args: &[&str], stdin: &[u8]) -> Result<Run, String> {
    let bin = gpg_binary().ok_or("GnuPG is not installed (or not found).")?;
    let mut child = command(bin)
        .args(args)
        .spawn()
        .map_err(|e| format!("Could not start gpg: {e}"))?;
    {
        let mut si = child.stdin.take().expect("piped stdin");
        // A closed pipe (gpg bailed early) is reported through status/exit.
        let _ = si.write_all(stdin);
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("gpg did not finish: {e}"))?;
    let mut status = Vec::new();
    let mut messages = Vec::new();
    for line in String::from_utf8_lossy(&out.stderr).lines() {
        if let Some(rest) = line.strip_prefix("[GNUPG:] ") {
            status.push(rest.to_string());
        } else if !line.trim().is_empty() {
            messages.push(line.trim_start_matches("gpg: ").to_string());
        }
    }
    Ok(Run { status_ok: out.status.success(), stdout: out.stdout, status, messages })
}

fn human(r: &Run, fallback: &str) -> String {
    // Last non-status line is usually the actionable one.
    r.messages.last().cloned().unwrap_or_else(|| fallback.to_string())
}

// ---------------------------------------------------------------- validation

fn is_fingerprint(s: &str) -> bool {
    let n = s.len();
    (n == 16 || n == 32 || n == 40 || n == 64) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_address(s: &str) -> bool {
    let mut parts = s.split('@');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(l), Some(d), None) => {
            !l.is_empty()
                && d.contains('.')
                && !s.starts_with('-')
                && !s.chars().any(|c| c.is_whitespace() || "<>\"'\\".contains(c))
        }
        _ => false,
    }
}

fn check_fpr(s: &str) -> Result<String, String> {
    let s = s.trim().replace(' ', "").to_uppercase();
    if is_fingerprint(&s) {
        Ok(s)
    } else {
        Err("That is not a key ID or fingerprint.".into())
    }
}

fn check_recipient(s: &str) -> Result<String, String> {
    let t = s.trim();
    let compact = t.replace(' ', "");
    if is_fingerprint(&compact) {
        return Ok(compact.to_uppercase());
    }
    if is_address(t) {
        return Ok(t.to_lowercase());
    }
    Err(format!("'{t}' is neither an address nor a fingerprint."))
}

// ---------------------------------------------------------------- colons

/// Undo gpg's C-style escaping in `--with-colons` fields (`\x3a` for ':').
fn unescape(field: &str) -> String {
    let b = field.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() && b[i + 1] == b'x' {
            if let Ok(v) = u8::from_str_radix(&field[i + 2..i + 4], 16) {
                out.push(v);
                i += 4;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn epoch_to_iso(s: &str) -> Option<String> {
    // Seconds since the epoch (gpg --fixed-list-mode). ISO date only; the
    // UI shows dates, not times.
    let secs: i64 = s.parse().ok()?;
    if secs <= 0 {
        return None;
    }
    let days = secs.div_euclid(86_400);
    // Civil-from-days (Howard Hinnant), proleptic Gregorian.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    Some(format!("{y:04}-{m:02}-{d:02}"))
}

fn validity_label(code: &str) -> &'static str {
    match code.chars().next().unwrap_or('-') {
        'u' => "ultimate",
        'f' => "full",
        'm' => "marginal",
        'n' => "never",
        'r' => "revoked",
        'e' => "expired",
        'd' => "disabled",
        'i' => "invalid",
        _ => "unknown",
    }
}

fn algo_label(algo: &str, bits: &str, curve: &str) -> String {
    if !curve.is_empty() {
        return curve.to_string();
    }
    match algo {
        "1" | "2" | "3" => format!("rsa{bits}"),
        "16" | "20" => format!("elgamal{bits}"),
        "17" => format!("dsa{bits}"),
        "18" => "ecdh".into(),
        "19" => "ecdsa".into(),
        "22" => "eddsa".into(),
        _ => format!("algo{algo}"),
    }
}

#[derive(Serialize, Clone, Debug, Default, PartialEq)]
pub struct UserId {
    pub uid: String,
    pub name: String,
    pub email: String,
    pub validity: String,
}

#[derive(Serialize, Clone, Debug, Default, PartialEq)]
pub struct SystemKey {
    pub fingerprint: String,
    pub key_id: String,
    pub algo: String,
    pub created: Option<String>,
    pub expires: Option<String>,
    pub validity: String,
    pub owner_trust: String,
    pub has_secret: bool,
    pub revoked: bool,
    pub expired: bool,
    pub disabled: bool,
    pub can_encrypt: bool,
    pub can_sign: bool,
    pub uids: Vec<UserId>,
}

fn split_uid(uid: &str) -> (String, String) {
    if let (Some(a), Some(b)) = (uid.rfind('<'), uid.rfind('>')) {
        if a < b {
            return (uid[..a].trim().to_string(), uid[a + 1..b].trim().to_lowercase());
        }
    }
    (uid.trim().to_string(), String::new())
}

/// Parse `gpg --with-colons --with-fingerprint --with-secret --list-keys`.
pub fn parse_keys(colons: &str) -> Vec<SystemKey> {
    let mut keys: Vec<SystemKey> = Vec::new();
    let mut awaiting_primary_fpr = false;
    for line in colons.lines() {
        let f: Vec<&str> = line.split(':').collect();
        match f.first().copied() {
            Some("pub") => {
                let caps = f.get(11).copied().unwrap_or("");
                let validity = f.get(1).copied().unwrap_or("-");
                keys.push(SystemKey {
                    key_id: f.get(4).copied().unwrap_or("").to_string(),
                    algo: algo_label(f.get(3).copied().unwrap_or(""), f.get(2).copied().unwrap_or(""), f.get(16).copied().unwrap_or("")),
                    created: epoch_to_iso(f.get(5).copied().unwrap_or("")),
                    expires: epoch_to_iso(f.get(6).copied().unwrap_or("")),
                    validity: validity_label(validity).into(),
                    owner_trust: validity_label(f.get(8).copied().unwrap_or("-")).into(),
                    has_secret: f.get(14).copied().unwrap_or("").contains('+'),
                    revoked: validity.starts_with('r'),
                    expired: validity.starts_with('e'),
                    disabled: caps.contains('D'),
                    // Upper-case letters: the whole key (any subkey) can.
                    can_encrypt: caps.contains('E'),
                    can_sign: caps.contains('S'),
                    ..Default::default()
                });
                awaiting_primary_fpr = true;
            }
            Some("fpr") if awaiting_primary_fpr => {
                if let Some(k) = keys.last_mut() {
                    k.fingerprint = f.get(9).copied().unwrap_or("").to_string();
                }
                awaiting_primary_fpr = false;
            }
            Some("sub") | Some("ssb") => {
                awaiting_primary_fpr = false;
                if let Some(k) = keys.last_mut() {
                    if f.get(14).copied().unwrap_or("").contains('+') {
                        k.has_secret = true;
                    }
                }
            }
            Some("uid") => {
                if let Some(k) = keys.last_mut() {
                    let uid = unescape(f.get(9).copied().unwrap_or(""));
                    let (name, email) = split_uid(&uid);
                    k.uids.push(UserId {
                        uid,
                        name,
                        email,
                        validity: validity_label(f.get(1).copied().unwrap_or("-")).into(),
                    });
                }
            }
            _ => {}
        }
    }
    keys
}

// ---------------------------------------------------------------- status

#[derive(Serialize, Clone, Debug, Default, PartialEq)]
pub struct SignatureInfo {
    /// "good" | "bad" | "unknown-key" | "expired" | "revoked" | "error"
    pub status: String,
    pub fingerprint: String,
    pub key_id: String,
    pub uid: String,
    /// gpg's TRUST_* verdict for the signing key: "ultimate" | "full" |
    /// "marginal" | "undefined" | "never" | "" (not evaluated).
    pub trust: String,
}

#[derive(Serialize, Clone, Debug, Default, PartialEq)]
pub struct DecryptOutcome {
    pub text: String,
    pub signatures: Vec<SignatureInfo>,
    /// Key IDs the message was encrypted to (ENC_TO).
    pub encrypted_to: Vec<String>,
}

pub fn parse_signatures(status: &[String]) -> Vec<SignatureInfo> {
    let mut sigs: Vec<SignatureInfo> = Vec::new();
    for s in status {
        let mut it = s.splitn(3, ' ');
        let tag = it.next().unwrap_or("");
        let a = it.next().unwrap_or("");
        let rest = it.next().unwrap_or("");
        match tag {
            "GOODSIG" | "BADSIG" | "EXPKEYSIG" | "REVKEYSIG" | "EXPSIG" => {
                sigs.push(SignatureInfo {
                    status: match tag {
                        "GOODSIG" => "good",
                        "BADSIG" => "bad",
                        "EXPKEYSIG" | "EXPSIG" => "expired",
                        _ => "revoked",
                    }
                    .into(),
                    key_id: a.to_string(),
                    uid: rest.to_string(),
                    ..Default::default()
                });
            }
            "ERRSIG" => {
                // ERRSIG keyid pkalgo hashalgo sigclass time rc [fpr]
                let fields: Vec<&str> = rest.split(' ').collect();
                let rc = fields.get(4).copied().unwrap_or("");
                sigs.push(SignatureInfo {
                    status: if rc == "9" { "unknown-key" } else { "error" }.into(),
                    key_id: a.to_string(),
                    fingerprint: fields.get(5).copied().unwrap_or("").to_string(),
                    ..Default::default()
                });
            }
            "VALIDSIG" => {
                // VALIDSIG fpr date time ... primary-fpr (last field)
                if let Some(last) = sigs.last_mut() {
                    let primary = rest.rsplit(' ').next().unwrap_or(a);
                    last.fingerprint = if is_fingerprint(primary) { primary } else { a }.to_string();
                }
            }
            t if t.starts_with("TRUST_") => {
                if let Some(last) = sigs.last_mut() {
                    last.trust = t.trim_start_matches("TRUST_").to_lowercase();
                }
            }
            _ => {}
        }
    }
    sigs
}

// ---------------------------------------------------------------- commands

#[derive(Serialize, Clone, Debug)]
pub struct GpgInfo {
    pub found: bool,
    pub path: Option<String>,
    pub version: Option<String>,
    pub homedir: Option<String>,
}

fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T, String> + Send + 'static) -> impl std::future::Future<Output = Result<T, String>> {
    async move {
        tauri::async_runtime::spawn_blocking(f)
            .await
            .map_err(|e| format!("gpg task failed: {e}"))?
    }
}

#[tauri::command]
pub async fn gpg_info() -> Result<GpgInfo, String> {
    blocking(|| {
        let Some(bin) = gpg_binary() else {
            return Ok(GpgInfo { found: false, path: None, version: None, homedir: None });
        };
        let v = run(&["--version"], b"")?;
        let version = String::from_utf8_lossy(&v.stdout)
            .lines()
            .next()
            .map(|l| l.trim_start_matches("gpg (GnuPG) ").trim_start_matches("gpg (GnuPG/MacGPG2) ").to_string());
        let homedir = {
            let mut c = Command::new(bin.with_file_name(exe("gpgconf")));
            c.args(["--list-dirs", "homedir"]).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());
            #[cfg(target_os = "windows")]
            {
                use std::os::windows::process::CommandExt;
                c.creation_flags(0x0800_0000);
            }
            c.output().ok().and_then(|o| String::from_utf8(o.stdout).ok()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
        };
        Ok(GpgInfo { found: true, path: Some(bin.display().to_string()), version, homedir })
    })
    .await
}

#[tauri::command]
pub async fn gpg_list_keys() -> Result<Vec<SystemKey>, String> {
    blocking(|| {
        let r = run(
            &["--with-colons", "--fixed-list-mode", "--with-fingerprint", "--with-secret", "--list-keys"],
            b"",
        )?;
        if !r.status_ok {
            return Err(human(&r, "gpg could not list the keyring."));
        }
        Ok(parse_keys(&String::from_utf8_lossy(&r.stdout)))
    })
    .await
}

#[tauri::command]
pub async fn gpg_export_public(fingerprint: String) -> Result<String, String> {
    blocking(move || {
        let fpr = check_fpr(&fingerprint)?;
        let r = run(&["--armor", "--export", "--", &fpr], b"")?;
        if !r.status_ok || r.stdout.is_empty() {
            return Err(human(&r, "No such key."));
        }
        Ok(String::from_utf8_lossy(&r.stdout).into_owned())
    })
    .await
}

/// Armored, passphrase-protected secret key. gpg-agent asks for the
/// passphrase through pinentry; Saavi only relays what gpg emits.
#[tauri::command]
pub async fn gpg_export_secret(fingerprint: String) -> Result<String, String> {
    blocking(move || {
        let fpr = check_fpr(&fingerprint)?;
        let r = run(&["--armor", "--export-secret-keys", "--", &fpr], b"")?;
        if !r.status_ok || r.stdout.is_empty() {
            return Err(human(&r, "gpg did not export the secret key (cancelled, or no secret key)."));
        }
        Ok(String::from_utf8_lossy(&r.stdout).into_owned())
    })
    .await
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct ImportOutcome {
    pub imported: u32,
    pub unchanged: u32,
    pub secret_imported: u32,
    pub fingerprints: Vec<String>,
}

#[tauri::command]
pub async fn gpg_import(armored: String) -> Result<ImportOutcome, String> {
    blocking(move || {
        let r = run(&["--import"], armored.as_bytes())?;
        let mut out = ImportOutcome::default();
        for s in &r.status {
            let f: Vec<&str> = s.split(' ').collect();
            match f.first().copied() {
                Some("IMPORT_OK") => {
                    if let Some(fpr) = f.get(2) {
                        out.fingerprints.push(fpr.to_string());
                    }
                }
                Some("IMPORT_RES") => {
                    // IMPORT_RES count no_user_id imported imported_rsa unchanged ... sec_read sec_imported sec_dups ...
                    out.imported = f.get(3).and_then(|x| x.parse().ok()).unwrap_or(0);
                    out.unchanged = f.get(5).and_then(|x| x.parse().ok()).unwrap_or(0);
                    out.secret_imported = f.get(10).and_then(|x| x.parse().ok()).unwrap_or(0);
                }
                _ => {}
            }
        }
        if out.fingerprints.is_empty() {
            return Err(human(&r, "Nothing importable was found."));
        }
        Ok(out)
    })
    .await
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct EncryptOutcome {
    pub armored: String,
    /// Recipients gpg refused because their key is not trusted enough; the
    /// caller may ask the user and retry with `trust_all`.
    pub untrusted: Vec<String>,
    /// Recipients with no usable key at all.
    pub missing: Vec<String>,
}

#[tauri::command]
pub async fn gpg_encrypt(
    text: String,
    recipients: Vec<String>,
    sign_with: Option<String>,
    trust_all: bool,
    locate_wkd: bool,
) -> Result<EncryptOutcome, String> {
    blocking(move || {
        if recipients.is_empty() {
            return Err("Name at least one recipient.".into());
        }
        let mut args: Vec<String> = vec!["--armor".into(), "--encrypt".into()];
        if let Some(fpr) = sign_with.as_deref().filter(|s| !s.is_empty()) {
            args.push("--sign".into());
            args.push("--local-user".into());
            args.push(check_fpr(fpr)?);
        }
        if trust_all {
            args.push("--trust-model".into());
            args.push("always".into());
        }
        if locate_wkd {
            // gpg's own lookup, same as `gpg --auto-key-locate wkd`: the
            // fetched key is imported into the keyring, as gpg always does.
            args.push("--auto-key-locate".into());
            args.push("local,wkd".into());
        }
        for r in &recipients {
            args.push("--recipient".into());
            args.push(check_recipient(r)?);
        }
        let argv: Vec<&str> = args.iter().map(String::as_str).collect();
        let r = run(&argv, text.as_bytes())?;
        let mut out = EncryptOutcome::default();
        for s in &r.status {
            // INV_RECP <reason> <recipient>
            if let Some(rest) = s.strip_prefix("INV_RECP ") {
                let mut it = rest.splitn(2, ' ');
                let reason = it.next().unwrap_or("");
                let who = it.next().unwrap_or("").to_string();
                if reason == "10" {
                    out.untrusted.push(who);
                } else {
                    out.missing.push(who);
                }
            }
        }
        if r.status_ok && !r.stdout.is_empty() {
            out.armored = String::from_utf8_lossy(&r.stdout).into_owned();
            return Ok(out);
        }
        if out.untrusted.is_empty() && out.missing.is_empty() {
            return Err(human(&r, "gpg could not encrypt."));
        }
        Ok(out)
    })
    .await
}

#[tauri::command]
pub async fn gpg_decrypt(armored: String) -> Result<DecryptOutcome, String> {
    blocking(move || {
        let r = run(&["--decrypt"], armored.as_bytes())?;
        let signatures = parse_signatures(&r.status);
        let encrypted_to = r
            .status
            .iter()
            .filter_map(|s| s.strip_prefix("ENC_TO ").and_then(|x| x.split(' ').next()).map(str::to_string))
            .collect();
        let okay = r.status.iter().any(|s| s == "DECRYPTION_OKAY");
        if !okay {
            let msg = if r.status.iter().any(|s| s.starts_with("NO_SECKEY")) {
                "None of the secret keys in the GnuPG keyring can open this message.".to_string()
            } else if r.status.iter().any(|s| s.starts_with("DECRYPTION_FAILED")) {
                human(&r, "Decryption failed (wrong passphrase, cancelled, or a damaged message).")
            } else if r.status.iter().any(|s| s.starts_with("NODATA")) {
                "That is not an OpenPGP message.".to_string()
            } else {
                human(&r, "gpg could not decrypt.")
            };
            return Err(msg);
        }
        Ok(DecryptOutcome { text: String::from_utf8_lossy(&r.stdout).into_owned(), signatures, encrypted_to })
    })
    .await
}

/// Delete a PUBLIC key. Keys that have a secret part are refused here on
/// purpose: removing a secret key is a gpg/Kleopatra-level decision.
#[tauri::command]
pub async fn gpg_delete_public(fingerprint: String) -> Result<(), String> {
    blocking(move || {
        let fpr = check_fpr(&fingerprint)?;
        let list = run(&["--with-colons", "--fixed-list-mode", "--with-fingerprint", "--with-secret", "--list-keys", "--", &fpr], b"")?;
        let keys = parse_keys(&String::from_utf8_lossy(&list.stdout));
        let Some(k) = keys.first() else { return Err("No such key.".into()) };
        if k.has_secret {
            return Err("This key has a secret part. Saavi will not delete secret keys from your GnuPG keyring; use gpg or Kleopatra if you really mean it.".into());
        }
        let r = run(&["--yes", "--delete-keys", "--", &fpr], b"")?;
        if !r.status_ok {
            return Err(human(&r, "gpg did not delete the key."));
        }
        Ok(())
    })
    .await
}

/// Generate a key in the system keyring. gpg asks for the passphrase via
/// pinentry; Saavi never sees it. Ed25519 signing primary + X25519
/// encryption subkey (or RSA-4096 both), no expiry — matching Saavi's own store.
#[tauri::command]
pub async fn gpg_generate(name: String, email: String, algo: String) -> Result<String, String> {
    blocking(move || {
        let email = email.trim().to_lowercase();
        if !is_address(&email) {
            return Err("That does not look like an email address.".into());
        }
        let name = name.trim().replace(['<', '>', '(', ')'], "");
        let uid = if name.is_empty() { email.clone() } else { format!("{name} <{email}>") };
        let (primary, sub) = match algo.as_str() {
            "rsa4096" => ("rsa4096", "rsa4096"),
            _ => ("ed25519", "cv25519"),
        };
        let r = run(&["--quick-generate-key", "--", &uid, primary, "cert,sign", "never"], b"")?;
        let fpr = r
            .status
            .iter()
            .find_map(|s| s.strip_prefix("KEY_CREATED ").and_then(|x| x.split(' ').nth(1)).map(str::to_string))
            .ok_or_else(|| human(&r, "gpg did not create the key (cancelled?)."))?;
        let r2 = run(&["--quick-add-key", "--", &fpr, sub, "encr", "never"], b"")?;
        if !r2.status_ok {
            return Err(format!(
                "The signing key {fpr} was created but the encryption subkey was not: {}",
                human(&r2, "gpg refused")
            ));
        }
        Ok(fpr)
    })
    .await
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;

    const LISTING: &str = "\
tru::1:1724112000:0:3:1:5
pub:u:255:22:1A2B3C4D5E6F7A8B:1700000000:0::u:::scESC:::::ed25519:::0:
fpr:::::::::ABCDEF0123456789ABCDEF0123456789ABCDEF01:
uid:u::::1700000000::HASH::Ada Lovelace <ada@example.org>::::::::::0:
uid:u::::1700000001::HASH2::Ada \\x3a Work <ada@work.example>::::::::::0:
sub:u:255:18:0011223344556677:1700000000::::::e:::+:::cv25519::
fpr:::::::::1111111111111111111111111111111111111111:
pub:f:4096:1:FFEEDDCCBBAA9988:1600000000:1900000000::f:::scESC::::::::0:
fpr:::::::::FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:
uid:f::::1600000000::HASH3::Grace Hopper <grace@proton.me>::::::::::0:
pub:r:3072:1:0000000000000001:1500000000:0::-:::sc::::::::0:
fpr:::::::::2222222222222222222222222222222222222222:
uid:r::::1500000000::HASH4::Old Key::::::::::0:
";

    #[test]
    fn parses_keys_secrets_uids_and_flags() {
        let keys = parse_keys(LISTING);
        assert_eq!(keys.len(), 3);
        let ada = &keys[0];
        assert_eq!(ada.fingerprint, "ABCDEF0123456789ABCDEF0123456789ABCDEF01");
        assert_eq!(ada.key_id, "1A2B3C4D5E6F7A8B");
        assert_eq!(ada.algo, "ed25519");
        assert!(ada.has_secret, "secret flag carried on the subkey");
        assert_eq!(ada.validity, "ultimate");
        assert_eq!(ada.created.as_deref(), Some("2023-11-14"));
        assert_eq!(ada.expires, None);
        assert!(ada.can_encrypt && ada.can_sign);
        assert_eq!(ada.uids.len(), 2);
        assert_eq!(ada.uids[0].email, "ada@example.org");
        assert_eq!(ada.uids[0].name, "Ada Lovelace");
        assert_eq!(ada.uids[1].name, "Ada : Work", "\\x3a unescaped");

        let grace = &keys[1];
        assert!(!grace.has_secret);
        assert_eq!(grace.algo, "rsa4096");
        assert_eq!(grace.validity, "full");
        assert_eq!(grace.expires.as_deref(), Some("2030-03-17"));

        let old = &keys[2];
        assert!(old.revoked);
        assert_eq!(old.uids[0].email, "");
        assert_eq!(old.uids[0].name, "Old Key");
        assert!(!old.can_encrypt);
    }

    #[test]
    fn parses_signature_status_lines() {
        let st: Vec<String> = [
            "ENC_TO 0011223344556677 18 0",
            "DECRYPTION_OKAY",
            "GOODSIG 1A2B3C4D5E6F7A8B Ada Lovelace <ada@example.org>",
            "VALIDSIG 1111111111111111111111111111111111111111 2024-01-01 1704067200 0 4 0 22 8 00 ABCDEF0123456789ABCDEF0123456789ABCDEF01",
            "TRUST_ULTIMATE 0 pgp",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let sigs = parse_signatures(&st);
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].status, "good");
        assert_eq!(sigs[0].fingerprint, "ABCDEF0123456789ABCDEF0123456789ABCDEF01", "primary fingerprint, not subkey");
        assert_eq!(sigs[0].trust, "ultimate");
        assert_eq!(sigs[0].uid, "Ada Lovelace <ada@example.org>");

        let bad: Vec<String> = ["BADSIG 1A2B3C4D5E6F7A8B Ada", "ERRSIG AAAAAAAAAAAAAAAA 22 8 00 1704067200 9 -"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let sigs = parse_signatures(&bad);
        assert_eq!(sigs[0].status, "bad");
        assert_eq!(sigs[1].status, "unknown-key");
    }

    #[test]
    fn validates_inputs() {
        assert!(check_fpr("abcd ef01 2345 6789 abcd ef01 2345 6789 abcd ef01").is_ok());
        assert!(check_fpr("1A2B3C4D5E6F7A8B").is_ok());
        assert!(check_fpr("--homedir").is_err());
        assert!(check_fpr("ZZZZZZZZZZZZZZZZ").is_err());
        assert_eq!(check_recipient("Ada@Example.org").unwrap(), "ada@example.org");
        assert!(check_recipient("-r x@y.z").is_err());
        assert!(check_recipient("ada@example.org --trust-model always").is_err());
        assert!(check_recipient("<ada@example.org>").is_err());
        assert!(check_recipient("nobody").is_err());
    }

    #[test]
    fn dates_convert() {
        assert_eq!(epoch_to_iso("0"), None);
        assert_eq!(epoch_to_iso("951782400").as_deref(), Some("2000-02-29"));
        assert_eq!(epoch_to_iso("1724112000").as_deref(), Some("2024-08-20"));
    }

    /// Real round trip against the installed gpg in a throwaway home.
    /// Skipped when gpg is missing; loopback pinentry is test-only.
    #[test]
    fn live_gpg_roundtrip() {
        let Some(bin) = gpg_binary() else {
            eprintln!("gpg not installed; skipping");
            return;
        };
        let home = std::env::temp_dir().join(format!("saavi-gpg-test-{}", std::process::id()));
        std::fs::create_dir_all(&home).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let h = home.to_string_lossy().to_string();
        let gpg = |args: &[&str], stdin: &[u8]| {
            let mut c = command(bin);
            c.env("GNUPGHOME", &h).args(["--pinentry-mode", "loopback", "--passphrase", ""]).args(args);
            let mut child = c.spawn().unwrap();
            child.stdin.take().unwrap().write_all(stdin).unwrap();
            child.wait_with_output().unwrap()
        };
        let gen = gpg(&["--quick-generate-key", "--", "Test <t@example.org>", "ed25519", "cert,sign", "never"], b"");
        let st = String::from_utf8_lossy(&gen.stderr).to_string();
        let fpr = st.lines().find_map(|l| l.strip_prefix("[GNUPG:] KEY_CREATED ")).and_then(|x| x.split(' ').nth(1)).unwrap().to_string();
        assert!(gpg(&["--quick-add-key", "--", &fpr, "cv25519", "encr", "never"], b"").status.success());

        let list = gpg(&["--with-colons", "--fixed-list-mode", "--with-fingerprint", "--with-secret", "--list-keys"], b"");
        let keys = parse_keys(&String::from_utf8_lossy(&list.stdout));
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].fingerprint, fpr);
        assert!(keys[0].has_secret && keys[0].can_encrypt && keys[0].can_sign);
        assert_eq!(keys[0].uids[0].email, "t@example.org");

        let enc = gpg(&["--armor", "--encrypt", "--sign", "--local-user", &fpr, "--recipient", "t@example.org"], b"hello keyring");
        assert!(enc.status.success(), "{}", String::from_utf8_lossy(&enc.stderr));
        let dec = gpg(&["--decrypt"], &enc.stdout);
        assert_eq!(String::from_utf8_lossy(&dec.stdout), "hello keyring");
        let status: Vec<String> = String::from_utf8_lossy(&dec.stderr).lines().filter_map(|l| l.strip_prefix("[GNUPG:] ").map(str::to_string)).collect();
        assert!(status.iter().any(|s| s == "DECRYPTION_OKAY"));
        let sigs = parse_signatures(&status);
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].status, "good");
        assert_eq!(sigs[0].fingerprint, fpr);
        assert_eq!(sigs[0].trust, "ultimate");

        // Tamper: flip a byte in the armored body → must not be DECRYPTION_OKAY.
        let mut t = enc.stdout.clone();
        let mid = t.len() / 2;
        t[mid] = if t[mid] == b'A' { b'B' } else { b'A' };
        let bad = gpg(&["--decrypt"], &t);
        assert!(!String::from_utf8_lossy(&bad.stderr).contains("DECRYPTION_OKAY"));

        let _ = gpg(&["--no-autostart", "--version"], b"");
        let _ = Command::new(bin.with_file_name(exe("gpgconf"))).env("GNUPGHOME", &h).args(["--kill", "all"]).output();
        let _ = std::fs::remove_dir_all(&home);
    }
}
