# Changelog

## 0.1.1 — 2026-08-18

- Fixed: the whole UI rendered at once — keyring, sealer, and the key
  wizard modal all stacked on top of each other. `hidden` sections were
  overridden by their own `display` rules; the app opened stuck behind
  the wizard overlay.
- The key wizard now ends on a "Your key is ready" step showing the new
  fingerprint, with an explicit "Save backup file…" button that opens a
  real save dialog. The old auto-download silently did nothing inside
  the app shell.
- Backup from the toolbar uses the same save dialog and reports where
  the file went in the status line.
- WKD recipient lookup goes through the shell's HTTP plugin — webview
  CORS blocked most domains before, so sealing to an address rarely
  found a key.

## 0.1.0 — 2026-08-18

- Initial scaffold: keyring table (−k), sealer (−d), passphrase-locked
  keystore, WKD recipient lookup, key generate/import/backup/delete.
- Six-theme family shared with Kaditham Mail (Varnam OKLCH engine).
- App icon: the violet key, transparent corners.
