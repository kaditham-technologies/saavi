# Changelog

## 0.1.2 — 2026-08-20

- Security: WKD results are accepted only when the fetched key carries a
  user ID for the exact address looked up (a domain's WKD server could
  otherwise hand back a key for someone else), and responses over 1 MiB
  are refused.
- Security: the webview CSP no longer allows `connect-src https:` — the
  shell talks to the network only through the Rust http plugin — and gains
  `object-src`/`base-uri`/`form-action 'none'`.
- Unseal now reports a tampered or malformed message as such instead of
  asking for a passphrase again — including when the right key is already
  unlocked and still cannot open it.
- Import: a cleartext key must be locked with a passphrase of at least 12
  characters; the imported key's real creation date is kept; re-importing
  the active key no longer retires a copy of itself.
- WKD redirects that land on plain HTTP are refused.
- Toolbar Backup reports write failures in the status line instead of
  staying silent.
- Releases fail rather than publish unsigned when the signing key is
  missing. README/SECURITY wording tightened to what the code does.
- Releases now also publish `SHA256SUMS` (+ clearsigned `.asc`) and a
  `latest.json` manifest for download pages; `docs/DISTRIBUTION.md`
  describes the GitHub + direct-download model.
- Test suite (`npm test`): 20 vitest cases over the keystore and WKD,
  run in CI.
- OpenPGP.js is built as its own chunk; `THIRD-PARTY-NOTICES.md` lists
  component licenses (FOSS preflight). Dependabot and an `npm audit` /
  `cargo audit` CI job added; ROADMAP and PARITY moved under `docs/`.

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
