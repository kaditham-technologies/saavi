# Changelog

## Unreleased

- **Key management** (system keyring): a Details panel (double-click or
  the Details button) with fingerprint, algorithm, expiry, validity,
  owner trust, user IDs and subkeys — and actions: set expiry, change
  passphrase, add / revoke user ID, set owner trust, certify another key
  (local or exportable), export public key, fetch a key from
  keys.openpgp.org by fingerprint. All through gpg; passphrases via pinentry.
- **Sign and Verify**: clearsign text with a chosen key and verify
  clearsigned messages, in both keyrings. Unseal of a clearsigned message
  verifies it.
- **Signing is explicit**: a "Sign as" choice in the sealer for both
  keyrings. Sealing no longer signs silently.
- **Files** (roadmap #2): seal / unseal files from the sealer or by
  dropping them on the window; `.gpg` / `.pgp` / `.asc` drops unseal,
  everything else seals. Binary OpenPGP output, signature verdicts shown.
- **Passphrase suggestion** in the key wizard: six EFF-diceware words
  (≈77 bits) from the CSPRNG, shown in clear, with a nudge to keep it in
  a password manager. A show/hide toggle on the passphrase fields.
- **Recipient lookup** falls back to keys.openpgp.org when a domain has
  no WKD (same address check and size cap as WKD).
- All questions and confirmations are in-app dialogs; no `confirm()` /
  `prompt()`, which misbehave inside webviews.
- **System GnuPG keyring** (roadmap #3). A keyring-source switch in the
  toolbar — Saavi store (default, unchanged) or the real `~/.gnupg`. In
  system mode every operation is the user's own `gpg`: list (with
  validity, secret-key presence, revoked/expired state), generate
  (ed25519 + cv25519 or RSA-4096, passphrase via pinentry), import,
  export public / backup secret, delete public keys, seal to keyring or
  WKD-located recipients with optional signing, unseal with gpg's
  signature verdict shown (good / bad / unknown key, plus trust level).
  Untrusted recipient keys are refused until confirmed per operation.
  Requires GnuPG; the app works exactly as before without it.
- macOS (universal `.dmg`) and Windows (`.msi`, `-setup.exe`) builds join
  Linux in every release, each GPG-signed and listed in `latest.json`.
  Release notes carry first-launch instructions for the OS warnings
  (no Apple/Microsoft code-signing yet).
- The webview can now write only to the file chosen in the save dialog —
  the static `$HOME/**` scope is gone (closes the last audit item).
- Toolchain: TypeScript 7, Vite 8 (rolldown), Vitest 4; Node 22 is now
  the floor. GitHub Actions bumped to current majors.
- Desktop polish: native widgets follow the active theme, thin
  scrollbars, no rubber-banding, visible keyboard focus, ⌘/Ctrl+1 / 2 to
  switch modes and ⌘/Ctrl+Enter to seal. Icon re-rendered from the SVG
  at 1024 px with `.icns` / `.ico`.

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
