# TODO — hardening backlog

Items surfaced by the FOSS preflight audit (2026-08-20) that were flagged
rather than fixed. Ordered by value. Tick them off as they land; each
should get a CHANGELOG line.

## Security

- [x] **Narrow the fs write scope.** Verified in `tauri-plugin-dialog`
      2.7.2 source (`commands.rs:251`): `save()` adds the chosen path to the
      fs scope itself. The static `$HOME/**` scope is gone; the webview can
      write only to the file the user just picked.
- [x] **Auto-lock.** Unlocked keys are dropped after 15 minutes without
      input, and on demand (Lock on the toolbar, ⌘L / Ctrl+L). Keychain-
      remembered keys reopen silently when next needed. The timeout is
      fixed; a setting can come if anyone asks.
- [x] **Signing is silent.** A "Sign as" choice in the sealer; sealing
      signs only when a key is chosen, and the result label says so.
- [x] **Signature verification on unseal (Saavi store, encrypted+signed).**
      `decryptText`/`decryptBytes` classify all signatures against candidates
      (own keys, To field, WKD/VKS, plus a by-key-id VKS lookup for an unknown
      signer) and the unseal shows the same verdicts as Verify. Trust badge is
      a fingerprint comparison, not a UID substring (audit M2).
- [ ] **Pin GitHub Actions to commit SHAs** (`tauri-action@v0`,
      `checkout@v4`, `setup-node@v4`, `rust-toolchain@stable`,
      `audit-check@v2`). Dependabot now tracks them, so pins stay fresh.
- [ ] **S2K choice.** OpenPGP.js locks stored keys with iterated+salted
      SHA by default. Argon2 is stronger against offline guessing but
      backups then need `gpg >= 2.4` to import. Decide, document in
      SECURITY.md either way.
- [ ] **Import: check the key carries the address** it is being filed
      under (`importKey` trusts the user-typed email). Warn, don't block.
      (A 12-character floor now applies when a cleartext key is locked on
      import; a locked key keeps whatever passphrase it came with.)
- [ ] **Transitive RustSEC warnings** (`unic-*`, `proc-macro-error`
      unmaintained; `glib 0.18` unsound iterator). All via Tauri/gtk-rs;
      clears when Tauri bumps. Re-check on each Tauri upgrade.

- [ ] **Show recipient fingerprints before sealing** (WKD or pasted), so
      a substituted key at the recipient's domain is at least visible.
- [ ] **Multiple pasted keys / mixed To field.** Only the first pasted
      armored block is used and addresses beside a pasted key are ignored;
      `gpg --export-secret-keys` with several keys imports only the first.
      Say so, or handle all of them.
- [ ] **Hidden-recipient messages** (wildcard key ID) never match in
      `neededKeyFor`; they read as "no key fits" instead of prompting.

- [ ] **System keyring, next slice:** smartcard status (`--card-status`),
      pick the git-signing key, revoke a whole key (import a revocation
      certificate; gpg has no batch-safe `--quick-revoke-key`).
- [x] **OS keychain** (roadmap #1): opt-in remember / silent unlock /
      forget. Untested on a real macOS/Windows store from CI; Linux
      needs a Secret Service daemon (the option hides without one).
- [ ] **System keyring on macOS without a GUI pinentry** (Homebrew gpg +
      no pinentry-mac): gpg fails to ask for the passphrase. Detect and
      point at `pinentry-mac`.

## KGpg parity backlog (gap review 2026-08-26)

- [x] **Publish key to a keyserver** (keys.openpgp.org upload + verification
      mail). Landed with revocation certificates; CHANGELOG "Unreleased".
- [x] **Revocation certificates** — generate/save for own keys, both
      keyrings. (Revoking by IMPORTING a certificate through the UI is still
      the system-keyring "next slice" item above.)
- [ ] **Keyserver search UI** — find a key by name/address on
      keys.openpgp.org and import it (lookup exists in the sealer; there is
      no browse/search surface). Includes "refresh key from keyserver".
- [ ] **Drag-and-drop files** onto the window to seal/unseal (file pickers
      exist; DnD is the KGpg-feel gesture).
- [ ] **Add a subkey** (gpg `--quick-add-key`) for system keys.
- [ ] **Key groups** (gpg group lines) — only if a real user asks.

## Project hygiene

- [x] **Tests.** `tests/` covers the keystore, import, rotation, seal /
      unseal, tamper detection, WKD hashing (draft-koch vector) and the
      WKD user-ID check. `e2e/` (Playwright, CI job `e2e`) drives the real
      UI in a browser: generate/rotate, click-for-details, seal→unseal
      round-trip, wrong-passphrase, Lock, update banner and keyserver
      publish against a mocked network. Still untested: the Tauri-only
      half (system GnuPG UI, native dialogs, installers — needs
      tauri-driver).
- [ ] **Formatter/linter** (prettier + eslint or biome) wired into CI, so
      CONTRIBUTING can promise it again.
- [ ] **Issue / PR templates**, `CODEOWNERS`.
- [ ] **Reproducible builds** (ROADMAP #6): publish hashes a third party
      can regenerate.
- [ ] **Apple Developer ID + notarization, Windows Authenticode** so
      testers stop seeing Gatekeeper / SmartScreen warnings. Builds for
      both platforms now ship unsigned-by-OS (GPG-signed only).
- [ ] **Download page** on the Kaditham site consuming `latest.json` and
      mirroring assets (docs/DISTRIBUTION.md). Template for Mail/Calendar.
- [ ] **First tagged release after this preflight** to exercise the new
      `SHA256SUMS` / `latest.json` steps end-to-end (they are untested
      until a tag runs).
