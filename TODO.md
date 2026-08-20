# TODO — hardening backlog

Items surfaced by the FOSS preflight audit (2026-08-20) that were flagged
rather than fixed. Ordered by value. Tick them off as they land; each
should get a CHANGELOG line.

## Security

- [x] **Narrow the fs write scope.** Verified in `tauri-plugin-dialog`
      2.7.2 source (`commands.rs:251`): `save()` adds the chosen path to the
      fs scope itself. The static `$HOME/**` scope is gone; the webview can
      write only to the file the user just picked.
- [ ] **Auto-lock.** `pgp.clearSession()` exists but is never called.
      Unlocked keys live in memory until the app exits. Add an idle timeout
      (e.g. 15 min) and a manual "Lock all" toolbar action.
- [ ] **Signing is silent.** `encryptText` signs with whichever key is
      unlocked without telling the user. Show "signed as <address>" on the
      sealed output, with a way to seal unsigned.
- [ ] **Signature verification on unseal.** `decryptText` never verifies
      (no sender key is passed) and the UI shows nothing either way. Verify
      against pasted keys / WKD and display signed-by + fingerprint, or an
      explicit "unsigned".
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

## Project hygiene

- [x] **Tests.** `tests/` covers the keystore, import, rotation, seal /
      unseal, tamper detection, WKD hashing (draft-koch vector) and the
      WKD user-ID check. Still untested: `main.ts` (UI) and `saveBackup`
      (needs the Tauri shell).
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
