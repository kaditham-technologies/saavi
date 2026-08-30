# TODO — hardening backlog

Items surfaced by the FOSS preflight audit (2026-08-20) that were flagged
rather than fixed. Ordered by value. Tick them off as they land; each
should get a CHANGELOG line.

## Security

- [ ] **H2 — protected headers beyond the Subject.** From/To/Date/Message-ID
      sit outside the signature, so surreptitious forwarding and replay can
      make a letter read as "signed by X" to someone X never wrote to. The
      truthfulness blocker on the authenticated-sender claim; outranks the key
      agent. Plan: `docs/H2-PROTECTED-HEADERS.md`.
- [ ] **Saavi as the key agent.** Keys out of browser storage and into a
      keychain-sealed store Saavi owns, served to paired clients over a
      loopback interface. Would be Saavi's first inbound surface — review it as
      such. Plan: `docs/KEY-AGENT.md`.
- [ ] **The update check runs once, at launch.** No timer and no re-check on
      focus, so an app left open never learns a release exists (observed on
      Linux, 0.4.2, the day 0.4.3 shipped). Give it the contract the webmail
      already has: hourly, plus on window focus, sharing one in-flight latch.
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
- [x] **Pin GitHub Actions to commit SHAs.** All 22 `uses:` lines in
      `ci.yml` and `release.yml` carry a SHA with the version as a trailing
      comment; Dependabot's github-actions ecosystem keeps them fresh.
- [ ] **The bundler still fetches an unpinned binary mid-build.**
      `tauri-action` downloads `AppRun-x86_64` from the `apprun-old` tag of
      tauri-apps/binary-releases with no checksum, inside the pinned action —
      so SHA pinning does not cover it. It is both a supply-chain input we do
      not verify and a build-time flake (a 504 there failed CI on a
      docs-only commit, 2026-08-29). Vendor it, or check it against a known
      hash before bundling.
- [x] **S2K choice — decided: stay on iterated-and-salted SHA.** Argon2 is
      the stronger KDF, but Argon2-locked keys need GnuPG 2.4+ to import and
      the backup file is the user's only way back; an unimportable backup
      loses the key outright. The defaults (six EFF words, ~77 bits; 12-char
      floor) also sit outside the band where a KDF decides anything.
      Reasoning and the revisit condition are in SECURITY.md → Crypto
      inventory.
- [ ] **Import: check the key carries the address** it is being filed
      under (`importKey` trusts the user-typed email). Warn, don't block.
      (A 12-character floor now applies when a cleartext key is locked on
      import; a locked key keeps whatever passphrase it came with.)
- [ ] **Transitive RustSEC warnings** (`unic-*`, `proc-macro-error`
      unmaintained; `glib 0.18` unsound iterator). All via Tauri/gtk-rs;
      clears when Tauri bumps. Re-check on each Tauri upgrade.

- [x] **Show recipient fingerprints before sealing** (WKD or pasted).
      Recipient pinning does this: first contact prints the fingerprint it
      just remembered, and a later disagreement stops the seal with both
      fingerprints side by side. See "Recipient key pinning" in
      SECURITY.md.
- [x] **Multiple pasted keys / mixed To field.** Handled rather than
      documented away, in 0.4.0: `pgp.splitKeyArmor` returns every armored
      block plus the surrounding text, so sealing, verifying and System
      GnuPG mode all take every pasted key and every typed address. Pinned
      by an e2e that mixes a pasted key with an address and expects the
      seal to refuse when that address cannot be resolved.
- [x] **Importing a secret-key blob no longer takes only the first key.**
      `pgp.importKey` counts the armored blocks and refuses a multi-key
      paste by name ("this paste carries N private keys"), because a ring
      holds one active key per address and there is no correct guess.
- [x] **Hidden-recipient messages prompt for the active key.**
      `decryptText` always knew to try a wildcard key ID; `neededKeyFor` and
      `neededKeyForBytes` did not, so a message that would have opened was
      reported as one that could not.

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

## Documenting pinning (2026-08-29)

Recipient key pinning landed across 0.3.6–0.3.9 and was documented
nowhere a user would look: the CHANGELOG describes it and `docs/PARITY.md`
tracks the shared-core contract, but the site's tutorials and the README
did not mention it at all. The chain below closes that, ending at the
Learn listing on kaditham.ie/saavi.

- [x] **Photograph the three pin surfaces.** `docs/screenshots/shots.js`
      now drives them with two generated keys claiming the same address —
      first contact (the fingerprint note), Known addresses, and the
      key-changed dialog — so no network or live WKD domain is needed.
- [x] **`/saavi/pinning/` — "Remembered keys".** The why (a fresh lookup
      cannot tell a rotation from a substitution), the first-contact
      moment, the Known addresses list and Forget, the change stop, and
      the withdrawn / revoked / unreachable answers.
- [x] **`/saavi/sealing/` points at it**, in the paragraph that used to
      say only that Saavi "finds their public key automatically".
- [x] **The Learn listing carries a fourth card**
      (`apps/saavi/page.html`, `grid-3` → `grid-2` so four cards make a
      2×2 rather than stranding one).

- [x] **README trust boundary** carries a pinning bullet.
- [x] **SECURITY.md** gains a "Recipient key pinning" section, and its
      key-substitution bullet no longer says recipients' fingerprints are
      "not yet displayed before sealing" — they have been since 0.3.6.

- [x] **`/saavi/sealing/` overstated the copy-to-self** — it promised a
      copy always came back to your own key, while an unsigned seal (and
      every sealed file) kept none. Fixed in the app rather than the
      sentence, in 0.4.0; pinned by an e2e spec that fails without it.
- [x] **The gentle guide's "Next steps"** links the new page, and the
      Saavi-store paragraph now points at it too.
- [x] **The Learn section** says fifteen minutes, for four pages.
- [ ] **`shots.js` cannot be run from inside the repo** — `package.json`
      has `"type": "module"`, so `node docs/screenshots/shots.js` dies with
      "require is not defined". It works only from a neutral working
      directory. Rename to `.cjs`, or say so in the header.
- [x] **Docs-to-app parity sweep of the tutorials** (0.4.0). Five drifted
      claims corrected on kaditham.ie: the window-hide lock is a five-minute
      timer, GnuPG-keyring changes are confirmed in Saavi's own dialog and
      not a native one, retired keys go only when deleted, System GnuPG
      needs gpg installed, and the key dialog's button says Continue. Worth
      repeating whenever the UI moves — every one of these was written true
      and went stale.

- [ ] **A walkthrough recording of the change stop**, the way
      `walkthroughs.js` covers first-key and sealing. It is the most
      persuasive thing the app does and it is currently a still.

## External audit, 2026-08-29 (post-0.4.0)

Five findings; all actioned. Notes on the two that were not simply "fix it".

- [x] **`pick_input()` accepted any absolute path from the webview.** The
      real primitive: tampered frontend code could name any readable file
      and have gpg decrypt it. The plaintext goes to a native save dialog,
      so exfiltration needed the user to accept that dialog — but the
      chosen path then enters the fs scope, and the http scope admits
      `https://*/.well-known/openpgpkey/**` on ANY domain, so a channel
      existed. The shell now records paths from `WindowEvent::DragDrop`
      that it observed itself; a path it did not see dropped gets the same
      native confirmation that guards the real keyring, naming the file.
      A dropped file is still one gesture, so the KGpg feel survives.
- [x] **Actions pinned to SHAs** — but see the `AppRun` item above: the
      auditor's finding does not close the whole hole, and pinning alone
      would have been a false sense of it.

- [ ] **A generated passphrase survives the switch to Import.** In the key
      dialog, picking six words and then switching the segment to Import
      leaves them in the passphrase field — which for an import means "the
      passphrase that unlocks the key you are pasting", so Continue fails
      with "that passphrase does not unlock this key". Present in Saavi and,
      by faithful parity, in Kaditham Mail's window. Clear the suggestion on
      the switch, in both.
