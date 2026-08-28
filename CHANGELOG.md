# Changelog

## Unreleased

- **Publish reaches your own domain.** "Publish key…" now also submits the
  public key to Kaditham's Web Key Directory when the address's domain is
  served there ("encrypted-email-ready" domains) — a confirmation mail to
  the address itself is the ownership proof, same as the keyserver's flow.
  Domains not served by Kaditham are skipped quietly; keys.openpgp.org
  publishing is unchanged.

## 0.3.5 — 2026-08-28

- **Sealing tells you it's working.** Sealing to an address kicks off key
  discovery over the network (WKD, then keys.openpgp.org), and until now
  the UI simply went quiet for the duration. The Seal button now reads
  "Looking up keys…" and stays disabled until discovery answers, so a
  second click can no longer race the first.
- **Key discovery can no longer hang.** Every discovery request carries a
  ten-second timeout; a recipient domain that accepts the connection and
  then goes silent used to pin sealing on the platform's TCP timeout —
  now it fails over to the next source within ten seconds, and the error
  says which domain could not be reached.
- **Stricter imports.** Importing a key that carries no user ID for the
  address it is being imported under is refused — every discovery source
  (WKD, keyserver, paste) now applies the same rule, so a key server or a
  pasted blob can never bind someone else's key to an address.
- **End-to-end tests for the UI** (`e2e/`, Playwright): the browser build is
  driven for real — generate and rotate keys, click-for-details, a full
  seal→unseal round-trip, wrong-passphrase rejection, Lock, the update
  banner and keyserver publishing against a mocked network. Ten scenarios,
  a new `e2e` CI job — and since the browser build is exactly the shared
  core the webmail vendors, this is also the parity floor for it.

## 0.3.4 — 2026-08-26

- **One-click updates.** When the banner announces a new release, Saavi now
  downloads the update package itself and verifies its signature against a
  public key baked into the running binary (Tauri updater, minisign — a
  separate key from the GPG release signing key) before offering a single
  **Install & restart** button. Nothing installs without that click; a
  package that fails verification is discarded and the browser flow
  returns.
- **One-click updates for .deb installs too.** The Tauri updater cannot
  drive dpkg, so Saavi walks the manual chain itself: it verifies
  `SHA256SUMS.asc` against the release key pinned in the app, checks the
  downloaded `.deb` against its signed checksum, and installs on your
  click through polkit's system authentication (`pkexec dpkg -i`), then
  relaunches.
- **The update check runs on every launch.** It was capped at once per
  calendar day, so "restart to see if there's an update" silently did
  nothing for the rest of the day. It is still a single GET of our own
  static manifest — nothing else changes: no third party, no identifiers,
  nothing downloaded or installed.

## 0.3.3 — 2026-08-26

- Header polish: the top-left mark is now the Saavi key tile (the launcher
  icon, inlined SVG) instead of the Tamil "சா" letters, and the tagline
  reads "Friendly desktop OpenPGP" — here and everywhere else it appeared
  (README, package metadata, the installer's short description).

## 0.3.2 — 2026-08-26

- **The running version is visible.** A quiet `vX.Y.Z` sits in the status
  bar next to the update control — "what version am I on?" no longer needs
  the package manager.
- **Publish your key to keys.openpgp.org.** A new action in key details
  uploads the public key (own keys only — Saavi store, or system keys with
  their secret half here). The key is findable by fingerprint immediately;
  the keyserver mails each address a verification link, and by-email search
  works once it is clicked.
- **Revocation certificates.** Key details can now save the signed "this key
  is no longer valid" note — generated up front with new Saavi-store keys
  (and stored alongside them), derived on demand for imported or older keys
  (unlock required), and produced by gpg itself for system keys. Keep it
  separate from backups; import + publish it if a key is ever lost or
  compromised. GnuPG-interop tested.

## 0.3.1 — 2026-08-26

- **Key details on a single click.** Clicking a key row now opens the details
  dialog directly, in both the Saavi store and System GnuPG views — it used to
  need a double-click or the toolbar's Details button, so a plain click looked
  like it did nothing.

## 0.3.0 — 2026-08-25

### Security (external audit + review response)

- **Signature verdicts on every unseal, both keyrings.** `decryptText` and
  `decryptBytes` now classify EVERY signature (good / bad / expired / revoked
  / unknown-key / unsigned) against candidate keys and return a worst-first
  summary — a bad signature can never hide behind a good one. The Saavi-store
  unseal shows the same Unsigned / Signed-by / trusted verdicts the system
  GnuPG path always did; an unknown signer is looked up by key ID on
  keys.openpgp.org (as an untrusted candidate — it can name a signer, never
  vouch for one). *(audit M1)*
- **"Your key" is a fingerprint comparison, never a UID substring.** The
  Verify and unseal trust badges compare the signer's fingerprint against
  this device's keys; a stranger's key whose user ID embeds your address can
  no longer render as "trusted key". *(audit M2)*
- **Corrupt store records are quarantined, not silently dropped.** A ring
  that fails to parse is parked under a quarantine key and surfaced as a loud
  alert in the key table, instead of the key simply vanishing. *(audit M3)*
- **Imported keys are re-locked with our S2K.** A cleartext or weak-S2K
  export is re-encrypted under the current passphrase on import. *(audit I3)*
- **System-keyring trust changes now confirm natively.** `gpg_import`,
  `gpg_set_ownertrust`, `gpg_recv_key` and `gpg_delete_public` show a native
  OK/Cancel dialog naming the fingerprint before touching `~/.gnupg`, so a
  webview alone cannot poison the keyring every other tool reads. *(audit L1)*
- **Keychain keys unlock lazily.** Remembered keys are no longer unlocked on
  every key-list refresh (which undid Lock and the idle timer); the table
  shows "remembered" from a keychain probe, and a key is decrypted only when
  actually used. A hidden window now also auto-locks. *(audit L2, L9)*
- **Decryption belt:** `DECRYPTION_FAILED` alongside `DECRYPTION_OKAY` now
  counts as failure. `human()` prefers an error/failure line over gpg's
  trailing "not certified" warning. Locked-key detection is structural (key
  IDs) with the error-string match only as a fallback. *(audit L4, L8, hardening)*
- **Encrypt-to-self in the sealer** so the sender keeps a readable record of
  what they sent. *(audit L6)*
- **WKD/VKS hardening:** the domain is validated before URL construction, and
  the size cap is enforced WHILE streaming (a chunked response with no
  Content-Length can no longer defeat it). The update manifest read is
  capped the same way. *(audit L7, 04)*

- **MIME layer for PGP/MIME letters** (`src/mime.ts`): builds and parses the
  inner MIME entity that gets encrypted — text + HTML alternatives,
  attachments, and the real Subject as a protected header
  (`protected-headers="v1"`, the Thunderbird/LAMPS convention) so the
  visible subject can stay "...". Base64 leaf parts throughout; the parser
  also reads foreign mail (quoted-printable, RFC 2047/2231 filenames,
  LF-only input). `buildEncryptedMessage` assembles the complete outer
  RFC 5322 + RFC 3156 `multipart/encrypted` message around an armored
  ciphertext — the exact wire bytes (webmail imports and submits them; a
  desktop export can write them as .eml).
- **GnuPG interop tests** (`tests/interop.test.ts`, skipped when no `gpg` on
  PATH): real GnuPG decrypts our sealed MIME letters and reports GOODSIG on
  our signatures; we decrypt GnuPG's ciphertext. Documented finding: OpenPGP
  text-mode literals canonicalise line endings, so nothing may depend on
  CRLF surviving decryption — the MIME parser is line-ending-agnostic.
- Sealer: the To field accepts addresses separated by commas, semicolons,
  spaces or new lines (before, anything but a comma made one unusable
  address). When no key is found the message now says why, per address:
  the domain publishes none over WKD and keys.openpgp.org has none —
  or the domain could not be reached at all.

## 0.2.1 — 2026-08-20

- **First run, fewer decisions** (Saavi store): a new key opens with six
  generated words already filled in — "New words" for another set, "Copy"
  (clipboard cleared after 30 s), "Use my own" to type a passphrase
  instead. "Remember in the OS keychain" starts ticked where a credential
  store exists, so the words are typed essentially never. Saavi still is
  not a password manager; the hint names a few.
- **Update indicator** (opt-in, check-only): tick "Check for updates" in
  the status bar and Saavi fetches the release manifest from kaditham.ie
  once a day; a pill appears when a newer version exists and opens the
  download page. Nothing is downloaded or installed; no identifiers sent.
- Fixed: on Linux the theme and keyring dropdowns rendered as white native
  controls regardless of theme.

## 0.2.0 — 2026-08-20

- **Auto-lock** (Saavi store): unlocked private keys are forgotten after
  15 minutes without input, and on demand — Lock on the keyring toolbar
  or ⌘L / Ctrl+L. Keys remembered in the OS keychain reopen silently when
  next needed; the rest ask for their passphrase again.
- **OS keychain** (roadmap #1, Saavi store): tick "remember in the OS
  keychain" when unlocking or creating a key and the passphrase is kept
  in macOS Keychain / Windows Credential Manager / Secret Service; Saavi
  then unlocks without asking. Per key, opt-in, "Forget" in Details.
  Offered only where a credential store exists.
- Security (review follow-ups): recipients are passed to gpg in exact-
  mailbox form (`<addr>`) — a bare address is a substring match that a
  look-alike key could win; a sender-chosen filename inside a sealed file
  is reduced to its basename before it becomes a save suggestion (it could
  point at `../../.ssh/authorized_keys`); gpg file operations now open the
  save dialog on the Rust side, so the webview never names an output
  file; relative PATH entries are ignored when locating gpg.
- Fixed: `TRUST_FULLY` signatures were shown as "not yet trusted"; large
  inputs could deadlock the gpg pipe; a hostile user ID could crash the
  keyring listing; dropping several files at once ran tangled flows;
  `IMPORT_RES` secret-key count was off by one; an expired or revoked
  signer was reported as tampering.
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
