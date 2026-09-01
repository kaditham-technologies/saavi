# Changelog

## Unreleased

- **Your keys now live on disk, sealed by the OS keychain.** In the desktop
  shell, the Saavi store stops being browser-profile storage and becomes a
  single file: every ring as one versioned bundle, encrypted under a
  generated secret the platform credential store holds, written atomically
  so a crash can never leave it half-written. Your first start after
  updating migrates automatically — and carefully: a backup is written and
  proven to open, the sealed store is written and proven to read back, and
  only then is the browser-held copy removed. If any of that fails, nothing
  has moved and Saavi says so. A store that exists but cannot be opened
  (the keychain refused, the secret is gone) is reported plainly rather
  than shown as an empty keyring. The browser build is unchanged. This is
  the groundwork for one keystore shared with Kaditham Mail, and for
  syncing keys between devices — the shape of the bundle is the point.

## 0.4.4 — 2026-08-30

- **Saavi notices a release while it is open.** The update check ran once, at
  launch, and nowhere else — so an app left open for days never learned a newer
  version existed. That is not a corner case; it is what happens to anyone who
  keeps Saavi open, which is rather the point of a desktop app. It now also
  checks hourly, and when the window comes back to the front. A tick and a
  focus arriving together share one request, and the front-of-window check is
  rate-limited so that switching windows does not poll the site. Turning the
  setting off still turns all of it off.
- **The headers a letter is judged by are now signed.** Until now the protected
  header carried only the Subject, so From, To, Date and Message-ID travelled
  outside the signature where anyone relaying a message could rewrite them. A
  signed letter could therefore be lifted out of its envelope and re-delivered
  under headers naming a different sender, recipient or day, and a reader had
  no way to tell. Sealed letters now carry all five inside the signature. This
  release is the groundwork: it changes what Saavi *sends*, and readers begin
  using it in a later one — messages remain readable by every client either
  way.
- **The window is no longer a third empty.** 0.4.3 opened at 1220×760 to fit
  the two-pane sealer, and overshot: the content ends at about 520px, so the
  bottom third was blank on first run. It now opens at 1220×560, which leaves
  a margin under the file dropzone without cutting into it.

## 0.4.3 — 2026-08-30

- **The window opens wide enough to hold both halves.** The default was
  860×640 — a two-pane sealer given one column's worth of room, so the
  result you had just produced was a stub beside a writing box nobody asked
  to be that tall. Saavi now opens at 1220×760, the writing box is shorter,
  and the result runs the full height of the work beside it. Every one of
  those was something people were dragging by hand on first run.
- **Copy sits on the block being copied.** The button lived at the head of
  the result pane, which is where the eye leaves as soon as it starts
  reading. It is now a glyph in the corner of the block itself — the way a
  code block behaves in a chat — and it says *Copied* where it stands,
  because a clipboard write is otherwise completely silent. A refused
  clipboard selects the text and says *Selected* instead.
- **The To field offers the people you already hold a key for.** Every
  address Saavi can seal to without a lookup is already in the store: the
  keys in your GnuPG ring, or the keys remembered from earlier seals plus
  your own addresses. They were being retyped from memory. A chevron in the
  field now lists them, grouped, with the last eight of each fingerprint,
  and marks the ones already in the To line. Typing an unknown address still
  works exactly as before — this only removes the need to when it is known.
- **An address and a pasted public key are no longer the same box.** A whole
  armored key had to go into a one-line input, where it was unreadable and
  unfixable. To is now two modes: *Address*, with the picker, and *Public
  key*, which is a proper paste area.
- **A quarantined key record stopped posing as an address.** A record that
  failed to parse is preserved under `saavi-ring-corrupt-<address>-<stamp>`,
  and the scan that lists your addresses accepted it because it still
  contains an `@`. It appeared in the Sign-as list, and would have appeared
  in the new recipient picker.

## 0.4.2 — 2026-08-29

- **The sealer shows you the result instead of hiding it.** Sealed and
  unsealed text used to appear below the buttons in a narrow column, so on a
  wide window half the screen sat empty and a letter you had just unsealed
  landed under the fold — you had to scroll to read it. The sealer is now
  two panes: what you are working on, and what came out. The result pane is
  always there, so it reads as a destination rather than something that
  materialises; the signature verdict and a Copy button sit at its head
  rather than beneath a wall of armour; and Seal/Unseal are visibly one pair
  with Sign/Verify another. On a narrow window the panes stack, the text box
  shrinks, and a new result scrolls itself into view.
- **Copy buttons where copying was the whole point.** A fingerprint exists
  to be read down a phone and a public key to be pasted into a mail, and
  both sat in a box you had to drag-select inside a webview. Every dialog
  code box now carries Copy, and so does the fingerprint on "Your key is
  ready". If the clipboard is refused, the text is selected instead.
- **Publishing to Kaditham WKD no longer fails in silence.** Only success
  printed anything: a rate limit, a key carrying no user ID for the address,
  or the service being down all produced the success message minus one
  paragraph, which nobody would notice. It now reports what the server said,
  and that the keyserver upload is unaffected.
- **Publish says the verification mail may land in spam**, because it does.
- Fixed: a blank button sat beside Close on every notice dialog.

## 0.4.1 — 2026-08-29

External audit; five findings, all actioned.

- **The webview can no longer name a file for gpg to open.** Saavi let the
  frontend pass an absolute path straight to gpg, because that is how a
  dropped file reaches it — but "the webview named it" and "you chose it"
  are different claims, and frontend code that had been tampered with could
  name any readable file and have it decrypted. The shell now records what
  it watched you drop; a path it did not see gets a confirmation naming the
  exact file before gpg reads it. Dropping a file is still one gesture.
- **A paste holding several private keys is refused by name.** Importing
  what `gpg --export-secret-keys` produces with no fingerprint took the
  first key and dropped the rest without a word. An address holds one active
  key, so there is no right guess to make; Saavi now says how many it found
  and asks for the one you meant.
- **A hidden-recipient message asks for your passphrase instead of claiming
  no key fits.** Messages sent with the recipient hidden carry an all-zero
  key ID on purpose, so nothing can match it by name. Unsealing already knew
  to try anyway; the unlock prompt did not, and reported a message that
  would have opened as one that could not.
- **Every GitHub Action is pinned to a commit SHA.** Not a complete fix, and
  TODO.md says why: the bundler still fetches an unpinned binary mid-build.
- **The keystore stays on iterated-and-salted SHA, decided rather than
  deferred.** Argon2 is the stronger key-derivation function, but keys
  locked with it need GnuPG 2.4 or newer to import, and your backup file is
  the only way back to your key — an unimportable backup loses it outright.
  Six random words are ~77 bits, which is well past the point where the
  derivation function is what an attacker struggles with. Reasoning and the
  condition to revisit are in SECURITY.md.

## 0.4.0 — 2026-08-29

- **Every seal is readable by you, not just the signed ones.** Saavi always
  sealed a copy back to your own key — but only when you had chosen a "Sign
  as" identity. Seal without signing and the ciphertext was one you could
  never open again, which for a copy-paste sealer is permanent: there is no
  Sent folder to fall back on. Sealed files were worse and lost the copy
  even when signed, and the plaintext is usually deleted once the `.gpg`
  exists. Both now keep your copy, and the result says "also readable by
  you" whether or not you signed.

  Which of your keys takes the copy: the identity you are signing as, or
  your only address, or — if you hold several and are not signing — the
  first, named in the result so the choice is never silent. Never all of
  them: sealing to every identity you own would tell the recipient, and
  anyone who sees the ciphertext, that those addresses are the same person.
  System GnuPG mode is untouched; `encrypt-to` in your `gpg.conf` owns this
  there.

- **The tutorials now describe the app that exists.** Reading every claim on
  kaditham.ie/saavi back against the code turned up five more places where
  the pages had drifted: unlocked keys are dropped five minutes after the
  window hides, not the moment it does; changes to the GnuPG keyring are
  confirmed in one of Saavi's own dialogs, not a native one (`window.confirm`
  is unreliable in a webview, which is why the app draws its own); retired
  keys go when you delete them rather than never; System GnuPG needs GnuPG
  installed and stays greyed out until Saavi finds it; and the key dialog's
  button says Continue, not Generate.

- **A pasted key no longer swallows the rest of the To field.** Any pasted
  public key used to short-circuit recipient resolution: a second pasted key
  and every address typed beside one were dropped without a word, so the
  sender believed everyone listed could open the letter when only the first
  could. Keys and addresses now mix freely — paste several, type several, or
  both — and each is resolved on its own terms, pasted keys pinned under
  their primary address and typed addresses looked up as usual. The same
  applies to verifying a signature, and to System GnuPG mode, where several
  pasted keys import in one go and addresses beside them stay recipients.

## 0.3.9 — 2026-08-29

- **Looking up a key is no longer the same as trusting it.** Key resolution
  can now decide everything — first contact, changed key, revoked, withdrawn
  — without writing anything down, and the decision is made durable only once
  you act on it. Saavi resolves at the moment you press Seal, so nothing
  changes here; Kaditham Mail re-checks recipients as you type, where
  recording trust for an address you merely typed and deleted would be wrong.

## 0.3.8 — 2026-08-29

- **A fingerprint can be remembered before its key is.** Saavi can now record
  that an address's key has a particular fingerprint without holding the key
  itself — what you have when someone reads their fingerprint to you over the
  phone. The next lookup fills the key in; one that disagrees is reported as
  a changed key, exactly as it would be for a key remembered in full. Added
  for Kaditham Mail, whose own pinning kept fingerprints only and would
  otherwise have had to forget every correspondent it knew.

## 0.3.7 — 2026-08-29

- **Remembered keys are per account, not per machine.** Two people sharing a
  machine no longer inherit each other's decisions about whose key is whose.
  Saavi itself has one account — the device — so nothing changes here; the
  scope exists because the shared core now backs Kaditham Mail's key
  pinning too, and there a browser really can hold several accounts.
- **A key that was taken away is not "no key found".** When an address whose
  key you have sealed to before stops publishing one, Saavi says the key was
  withdrawn and refuses to seal, rather than reporting a plain miss — the
  one case where pasting a replacement or sending in clear is exactly wrong.

## 0.3.6 — 2026-08-29

- **Saavi remembers whose key is whose.** Until now every seal asked WKD (or
  keys.openpgp.org) fresh and forgot the answer, so a rotated key and a
  substituted key were the same silent event. The first key seen for an
  address is now remembered, and a later answer that disagrees stops the
  seal and shows both fingerprints side by side until you accept it. A
  first contact shows the fingerprint it just pinned, which is the one
  moment you can still check it with the person. Remembered addresses are
  listed under Keys, and can be forgotten there.
- **Revoked recipient keys are refused.** Revoking a key does not change its
  fingerprint, so a key check that only compares fingerprints cannot see it.
  Every discovered key is now inspected before use: a revoked one is
  refused by name, remembered as revoked, and never served again — not even
  by a later copy published without the revocation signature.
- **Sealing works offline to people you have sealed to before.** When no key
  server can be reached at all, the remembered key is used and the message
  says so. A domain that answers and no longer publishes a key is a
  different matter — that is a withdrawal, and the remembered key is not
  substituted for it.
- **A pasted public key is remembered under its own address only.** A key
  may name several addresses, including ones its holder does not own, so
  only the address it is primarily known by is pinned.
- **Fixed: the keyring's internal records were read as if they were
  addresses.** The store's alert list and any quarantined record share the
  key prefix used for addresses, so once a record had been quarantined every
  subsequent read quarantined the alert list again, over and over.

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
