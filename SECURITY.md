# Security

## Reporting a vulnerability

Email **security@kaditham.me** (a PGP key for it is discoverable via WKD).
Please do not open public issues for vulnerabilities. We aim to respond
within 72 hours and to credit reporters unless they prefer otherwise.

## Threat model

Saavi exists because browser-delivered E2EE has a boundary it cannot
close: extensions and anything else sharing the browser profile can watch
the page, the keystrokes, and the storage. Saavi is a native shell with
no extension ecosystem.

**Saavi protects against:**
- Server-side reading of your keys or plaintext — there is no server;
  keys are generated and used on-device only.
- Theft of the keystore file — private keys are stored passphrase-locked
  (OpenPGP S2K); the file alone is not enough. Unlocked keys are held in
  memory only, and dropped after 15 minutes without input or on Lock.
- Key substitution in transit — WKD lookups are HTTPS end to end
  (redirects to plain HTTP are refused), the returned key must carry a
  user ID for the exact address asked for, and your own keys' fingerprints
  are shown for out-of-band verification. Beyond the transport, the Saavi
  store pins recipient keys on first use and stops the seal when one
  changes; see "Recipient key pinning" below for what that does and does
  not promise. A domain's own WKD server is still trusted for its users on
  first contact, as in GnuPG.

Generated keys do not expire; rotation in Saavi (generate a new key, the
old one is retired but kept) is the intended lifecycle.

**Saavi does NOT protect against:**
- A compromised operating system or user account (keyloggers, memory
  scrapers). No desktop app can.
- A weak passphrase on the keystore.
- Loss: there is no escrow and no recovery. The backup file plus the
  passphrase are the only path back.

## Recipient key pinning (Saavi store)

WKD and keys.openpgp.org answer "what is the key for this address?" fresh
on every seal and remember nothing, so on their own they cannot tell a key
rotation from a substitution — and neither event is ever shown to the
person sealing. `src/pins.ts` keeps that missing record. Policy lives
there; prompts do not, so Saavi and Kaditham Mail's KGPG window apply the
same rules through different UIs.

- **First use writes a pin and shows its fingerprint**, once. Trust on
  first use is only trustworthy if the first use is visible, and this is
  the moment the fingerprint can still be confirmed out of band.
- **A changed key stops the seal.** One question per seal, listing every
  changed recipient with both fingerprints, both sources, and the date the
  old key was first seen. Declining seals nothing to anyone — a partial
  send that reaches some recipients and silently drops the rest is treated
  as the worse outcome.
- **A withdrawn key refuses** instead of falling back to the remembered
  one: a key that was taken away is not a safe substitute. A revoked key
  refuses and points at asking for the replacement. An unreachable domain
  seals to the remembered key and says that is what it did.
- **Your own addresses are never pinned** — your keyring is the answer for
  those. A pasted key pins under its primary address only, so a key that
  also claims a colleague's address cannot quietly become the remembered
  key for that colleague.
- **Verifying never pins.** A signature verdict reports a fingerprint; it
  does not authorise sending anything to it. Verification uses pinned keys
  as candidates but never writes a pin and never raises a key-change
  question. Sealing is the only path that pins.
- **Pins are scoped to an owner**, so two accounts on one machine do not
  inherit each other's trust decisions. The desktop app passes one
  device-wide scope; the webmail scopes per signed-in user.

**What pinning is not.** Pins are public key material, not secrets — an
unreadable pin record is dropped rather than quarantined, because it is
always re-derivable from the network, and a full storage quota never
breaks sealing. More importantly, a pin asserts only *the same key as last
time*. It is not an identity check. The out-of-band fingerprint
confirmation at first contact is the step that authenticates anybody, and
Saavi can prompt for it but cannot perform it.

System GnuPG mode does not pin: trust there is gpg's own web of trust, and
an untrusted recipient key is refused until you say "this once".

## OS keychain (Saavi store, opt-in)

If the user asks Saavi to remember a Saavi-store passphrase, it is written
to the platform credential store (`keyring` crate: macOS Keychain, Windows
Credential Manager, Secret Service on Linux) under service
`ie.kaditham.saavi`, one entry per key fingerprint. The key's protection
at rest then rests on the OS login and the store's own guarantees rather
than on a passphrase only the user knows — the standard desktop trade,
stated in the checkbox itself. Nothing is remembered unless ticked; the
entry can be removed from Details → "Forget in keychain". The system
GnuPG keyring is unaffected: gpg-agent owns its own caching.

## The key store on disk (shell)

In the shell, the Saavi store is not webview storage: it is a single ring
bundle — every ring, the corruption alarms, and any quarantined records,
as one versioned unit (`src/bundle.ts`, docs/KEY-SYNC.md) — sealed with
OpenPGP symmetric encryption under a generated 256-bit secret held in the
platform credential store (`ie.kaditham.saavi` / `store:v1`), and written
atomically by the shell (`src-tauri/src/store.rs`, temp + fsync + rename,
owner-only permissions). The private keys inside remain passphrase-locked
exactly as before; the sealed file is a second layer, so a copied store
file is opaque without the OS keychain secret, and the at-rest protection
of the *file* rests on the OS login. The browser build keeps localStorage
— a web page has nowhere better.

Two behaviours are deliberate and load-bearing:

- **A store that exists but cannot be opened is BLOCKED, loudly** —
  keychain refused, secret missing, file damaged. It is never presented as
  an empty keyring, because the natural "fix" for an empty keyring is
  generating a second identity.
- **Migration destroys nothing.** Moving browser-held rings to disk first
  writes a backup and proves it reads back intact, then writes the sealed
  store and proves *it* reads back intact, and only then removes the
  browser copy. Any failure leaves everything where it was.

There is deliberately no command to delete the store secret: an orphaned
secret is harmless, a deleted one strands the store.

## System GnuPG mode

When the user switches the keyring source to System GnuPG, Saavi is a
front end to the installed `gpg` binary (`src-tauri/src/gpg.rs`):

- Fixed argument sets per operation; no shell, no user-controlled flags.
  Fingerprints must be hex and addresses must be a single `user@host` with
  no whitespace or brackets before they become arguments; all key and
  message material goes over stdin.
- Passphrases: gpg-agent + the user's pinentry. Saavi never prompts for,
  receives, or caches a system-key passphrase. (`--pinentry-mode loopback`
  is used only in the Rust test suite, against a throwaway `GNUPGHOME`.)
- Trust: gpg's trust model is respected. `--trust-model always` is sent
  only after the user confirms a specific untrusted recipient for one
  operation. Unseal shows `GOODSIG`/`BADSIG`/`ERRSIG` and `TRUST_*` verbatim.
- WKD in this mode is gpg's own `--auto-key-locate local,wkd`, so fetched
  keys land in the GnuPG keyring exactly as they would from the command line.
- The binary is found on `PATH` and the standard install directories for
  each OS; the path and version in use are shown in the toolbar. There is
  no environment-variable override (that would be a hijack vector).
- Deleting secret keys is refused; public-key deletion asks first.

## Crypto inventory

- OpenPGP operations: [OpenPGP.js](https://github.com/openpgpjs/openpgpjs)
  (Curve25519 default, RSA-4096 for legacy interop). No other crypto
  implementations are accepted into the codebase.
- System GnuPG mode: the user's installed GnuPG does everything; Saavi
  parses its output.
- Randomness: the platform CSPRNG via WebCrypto (Saavi store).
- Key-derivation for the keystore: **iterated-and-salted SHA (OpenPGP S2K
  mode 3), deliberately, not Argon2.** OpenPGP.js can produce Argon2-locked
  keys and Argon2 is the stronger KDF, but a key locked that way can only be
  imported by GnuPG 2.4 or newer — and a Saavi backup file is the user's
  only route back to their key. An unimportable backup on the machine where
  it is finally needed loses the key outright, which is a worse outcome than
  the attack Argon2 defends against. That attack also lands where Saavi is
  strongest: the wizard fills in six EFF words (~77 bits) and refuses
  anything under 12 characters, and no KDF is the deciding factor at that
  entropy — Argon2's advantage is largest for weak passphrases, which is the
  band these defaults are built to avoid. **Revisit when** GnuPG 2.4+ is
  broadly deployed on the platforms users restore onto, or if the passphrase
  floor is ever relaxed. Changing it is one `config.s2kType` line, so this
  is a decision rather than a limitation.
- Post-quantum: tracked in [docs/ROADMAP.md](docs/ROADMAP.md) — hybrid ML-KEM
  composites will be offered when OpenPGP.js ships the
  draft-ietf-openpgp-pqc algorithms, at which point key rotation inside
  Saavi is the migration path.

## Updates

With **Check for updates** ticked (the default; untick to opt out), Saavi
fetches `https://kaditham.ie/wp-content/uploads/saavi/latest.json` once
per launch and shows a banner if the version there is newer. The request
carries no identifiers and goes to our own site, not GitHub.

When a newer release exists, Saavi downloads the update package and
verifies its signature against a public key **baked into the running
binary** (a minisign key, separate from the GPG release key) before
anything is installed — a package that does not verify is discarded.
Installing still takes your explicit click on **Install & restart**;
nothing is ever installed silently. The manifest alone can only make
Saavi *say* a release exists.

A `.deb` install updates through dpkg instead (the Tauri updater cannot
drive it): Saavi fetches `SHA256SUMS.asc`, verifies the clearsigned list
against the **release key pinned in the app** (the same key the download
page documents), checks the downloaded `.deb` against its entry, and only
then offers **Install & restart** — which asks through polkit's own
system authentication dialog before `dpkg -i` runs. The chain is the same
one manual verification walks; the app just walks it for you. Every
installer remains GPG-signed with `SHA256SUMS` + `SHA256SUMS.asc` for
out-of-band verification, and the browser flow stays as the fallback.
