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
  are shown for out-of-band verification. Recipients' fingerprints are not
  yet displayed before sealing (see TODO.md): a domain's own WKD server is
  trusted for its users, as in GnuPG.

Generated keys do not expire; rotation in Saavi (generate a new key, the
old one is retired but kept) is the intended lifecycle.

**Saavi does NOT protect against:**
- A compromised operating system or user account (keyloggers, memory
  scrapers). No desktop app can.
- A weak passphrase on the keystore.
- Loss: there is no escrow and no recovery. The backup file plus the
  passphrase are the only path back.

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

Installs the updater cannot serve — a `.deb`, where updates belong to
dpkg/apt — keep the manual flow: the banner opens the download page, and
every installer remains GPG-signed with `SHA256SUMS` + `SHA256SUMS.asc`
for out-of-band verification.
