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
  (OpenPGP S2K); the file alone is not enough.
- Key substitution in transit — WKD lookups are HTTPS, and fingerprints
  are always displayed for out-of-band verification.

**Saavi does NOT protect against:**
- A compromised operating system or user account (keyloggers, memory
  scrapers). No desktop app can.
- A weak passphrase on the keystore.
- Loss: there is no escrow and no recovery. The backup file plus the
  passphrase are the only path back.

## Crypto inventory

- OpenPGP operations: [OpenPGP.js](https://github.com/openpgpjs/openpgpjs)
  (Curve25519 default, RSA-4096 for legacy interop). No other crypto
  implementations are accepted into the codebase.
- Randomness: the platform CSPRNG via WebCrypto.
- Post-quantum: tracked in [docs/ROADMAP.md](docs/ROADMAP.md) — hybrid ML-KEM
  composites will be offered when OpenPGP.js ships the
  draft-ietf-openpgp-pqc algorithms, at which point key rotation inside
  Saavi is the migration path.
