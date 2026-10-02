# Sign in with Kaditham Mail (0.6.0)

Status: **built 2026-10-02**, awaiting the argus + cerberus gate. Roadmap item 4
("Kaditham Mail pairing"); the first step of [KEY-SYNC.md](KEY-SYNC.md) that a
customer can feel. Related: the webmail's `docs/KEYCHAIN.md` (the keychain this
signs into) and `docs/ZERO-ACCESS.md` (the password split).

## What it is, for the customer

On a new computer: open Saavi, sign in with a Kaditham Mail address and
password (and the 6-digit code, when two-factor is on), and the encryption keys
the webmail already uses are here — the active key and every retired one, so
old sealed mail opens too. They land in 0.5.0's sealed disk store, so after the
first time Saavi needs no network and no sign-in to work. Saavi without an
account is unchanged: the sign-in is an offer on first run, easy to skip, and a
row in the toolbar afterwards.

## Decisions (founder, 2026-10-02)

- **Signing out keeps the keys.** They are the customer's, sealed by the OS
  keychain on this device; signing out forgets the session (refresh token,
  in-memory secrets), not the keys. Removing keys stays the explicit
  per-key Delete it always was.
- **Two-factor is supported, not required.** An account with TOTP on gets the
  code step; an account without it signs in with the password.
- **A published-key mismatch warns; it never blocks.** See "The match check".
- **The device list includes app passwords** (Thunderbird, phone Mail): they
  cannot reach the keychain, but they are "what is signed in to my account".
- **First-run offer**, not a settings-only feature.

## The five things that make it more than a sign-in

1. **Proof the server did not cheat, on screen.** After restore Saavi compares
   three fingerprints for each address: the key it just unlocked here (the
   only one it trusts — the public half is derived from the private half, the
   cerberus V1 rule), the key the address publishes over WKD (what everyone
   else's mail app seals to), and the key the keychain blob claims. All three
   equal: "Your published key matches this device ✓" with the fingerprint.
   Any disagreement: a loud amber panel naming which source says what and what
   it would mean (a rotation still propagating; or a server answering
   differently than it should). Warn only — the customer may know why.
2. **Never a silent wait, never a dead end.** Every step is narrated
   ("Checking your password… · Signing in… · Fetching your keychain… ·
   Unlocking 2 keys… · Sealing them to this computer… · Checking your
   published key…"), and each Argon2/PBKDF2 step yields a frame first so the
   spinner paints before the main thread is taken (the webmail's 7-second
   silent unlock, 2026-10-02, is the lesson). Every failure names itself and
   the next step: wrong password · wrong code · rate limited (with the
   server's wait) · server unreachable · no keychain yet (offer to use Saavi's
   own keys, or start one in the webmail) · a key that wears an older
   passphrase (ask for it, per ring) · a damaged keychain (nothing installed,
   nothing lost).
3. **Where your keys live.** The account panel lists the devices that have
   downloaded the keychain (label + first/last seen, "this computer" marked),
   from the broker's new `GET /signup/api/keychain/devices`, and the account's
   app passwords (description, created, scope) from JMAP `x:AppPassword/get`.
   Seeing, not revoking: revocation needs a key rotation to mean anything and
   is KEY-SYNC S3.
4. **Instant after the first time.** Keys live in the sealed disk store; the
   session's refresh token lives in the OS keychain (never webview storage);
   no network is needed to seal, unseal or sign.
5. **Changes from other devices arrive — never silently.** On window focus
   (rate-limited, one in flight) Saavi asks the cheap status endpoint for the
   keychain version. Newer than the one this device last accepted: a banner
   "Your keychain changed on another device — bring it here?" The update is
   adopted only through `restore()`, i.e. only after the password proves every
   ring (cerberus V7: the merge path never adopts key material).

## Flows

### Sign in
1. Address + password. `deriveAuthSecret(password, address)` (PBKDF2, 600k,
   on-device; the password itself never leaves — the split).
2. PKCE `POST /api/auth` `{type:'authCode', clientId:'kaditham-saavi', …}`.
   `mfaRequired` → the code step, then the same call with `mfaToken`.
   (`kaditham-saavi` verified against staging Stalwart 2026-10-02: auth, token,
   refresh and the keychain status all answer for it — Stalwart does not
   require client registration, so Saavi is a distinct client in the logs.)
3. `POST /auth/token` (authorization_code). Access token in memory; the
   refresh token in the OS keychain (`account:v1` slot, see keychain.rs),
   with the address and server origin. No token is ever written to
   webview storage.
4. In memory for this session only: the account secret (the keychain's P6
   proof) and the password (the ring lock). A resumed session has neither:
   status and the device list work, restore/sync ask for the password.

### Restore (the core, shared with the webmail)
`mailkeychain.restore()` — moved here from the webmail unchanged in behaviour:
strict `parseBlob`, `bindRecord` (public half derived; UID must name the
address for actives), per-ring passphrase proof (rings that open are kept,
the rest reported pending with their own retry), full rollback when nothing
opens (storage AND session memory), only addresses the account owns. Saavi
then flushes the disk store.

### Sync
Push after local key events (generate, import, rotate) when signed in with the
password in hand; the 409 merge path, the no-shrink and no-drop guards, and the
rings-hash marker all as in the webmail. Pull only by restore.

## The core move

The webmail's `src/keychain.ts` becomes Saavi core `src/mailkeychain.ts`
(name avoids Saavi's `src/keychain.ts`, the OS-keychain bridge). Two seams:
- **transport**: `./server` (`apiUrl`, `netFetch`) — the webmail has its own
  `server.ts`; Saavi's routes through `tauri-plugin-http`, scoped in
  `capabilities/default.json` to exactly the account paths on
  `mail.kaditham.ie` (and the `mail.kaditham.me` staging twin).
- **store**: `pgp.installRing` / `pgp.uninstallRing` replace the file's old
  direct `localStorage['kad-pgp-…']` writes, so the same file writes through
  whichever `RingStore` the app installed (sealed disk in Saavi, localStorage
  in the webmail — byte-identical keys there via the sync script's existing
  `saavi-ring-` → `kad-pgp-` rename).
- **device name**: `useDeviceName()` — Saavi sends `X-Device-Name: Saavi on
  <OS>`; the webmail may adopt it later (the broker falls back to a coarse
  browser-on-OS label from the User-Agent).

Webmail follow-up (not done here — the webmail is mid-release): add
`{ echo "$BANNER"; cat "$SAAVI/src/mailkeychain.ts"; } > src/keychain.ts` to
`scripts/sync-saavi.sh` and re-run it; its tests (`keychain*.test.ts`) now live
here too.

## Broker change (signup)

- On every keychain fetch, the fetcher entry for the device mark records a
  `label` (`X-Device-Name`, sanitised, ≤ 60 chars; fallback "Browser on OS"
  from the User-Agent) and `seen` (last fetch). The novel/notified semantics
  are untouched: a device is still marked familiar only after the alert mail
  provably went out (cerberus V5), and only notified marks count as familiar.
- `GET /signup/api/keychain/devices`: Bearer, per-account rate limit after
  auth; returns `[{ label, firstAt, lastAt, current }]` — no IPs, no marks.
  No P6 proof: it reveals nothing a session holder could not learn from the
  alert mails, and the panel must work on a resumed session.

## Threat notes

- The account credential alone still cannot open a ring: the blob is locked
  to the password (Argon2 S2K), and the broker never sees the password (the
  split). A broker that lies about the blob gets nothing installed (bindRecord
  + per-ring proof); a broker that lies about WKD gets the match panel.
- The refresh token is the new long-lived secret on the device; it sits in the
  OS keychain beside the store secret. Sign-out deletes it. It cannot fetch
  the keychain on its own (P6 proof needs the password).
- `http:default` gains the account paths on two hosts, nothing wildcard.
- Residuals: the device list is self-reported labels (a thief can name their
  device "Saavi on macOS"); the list shows that a device exists, not that it
  is honest. Revocation is S3.

## Out of 0.6.0

QR device-to-device pairing (KEY-SYNC S2, the 0.7.0 headline); revoking a
device; syncing pins; recovery-kit restore inside Saavi (the webmail does it;
Saavi points there).
