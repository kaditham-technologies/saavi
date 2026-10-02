# Sign in with Kaditham Mail (0.6.0)

Status: **built 2026-10-02; gate findings (argus + cerberus) folded the same
day.** Roadmap item 4 ("Kaditham Mail pairing"); the first step of
[KEY-SYNC.md](KEY-SYNC.md) a customer can feel. Related: the webmail's
`docs/KEYCHAIN.md` (the keychain this signs into) and `docs/ZERO-ACCESS.md`
(the password split).

## What it is, for the customer

On a new computer: open Saavi, sign in with a Kaditham Mail address and
password (and the 6-digit code, when two-factor is on), and the encryption keys
the webmail already uses are here — the active key and every retired one, so
old sealed mail opens too. They land in 0.5.0's sealed disk store, so after the
first time Saavi needs no network and no sign-in to work. Saavi without an
account is unchanged: the sign-in is an offer on first run, easy to skip, and a
button at the right of the header afterwards.

## Decisions (product decision, 2026-10-02)

- **One server, in every build.** Saavi signs in to `https://mail.kaditham.ie`
  and nothing else — no staging origin in source, capability, UI or tests, not
  even in dev builds. The password derivation is the same everywhere, so a
  binary that can be pointed at a looser server can be made to send a
  production password there. UI previews in the dev server use an in-page
  fake server, never the network. (Separately, outside Saavi: the staging mail
  server should get its own derivation realm, so a credential typed into
  staging is never a production credential. Follow-up, not this release.)
- **Signing out keeps the keys.** They are the customer's, sealed by the OS
  keychain on this computer. Signing out ends the session *on this computer*.
- **Two-factor is supported, not required.**
- **A key-check disagreement warns; it never blocks.**
- **The device list includes app passwords** (Thunderbird, phone Mail).
- **First-run offer**, not a settings-only feature.

## The five things that make it more than a sign-in

1. **The key check** — what each vantage point says about your key, and what
   that proves (below).
2. **Never a silent wait, never a dead end.** Every step is narrated, each
   key-derivation step yields a frame first so the spinner paints, and every
   failure names itself and the next step: wrong password · wrong code · rate
   limited (fixed copy) · server unreachable · no keychain yet · a key wearing
   an older passphrase (asked per key) · a damaged keychain (nothing
   installed, nothing lost) · the alias list unavailable (asked, never acted
   on silently). A failed or skipped first restore is retried from the panel
   with **Bring keys here**.
3. **Where your keys live.** Devices that downloaded the keychain (label,
   first/last seen, this computer marked) from `GET
   /signup/api/keychain/devices`, and the app passwords from JMAP
   `x:AppPassword/get`. Seeing, not revoking — revocation needs a key
   rotation to mean anything (KEY-SYNC S3).
4. **Instant after the first time.** Keys in the sealed disk store; no
   network needed to seal, unseal or sign.
5. **Changes from other devices arrive — never silently.** See "The banner".

## The key check

Four vantage points, each compared with this computer's key:

| Leg | What it is | What agreement proves | What it cannot prove |
|---|---|---|---|
| **This computer** | The key Saavi holds and opened; public half derived from the private half on install | — (the reference) | — |
| **What the domain published** | The key `<domain>` served *this computer, just now*, over WKD | That the domain's directory answered this computer with your key | That it answers everyone else the same |
| **Your account keychain** | The keychain's active key, fingerprinted from its *private* half | That your other devices will treat this key as current | Anything about what senders see |
| **keys.openpgp.org** | A directory Kaditham does not run, holding only keys whose owner confirmed the address by mail | Independent evidence that the domain is not showing you something different | That senders use it (most look up the domain) |

Each leg is **agrees / differs / absent / unreachable / not read**. Absent and
unreachable are never a mismatch: they are "nothing to compare", said so. Only
a present, different fingerprint differs.

The summary uses the domain and the keychain only: **consistent** (badge:
"Matches what `<domain>` published to this computer just now ✓"), **differs**,
**not published**, **not checked** (domain unreachable), or **no key here**.
keys.openpgp.org is reported beside the summary and never changes it: agreement
there is the strongest sign available; a different key there is often an old
key the owner published themselves, and is worth a look; absence is neutral.

Every state carries its own copy, written to claim only what it proves. A
"differs" names which leg differs and both readings (a change still
propagating, or something to take seriously). Sealing is never blocked.

## Adoption — when another source names a different current key

`restore()` changes the active key of a ring **already on this computer** only
for addresses in an *adoption plan* (`adoption.ts`); the merge rules are
otherwise unchanged. The plan's target per address is:

- by default, **the key the domain publishes** (the server-named current key —
  never the keychain blob's order alone);
- on the customer's explicit choice, **the keychain's active key** — offered
  when the published key has not caught up with the keychain, showing both
  fingerprints.

**A retired key never becomes current again unasked.** If the target is a key
this computer holds as retired, adoption stops for that address and asks — a
first-class, danger-styled confirm, default no — explaining that a source
naming a retired key as current is a device that missed the change, a directory
that has not caught up, or someone trying to turn the account back to a key
they hold, and that Saavi cannot tell which. Declining keeps the current key;
the rest of the plan proceeds. Every adoption is still proof-gated: nothing is
installed unless the password opens it.

## The banner — changes from other devices

On window focus (at most once a minute, one request in flight) Saavi reads the
keychain's version and compares it with the newest version this computer knows:
the sync marker's (what it last pushed or accepted), or — for a computer that
never synced — a per-account baseline set at its first status read. Ahead: a
banner and a dot on the account button offering **Bring it here**. Answering
it moves that floor — including when every key turns out to be here already
(`mailkeychain.acceptVersion` bumps the marker only when the local rings still
hash to it; it adopts nothing) — so a version never asks twice.

## Flows

### Sign in
1. Address + password. `deriveAuthSecret(password, address)` (PBKDF2, 600k, on
   the device; the password itself never leaves — the split).
2. PKCE `POST /api/auth` `{type:'authCode', clientId:'kaditham-saavi', …}`;
   `mfaRequired` → the code step. (`kaditham-saavi` verified against Stalwart
   v0.16.16, 2026-10-02: auth, token, refresh and keychain status answer; it
   needs no registration, so Saavi is a distinct client in the logs.)
3. `POST /auth/token`. Access token in memory; refresh token, address and
   server in the OS keychain (`account:v1`) — never webview storage.
4. The password and the account secret (the keychain's P6 proof) live in
   memory **only for the operation that needs them** — restore, push,
   adoption — and are forgotten after it; the next one asks again. Status,
   the device list, app passwords and the banner need neither.

### Refresh
Only a refused grant ends a session — 400 (`invalid_grant`), 401, 403. A 5xx,
a 429 or no answer keeps it and says "the server is not answering" (never
"your session has ended"). A sign-out bumps an epoch, so a refresh or resume
already in flight cannot write the session back.

### Sign out
Deletes the refresh token from this computer's keychain and forgets the
session. **It does not revoke the token at the server, because the server
offers no way to:** Stalwart v0.16.16's discovery document
(`/.well-known/oauth-authorization-server`, read on staging 2026-10-02) lists
token, authorization, device, registration, introspection, userinfo and jwks
endpoints and **no `revocation_endpoint`**; `POST /auth/revoke`,
`/auth/revocation` and `/oauth/revoke` answer 404 (`/auth/token/<anything>` is
the token endpoint's prefix route answering `invalid_grant`, not a
revocation). The copy says so: sign-out ends the session on this computer;
**changing the password ends sessions everywhere.**

### Restore (core, shared with the webmail)
`mailkeychain.restore()`, behaviour unchanged from the webmail: strict
`parseBlob`, `bindRecord`, per-ring passphrase proof, full rollback when nothing
opens, only addresses the account owns. Saavi then flushes the disk store.

### Sync
Push after local key events (generate, import) when the customer agrees — the
key is re-locked under the account password first (additive), so every device
opens it — and from **Sync now**. Sync refuses to silently make this
computer's key current everywhere when the account names another, and refuses
when the alias list is unavailable. Pull only by restore.

## The core move

The webmail's `src/keychain.ts` is Saavi core `src/mailkeychain.ts`. Seams:
`./server` (`apiUrl`, `netFetch` — Saavi's goes through the Tauri http client
and refuses any origin but mail.kaditham.ie), `pgp.installRing` /
`uninstallRing` (writes through the host's RingStore), `useDeviceName()`.
Webmail follow-up: map `mailkeychain.ts` → `src/keychain.ts` in its
`scripts/sync-saavi.sh` (PARITY.md).

## Network surface

`capabilities/default.json` allows the http client exactly: WKD paths on any
https host (recipient lookup needs it — a narrow channel, stated as such),
keys.openpgp.org, the Kaditham WKD publish endpoint, the account paths on
mail.kaditham.ie (`/api/auth`, `/auth/token`, `/.well-known/jmap`, `/jmap`
and `/jmap/`, the three keychain paths), the update manifest and release
assets. **Redirects are checked against that scope on every hop**:
tauri-plugin-http 2.7.0 added `scopeRedirects` (its `config.rs` deserialises
the key camelCase with `deny_unknown_fields`; `commands.rs` applies the scope
in the redirect policy), and `tauri.conf.json` turns it on.
`tests/shipped-config.test.ts` pins all of this.

## Broker (signup)

- Each keychain fetch refreshes the device's `label` (X-Device-Name, ≤ 60
  printable ASCII; else "Browser on OS"), first and last seen. The download
  alarm's record (`at`, `notified`, the novel test) is untouched.
- `GET /signup/api/keychain/devices`: per-IP budget *before* the Stalwart
  lookup, then Bearer + per-account limit; returns `{label, firstAt, lastAt,
  current}` — no marks, no IPs. No P6 proof: it reveals nothing the alert
  mails do not, and the panel must open without the password.

## Threat notes

- The account credential alone cannot open a ring: the blob is locked to the
  password, which the server never sees. A broker that lies about the blob
  gets nothing installed (bindRecord + per-ring proof); a domain that lies
  about the published key meets the key check, and keys.openpgp.org gives an
  independent view.
- **The refresh token is the long-lived secret on the device**, in the OS
  keychain. Its reach is the **whole mailbox** — it mints bearers that read,
  send and delete mail and list app passwords — though not the keychain's
  keys (P6 proof needs the password). It lives until it expires or the
  password changes; sign-out cannot revoke it (above).
- Residuals: device labels are self-reported; a session thief can name a
  device anything. Revocation is KEY-SYNC S3.

## Out of 0.6.0

QR device-to-device pairing (KEY-SYNC S2, the 0.7.0 headline); revoking a
device; syncing pins; recovery-kit restore inside Saavi (the webmail does it).
