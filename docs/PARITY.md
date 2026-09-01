# Parity: Saavi ↔ Kaditham Mail's KGPG window

Saavi and the floating KGPG window inside the Kaditham Mail web client
are the same product in two bodies. This file is the contract that keeps
them from drifting.

## Shared core (Saavi is upstream)

`src/pgp.ts` (keystore + every OpenPGP operation), `src/wkd.ts`
(WKD lookup) and `src/pins.ts` (recipient key pinning) are owned HERE.
The webmail vendors them via
`scripts/sync-saavi.sh` in its repo, which applies only declared,
mechanical brandings (storage prefix, backup-file wording) and records
the upstream commit in `.saavi-core-ref`. **Never edit those files in
the webmail** — change them here, then re-sync.

## The UI is not shared — but drift is noticed now

Layout cannot be vendored the way the core is. Saavi's `index.html` is a
two-view desktop app; the webmail's is a whole mail client with the sealer as
one pane inside it, and the handlers differ where it matters (the webmail asks
its directory before WKD, signs as the signed-in account, unlocks through
`openPgpModal`). Porting a UI change is hand work, and this file is the
contract for it.

Divergence is allowed — it just has to be **named**, not accidental. Declared
app-specific, and deliberately NOT ported either way: Kaditham WKD publish,
"Sign as", the file dropzone, the System GnuPG keyring switch, the directory
lookup, the zero-access storage toggle.

What is not allowed is drift nobody sees, which is what happened between 0.4.2
and 0.4.3: Saavi refaced its sealer, the core lane carried the crypto across on
schedule, and the webmail went on serving the old shape with a current core
until someone happened to look at both.

So the webmail's `scripts/auto-sync-core.sh` now also watches Saavi's
`index.html`, `src/style.css`, `src/main.ts` and `src/ui.ts`:

- `.saavi-ui-tag` records the Saavi release whose UI the webmail has been
  brought level with **by hand** — not the release whose core it holds.
- When a new release moves any of those files since that tag, the lane cannot
  fix it, so it says so: a line in the cron log, a line appended to
  `.saavi-ui-drift`, and — the part that actually gets read — a paragraph in
  the sync commit message.
- After porting, declare it level: `echo <tag> > .saavi-ui-tag`, in the same
  commit as the port.

The detector reports that Saavi's UI moved. It cannot tell whether the move
mattered to the webmail; that judgement is the point of the feature matrix
below.

## Feature matrix

| Feature | Saavi | KGPG window | Notes |
|---|---|---|---|
| Key table (−k): generate/import/backup/delete, rings per address | ✓ | ✓ | shared core |
| Sealer (−d): encrypt/decrypt text | ✓ | ✓ | shared core |
| Two-pane sealer: the work left, the result right | ✓ | ✓ | layout only; auto-fit collapses to one column in a narrow window |
| Copy glyph on the result block, confirming in place | ✓ | ✓ | a clipboard write is otherwise silent |
| Recipient picker: addresses you already hold a key for | ✓ (GnuPG ring, or pins + own addresses) | ✓ (pins + own addresses) | typing an unknown address still works |
| Address ↔ pasted-key input modes | ✓ | ✓ | a one-line input was the wrong container for an armored block |
| Clearsign / verify (Sign, Verify buttons) | ✓ | ✓ | core (`pgp.ts` `signText`/`verifyText`); webmail signs as the signed-in address, Saavi picks under Sign as |
| WKD recipient lookup | ✓ | ✓ | webmail: directory first, WKD fallback |
| Suggested passphrase (6 EFF words) + strength read | ✓ | ✓ | core (`passphrase.ts`, `wordlist.ts`); shown in clear, "Use my own" opts out |
| Recipient key pinning (TOFU) | ✓ (device scope) | ✓ (per signed-in account) | core (`pins.ts`); policy shared, prompts are per-app |
| Withdrawn recipient key holds the send | ✓ | ✓ | core (`pins.ts` `withdrawn`); never downgrades to plaintext |
| Revoked/unusable recipient key refused | ✓ | needs sync | core (`pgp.ts` `keyState`), checked on every seal |
| Named themes (Paper…Phosphor) | ✓ | ✓ | shared palette family, not shared code |
| Protected headers: From/To/Cc/Date/Message-ID inside the signature (H2) | core ✓, app n/a | needs wiring | core (`mime.ts`); the webmail must pass the same values it puts outside, and attribute from the signed copies — see `docs/H2-PROTECTED-HEADERS.md` |
| Paste-a-public-key recipient | ✓ | ✓ | armor normalized in core (single-line paste); pinned under its PRIMARY address only |
| Kaditham directory + WKD publish | ✓ (mail-confirm link) | ✓ (automatic, bearer-authed at key creation) | service feature, not core; app proves ownership via `/signup/api/wkd/publish` confirmation mail |
| Zero-access storage toggle | n/a | ✓ (Settings) | server feature |
| Account identities as addresses | planned pairing | ✓ | |
| OS keychain | planned | n/a (browser) | the reason Saavi exists |
| Sealed on-disk key store (ring bundle) | ✓ (shell; 0.5.0) | n/a (browser keeps localStorage) | core carries the bundle format + `RingStore` backend hook (`bundle.ts`, `pgp.ts`); the disk mirror and migration are Saavi-only (`diskstore.ts`, `store.rs`) |
| Publish key to keys.openpgp.org | ✓ | ✓ | core (`vks.ts` upload + request-verify) |
| Revocation certificates | ✓ | ✓ | core (`pgp.ts`); system keys via gpg (Saavi-only) |
| System GnuPG keyring (`gpg.rs`/`gpg.ts`) | ✓ | n/a (browser) | Saavi-only; delegates to the user's gpg |

## Pinning notes for the webmail sync

`passphrase.ts` and `wordlist.ts` are core too — they were NOT vendored
until 2026-08-29, so the webmail could not offer a suggestion at all and had
a hand-rolled strength read that had drifted permissive. Anything that
answers "is this good enough?" belongs in the core, not in each app.

`pins.ts` is core and must be vendored by `scripts/sync-saavi.sh` alongside
`pgp.ts` and `wkd.ts`. Two things need declaring there:

- **Storage prefix.** `PIN_PREFIX = 'saavi-pin-'` is branded the same
  mechanical way as `pgp.ts`'s `STORE_PREFIX`.
- **Committing.** `resolve()` takes `{ commit: false }` for callers that
  re-resolve speculatively (the composer, on every keystroke). They call
  `remember()` once the user acts — sends the letter, or reads one that
  verified — so a typed-then-deleted address leaves no trust record.
- **Seeding.** `seed()` records a fingerprint whose key is not in hand, so a
  store that kept fingerprints only can be carried over rather than dropped.
  Dropping such records would turn every existing correspondent back into a
  first contact, which is the exact moment a substituted key goes unnoticed.
- **Owner scope.** Every entry point takes an owner as its first argument and
  keys records `<prefix><owner>|<address>`. The webmail passes the signed-in
  username, so two accounts on one browser never inherit each other's trust
  decisions; Saavi passes `''` — its keyring is the device.
- **Lookup order.** `pins.resolve()` takes the lookup chain as an argument
  precisely so the webmail can ask its directory first and fall back to WKD,
  and record which of the two answered. Use `source: 'directory'` for the
  former — the change dialog names the source, and "the directory now says
  something different from what the domain said" is the case a user most
  needs spelled out.

The policy itself (what counts as a change, when a pin may be substituted
for a failed lookup, refusing revoked keys, holding a withdrawn one) is NOT
to be reimplemented in the webmail. Only the dialog is per-app.

The webmail carried its own `src/pinning.ts` until 0.3.7 — account-scoped
fingerprint-only TOFU, with no revocation check and no stored key. Owner
scoping and the withdrawn-key hold came from it and are now in the core;
the webmail migrates its `kad-pins:<owner>` records on first read and the
old module is gone.

## The rule

A new capability lands in the shared core when it is about keys or
sealing; platform-specific surfaces (service integration, OS
integration) stay in their own repo but get a row in this table —
in both copies of this file.
