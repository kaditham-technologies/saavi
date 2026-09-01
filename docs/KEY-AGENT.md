# Saavi as the key agent

Status: **phase 0 built 2026-09-01** (one store on disk — bundle.ts,
diskstore.ts, store.rs; ships as 0.5.0); phases 1+ planned. Written
2026-08-30.
Page version: https://claude.ai/code/artifact/22c10115-0802-42ec-a7f0-42e993043d4f

Private keys stop living in browser storage. Saavi holds them and performs
the crypto; the webmail and the mail app ask it to. A passphrase is never
typed into a web page again.

This fulfils and expands **roadmap item 4** ("Kaditham Mail pairing"), which
scoped the same relationship as publishing keys and syncing identities.

## Why

The webmail keeps each account's passphrase-encrypted private key in browser
`localStorage` and asks for the passphrase in an HTML form. That is the best
a web page can do, and it is the largest remaining gap in the end-to-end
story: anything that runs JavaScript on the mail origin takes both halves and
decrypts every message the account has ever received — offline, permanently,
invisibly.

## Where the key lives, precisely

The current arrangement is often described more loosely than it deserves.
Saavi's keychain integration (`src/keychain.ts` → `src-tauri/src/keychain.rs`)
stores **passphrases**, keyed by fingerprint, opt-in per key. The encrypted
key blob itself sits in Saavi's webview storage. The webmail holds its own
separate blob in the browser. **Neither app puts key material in the keychain
today.**

    Webmail today                      With the agent
    ─────────────                      ──────────────
    webmail (browser tab)              webmail · Kaditham Mail app
    browser localStorage        ←key    Saavi, paired and approved
      encrypted blob                   key file on disk,          ←key
      passphrase typed into the page     sealed by a keychain secret
    operating system

Clients send text and receive text. There is no endpoint that returns private
key material, so there is nothing for a compromised client to take — only
operations it can request, while Saavi is unlocked, in view of the user.

## Threat model

| Attacker | Webmail today | With the agent |
|---|---|---|
| Script injection on the mail origin | Takes the blob and captures the passphrase. Complete offline decryption of the mailbox, permanently, with no trace. | May request unseals while Saavi is unlocked. Cannot obtain the key. Damage bounded to the unlocked window and visible in the activity list. |
| Another program on the same machine | No local surface to attack. | Needs a token the user granted in a native dialog it cannot draw over, forge or dismiss. |
| A hostile web page the user visits | No local surface to attack. | Refused twice: origin allowlist on every response, and the pairing token it does not hold. |
| Stolen laptop, powered off | Blob is recoverable from the browser profile; only passphrase strength protects the mail. | File is sealed by a keychain secret bound to the user's login credential. |
| The mail server | Sees ciphertext and metadata. | Unchanged. This does nothing about metadata. |

## This would be Saavi's first inbound surface

The capability manifest states the posture plainly: the Rust HTTP client is
scoped to exactly the hosts the app needs, "so compromised frontend code gets
no arbitrary-host exfiltration channel". Every existing permission narrows
something **outbound**.

A local listener is a different kind of thing. It accepts connections rather
than making them, it sits outside Tauri's capability model entirely, and it is
reachable by every process on the machine the moment it binds. That is not a
reason to refuse it — gpg-agent, Kleopatra and every password manager made the
same trade — but the agent is then the highest-risk code in the product and
must be reviewed as such, not as an incremental feature.

## The interface

Bound to `127.0.0.1` only. Every call carries a pairing token; every response
carries an origin allowlist header.

    GET  /agent/hello         version, capabilities, locked or unlocked
    POST /agent/pair          begins the approval ceremony; returns a token
    GET  /agent/keys          public metadata only: address, fingerprint, created, active
    POST /agent/public-key    armoured public key for one of your addresses
    POST /agent/seal          text and recipients in; armoured message out
    POST /agent/unseal        armoured in; text and signature verdicts out
    POST /agent/sign          clearsign with the active key
    POST /agent/verify        check a clearsigned message against candidates
    POST /agent/unlock        raises Saavi's own passphrase prompt, natively

**There is no export endpoint, and there never will be.** Private key material
has no route out of the agent. Backup stays inside Saavi's own window, where
the user is present and the file dialog belongs to the operating system.

**Unlock is the load-bearing detail.** A client may ask Saavi to unlock; it may
never carry a passphrase. Saavi raises its own window and takes the passphrase
there, or retrieves it from the keychain as it already does. The moment a
passphrase can cross the interface, a compromised client can phish it — handing
back exactly what this plan exists to take away.

## Pairing

Any local process can open a connection to a loopback port. What it cannot do
is get past a dialog the user did not expect.

1. The client detects Saavi and asks to pair, naming itself and its origin.
2. Saavi raises a **native** window: "Kaditham Mail at https://mail.kaditham.ie
   wants to use your keys", carrying a four-digit code. A page cannot draw over
   it or dismiss it.
3. The client displays the same code; the user checks they match before
   approving. This is what defeats a local process racing the dialog — it can
   trigger the prompt, but it cannot make the user's own screen show its code.
4. Saavi records the grant (name, origin, token, time) and returns the token.
5. Paired clients appear in settings with a Revoke button and last-used time.

## Transport, decided

- Loopback HTTP bound to `127.0.0.1` only — never `0.0.0.0`, which would put
  the user's keys on the office network.
- `Access-Control-Allow-Origin` for paired origins only. Never a wildcard.
- Chrome requires a Private Network Access preflight for a public page calling
  loopback; the agent answers it explicitly.
- A fixed port with a small fallback range, which clients probe.
- **Considered and deferred:** a browser extension using native messaging.
  Stronger origin binding and no local listener at all, but two more artefacts
  to sign, ship and put through store review. Revisit as hardening once the
  interface has settled.

## Lock policy: the sudo model

Saavi already drops unlocked keys after fifteen minutes and on demand, and the
agent must honour both: locking Saavi locks every client at once, requests are
refused with "unlock Saavi", and the webmail shows a sealed placeholder rather
than a passphrase prompt of its own.

There is a hole the current design would otherwise carry straight through. The
roadmap records that **keychain-remembered keys reopen silently when next
needed** — right for a person clicking Unseal, wrong for a paired client,
because it means Lock stops nothing: a compromised client simply asks again and
the keychain re-opens the key with nobody present.

**Decided: an agent-served request after a lock requires the device password,
the way `sudo` does.** Not the PGP passphrase — the operating system's own
authentication: polkit on Linux, Touch ID or the login password on macOS,
Windows Hello. Three properties fall out of that choice:

- **It cannot be forged by a web page.** The prompt belongs to the operating
  system, not even to Saavi, so nothing rendered in a browser can imitate it.
- **The passphrase invariant survives.** A passphrase still never crosses the
  interface, and the user is not made to retype six words to read a letter.
- **Silence becomes impossible.** A compromised client can provoke the prompt,
  but it cannot answer it, and the user sees an authentication request they did
  not initiate — which is itself the alarm.

The timing model is `sudo`'s too: authenticate once, and agent requests are
served until the existing fifteen-minute idle lock drops the keys, at which
point the next request asks again. That reuses the auto-lock timer already in
the app rather than inventing a second clock.

Pairing a new client should take the same authentication. Granting a program
access to your keys is at least as consequential as reading one letter.

Implementation cost, stated honestly: this is three platform APIs rather than
one. Linux has precedent in the tree — the `.deb` updater already installs
through polkit. macOS is `LocalAuthentication`, and the cleanest form there may
not be a prompt we raise at all: a keychain item stored with a user-presence
access-control flag makes the OS enforce it on read. Windows is
`UserConsentVerifier`. Budget for the platform work; do not assume the
`keyring` crate covers it.

## Visible activity

Every operation appears in a live list in Saavi, naming the client that asked.
Rate limits per client; a burst raises a native prompt rather than being served
quietly.

That pair is the honest mitigation for a compromised client: it makes bulk
exfiltration *noisy*. It does not stop a patient attacker reading one message
at a time, and the documentation should say so rather than imply otherwise.

## What this does not protect

- **Plaintext still reaches the client.** After an unseal the message is on
  screen. Script injection can read what is on screen. The agent protects keys,
  not mail already open.
- **Nothing for mobile**, or for anyone who will not install software. The
  browser-only path stays as it is — which is why it cannot be removed, only
  demoted.
- **Metadata is untouched.**
- **A compromised OS account while unlocked is total**, as with every agent of
  this kind, gpg-agent included.

## Prerequisite: the two keyrings problem

Saavi and the webmail **do not share a keystore**. Saavi keeps its ring in its
own webview storage; the webmail keeps a separate one in the browser. Install
both on one machine today and you get two unrelated keyrings and a confused
user. They share the code that manages rings — `pgp.ts` and its siblings — but
never the rings themselves.

So the first work is not the agent. It is moving Saavi's store out of webview
storage into a file on disk sealed by a keychain secret, with a migration that
takes a backup and verifies the backup opens *before* writing anything new —
destroying a private key is the one mistake in this product that cannot be
undone.

The motive is worth stating plainly: this is **not** because Saavi's webview
storage is currently exploitable. Saavi loads only local content and its HTTP
scope is narrow. The reason is that a store two programs can share has to live
somewhere both can reach, and a file with an OS-held secret is the only such
place.

## Phases

- **0 — One store, on disk.** Saavi's ring moves from webview storage to a file
  sealed by a keychain secret. Migration runs once, takes a backup, verifies it
  opens before writing anything new. No listener, no new attack surface.
  Ships as an ordinary Saavi release; useful on its own. **This is 0.5.0.**
- **1 — The interface, carrying no secrets.** Loopback listener, pairing
  ceremony, and only the endpoints that cannot leak: hello, keys, public-key,
  verify. Proves discovery, origin allowlist, the PNA preflight and the
  ceremony while there is nothing worth stealing. Webmail feature-detects and
  shows "Saavi connected".
- **GATE — cerberus reviews phases 1 and 2 together**, before any endpoint that
  decrypts is released: pairing, origin binding, rate limits, the unlock path,
  the lock-versus-keychain decision, and the invariant that a passphrase never
  crosses the interface.
- **2 — Seal and unseal through the agent.** Where a client is paired, crypto
  routes through Saavi; where it is not, today's in-browser path is untouched.
  Both stay live.
- **3 — Migration and the recommended path.** Browser-held keys import into the
  agent and leave browser storage, only after a verified backup. Onboarding
  recommends Saavi. Docs state what the agent protects and what it does not.
  Themis reviews migration and activity-list retention.
- **4 — Kaditham Mail.** The standalone desktop client, built down from the
  webmail rather than up from Saavi, using the same interface. It also gets
  the two things a browser cannot have: a WebSocket held in Rust with a real
  Authorization header (so live updates need no relay), and system
  notifications. Reuses Saavi's signing, mirror and updater pipeline.

## Ordering: what this must not jump ahead of

The E2EE readiness plan still carries **H2** open — see
[H2-PROTECTED-HEADERS.md](H2-PROTECTED-HEADERS.md). That is a correctness
defect in a claim the product already makes to customers. This plan is an
upgrade to a claim the product makes honestly. **Close H2 first.** An agent
guarding keys perfectly, inside a client that can be induced to attribute a
letter to the wrong sender, is the wrong order to fix things in.

## Unresolved

- **Will Safari call loopback from an HTTPS page?** Chrome treats loopback as a
  trustworthy origin and permits it after a preflight; Firefox is close behind.
  Safari is the strict one, and if it refuses, Safari users need the extension
  path or no agent at all. Verify before phase 1 is designed in detail — it is
  the assumption everything rests on.
- **Does Saavi start at login?** An agent only running when the user remembered
  to open it fails half the time, and the failure looks like broken mail.
  Auto-start is a much better experience and a much bigger commitment.
- **How does a port collision behave?** Whatever the choice, another process
  holding the port must produce a clear message rather than a client that
  silently concludes no agent is installed.
- **One agent, several accounts?** The mail product already has multiple
  identities per account and tenants above that. Cheaper to decide now than to
  retrofit.
