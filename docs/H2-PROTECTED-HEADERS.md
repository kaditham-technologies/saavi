# H2 — protected headers beyond the Subject

Status: **built** (2026-08-30) — core, send and read. Awaiting the gate
and an end-to-end test against real mailboxes. Written 2026-08-30.
This is the truthfulness blocker on the "authenticated sender" claim, and it
outranks [KEY-AGENT.md](KEY-AGENT.md) in the queue.

## The defect

Protected headers currently cover the Subject and nothing else. In
`src/mime.ts`, `buildMimeEntity` emits exactly one:

```ts
const protectedHeaders = src.subject !== undefined ? [`Subject: …`] : [];
```

Everything else the reader tells the user about a letter — who sent it, who it
was sent to, when — comes from the outer headers built by
`buildEncryptedMessage`. Those are not signed, and anyone who relays the
message can rewrite them.

## What that allows

**Surreptitious forwarding** (Davis, 2001). Alice signs a letter and seals it
to Mallory. Mallory decrypts, takes the still-signed inner entity, re-seals it
to Carol, and writes outer headers saying it came from Alice. Carol's client
then:

1. resolves Alice's published key from the directory or WKD,
2. verifies the signature against it — and it *is* a real Alice signature,
3. displays "End-to-end encrypted · signed by alice@…",
4. and writes a pin recording that key for Alice.

Carol now believes Alice wrote to her. Alice did write it — to someone else,
possibly long ago, possibly meaning something entirely different in its
original context.

**Replay** is the same defect with one actor: re-deliver a captured letter
later under a fresh Date and Message-ID.

Nothing in the current reader can catch either, because every value it uses to
attribute the letter sits outside the signature. See the reader's signer
binding in the webmail's `main.ts` (the `matchesSender` fingerprint check): it
is a correct check of *which key signed*, answering a question that was never
the one in doubt.

## The fix, in one sentence

Put From, To, Cc, Date and Message-ID inside the signed entity, and make the
reader attribute the letter from **those** values rather than the visible ones.

That last clause is the half that matters. Comparing inner against outer and
warning on a mismatch is not sufficient on its own — the attacker controls the
outer headers completely and can simply copy the inner values into them. The
security comes from displaying what was signed. The comparison then becomes a
useful *consistency* signal rather than the defence itself.

## Core changes — Saavi, `src/mime.ts`

1. **`buildMimeEntity` gains `from`, `to`, `cc`, `date`, `messageId`**, emitted
   alongside `Subject` on the entity that already declares
   `protected-headers="v1"`. No new mechanism: the same header block that
   carries the Subject today.

2. **`MimeEntity` gains the parsed fields**, and `parseMimeEntity` adopts them
   under exactly the existing rule — depth 0 only, and only where the
   Content-Type declares `protected-headers="v1"`. That hardening already
   exists for Subject and **must not be relaxed** for the new fields: a
   protected header adopted from a nested part is a header the attacker chose.

3. **Absent fields parse as `null`.** Every letter sent before this ships
   carries no protected From, and that must read as "cannot check" — never as
   "forged".

4. **Bcc is never emitted**, exactly as today. The submission envelope carries
   those recipients and no header ever does.

5. **Tests**: build/parse round-trip per field; nested-part injection rejected
   for each new field, not just Subject; a legacy Subject-only entity still
   parses; and the GnuPG interop harness extended so the emitted headers
   survive a real `gpg` round-trip.

## Send-side sequencing — webmail

A real ordering change, and the piece most likely to go wrong quietly.

Today `buildEncryptedMessage` generates the Message-ID and the Date *itself*,
after the inner entity has already been built and signed. For the protected
copies to match the visible ones, both values must be decided **before** the
inner entity is built, then passed to both calls. From, To and Cc compose
already knows.

Any mismatch introduced here looks exactly like an attack to a correct reader,
so this needs an end-to-end test that sends a real letter and asserts the
protected and visible headers agree.

## Read-side rules — webmail

Attribute from the signed headers:

- **"Signed by X"** where X is the *protected* From and the signature verifies
  against the key published for that address. The existing fingerprint binding
  stays exactly as it is; it is necessary and was never sufficient.
- **Show the protected Date** as the letter's date.
- **Protected From ≠ visible From, or protected Date far from visible Date** —
  that divergence *is* the forwarding or replay tell. Say so prominently rather
  than quietly preferring one value over the other.
- **Reader's own address present in protected To or Cc** — positive
  confirmation the letter was addressed to them. This is the check that
  actually defeats surreptitious forwarding.
- **Reader's address absent** — inconclusive, **not** damning. A blind-copied
  recipient is legitimately absent from To and Cc, and one ciphertext serves
  every recipient, so per-recipient protected headers are not available. Word
  it as "not addressed to you directly (or you were blind-copied)".
- **No protected From at all (legacy)** — "signed by X · older format, cannot
  confirm this copy was sent to you."

## The pin question

Cerberus's original note asks that the pin write be refused unless the
attribution checks pass. Worth thinking about rather than adopting reflexively.

A pin records address → fingerprint. Neither attack above can cause a *wrong*
key to be pinned, because the signature must still verify against the key
currently published for that address. What they falsify is the attribution of
content, not the key binding. Gating the pin therefore buys little and costs
continuity data that is independently valuable.

**Decided as recommended (2026-08-30):** gate the wording strictly; keep the
pin, except where the signed From disagrees with the envelope — there the
attribution itself is in doubt, so the letter is not evidence about anyone's
key.

**Original reasoning:** gate the wording strictly; keep the pin. Record the
decision either way. And note that the genuinely dangerous pinning case is a
hostile directory serving a key it minted for an address it does not own —
open item V4 — which protected headers do not address at all.

## Order of work

1. ~~Saavi core plus tests.~~ **DONE 2026-08-30.** `buildMimeEntity` emits
   From/To/Cc/Date/Message-ID; `MimeEntity` and `parseMimeEntity` read them
   back under the same depth-0 `protected-headers="v1"` guard the Subject
   has always had. 14 unit tests plus a GnuPG interop test — 108 green.
   Addresses only, lowercased and de-duplicated, display names discarded,
   because these values exist to be compared and never shown. Still to do:
   cut a release so the core sync lane carries it to the webmail.
2. ~~Webmail send-side sequencing.~~ **DONE** (webmail `5ae98f3`). Date and
   Message-ID are decided once, before the entity is built, and handed to both
   halves along with one sender and one recipient list. Drafts deliberately
   excluded: encrypted to self and unsigned, so protected headers there would
   assert what no signature backs.
3. ~~Webmail read-side attribution and wording.~~ **DONE** (webmail `e8073c5`).
   The reader judges from the signed headers; "to you" comes from the signed
   To/Cc; absent recipients are stated, never accused over (Bcc is
   indistinguishable); a signed From disagreeing with the envelope warns and is
   NOT pinned; a letter signed more than a day before delivery shows both
   dates. Own sent mail is exempt from the recipient checks.
4. **Gate:** argus and cerberus on 2 and 3 together.
5. Product copy pass — anywhere the site or the pricing page claims an
   authenticated sender.

Steps 2 and 3 need not ship together: letters sent after step 2 carry protected
headers no reader uses yet, which is harmless because the fields are additive.
They must not be *assumed* simultaneous, though — a reader that requires them
before senders emit them would mark every legitimate letter unverifiable.

## Interop

`protected-headers="v1"` is the LAMPS convention Thunderbird already uses for
the Subject; extending it to more headers follows the same convention rather
than inventing one. Test against Thunderbird and `gpg` before release on two
points: a client that does not understand the fields must still render the
message, and a client that does must not display the headers twice.
