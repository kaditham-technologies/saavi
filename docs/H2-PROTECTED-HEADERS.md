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
   dates. Your own mail is exempt from the recipient checks.

   Refined after the argus review (webmail `2bc77ef`), and these are the rules
   as built:

   - **"Your own" means a copy that was not delivered to you**, not merely one
     whose signed From is yours. The signed From alone was a hole: an attacker
     cannot re-sign the letter, but she can re-encrypt the still-signed entity
     to your published key and post it back, and a signed From of yours would
     then switch the recipient check off. Keying on the Sent folder instead
     would cry wolf as soon as you archived something you had written, so the
     test is "not in the Inbox" — Sent and anything you filed stay exempt.
   - **`null` and `[]` are different answers and the reader keeps them apart.**
     `null` is "does not say" (every pre-H2 letter); `[]` is "said so and named
     nobody" — `To: undisclosed-recipients:;`, or group syntax whose members
     `addrSpecs` refuses. Neither is evidence of forwarding. Only an actual
     name puts the reader on notice.
   - **The From mismatch is tested before the key-change branch.** In an
     `else if` after it, a letter that was both signed-as-someone-else AND
     from a changed key showed only "key CHANGED" — and "Trust the new key"
     then pinned it, which this document forbids. It is the stronger signal,
     so it is checked first, and it still pins nothing.
   - **The chip says "not addressed to you *directly*".** One ciphertext
     serves every recipient, so per-recipient protected headers do not exist
     and a blind-copied reader is legitimately absent from the signed To/Cc.
     The chip is what gets read at a glance; the tooltip carries the rest.
4. **Gate:** argus and cerberus on 2 and 3 together. **argus DONE
   2026-08-30** — four findings, all closed: a `foldHeader` bug that dropped
   the separator when folding a long header (saavi `5c68f16`, so twelve
   recipients parsed back as two and the reader accused legitimate ones), plus
   the three attribution refinements recorded under 3. **cerberus DONE
   2026-08-30** — nine findings, and none of them a way to pin a wrong key: it
   could construct no route to `pins.remember` for a key not currently
   published for the address, and concurs with keeping the pin. Open, in ITS
   numbering (NOT the earlier V4-V7 series):

   - **V-1 MEDIUM-HIGH — the reader compares the signed headers but still
     *displays* the unsigned ones.** `messageMeta` renders the envelope
     From/To/Cc/date as the headline; the H2 verdict is a small chip beneath.
     This is the thing line 53 above calls insufficient — "the security comes
     from displaying what was signed". For To/Cc there is no comparison at
     all: we ask only "am I in the signed set", never "does the signed set
     resemble the visible one", so a forwarded copy can carry an
     attacker-authored `Cc: legal@, ceo@` that nothing questions.
   - **V-2 MEDIUM** — the key-changed branch discards `toMe`/`notNamed`/`stale`,
     and "Trust the new key" rewrites the chip to the flat pre-H2 wording.
     Branches must compose, not shadow.
   - **V-3 MEDIUM** — the replay tell is only a colour and a `title`, and
     `title` does not render on touch at all. Put the signed date in the text.
   - **V-4 MEDIUM** — the signed Message-ID is parsed, signed, then never read.
     It is the one replay check needing no clock.
   - **V-5 MEDIUM (cry-wolf)** — `ownAddresses()` is username + JMAP identities
     only, so aliases, plus-addressing and list mail all get "not addressed to
     you directly". High base rate.
   - **V-6** — the `own = mine && !inInbox` choice is sound in intent but the
     wrong shape: the attacker steers delivery out of the Inbox (spam to Junk,
     or matching a sieve `fileinto`), and it is state-dependent, so the same
     letter changes its story when filed. Use `!hasReceivedHeader(em)` instead
     — monotonic, and she cannot deliver without generating one. Bounded to
     self-spoofing, so low-medium.
   - **V-7 / V-8 LOW-MEDIUM** — a signed From with no signed To/Cc degrades
     open with an EMPTY tooltip, more confident than the legacy path; and
     `stale` uses `Math.abs`, so a sender with a fast clock is shown the
     replay warning.
   - **V-9 — H2 AMPLIFIES the old V4.** A hostile directory previously bought
     "signed by bob@bank.com"; post-H2 it buys the corroborated "signed by
     bob@bank.com, **to you**", plus a pin. **Hold step 5's "authenticated
     sender" copy until the old V4 closes.**

   Confirmed clean: the depth-0 guard (no nested part reaches it), header
   injection and smuggling, send-side truthfulness (protected and visible
   copies provably cannot diverge), the legacy path (no existing legitimate
   letter is newly accused, except through V-5/V-8), and all four argus fixes.
   Untested by anything: `attributionOf` and the chip wording have no unit or
   e2e coverage at all — the layer that turns a parse into a security claim.
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
