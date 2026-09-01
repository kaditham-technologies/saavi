# Multi-device key sync

Status: **S0 built 2026-09-01** (bundle.ts + the sealed disk store,
diskstore.ts/store.rs — the 0.5.0 on-disk format below); S1–S3 planned.
Written 2026-08-30.
Supersedes the one-line sketch of P4 in the E2EE readiness plan.
Blocks: 0.5.0's on-disk format. Related: [KEY-AGENT.md](KEY-AGENT.md).

Sibling, shipped 2026-08-31: the **webmail keychain** (the webmail repo's
`docs/KEYCHAIN.md`) — the webmail lane's v1 of this idea, a passphrase-locked
ring blob behind the account broker. It satisfies this document's underlying
test (enrolment needs a secret the server has never seen: the passphrase) but
not its stricter rule (the account credential does obtain the ciphertext), and
a browser tab cannot do the OS-sealed device keys below. When this design
ships, the broker blob becomes one of its envelopes, not the whole story.

One identity, present on every device the customer uses, each device sealing
its copy with its own operating system. Not one keychain — a keychain is
device-local by definition, and there is no single Saavi that a phone and a
laptop both talk to. What makes them feel like one thing is sync.

## The rule everything else hangs off

**The mail account credential must never be sufficient to obtain the ring.**

If signing in to the mail account could enrol a new device, then Kaditham could
enrol itself and read the customer's mail, and the end-to-end claim is a
decoration. Every mechanism below is designed so that enrolling a device
requires either possession of an existing device, or a secret the server has
never seen.

This is the line that separates this product from "encrypted at rest".

## What has to travel

1. **The ring** — the active private key and every retired one. Retired keys
   are not optional: without them, a new device cannot read old mail. Changes
   rarely (generation, rotation, import).
2. **Pins** — the TOFU record of recipient keys. Changes constantly, on every
   letter read or sent. Divergent pins across devices do not weaken anything,
   but they do produce "this key changed" on one device and silence on
   another, which teaches customers to ignore the warning.
3. Settings and signatures — convenience, not security. Last.

**Scope for v1: the ring.** Pins are the immediate follow-up, and the container
must have a place for them from the start.

## One structure, three envelopes

The design that keeps this tractable: a single **ring bundle** — versioned,
self-describing, serialisable as a unit — that is then wrapped differently
depending on where it is going.

```
bundle
  version
  addresses[]
  keys[]            active + retired: armoured private key, created,
                    revocation certificate where captured
  pins[]            (reserved for v1.1)
  hash
```

- **At rest on a device** — encrypted with a device key, sealed by the OS
  keychain. This is what 0.5.0 builds.
- **In transit between devices** — encrypted to an ephemeral public key from
  the pairing ceremony.
- **In escrow** — encrypted with a key derived from the recovery phrase.

0.5.0 therefore does not need to know anything about sync. It needs to stop
producing "localStorage, but in a file" and start producing a bundle. Getting
that shape right now costs nothing and saves a migration across three
platforms later.

## Mechanism A — recovery kit (escrow)

The bundle is encrypted under a key derived from a **generated** recovery
phrase using Argon2id, and stored server-side as an opaque blob. A new device
signs in, fetches the blob, takes the phrase from the customer, and unseals it
into its own keystore.

- The phrase is **generated, never chosen**. A user-chosen phrase is the single
  point where this design fails, because the blob is grindable offline by
  anyone who takes the server.
- Argon2id with deliberately heavy parameters, stored **in the envelope** so
  they can be raised later without stranding old blobs.
- The phrase never leaves the client. The server stores ciphertext and cannot
  do anything with it.

**Note on Argon2 and the existing S2K decision.** SECURITY.md records that
Saavi's *backup file* stays on iterated-and-salted SHA because an
Argon2-locked key needs GnuPG 2.4+ to import, and the backup is the customer's
only way back. That reasoning applies to the gpg-importable backup and **not**
to this envelope, which is ours and is never handed to gpg. Argon2id is correct
here. Do not "fix" the inconsistency; it is deliberate.

Escrow is not merely convenience. **It is the only thing standing between a
customer and permanent loss of every sealed letter they own** if their devices
are lost together. A business that cannot read seven years of mail after a
stolen laptop does not stay a customer, and a product that allows that outcome
silently is not sellable to businesses. The recovery kit is the answer, and it
should be presented the way the 2FA spare-key ticket already is — a keepsake
produced during onboarding, once, on paper if they like.

## Mechanism B — device-to-device pairing

The everyday path when both devices are to hand, and the stronger of the two.

1. The new device generates an ephemeral X25519 keypair and shows a QR code
   (and a short code, for anyone without a camera) carrying its public key.
2. The existing device reads it, and both screens display the same **short
   authentication string** derived from both halves. The customer confirms
   they match.
3. The existing device encrypts the bundle to the ephemeral public key and
   pushes it through the server as an opaque, short-lived relay object.
4. The new device fetches, unseals, seals into its own keystore, and the
   ephemeral key is discarded.

Nothing decryptable ever rests on the server, and there is no long-term secret
to grind. The short authentication string is what defeats a server that tries
to substitute its own ephemeral key — without it, the relay could man in the
middle the enrolment, which is exactly the attack the product exists to refuse.

This is the linked-device model from Signal and Matrix. It is well trodden;
follow it rather than inventing.

## Merge rules

Ring changes are rare but real — rotate on the laptop while the phone is off.
Two rules keep it safe:

- **The ring is append-mostly.** A merge is the union of key records by
  fingerprint; the newest *active* designation wins by timestamp.
- **Sync can never remove a private key.** A key that disappears takes years of
  readable mail with it. Removal is a deliberate local act with a backup
  ceremony in front of it, never a consequence of two devices disagreeing.

When pins join in v1.1: merge by address, newer `lastSeen` wins, and a genuine
conflict — two devices holding different fingerprints for one address — must
surface as the same "key changed" prompt the reader already shows. It must not
be resolved silently, because a silent resolution is indistinguishable from the
attack pinning exists to catch.

## What the server can see

Stated plainly, because it will be asked:

- That a customer has an escrow blob, its size, and when it changed.
- Which devices fetched it, and when.
- For pairing: that a relay object existed briefly between two sessions.

It cannot see the recovery phrase, the ephemeral keys, or any ring content.
Retention and deletion-on-account-closure need themis, as does the question of
whether an encrypted blob the operator cannot read is personal data it holds.

## What this adds to the audited surface

Sync is new code in a codebase whose value depends on staying small enough to
read. Worth being deliberate about where it lands.

The split is favourable. The parts that must be auditable are small and
belong in the core: the bundle format, the Argon2id envelope, and the
ephemeral pairing exchange with its short authentication string. That is a
few hundred lines of well-understood construction.

Everything else — storing an opaque blob, listing devices, relaying a
short-lived object between two sessions — is broker-side, and **does not need
to be trusted for the claim to hold**. That is the whole point of doing the
crypto correctly: the transport is allowed to be hostile. An auditor reading
Saavi can confirm the customer's secrets never reach the server without
reading a line of the server.

So the rule for this work: **anything that touches a key or derives one goes
in the core and gets audited; anything that moves ciphertext around stays in
the broker and does not.** If a change cannot be placed cleanly on one side of
that line, it is the wrong shape.

## Device list and honest revocation

Customers see their devices, named, with last-seen, and can remove one.

Removal must be honest about what it does. It stops that device receiving
future updates and bars it from pairing others. **It cannot claw back the key
that device already holds** — no such power exists, and implying otherwise
would be the most dangerous sentence in the product. The only real remedy for a
lost device is key rotation, which Saavi already supports. Say so, in those
words, next to the button.

## Phases

- **S0 — the bundle format.** Ships inside 0.5.0. The on-disk store becomes a
  versioned bundle, exportable as a unit, with a reserved slot for pins. No
  sync, no server, no new surface.
- **S1 — the recovery kit.** Generated phrase, Argon2id, opaque blob on the
  broker, restore on a new device. Solves the new phone and the lost-everything
  case, and needs no second device present. Cerberus gate; themis on retention.
- **S2 — device-to-device pairing.** QR plus short authentication string,
  ephemeral relay. The everyday path once mobile has a camera to point.
  Cerberus gate.
- **S3 — pins in the bundle, ongoing sync, device list and revocation UI.**

S1 before S2 despite S2 being the stronger mechanism: S1 is simpler, unblocks
mobile immediately, and delivers the recovery story that makes the product
sellable. Its exposure — a grindable blob — is answerable with a generated
phrase and a memory-hard KDF, which S2 does not need but S1 can afford.

## Open questions

- **Is the recovery phrase separate from the key passphrase?** Separate is
  cleaner: different jobs, different rotation, and a compromised passphrase
  should not hand over every device. It is a second secret for the customer to
  keep, which the existing spare-key ritual already has a shape for. Leaning
  separate.
- **Where does the blob live?** The signup broker is the natural home — it
  already holds org records and has the authenticated-endpoint pattern. Confirm
  rather than assume.
- **Argon2id parameters**, and confirming they are stored in the envelope so
  they can be raised without stranding old blobs.
- **Does an org admin ever get a copy?** Not by default, and not by accident.
  The moment escrow exists, someone will ask for administrative escrow, and
  that is a different product promise with different law attached — it belongs
  to the P6 offboarding stance, decided deliberately and in the open. The
  design must make it impossible to bolt on quietly, which means the blob is
  encrypted to a secret only the customer has ever held, and no code path
  anywhere accepts an operator-supplied key.
