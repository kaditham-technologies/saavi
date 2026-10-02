// The keychain's stateful flows — sync, restore, and the marker that binds
// them — against an in-memory broker that enforces the same contract the
// real one does (versioned optimistic concurrency, the no-shrink guards).
// The pure-core file (keychain.test.ts) asks whether each part is right;
// this one asks whether the ceremony as a whole leaves the device in a
// state the NEXT sync agrees with. Every regression pinned here shipped
// once: the restore marker that recorded the blob's addresses instead of
// the device's (wedging every future sync), the blob-hashed marker that
// forced one spurious push per restore, and the all-or-nothing passphrase
// proof that locked multi-passphrase accounts out of restoring anything.
import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as openpgp from 'openpgp';

// ---- module doubles, in place before the modules under test load ----

const store = new Map<string, string>();
vi.stubGlobal('localStorage', {
  getItem: (k: string) => store.get(k) ?? null,
  setItem: (k: string, v: string) => void store.set(k, String(v)),
  removeItem: (k: string) => void store.delete(k),
  clear: () => store.clear(),
});

/** An in-memory broker speaking the keychain routes' contract. */
class FakeBroker {
  chain: { blob: string; version: number } | null = null;
  private json(status: number, body: unknown): Response {
    return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
  }
  private armors(rings: Record<string, { active: { privateKey: string }; retired: { privateKey: string }[] }>): string[] {
    return Object.values(rings ?? {})
      .flatMap((r) => [r?.active, ...(Array.isArray(r?.retired) ? r.retired : [])])
      .map((k) => (typeof k?.privateKey === 'string' ? k.privateKey.replace(/\r\n/g, '\n').trim() : ''))
      .filter(Boolean);
  }
  handle(url: string, init?: RequestInit): Response {
    if (url.endsWith('/signup/api/keychain') && (init?.method ?? 'GET') === 'GET') {
      return this.json(200, this.chain
        ? { exists: true, version: this.chain.version, updatedAt: 'now', lastFetchAt: null }
        : { exists: false, version: 0, updatedAt: null, lastFetchAt: null });
    }
    if (url.endsWith('/signup/api/keychain/fetch')) {
      // P6: the real broker demands proof of the account secret alongside
      // the bearer (ZERO-ACCESS.md M0) — the contract double does too.
      const fp = JSON.parse(String(init?.body ?? 'null'));
      if (fp?.proof !== SECRET) return this.json(403, { error: 'Confirm your account password.', code: 'proof-required' });
      if (!this.chain) return this.json(404, { error: 'This account has no keychain yet.' });
      return this.json(200, { blob: this.chain.blob, version: this.chain.version, updatedAt: 'now' });
    }
    // the push
    const p = JSON.parse(String(init?.body ?? 'null'));
    if (p?.proof !== SECRET) return this.json(403, { error: 'Confirm your account password.', code: 'proof-required' });
    const rings = JSON.parse(p.blob).rings as Record<string, { active: { privateKey: string }; retired: { privateKey: string }[] }>;
    if (!Object.keys(rings).length) return this.json(400, { error: 'A keychain must hold at least one key.' });
    const force = p.force === true;
    const ifVersion = p.ifVersion == null ? null : Number(p.ifVersion);
    const current = this.chain;
    if (!force && (current?.version ?? null) !== ifVersion && !(current == null && ifVersion === null)) {
      return this.json(409, { error: 'The keychain changed on another device.', version: current?.version ?? 0 });
    }
    if (!force && current) {
      const prior = JSON.parse(current.blob).rings as typeof rings;
      const incoming = new Set(Object.keys(rings).map((e) => e.toLowerCase()));
      const dropped = Object.keys(prior).filter((e) => !incoming.has(e.toLowerCase()));
      if (dropped.length) return this.json(409, { error: `Refusing to drop keys for ${dropped.join(', ')}.`, version: current.version });
      // The signed purge is the one sanctioned armor drop. The REAL
      // broker's signature verification is proven in the signup repo's
      // keychain-purge tests; this contract double checks the shape and
      // demands a signature entry, like the real route demands a valid one.
      const purge = p.purge && typeof p.purge === 'object' && p.purge.signatures
        && Object.keys(p.purge.signatures).length > 0;
      if (!purge) {
        const have = new Map<string, number>();
        for (const a of this.armors(rings)) have.set(a, (have.get(a) ?? 0) + 1);
        for (const a of this.armors(prior)) {
          const n = (have.get(a) ?? 0) - 1;
          if (n < 0) return this.json(409, { error: 'Refusing to drop stored key material.', version: current.version });
          have.set(a, n);
        }
      }
    }
    this.chain = { blob: p.blob, version: (current?.version ?? 0) + 1 };
    return this.json(200, { version: this.chain.version });
  }
}
const SECRET = 'test-account-secret';
const broker = new FakeBroker();

vi.mock('../src/server', () => ({
  apiUrl: (p: string) => p,
  netFetch: (url: string, init?: RequestInit) => Promise.resolve(broker.handle(url, init)),
}));

import * as keychain from '../src/mailkeychain';
import * as pgp from '../src/pgp';

// ---- fixtures ----

const USER = 'me@x.ie';
const ALIAS = 'alias@x.ie';

async function makeRecord(email: string, passphrase: string): Promise<{ publicKey: string; privateKey: string; created: string }> {
  const { privateKey, publicKey } = await openpgp.generateKey({
    userIDs: [{ name: 'T', email }],
    passphrase,
    type: 'ecc',
    curve: 'curve25519Legacy' as const,
    format: 'armored',
  });
  return { publicKey, privateKey, created: '2026-01-01T00:00:00.000Z' };
}

const blobOf = (rings: Record<string, unknown>): string =>
  JSON.stringify({ v: 1, exportedAt: '2026-01-01T00:00:00.000Z', rings });

const ringOn = (email: string): string | null => store.get('saavi-ring-' + email) ?? null;
const marker = (username = USER): { version: number; hash: string; emails: string[] } | null =>
  JSON.parse(store.get('kad-keychain:' + username) ?? 'null');

beforeEach(() => {
  store.clear();
  pgp.clearSession();
  broker.chain = null;
  keychain.useProof(() => SECRET);
  keychain.useAuthority(async () => ({}));
});

describe('restore', () => {
  it('records the marker from what THIS device holds, not the blob — and the next sync agrees', async () => {
    // The blob carries two addresses; this device only owns (and restores)
    // one. A marker naming both wedges every later sync on the address
    // no-shrink check; a marker hashing the blob instead of the bound local
    // rings forces one spurious push. Both shipped once.
    const mine = await makeRecord(USER, 'pass one');
    const other = await makeRecord(ALIAS, 'pass one');
    broker.chain = { blob: blobOf({ [USER]: { active: mine, retired: [] }, [ALIAS]: { active: other, retired: [] } }), version: 3 };

    const r = await keychain.restore(USER, 'pass one', [USER]);
    expect(r.pending).toEqual([]);
    expect(ringOn(USER)).not.toBeNull();
    expect(ringOn(ALIAS)).toBeNull();
    expect(marker()?.emails).toEqual([USER]);

    await expect(keychain.sync(USER, [USER])).resolves.toBe('unchanged');
    expect(broker.chain!.version, 'no spurious push after a restore').toBe(3);
  });

  it('proves the passphrase per ring: keeps what opens, uninstalls and reports the rest', async () => {
    const mine = await makeRecord(USER, 'pass one');
    const other = await makeRecord(ALIAS, 'pass two');
    broker.chain = { blob: blobOf({ [USER]: { active: mine, retired: [] }, [ALIAS]: { active: other, retired: [] } }), version: 1 };

    const r = await keychain.restore(USER, 'pass one', [USER, ALIAS]);
    expect(r.pending).toEqual([ALIAS]);
    expect(ringOn(USER)).not.toBeNull();
    expect(ringOn(ALIAS), 'an unproven ring must not survive').toBeNull();
    expect(marker()?.emails).toEqual([USER]);
    await expect(keychain.sync(USER, [USER, ALIAS])).resolves.toBe('unchanged');

    // Second pass with the other passphrase picks up exactly the pending ring.
    const r2 = await keychain.restore(USER, 'pass two', [USER, ALIAS]);
    expect(r2.pending).toEqual([]);
    expect(ringOn(ALIAS)).not.toBeNull();
    expect(marker()?.emails?.sort()).toEqual([ALIAS, USER].sort());
    await expect(keychain.sync(USER, [USER, ALIAS])).resolves.toBe('unchanged');
  });

  it('rolls everything back — session memory included — when nothing opens', async () => {
    const mine = await makeRecord(USER, 'pass one');
    broker.chain = { blob: blobOf({ [USER]: { active: mine, retired: [] } }), version: 1 };

    await expect(keychain.restore(USER, 'wrong words entirely', [USER]))
      .rejects.toThrow('does not open');
    expect(ringOn(USER)).toBeNull();
    expect(marker()).toBeNull();
    expect(pgp.hasUnlockedKeys(), 'no unlocked key may outlive its rollback').toBe(false);
  });
});

describe('sync', () => {
  it('merges on conflict and still records only the LOCAL rings in the marker', async () => {
    // Another device holds the alias's ring; this one holds only its own.
    const other = await makeRecord(ALIAS, 'pass two');
    broker.chain = { blob: blobOf({ [ALIAS]: { active: other, retired: [] } }), version: 5 };
    const mine = await makeRecord(USER, 'pass one');
    store.set('saavi-ring-' + USER, JSON.stringify({ active: mine, retired: [] }));

    await expect(keychain.sync(USER, [USER, ALIAS])).resolves.toBe('merged');
    // The union reached the broker; nothing was dropped from it.
    const pushed = JSON.parse(broker.chain!.blob);
    expect(Object.keys(pushed.rings).sort()).toEqual([ALIAS, USER].sort());
    // The marker stays the device's own truth (argus re-review A).
    expect(marker()?.emails).toEqual([USER]);
    await expect(keychain.sync(USER, [USER, ALIAS])).resolves.toBe('unchanged');
  });

  it('defers rather than shrink: a marker address with no local ring blocks the push', async () => {
    const mine = await makeRecord(USER, 'pass one');
    store.set('saavi-ring-' + USER, JSON.stringify({ active: mine, retired: [] }));
    store.set('kad-keychain:' + USER, JSON.stringify({ version: 2, hash: 'stale', emails: [USER, ALIAS] }));

    await expect(keychain.sync(USER, [USER, ALIAS])).rejects.toThrow('deferred');
  });
});

describe('the proof gate (P6)', () => {
  const seedRing = async () =>
    store.set('saavi-ring-' + USER, JSON.stringify({ active: await makeRecord(USER, 'pass one is long'), retired: [] }));

  it('a resumed session (no secret in hand) DEFERS the push instead of failing loudly', async () => {
    keychain.useProof(() => null);
    await seedRing();
    await expect(keychain.sync(USER, [USER])).rejects.toThrow(/deferred/);
    expect(broker.chain).toBeNull(); // and nothing proof-less ever reached the wire
  });
  it('a resumed session cannot restore — the error says to sign in, not "wrong passphrase"', async () => {
    broker.chain = { blob: JSON.stringify({ v: 1, rings: {} }), version: 1 };
    keychain.useProof(() => null);
    await expect(keychain.restore(USER, 'whatever', [USER])).rejects.toThrow(/[Ss]ign in/);
  });
  it('a wrong proof is a 403 the sync surfaces, never a silent skip', async () => {
    keychain.useProof(() => 'not-the-secret');
    await seedRing();
    await expect(keychain.sync(USER, [USER])).rejects.toThrow();
    expect(broker.chain).toBeNull();
  });
});

describe('the recovery kit flow (M5)', () => {
  // Real key generation, two re-locks and a phrase proof — comfortably over
  // the 5 s default when the suite runs loaded.
  it('mints, syncs as v2, and recovers with the phrase under a NEW password — additively', { timeout: 30_000 }, async () => {
    const PHRASE = 'apple brave cable daisy eagle fable gamma habit';
    // A split-born device: the ring is locked under the (old) password.
    const rec = await makeRecord(USER, 'old-password');
    store.set('saavi-ring-' + USER, JSON.stringify({ active: rec, retired: [] }));
    await keychain.sync(USER, [USER]);
    expect(broker.chain!.version).toBe(1);
    expect(JSON.parse(broker.chain!.blob).v).toBe(1);

    // The kit ceremony's core: build the phrase envelope, record it, sync —
    // the blob turns v2 and carries the envelope.
    const { id, envelope } = await keychain.buildEnvelope([USER], 'old-password', PHRASE);
    keychain.recordEnvelope(USER, id, envelope, false);
    await keychain.sync(USER, [USER]);
    const pushed = JSON.parse(broker.chain!.blob);
    expect(pushed.v).toBe(2);
    expect(Object.keys(pushed.envelopes)).toEqual([id]);

    // The password is lost. A fresh device signs in with the NEW password
    // and offers the phrase.
    const chain = broker.chain;
    store.clear();
    pgp.clearSession();
    broker.chain = chain;
    const { recovered } = await keychain.restoreWithPhrase(USER, PHRASE, [USER], 'new-password');
    expect(recovered).toEqual([USER]);
    await expect(pgp.unlockPrivateKey(USER, 'new-password')).resolves.toBeUndefined();
    // Additive (C5): the blob's original armor — locked under the lost
    // password — rides along as retired, so the broker's armor-multiset
    // guard sees only growth on the push that follows…
    const ring = JSON.parse(ringOn(USER)!) as { retired: { privateKey: string }[] };
    expect(ring.retired.map((r) => r.privateKey.trim())).toContain(rec.privateKey.trim());
    // …and that push actually happens: the re-locked ring must not live on
    // this device alone.
    await expect(keychain.sync(USER, [USER])).resolves.toBe('pushed');
    const after = JSON.parse(broker.chain!.blob);
    expect(broker.chain!.version).toBe(3);
    expect(after.v, 'the kit survives the recovery push').toBe(2);
    expect(Object.keys(after.envelopes)).toEqual([id]);
  });

  it('a wrong phrase recovers nothing and leaves no ring behind', { timeout: 30_000 }, async () => {
    const PHRASE = 'apple brave cable daisy eagle fable gamma habit';
    const rec = await makeRecord(USER, 'old-password');
    store.set('saavi-ring-' + USER, JSON.stringify({ active: rec, retired: [] }));
    await keychain.sync(USER, [USER]);
    const { id, envelope } = await keychain.buildEnvelope([USER], 'old-password', PHRASE);
    keychain.recordEnvelope(USER, id, envelope, false);
    await keychain.sync(USER, [USER]);

    const chain = broker.chain;
    store.clear();
    pgp.clearSession();
    broker.chain = chain;
    await expect(keychain.restoreWithPhrase(USER, 'eight totally wrong words typed here now yes', [USER], 'new-password'))
      .rejects.toThrow('does not open');
    expect(ringOn(USER)).toBeNull();
  });
});

describe('the signed purge (C2)', () => {
  it('drops only the superseded same-key locks, keeps rotated keys, and the next sync agrees', { timeout: 30_000 }, async () => {
    // The additive re-lock's leavings: the ACTIVE key also present retired
    // under an older lock. A genuinely different (rotated) key stays.
    const rec = await makeRecord(USER, 'new-pass');
    const parsed = await openpgp.readPrivateKey({ armoredKey: rec.privateKey });
    const unlocked = await openpgp.decryptKey({ privateKey: parsed, passphrase: 'new-pass' });
    const oldLock = { publicKey: rec.publicKey, privateKey: (await openpgp.encryptKey({ privateKey: unlocked, passphrase: 'old-pass' })).armor(), created: rec.created };
    const rotated = await makeRecord(USER, 'ancient-pass');
    // The active wears epoch 1 — exactly what the re-lock that retired
    // oldLock would have written. The purge is epoch-aware: same key AND
    // strictly older lock, or it stays (destruction wants certainty).
    store.set('saavi-ring-' + USER, JSON.stringify({ active: { ...rec, lockEpoch: 1 }, retired: [oldLock, rotated] }));
    await keychain.sync(USER, [USER]);
    expect(broker.chain!.version).toBe(1);

    const r = await keychain.purge(USER, [USER], 'new-pass');
    expect(r).toBe('purged');

    // Server and device agree: the old lock is gone, the rotated key is not.
    const pushed = JSON.parse(broker.chain!.blob) as { rings: Record<string, { retired: { privateKey: string }[] }> };
    expect(pushed.rings[USER].retired.map((x) => x.privateKey.trim())).toEqual([rotated.privateKey.trim()]);
    const local = JSON.parse(store.get('saavi-ring-' + USER)!) as { retired: { privateKey: string }[] };
    expect(local.retired.map((x) => x.privateKey.trim())).toEqual([rotated.privateKey.trim()]);
    await expect(keychain.sync(USER, [USER])).resolves.toBe('unchanged');

    // Nothing left to purge — and the clean run says so without pushing.
    await expect(keychain.purge(USER, [USER], 'new-pass')).resolves.toBe('nothing-to-purge');
    expect(broker.chain!.version).toBe(2);
  });

  it('a ring the secret does not open keeps its armors — possession only, never best-effort', { timeout: 30_000 }, async () => {
    const rec = await makeRecord(USER, 'a-different-lock');
    const parsed = await openpgp.readPrivateKey({ armoredKey: rec.privateKey });
    const unlocked = await openpgp.decryptKey({ privateKey: parsed, passphrase: 'a-different-lock' });
    const oldLock = { publicKey: rec.publicKey, privateKey: (await openpgp.encryptKey({ privateKey: unlocked, passphrase: 'older-still' })).armor(), created: rec.created };
    store.set('saavi-ring-' + USER, JSON.stringify({ active: rec, retired: [oldLock] }));
    await keychain.sync(USER, [USER]);

    // The session secret opens nothing here — no signature, no purge.
    await expect(keychain.purge(USER, [USER], 'not-the-lock')).resolves.toBe('nothing-to-purge');
    expect(broker.chain!.version).toBe(1);
    expect((JSON.parse(broker.chain!.blob) as { rings: Record<string, { retired: unknown[] }> }).rings[USER].retired).toHaveLength(1);
  });
});

describe('swap-lock restore (A1)', () => {
  it('a device offline through a password change adopts the new lock — additively', { timeout: 30_000 }, async () => {
    // This device holds the ring under the OLD password (epoch 0).
    const rec = await makeRecord(USER, 'old password lock');
    store.set('saavi-ring-' + USER, JSON.stringify({ active: { ...rec, lockEpoch: 0 }, retired: [] }));

    // Another device re-locked the SAME key under the new password and
    // pushed (epoch 1) — this one slept through it.
    const parsed = await openpgp.readPrivateKey({ armoredKey: rec.privateKey });
    const unlocked = await openpgp.decryptKey({ privateKey: parsed, passphrase: 'old password lock' });
    const newArmor = (await openpgp.encryptKey({ privateKey: unlocked, passphrase: 'new password lock' })).armor();
    broker.chain = {
      blob: JSON.stringify({ v: 1, rings: { [USER]: {
        active: { publicKey: rec.publicKey, privateKey: newArmor, created: rec.created, lockEpoch: 1 },
        retired: [{ ...rec, lockEpoch: 0 }],
      } } }),
      version: 4,
    };

    // Restoring with the NEW password swaps the local lock…
    const r = await keychain.restore(USER, 'new password lock', [USER]);
    expect(r.pending).toEqual([]);
    const ring = JSON.parse(store.get('saavi-ring-' + USER)!) as { active: { privateKey: string; lockEpoch?: number }; retired: { privateKey: string }[] };
    expect(ring.active.lockEpoch).toBe(1);
    const active = await openpgp.readPrivateKey({ armoredKey: ring.active.privateKey });
    await expect(openpgp.decryptKey({ privateKey: active, passphrase: 'new password lock' })).resolves.toBeDefined();
    // …and the old armor survives retired (additive — the multiset guard).
    expect(ring.retired.map((x) => x.privateKey.trim())).toContain(rec.privateKey.trim());

    // The wrong password swaps nothing and leaves the ring as it was.
    store.set('saavi-ring-' + USER, JSON.stringify({ active: { ...rec, lockEpoch: 0 }, retired: [] }));
    pgp.clearSession();
    await expect(keychain.restore(USER, 'not either password', [USER])).rejects.toThrow();
    const after = JSON.parse(store.get('saavi-ring-' + USER)!) as { active: { lockEpoch?: number } };
    expect(after.active.lockEpoch).toBe(0);
  });
});

describe('rotation adoption (2026-10-01)', () => {
  // Browser B still holds the account's OLD key as active; browser A made a
  // new one (rotation, or a fresh key after a retire) and pushed it. B kept
  // sealing Sent copies to the retired key. A fresh sign-in on B now adopts
  // the new key — but only the one the server names, and only if it opens.
  it('a stale device adopts the server-named key, keeping its old one retired', { timeout: 30_000 }, async () => {
    const old = await makeRecord(USER, 'account secret');
    const fresh = await makeRecord(USER, 'account secret');
    store.set('saavi-ring-' + USER, JSON.stringify({ active: old, retired: [] }));
    broker.chain = { blob: blobOf({ [USER]: { active: fresh, retired: [] } }), version: 2 };
    const freshFpr = (await openpgp.readKey({ armoredKey: fresh.publicKey })).getFingerprint().toLowerCase();

    // Without `adopt`, restore leaves a differing ring alone — the old behaviour.
    await expect(keychain.restore(USER, 'account secret', [USER])).rejects.toThrow('already on this device');

    const r = await keychain.restore(USER, 'account secret', [USER], undefined, { adopt: { [USER]: freshFpr } });
    expect(r.pending).toEqual([]);
    const ring = JSON.parse(ringOn(USER)!) as { active: { privateKey: string }; retired: { privateKey: string }[] };
    expect(ring.active.privateKey.trim()).toBe(fresh.privateKey.trim());
    expect(ring.retired.map((x) => x.privateKey.trim()), 'the old key stays — mail sealed to it must open').toContain(old.privateKey.trim());
    expect(pgp.isUnlocked(USER)).toBe(true);
    // The next sync merges cleanly and keeps the NEW key in front.
    await keychain.sync(USER, [USER]);
    const pushed = JSON.parse(broker.chain!.blob).rings[USER];
    expect(pushed.active.privateKey.trim()).toBe(fresh.privateKey.trim());
  });

  it('adopts nothing the server did not name, and nothing the secret does not open', { timeout: 30_000 }, async () => {
    const old = await makeRecord(USER, 'account secret');
    const planted = await makeRecord(USER, 'account secret');
    store.set('saavi-ring-' + USER, JSON.stringify({ active: old, retired: [] }));
    broker.chain = { blob: blobOf({ [USER]: { active: planted, retired: [] } }), version: 2 };
    const oldFpr = (await openpgp.readKey({ armoredKey: old.publicKey })).getFingerprint().toLowerCase();
    await expect(keychain.restore(USER, 'account secret', [USER], undefined, { adopt: { [USER]: 'f'.repeat(40) } }))
      .rejects.toThrow('already on this device');
    expect(JSON.parse(ringOn(USER)!).active.privateKey.trim()).toBe(old.privateKey.trim());

    const otherLock = await makeRecord(USER, 'a rotation passphrase');
    const otherFpr = (await openpgp.readKey({ armoredKey: otherLock.publicKey })).getFingerprint().toLowerCase();
    broker.chain = { blob: blobOf({ [USER]: { active: otherLock, retired: [] } }), version: 3 };
    await pgp.unlockPrivateKey(USER, 'account secret');   // the device was working before the attempt
    await expect(keychain.restore(USER, 'account secret', [USER], undefined, { adopt: { [USER]: otherFpr } })).rejects.toThrow();
    expect(pgp.isUnlocked(USER), 'a failed adoption must not relock the key the device was using').toBe(true);
    const after = JSON.parse(ringOn(USER)!) as { active: { publicKey: string } };
    expect((await openpgp.readKey({ armoredKey: after.active.publicKey })).getFingerprint().toLowerCase(), 'rolled back to the ring it displaced').toBe(oldFpr);
  });
});

describe('no rollback of the active key (2026-09-30 v6)', () => {
  // A 0.3.0 tab left open since before a key change merged "local active
  // wins" and pushed the retired key back in front: v6 held the OLD key
  // active and the NEW one retired, and every fresh restore came up on a
  // key the password no longer opened.
  const fprOf = async (r: { publicKey: string }): Promise<string> =>
    (await openpgp.readKey({ armoredKey: r.publicKey })).getFingerprint().toLowerCase();

  it('a stale device\'s merge keeps the key another device moved to in front', { timeout: 30_000 }, async () => {
    const old = await makeRecord(USER, 'account secret');
    const fresh = await makeRecord(USER, 'account secret');
    store.set('saavi-ring-' + USER, JSON.stringify({ active: old, retired: [] }));
    store.set('kad-keychain:' + USER, JSON.stringify({ version: 1, hash: 'stale', emails: [USER] }));
    broker.chain = { blob: blobOf({ [USER]: { active: fresh, retired: [old] } }), version: 2 };

    await expect(keychain.sync(USER, [USER])).resolves.toBe('merged');
    const pushed = JSON.parse(broker.chain!.blob).rings[USER];
    expect(pushed.active.privateKey.trim(), 'the retired key never goes back in front').toBe(fresh.privateKey.trim());
    expect(pushed.retired.map((r: { privateKey: string }) => r.privateKey.trim())).toContain(old.privateKey.trim());
  });

  it('a device\'s own unpushed rotation still wins the merge', { timeout: 30_000 }, async () => {
    const k1 = await makeRecord(USER, 'account secret');
    const k2 = await makeRecord(USER, 'account secret');
    store.set('saavi-ring-' + USER, JSON.stringify({ active: k2, retired: [k1] }));
    store.set('kad-keychain:' + USER, JSON.stringify({ version: 1, hash: 'stale', emails: [USER] }));
    broker.chain = { blob: blobOf({ [USER]: { active: k1, retired: [] } }), version: 2 };
    await keychain.sync(USER, [USER]);
    expect(JSON.parse(broker.chain!.blob).rings[USER].active.privateKey.trim()).toBe(k2.privateKey.trim());
  });

  it('restore of a rolled-back blob puts the key the server names in front', { timeout: 30_000 }, async () => {
    const old = await makeRecord(USER, 'an old passphrase');   // the retired key: the password does not open it
    const fresh = await makeRecord(USER, 'account secret');
    broker.chain = { blob: blobOf({ [USER]: { active: old, retired: [{ ...fresh, lockEpoch: 1 }] } }), version: 6 };

    // Without the server's word, the blob's order stands — and nothing opens.
    await expect(keychain.restore(USER, 'account secret', [USER])).rejects.toThrow();
    expect(ringOn(USER)).toBeNull();

    keychain.useAuthority(async () => ({ [USER]: [await fprOf(fresh)] }));
    const r = await keychain.restore(USER, 'account secret', [USER]);
    expect(r.pending).toEqual([]);
    const ring = JSON.parse(ringOn(USER)!);
    expect(await fprOf(ring.active)).toBe(await fprOf(fresh));
    expect(ring.retired.map((x: { privateKey: string }) => x.privateKey.trim())).toContain(old.privateKey.trim());
    expect(pgp.isUnlocked(USER)).toBe(true);
  });

  it('ranks the server\'s keys: zero-access names the new key, a stale directory the old one', { timeout: 30_000 }, async () => {
    const old = await makeRecord(USER, 'account secret');
    const fresh = await makeRecord(USER, 'account secret');
    broker.chain = { blob: blobOf({ [USER]: { active: old, retired: [fresh] } }), version: 6 };
    keychain.useAuthority(async () => ({ [USER]: [await fprOf(fresh), await fprOf(old)] }));
    await keychain.restore(USER, 'account secret', [USER]);
    expect(await fprOf(JSON.parse(ringOn(USER)!).active)).toBe(await fprOf(fresh));
  });

  it('a stale device that re-locked its old key still loses the merge to the key another device moved to', { timeout: 30_000 }, async () => {
    const old = await makeRecord(USER, 'old password');
    const fresh = await makeRecord(USER, 'account secret');
    // B's password change re-locked the OLD key: a new armor of a retired key.
    const relocked = (await openpgp.encryptKey({
      privateKey: await openpgp.decryptKey({ privateKey: await openpgp.readPrivateKey({ armoredKey: old.privateKey }), passphrase: 'old password' }),
      passphrase: 'account secret',
    })).armor();
    store.set('saavi-ring-' + USER, JSON.stringify({ active: { ...old, privateKey: relocked, lockEpoch: 1 }, retired: [] }));
    store.set('kad-keychain:' + USER, JSON.stringify({ version: 1, hash: 'stale', emails: [USER] }));
    broker.chain = { blob: blobOf({ [USER]: { active: fresh, retired: [old] } }), version: 2 };
    await keychain.sync(USER, [USER]);
    expect(await fprOf(JSON.parse(broker.chain!.blob).rings[USER].active)).toBe(await fprOf(fresh));
  });

  it('a healthy device facing an already rolled-back blob keeps the server-named key in front', { timeout: 30_000 }, async () => {
    const old = await makeRecord(USER, 'old password');
    const fresh = await makeRecord(USER, 'account secret');
    store.set('saavi-ring-' + USER, JSON.stringify({ active: fresh, retired: [old] }));
    store.set('kad-keychain:' + USER, JSON.stringify({ version: 5, hash: 'stale', emails: [USER] }));
    broker.chain = { blob: blobOf({ [USER]: { active: old, retired: [fresh] } }), version: 6 };   // v6
    keychain.useAuthority(async () => ({ [USER]: [await fprOf(fresh)] }));
    await keychain.sync(USER, [USER]);
    expect(await fprOf(JSON.parse(broker.chain!.blob).rings[USER].active), 'never agrees with the rollback').toBe(await fprOf(fresh));
  });

  it('a named key that does not open falls back to the blob\'s own order', { timeout: 30_000 }, async () => {
    const cur = await makeRecord(USER, 'account secret');
    const other = await makeRecord(USER, 'someone else\'s lock');
    broker.chain = { blob: blobOf({ [USER]: { active: cur, retired: [other] } }), version: 3 };
    keychain.useAuthority(async () => ({ [USER]: [await fprOf(other)] }));
    const r = await keychain.restore(USER, 'account secret', [USER]);
    expect(r.pending).toEqual([]);
    expect(await fprOf(JSON.parse(ringOn(USER)!).active)).toBe(await fprOf(cur));
  });
});
