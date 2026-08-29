import { beforeEach, describe, expect, it } from 'vitest';
import * as openpgp from 'openpgp';
import * as pins from '../src/pins';

const OWNER = 'me@kaditham.ie';
const THEM = 'them@example.org';
const OTHER = 'other@example.org';

/** A throwaway recipient keypair. Kept out of the Saavi ring on purpose:
 *  pins are about keys you do NOT hold. */
async function makeKey(email: string): Promise<{ pub: string; priv: openpgp.PrivateKey }> {
  const { privateKey, publicKey } = await openpgp.generateKey({
    type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: email, email }], format: 'armored',
  });
  return { pub: publicKey, priv: await openpgp.readPrivateKey({ armoredKey: privateKey }) };
}

const found = (key: string, source: pins.PinSource = 'wkd'): pins.LookupFn =>
  async () => ({ key, source, status: 'found' });
const unreachable: pins.LookupFn = async () => ({ key: null, source: 'wkd', status: 'unreachable', detail: 'offline' });
const publishesNone: pins.LookupFn = async () => ({ key: null, source: 'wkd', status: 'none' });

beforeEach(() => { localStorage.clear(); });

describe('pinning', () => {
  it('pins on first contact and says so', async () => {
    const k = await makeKey(THEM);
    const r = await pins.resolve(OWNER, THEM, found(k.pub));
    expect(r.state).toBe('ok');
    if (r.state !== 'ok') return;
    expect(r.firstContact).toBe(true);
    expect(r.offline).toBe(false);
    expect(r.key).toBe(k.pub);
    const stored = pins.pinFor(OWNER, THEM)!;
    expect(stored.source).toBe('wkd');
    expect(stored.fingerprint).toHaveLength(40);
    expect(stored.fingerprint).toBe(stored.fingerprint.toLowerCase());
  });

  it('normalises the address it pins under', async () => {
    const k = await makeKey(THEM);
    await pins.resolve(OWNER, '  Them@Example.ORG ', found(k.pub));
    expect(pins.pinFor(OWNER, THEM)).not.toBeNull();
    expect(pins.all(OWNER)).toHaveLength(1);
  });

  it('a second lookup of the same key is not a first contact', async () => {
    const k = await makeKey(THEM);
    await pins.resolve(OWNER, THEM, found(k.pub));
    const r = await pins.resolve(OWNER, THEM, found(k.pub));
    expect(r.state).toBe('ok');
    if (r.state !== 'ok') return;
    expect(r.firstContact).toBe(false);
  });

  it('refreshes the stored armor when the fingerprint still matches', async () => {
    // A rotated subkey or a new user ID leaves the primary fingerprint alone.
    // The pin must take the new armor, or the offline path serves a stale key.
    const k = await makeKey(THEM);
    await pins.resolve(OWNER, THEM, found(k.pub));
    const reformed = await openpgp.reformatKey({
      privateKey: k.priv, userIDs: [{ name: 'Them', email: THEM }, { name: 'Them at work', email: OTHER }], format: 'armored',
    });
    expect(reformed.publicKey).not.toBe(k.pub);
    const r = await pins.resolve(OWNER, THEM, found(reformed.publicKey));
    expect(r.state).toBe('ok');
    expect(pins.pinFor(OWNER, THEM)!.publicKey).toBe(reformed.publicKey);
  });

  it('reports a different key as changed and writes nothing until accepted', async () => {
    const a = await makeKey(THEM);
    await pins.resolve(OWNER, THEM, found(a.pub));
    const before = pins.pinFor(OWNER, THEM)!;

    const b = await makeKey(THEM);
    const r = await pins.resolve(OWNER, THEM, found(b.pub, 'vks'));
    expect(r.state).toBe('changed');
    if (r.state !== 'changed') return;
    expect(r.pin.fingerprint).toBe(before.fingerprint);
    expect(r.fingerprint).not.toBe(before.fingerprint);
    // declining is simply never calling accept()
    expect(pins.pinFor(OWNER, THEM)!.publicKey).toBe(a.pub);

    pins.accept(OWNER, r);
    const after = pins.pinFor(OWNER, THEM)!;
    expect(after.publicKey).toBe(b.pub);
    expect(after.source).toBe('vks');
    expect(after.firstSeen).toBe(before.firstSeen); // when the ADDRESS was first known
  });

  it('falls back to the pin when nothing can be reached', async () => {
    const k = await makeKey(THEM);
    await pins.resolve(OWNER, THEM, found(k.pub));
    const r = await pins.resolve(OWNER, THEM, unreachable);
    expect(r.state).toBe('ok');
    if (r.state !== 'ok') return;
    expect(r.offline).toBe(true);
    expect(r.key).toBe(k.pub);
  });

  it('reports a withdrawn key rather than substituting the pin', async () => {
    // A withdrawn key is a decision by its owner, not a network failure —
    // and it must never read as "no key yet", which invites plaintext.
    const k = await makeKey(THEM);
    await pins.resolve(OWNER, THEM, found(k.pub));
    const r = await pins.resolve(OWNER, THEM, publishesNone);
    expect(r.state).toBe('withdrawn');
    if (r.state !== 'withdrawn') return;
    expect(r.pin.publicKey).toBe(k.pub);
  });

  it('misses cleanly for an address that was never pinned', async () => {
    const r = await pins.resolve(OWNER, THEM, unreachable);
    expect(r.state).toBe('missing');
    if (r.state !== 'missing') return;
    expect(pins.all(OWNER)).toHaveLength(0);
  });

  it('stops on a revoked key even though its fingerprint is unchanged', async () => {
    const k = await makeKey(THEM);
    await pins.resolve(OWNER, THEM, found(k.pub));
    const { publicKey: revoked } = await openpgp.revokeKey({ key: k.priv, format: 'armored' });

    const r = await pins.resolve(OWNER, THEM, found(revoked));
    expect(r.state).toBe('revoked');
    expect(pins.pinFor(OWNER, THEM)!.revokedAt).toBeTruthy();

    // and the offline path must never serve it again — it says why, rather
    // than reporting a vague "no key found"
    const off = await pins.resolve(OWNER, THEM, unreachable);
    expect(off.state).toBe('revoked');

    // nor may a copy served WITHOUT the revocation signature reinstate it
    const rollback = await pins.resolve(OWNER, THEM, found(k.pub));
    expect(rollback.state).toBe('revoked');
    expect(pins.pinFor(OWNER, THEM)!.revokedAt).toBeTruthy();
  });

  it('lets a genuinely new key replace a revoked one, once accepted', async () => {
    const old = await makeKey(THEM);
    await pins.resolve(OWNER, THEM, found(old.pub));
    const { publicKey: revoked } = await openpgp.revokeKey({ key: old.priv, format: 'armored' });
    await pins.resolve(OWNER, THEM, found(revoked));

    const fresh = await makeKey(THEM);
    const r = await pins.resolve(OWNER, THEM, found(fresh.pub));
    expect(r.state).toBe('changed');
    if (r.state !== 'changed') return;
    pins.accept(OWNER, r);
    const now = pins.pinFor(OWNER, THEM)!;
    expect(now.publicKey).toBe(fresh.pub);
    expect(now.revokedAt).toBeUndefined();
  });

  it('lists and forgets', async () => {
    await pins.resolve(OWNER, THEM, found((await makeKey(THEM)).pub));
    await pins.resolve(OWNER, OTHER, found((await makeKey(OTHER)).pub));
    expect(pins.all(OWNER).map((p) => p.address)).toEqual([OTHER, THEM]);
    pins.forget(OWNER, THEM);
    expect(pins.pinFor(OWNER, THEM)).toBeNull();
    expect(pins.all(OWNER)).toHaveLength(1);
  });

  it('keeps one account\'s trust out of another\'s', async () => {
    const mine = await makeKey(THEM);
    await pins.resolve(OWNER, THEM, found(mine.pub));
    // a second account on the same machine has decided nothing
    expect(pins.pinFor('someone@else.test', THEM)).toBeNull();
    expect(pins.all('someone@else.test')).toHaveLength(0);
    // and its own first contact is a first contact, not a change
    const theirs = await makeKey(THEM);
    const r = await pins.resolve('someone@else.test', THEM, found(theirs.pub));
    expect(r.state).toBe('ok');
    if (r.state !== 'ok') return;
    expect(r.firstContact).toBe(true);
    expect(pins.pinFor(OWNER, THEM)!.publicKey).toBe(mine.pub); // untouched
  });

  it('adopts pins written before scoping existed', async () => {
    const k = await makeKey(THEM);
    const legacy = { address: THEM, fingerprint: 'a'.repeat(40), publicKey: k.pub, source: 'wkd',
      firstSeen: '2026-01-01T00:00:00.000Z', lastSeen: '2026-01-01T00:00:00.000Z' };
    localStorage.setItem('saavi-pin-' + THEM, JSON.stringify(legacy));
    // the device scope inherits it; a named account does not
    expect(pins.pinFor('', THEM)!.firstSeen).toBe('2026-01-01T00:00:00.000Z');
    expect(localStorage.getItem('saavi-pin-' + THEM)).toBeNull();
    expect(pins.pinFor(OWNER, THEM)).toBeNull();
  });

  it('ignores unreadable records rather than quarantining them', async () => {
    // Unlike a private key, a pin is always re-derivable from the network.
    localStorage.setItem(`saavi-pin-${OWNER}|broken@example.org`, '{not json');
    expect(pins.all(OWNER)).toHaveLength(0);
    expect(pins.pinFor(OWNER, 'broken@example.org')).toBeNull();
  });
});

describe('keyState', () => {
  it('separates revoked from merely unusable', async () => {
    const { keyState } = await import('../src/pgp');
    const k = await makeKey(THEM);
    const live = await keyState(k.pub);
    expect(live).toMatchObject({ revoked: false, usable: true });
    expect(live.fingerprint).toHaveLength(40);

    const { publicKey: revoked } = await openpgp.revokeKey({ key: k.priv, format: 'armored' });
    const dead = await keyState(revoked);
    expect(dead.revoked).toBe(true);
    expect(dead.usable).toBe(false);
    expect(dead.fingerprint).toBe(live.fingerprint); // the whole point
  });
});

describe('seeded (fingerprint-only) pins', () => {
  it('accepts the matching key later, without calling it a first contact', async () => {
    const k = await makeKey(THEM);
    const fp = await (await import('../src/pgp')).rawFingerprintOf(k.pub);
    expect(pins.seed(OWNER, THEM, fp, 'directory', '2026-01-02T00:00:00.000Z')).not.toBeNull();
    expect(pins.pinFor(OWNER, THEM)!.publicKey).toBe('');

    const r = await pins.resolve(OWNER, THEM, found(k.pub));
    expect(r.state).toBe('ok');
    if (r.state !== 'ok') return;
    expect(r.firstContact).toBe(false);          // the fingerprint was already known
    expect(pins.pinFor(OWNER, THEM)!.publicKey).toBe(k.pub);
    expect(pins.pinFor(OWNER, THEM)!.firstSeen).toBe('2026-01-02T00:00:00.000Z');
  });

  it('still catches a key that disagrees with the seeded fingerprint', async () => {
    const fp = await (await import('../src/pgp')).rawFingerprintOf((await makeKey(THEM)).pub);
    pins.seed(OWNER, THEM, fp, 'directory');
    const other = await makeKey(THEM);
    const r = await pins.resolve(OWNER, THEM, found(other.pub));
    expect(r.state).toBe('changed');
  });

  it('has no key to fall back on when the network is down', async () => {
    pins.seed(OWNER, THEM, 'b'.repeat(40), 'directory');
    const r = await pins.resolve(OWNER, THEM, unreachable);
    expect(r.state).toBe('missing');            // never seals to an empty key
  });

  it('refuses nonsense and never overwrites a real pin', async () => {
    expect(pins.seed(OWNER, THEM, 'not-a-fingerprint', 'directory')).toBeNull();
    const k = await makeKey(THEM);
    await pins.resolve(OWNER, THEM, found(k.pub));
    expect(pins.seed(OWNER, THEM, 'c'.repeat(40), 'directory')).toBeNull();
    expect(pins.pinFor(OWNER, THEM)!.publicKey).toBe(k.pub);
  });
});

describe('resolving without committing', () => {
  it('decides everything and writes nothing', async () => {
    const k = await makeKey(THEM);
    const r = await pins.resolve(OWNER, THEM, found(k.pub), { commit: false });
    expect(r.state).toBe('ok');
    if (r.state !== 'ok') return;
    expect(r.firstContact).toBe(true);
    expect(r.pin).toBeNull();
    expect(r.fingerprint).toHaveLength(40);
    expect(pins.pinFor(OWNER, THEM)).toBeNull();   // typing an address is not trust
  });

  it('still catches a change without recording anything new', async () => {
    const a = await makeKey(THEM);
    await pins.resolve(OWNER, THEM, found(a.pub));
    const b = await makeKey(THEM);
    const r = await pins.resolve(OWNER, THEM, found(b.pub), { commit: false });
    expect(r.state).toBe('changed');
    expect(pins.pinFor(OWNER, THEM)!.publicKey).toBe(a.pub);
  });

  it('does not mark a revoked key when it is only looking', async () => {
    const k = await makeKey(THEM);
    await pins.resolve(OWNER, THEM, found(k.pub));
    const { publicKey: revoked } = await openpgp.revokeKey({ key: k.priv, format: 'armored' });
    const r = await pins.resolve(OWNER, THEM, found(revoked), { commit: false });
    expect(r.state).toBe('revoked');
    expect(pins.pinFor(OWNER, THEM)!.revokedAt).toBeUndefined();
  });

  it('remember() commits it, keeping the address\'s first-seen date', async () => {
    const k = await makeKey(THEM);
    const r = await pins.resolve(OWNER, THEM, found(k.pub), { commit: false });
    if (r.state !== 'ok') throw new Error('expected ok');
    const first = pins.remember(OWNER, THEM, r.key, r.fingerprint, 'directory');
    expect(pins.pinFor(OWNER, THEM)!.publicKey).toBe(k.pub);
    expect(pins.pinFor(OWNER, THEM)!.source).toBe('directory');

    const again = pins.remember(OWNER, THEM, r.key, r.fingerprint, 'directory');
    expect(again.firstSeen).toBe(first.firstSeen);
  });
});
