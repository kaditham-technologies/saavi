import { beforeEach, describe, expect, it } from 'vitest';
import * as openpgp from 'openpgp';
import * as pins from '../src/pins';

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
    const r = await pins.resolve(THEM, found(k.pub));
    expect(r.state).toBe('ok');
    if (r.state !== 'ok') return;
    expect(r.firstContact).toBe(true);
    expect(r.offline).toBe(false);
    expect(r.key).toBe(k.pub);
    const stored = pins.pinFor(THEM)!;
    expect(stored.source).toBe('wkd');
    expect(stored.fingerprint).toHaveLength(40);
    expect(stored.fingerprint).toBe(stored.fingerprint.toLowerCase());
  });

  it('normalises the address it pins under', async () => {
    const k = await makeKey(THEM);
    await pins.resolve('  Them@Example.ORG ', found(k.pub));
    expect(pins.pinFor(THEM)).not.toBeNull();
    expect(pins.all()).toHaveLength(1);
  });

  it('a second lookup of the same key is not a first contact', async () => {
    const k = await makeKey(THEM);
    await pins.resolve(THEM, found(k.pub));
    const r = await pins.resolve(THEM, found(k.pub));
    expect(r.state).toBe('ok');
    if (r.state !== 'ok') return;
    expect(r.firstContact).toBe(false);
  });

  it('refreshes the stored armor when the fingerprint still matches', async () => {
    // A rotated subkey or a new user ID leaves the primary fingerprint alone.
    // The pin must take the new armor, or the offline path serves a stale key.
    const k = await makeKey(THEM);
    await pins.resolve(THEM, found(k.pub));
    const reformed = await openpgp.reformatKey({
      privateKey: k.priv, userIDs: [{ name: 'Them', email: THEM }, { name: 'Them at work', email: OTHER }], format: 'armored',
    });
    expect(reformed.publicKey).not.toBe(k.pub);
    const r = await pins.resolve(THEM, found(reformed.publicKey));
    expect(r.state).toBe('ok');
    expect(pins.pinFor(THEM)!.publicKey).toBe(reformed.publicKey);
  });

  it('reports a different key as changed and writes nothing until accepted', async () => {
    const a = await makeKey(THEM);
    await pins.resolve(THEM, found(a.pub));
    const before = pins.pinFor(THEM)!;

    const b = await makeKey(THEM);
    const r = await pins.resolve(THEM, found(b.pub, 'vks'));
    expect(r.state).toBe('changed');
    if (r.state !== 'changed') return;
    expect(r.pin.fingerprint).toBe(before.fingerprint);
    expect(r.fingerprint).not.toBe(before.fingerprint);
    // declining is simply never calling accept()
    expect(pins.pinFor(THEM)!.publicKey).toBe(a.pub);

    pins.accept(r);
    const after = pins.pinFor(THEM)!;
    expect(after.publicKey).toBe(b.pub);
    expect(after.source).toBe('vks');
    expect(after.firstSeen).toBe(before.firstSeen); // when the ADDRESS was first known
  });

  it('falls back to the pin when nothing can be reached', async () => {
    const k = await makeKey(THEM);
    await pins.resolve(THEM, found(k.pub));
    const r = await pins.resolve(THEM, unreachable);
    expect(r.state).toBe('ok');
    if (r.state !== 'ok') return;
    expect(r.offline).toBe(true);
    expect(r.key).toBe(k.pub);
  });

  it('does NOT substitute the pin when the domain answers and publishes nothing', async () => {
    // A withdrawn key is a decision by the owner, not a network failure.
    const k = await makeKey(THEM);
    await pins.resolve(THEM, found(k.pub));
    const r = await pins.resolve(THEM, publishesNone);
    expect(r.state).toBe('missing');
    if (r.state !== 'missing') return;
    expect(r.hadPin).toBe(true);
    expect(r.status).toBe('none');
  });

  it('misses cleanly for an address that was never pinned', async () => {
    const r = await pins.resolve(THEM, unreachable);
    expect(r.state).toBe('missing');
    if (r.state !== 'missing') return;
    expect(r.hadPin).toBe(false);
    expect(pins.all()).toHaveLength(0);
  });

  it('stops on a revoked key even though its fingerprint is unchanged', async () => {
    const k = await makeKey(THEM);
    await pins.resolve(THEM, found(k.pub));
    const { publicKey: revoked } = await openpgp.revokeKey({ key: k.priv, format: 'armored' });

    const r = await pins.resolve(THEM, found(revoked));
    expect(r.state).toBe('revoked');
    expect(pins.pinFor(THEM)!.revokedAt).toBeTruthy();

    // and the offline path must never serve it again
    const off = await pins.resolve(THEM, unreachable);
    expect(off.state).toBe('missing');

    // nor may a copy served WITHOUT the revocation signature reinstate it
    const rollback = await pins.resolve(THEM, found(k.pub));
    expect(rollback.state).toBe('revoked');
    expect(pins.pinFor(THEM)!.revokedAt).toBeTruthy();
  });

  it('lets a genuinely new key replace a revoked one, once accepted', async () => {
    const old = await makeKey(THEM);
    await pins.resolve(THEM, found(old.pub));
    const { publicKey: revoked } = await openpgp.revokeKey({ key: old.priv, format: 'armored' });
    await pins.resolve(THEM, found(revoked));

    const fresh = await makeKey(THEM);
    const r = await pins.resolve(THEM, found(fresh.pub));
    expect(r.state).toBe('changed');
    if (r.state !== 'changed') return;
    pins.accept(r);
    const now = pins.pinFor(THEM)!;
    expect(now.publicKey).toBe(fresh.pub);
    expect(now.revokedAt).toBeUndefined();
  });

  it('lists and forgets', async () => {
    await pins.resolve(THEM, found((await makeKey(THEM)).pub));
    await pins.resolve(OTHER, found((await makeKey(OTHER)).pub));
    expect(pins.all().map((p) => p.address)).toEqual([OTHER, THEM]);
    pins.forget(THEM);
    expect(pins.pinFor(THEM)).toBeNull();
    expect(pins.all()).toHaveLength(1);
  });

  it('ignores unreadable records rather than quarantining them', async () => {
    // Unlike a private key, a pin is always re-derivable from the network.
    localStorage.setItem('saavi-pin-broken@example.org', '{not json');
    expect(pins.all()).toHaveLength(0);
    expect(pins.pinFor('broken@example.org')).toBeNull();
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
