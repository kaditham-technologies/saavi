// The ring bundle (docs/KEY-SYNC.md S0): the store as one versioned,
// self-describing, sealable unit. What these tests pin: nothing is ever
// silently dropped in either direction, a newer or tampered bundle is
// refused rather than guessed at, and the sealed envelope only opens with
// its secret.
import { describe, expect, it } from 'vitest';
import {
  BUNDLE_VERSION, bundleFromStore, hashRings, makeBundle, parseBundle,
  sealBundle, serialiseBundle, storeEntries, type BundleRing,
} from '../src/bundle';
import { STORE_PREFIX } from '../src/pgp';

const rec = (tag: string) => ({
  publicKey: `-----BEGIN PGP PUBLIC KEY BLOCK-----\n${tag}-pub`,
  privateKey: `-----BEGIN PGP PRIVATE KEY BLOCK-----\n${tag}-priv`,
  created: '2026-01-01T00:00:00.000Z',
});
const ring = (address: string, retired = 0): BundleRing => ({
  address,
  active: rec(address),
  retired: Array.from({ length: retired }, (_, i) => rec(`${address}-r${i}`)),
});

describe('bundle format', () => {
  it('round-trips through serialise and parse', async () => {
    const b = await makeBundle({
      rings: [ring('a@x.ie', 2), ring('b@y.ie')],
      alerts: [{ email: 'c@z.ie', at: 'then', quarantineKey: STORE_PREFIX + 'corrupt-c@z.ie-1' }],
      quarantined: [{ key: STORE_PREFIX + 'corrupt-c@z.ie-1', raw: '{broken' }],
      extras: { [STORE_PREFIX + 'future-thing']: 'kept' },
      pins: [],
    });
    const back = await parseBundle(serialiseBundle(b));
    expect(back).toEqual(b);
  });

  it('hashes rings the same regardless of listing order', async () => {
    const a = ring('a@x.ie', 1);
    const b = ring('b@y.ie');
    expect(await hashRings([a, b])).toBe(await hashRings([b, a]));
    const changed = { ...a, active: rec('other') };
    expect(await hashRings([changed, b])).not.toBe(await hashRings([a, b]));
  });

  it('refuses what it cannot vouch for', async () => {
    await expect(parseBundle('not json')).rejects.toThrow(/not readable/);
    await expect(parseBundle('{"format":"something-else"}')).rejects.toThrow(/not a Saavi ring bundle/);

    const b = await makeBundle({ rings: [ring('a@x.ie')], alerts: [], quarantined: [], extras: {}, pins: [] });
    const newer = { ...b, version: BUNDLE_VERSION + 1 };
    await expect(parseBundle(JSON.stringify(newer))).rejects.toThrow(/newer Saavi/);

    // A ring altered after hashing must fail the integrity self-check.
    const tampered = JSON.parse(serialiseBundle(b));
    tampered.rings[0].active.publicKey = 'substituted';
    await expect(parseBundle(JSON.stringify(tampered))).rejects.toThrow(/integrity/);

    const gutted = JSON.parse(serialiseBundle(b));
    gutted.rings[0].active.privateKey = '';
    await expect(parseBundle(JSON.stringify(gutted))).rejects.toThrow(/malformed/);
  });
});

describe('sealed envelope', () => {
  it('round-trips under its secret and refuses another', async () => {
    const { sealBundle: seal, unsealBundle: unseal } = await import('../src/bundle');
    const text = serialiseBundle(await makeBundle({ rings: [ring('a@x.ie')], alerts: [], quarantined: [], extras: {}, pins: [] }));
    const sealed = await seal(text, 'right-secret');
    expect(sealed).toContain('BEGIN PGP MESSAGE');
    expect(sealed).not.toContain('a@x.ie');
    expect(await unseal(sealed, 'right-secret')).toBe(text);
    await expect(unseal(sealed, 'wrong-secret')).rejects.toThrow();
  });
});

describe('store translation', () => {
  it('carries every kind of entry both ways, losing nothing', async () => {
    const entries: Record<string, string> = {
      [STORE_PREFIX + 'a@x.ie']: JSON.stringify({ active: rec('a@x.ie'), retired: [rec('a@x.ie-r0')] }),
      [STORE_PREFIX + 'alerts']: JSON.stringify([{ email: 'q@z.ie', at: 'then', quarantineKey: STORE_PREFIX + 'corrupt-q@z.ie-1' }]),
      [STORE_PREFIX + 'corrupt-q@z.ie-1']: '{broken',
      [STORE_PREFIX + 'unknown-marker']: 'kept verbatim',
    };
    const b = await bundleFromStore(entries);
    expect(b.rings).toHaveLength(1);
    expect(b.alerts).toHaveLength(1);
    expect(b.quarantined).toEqual([{ key: STORE_PREFIX + 'corrupt-q@z.ie-1', raw: '{broken' }]);
    expect(b.extras[STORE_PREFIX + 'unknown-marker']).toBe('kept verbatim');
    expect(storeEntries(b)).toEqual(entries);
  });

  it('adopts a v1 bare record as an active ring', async () => {
    const b = await bundleFromStore({ [STORE_PREFIX + 'old@x.ie']: JSON.stringify(rec('old@x.ie')) });
    expect(b.rings).toEqual([{ address: 'old@x.ie', active: rec('old@x.ie'), retired: [] }]);
  });

  it('keeps the active key when only a retired sibling is defective', async () => {
    const broken = { publicKey: 'PUB', privateKey: 'PRIV' }; // no `created`
    const b = await bundleFromStore({
      [STORE_PREFIX + 'a@x.ie']: JSON.stringify({ active: rec('a@x.ie'), retired: [rec('a@x.ie-r0'), broken] }),
    });
    // The ring survives with the records that hold…
    expect(b.rings).toEqual([{ address: 'a@x.ie', active: rec('a@x.ie'), retired: [rec('a@x.ie-r0')] }]);
    // …and the defective record is parked and flagged, not dropped.
    expect(b.quarantined).toHaveLength(1);
    expect(b.quarantined[0].raw).toBe(JSON.stringify(broken));
    expect(b.alerts).toHaveLength(1);
    expect(b.alerts[0].email).toBe('a@x.ie');
  });

  it('quarantines an unreadable ring instead of dropping it', async () => {
    const b = await bundleFromStore({ [STORE_PREFIX + 'bad@x.ie']: 'not a ring at all' });
    expect(b.rings).toHaveLength(0);
    expect(b.quarantined).toHaveLength(1);
    expect(b.quarantined[0].raw).toBe('not a ring at all');
    expect(b.alerts).toHaveLength(1);
    expect(b.alerts[0].email).toBe('bad@x.ie');
    // And the parked record survives the trip back to entries.
    expect(Object.values(storeEntries(b))).toContain('not a ring at all');
  });
});
