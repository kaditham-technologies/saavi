// The sealed disk store (docs/KEY-AGENT.md phase 0). What these tests pin:
// the migration removes nothing until both the backup and the sealed store
// have been read back and verified; an unopenable store is BLOCKED, never
// silently empty; browser-held rings found beside a disk store are adopted
// or reported, never overwritten; and a failing flush alarms, retries, and
// loses nothing.
import { beforeEach, describe, expect, it } from 'vitest';
import * as pgp from '../src/pgp';
import { bundleFromStore, sealBundle, serialiseBundle, unsealBundle, parseBundle } from '../src/bundle';
import { initDiskStore, type DiskIo } from '../src/diskstore';

const P = pgp.STORE_PREFIX;
const rec = (tag: string) => ({
  publicKey: `-----BEGIN PGP PUBLIC KEY BLOCK-----\n${tag}-pub`,
  privateKey: `-----BEGIN PGP PRIVATE KEY BLOCK-----\n${tag}-priv`,
  created: '2026-01-01T00:00:00.000Z',
});
const ringJson = (tag: string) => JSON.stringify({ active: rec(tag), retired: [] });

interface FakeState { store: string | null; secret: string | null; backups: Map<string, string> }
function fakeIo(init?: Partial<FakeState>): { io: DiskIo; state: FakeState } {
  const state: FakeState = { store: init?.store ?? null, secret: init?.secret ?? null, backups: init?.backups ?? new Map() };
  const io: DiskIo = {
    readStore: async () => state.store,
    writeStore: async (c) => { state.store = c; },
    writeBackup: async (c) => {
      const name = `ring-backup-${state.backups.size + 1}.json`;
      state.backups.set(name, c);
      return { name, path: `/data/${name}` };
    },
    readBackup: async (n) => {
      const v = state.backups.get(n);
      if (v === undefined) throw new Error('no such backup');
      return v;
    },
    getSecret: async () => state.secret,
    setSecret: async (s) => { state.secret = s; },
  };
  return { io, state };
}

async function sealedStoreWith(entries: Record<string, string>, secret: string): Promise<string> {
  return sealBundle(serialiseBundle(await bundleFromStore(entries)), secret);
}

const flushStates: (string | null)[] = [];
const onFlush = (m: string | null): void => { flushStates.push(m); };

beforeEach(() => {
  localStorage.clear();
  pgp.setRingStore(pgp.localRingStore);
  flushStates.length = 0;
});

describe('fresh install', () => {
  it('creates a secret and a verified empty store', async () => {
    const { io, state } = fakeIo();
    const ds = await initDiskStore(io, onFlush);
    expect(ds.status).toEqual({ state: 'disk' });
    expect(state.secret).not.toBeNull();
    const b = await parseBundle(await unsealBundle(state.store!, state.secret!));
    expect(b.rings).toEqual([]);
  });

  it('stays on browser storage when the keychain will not keep the secret', async () => {
    const { io } = fakeIo();
    io.getSecret = async () => null; // never persists
    localStorage.setItem(P + 'a@x.ie', ringJson('a@x.ie'));
    const ds = await initDiskStore(io, onFlush);
    expect(ds.status.state).toBe('browser');
    expect(ds.status.state === 'browser' && ds.status.error).toMatch(/keychain/i);
    expect(localStorage.getItem(P + 'a@x.ie')).toBe(ringJson('a@x.ie'));
    expect(pgp.ringAddresses()).toEqual(['a@x.ie']); // still served from localStorage
  });
});

describe('migration', () => {
  it('moves rings only after backup and store both verify, then clears the browser copy', async () => {
    localStorage.setItem(P + 'a@x.ie', ringJson('a@x.ie'));
    localStorage.setItem(P + 'alerts', JSON.stringify([{ email: 'q@z.ie', at: 'then', quarantineKey: P + 'corrupt-q@z.ie-1' }]));
    localStorage.setItem(P + 'corrupt-q@z.ie-1', '{broken');
    localStorage.setItem('saavi-theme', 'paper'); // not ours; must survive
    const { io, state } = fakeIo();
    const ds = await initDiskStore(io, onFlush);

    expect(ds.status).toEqual({ state: 'disk', migratedFrom: 'browser', backupPath: '/data/ring-backup-1.json' });
    expect(state.backups.size).toBe(1);
    const stored = await parseBundle(await unsealBundle(state.store!, state.secret!));
    expect(stored.rings.map((r) => r.address)).toEqual(['a@x.ie']);
    expect(stored.quarantined).toHaveLength(1);
    // The browser copy is gone, the unrelated key is not, and reads now
    // come from the mirror.
    expect(localStorage.getItem(P + 'a@x.ie')).toBeNull();
    expect(localStorage.getItem(P + 'corrupt-q@z.ie-1')).toBeNull();
    expect(localStorage.getItem('saavi-theme')).toBe('paper');
    expect(pgp.ringAddresses()).toEqual(['a@x.ie']);
    expect(pgp.storeAlerts()).toHaveLength(1);
  });

  it('aborts untouched when the backup does not read back intact', async () => {
    localStorage.setItem(P + 'a@x.ie', ringJson('a@x.ie'));
    const { io, state } = fakeIo();
    io.readBackup = async () => 'garbage';
    const ds = await initDiskStore(io, onFlush);
    expect(ds.status.state).toBe('browser');
    expect(state.store).toBeNull(); // nothing was written past the failed proof
    expect(localStorage.getItem(P + 'a@x.ie')).toBe(ringJson('a@x.ie'));
  });

  it('aborts untouched when the sealed store does not read back', async () => {
    localStorage.setItem(P + 'a@x.ie', ringJson('a@x.ie'));
    const { io } = fakeIo();
    io.readStore = async () => null; // exists-check passes, read-back proof fails
    const ds = await initDiskStore(io, onFlush);
    expect(ds.status.state).toBe('browser');
    expect(localStorage.getItem(P + 'a@x.ie')).toBe(ringJson('a@x.ie'));
  });
});

describe('opening an existing store', () => {
  it('serves rings from the mirror and flushes changes back sealed', async () => {
    const { io, state } = fakeIo({ secret: 's3cret' });
    state.store = await sealedStoreWith({
      [P + 'a@x.ie']: ringJson('a@x.ie'),
      [P + 'alerts']: JSON.stringify([{ email: 'q@z.ie', at: 'then', quarantineKey: P + 'corrupt-q@z.ie-1' }]),
      [P + 'corrupt-q@z.ie-1']: '{broken',
    }, 's3cret');
    const ds = await initDiskStore(io, onFlush);
    expect(ds.status).toEqual({ state: 'disk' });
    expect(pgp.ringAddresses()).toEqual(['a@x.ie']);

    // A write through pgp.ts must land in the sealed file.
    pgp.dismissStoreAlert(P + 'corrupt-q@z.ie-1');
    await ds.flushNow();
    const after = await parseBundle(await unsealBundle(state.store!, 's3cret'));
    expect(after.alerts).toEqual([]);
    expect(after.quarantined).toHaveLength(1); // dismissing the alarm never drops the parked record
  });

  it('is BLOCKED when the secret is gone, and touches nothing', async () => {
    const { io, state } = fakeIo();
    state.store = await sealedStoreWith({ [P + 'a@x.ie']: ringJson('a@x.ie') }, 'lost');
    const before = state.store;
    localStorage.setItem(P + 'b@y.ie', ringJson('b@y.ie'));
    const ds = await initDiskStore(io, onFlush);
    expect(ds.status.state).toBe('blocked');
    expect(state.store).toBe(before);
    expect(localStorage.getItem(P + 'b@y.ie')).toBe(ringJson('b@y.ie'));
    expect(pgp.ringAddresses()).toEqual(['b@y.ie']); // localStorage still rules
  });

  it('is BLOCKED when the store will not unseal', async () => {
    const { io, state } = fakeIo({ secret: 'right', store: 'not an armored message' });
    const ds = await initDiskStore(io, onFlush);
    expect(ds.status.state).toBe('blocked');
    expect(state.store).toBe('not an armored message');
  });

  it('is BLOCKED — not a fresh keyring — when the file is gone but the secret survives', async () => {
    // The wiped-store / evil-maid case: a secret with no file is a store
    // that EXISTED. Writing a verified empty store here would invite the
    // user to mint a second identity.
    const { io, state } = fakeIo({ secret: 'survivor' });
    const ds = await initDiskStore(io, onFlush);
    expect(ds.status.state).toBe('blocked');
    expect(ds.status.state === 'blocked' && ds.status.missingStore).toBe(true);
    expect(state.store).toBeNull(); // nothing written

    // Starting over is an explicit decision, not a default.
    const fresh = await initDiskStore(io, onFlush, pgp.localRingStore, undefined, { acceptMissingStore: true });
    expect(fresh.status).toEqual({ state: 'disk' });
    expect(state.store).not.toBeNull();
  });

  it('merges browser-held alarm lists instead of reporting "a keyring for alerts"', async () => {
    const { io, state } = fakeIo({ secret: 's3cret' });
    state.store = await sealedStoreWith({
      [P + 'alerts']: JSON.stringify([{ email: 'a@x.ie', at: 'then', quarantineKey: P + 'corrupt-a@x.ie-1' }]),
      [P + 'corrupt-a@x.ie-1']: '{broken',
    }, 's3cret');
    localStorage.setItem(P + 'alerts', JSON.stringify([{ email: 'b@y.ie', at: 'later', quarantineKey: P + 'corrupt-b@y.ie-2' }]));
    localStorage.setItem(P + 'corrupt-b@y.ie-2', '{also broken');
    const ds = await initDiskStore(io, onFlush);
    expect(ds.coexist).toEqual([]);
    expect(pgp.storeAlerts().map((a) => a.quarantineKey).sort())
      .toEqual([P + 'corrupt-a@x.ie-1', P + 'corrupt-b@y.ie-2']);
    expect(localStorage.getItem(P + 'alerts')).toBeNull();
    expect(localStorage.getItem(P + 'corrupt-b@y.ie-2')).toBeNull(); // parked record adopted too
  });

  it('reports an unreadable browser ring instead of quarantining it behind the user’s back', async () => {
    const { io, state } = fakeIo({ secret: 's3cret' });
    state.store = await sealedStoreWith({ [P + 'a@x.ie']: ringJson('a@x.ie') }, 's3cret');
    localStorage.setItem(P + 'b@y.ie', 'not a ring at all');
    const ds = await initDiskStore(io, onFlush);
    expect(ds.coexist).toEqual([{ address: 'b@y.ie', storageKey: P + 'b@y.ie', kind: 'unreadable' }]);
    expect(ds.adopted).toEqual([]);
    expect(localStorage.getItem(P + 'b@y.ie')).toBe('not a ring at all');
    const after = await parseBundle(await unsealBundle(state.store!, 's3cret'));
    expect(after.rings.map((r) => r.address)).toEqual(['a@x.ie']);
  });

  it('keeps the coexist report and the browser copies when the adoption flush fails', async () => {
    const { io, state } = fakeIo({ secret: 's3cret' });
    state.store = await sealedStoreWith({ [P + 'a@x.ie']: ringJson('a@x.ie') }, 's3cret');
    localStorage.setItem(P + 'a@x.ie', ringJson('a@x.ie-DIFFERENT'));
    localStorage.setItem(P + 'b@y.ie', ringJson('b@y.ie'));
    io.writeStore = async () => { throw new Error('disk full'); };
    const ds = await initDiskStore(io, onFlush, pgp.localRingStore, 60_000);
    // The conflict report survives the write failure…
    expect(ds.coexist).toEqual([{ address: 'a@x.ie', storageKey: P + 'a@x.ie', kind: 'differs' }]);
    // …and the adopted ring's browser copy is NOT removed: disk never held it.
    expect(localStorage.getItem(P + 'b@y.ie')).toBe(ringJson('b@y.ie'));
    expect(flushStates).toEqual(['disk full']);
  });

  it('adopts a browser ring the store lacks and reports one it holds differently', async () => {
    const { io, state } = fakeIo({ secret: 's3cret' });
    state.store = await sealedStoreWith({ [P + 'a@x.ie']: ringJson('a@x.ie') }, 's3cret');
    localStorage.setItem(P + 'a@x.ie', ringJson('a@x.ie-DIFFERENT'));
    localStorage.setItem(P + 'b@y.ie', ringJson('b@y.ie'));
    const ds = await initDiskStore(io, onFlush);

    expect(ds.coexist).toEqual([{ address: 'a@x.ie', storageKey: P + 'a@x.ie', kind: 'differs' }]);
    expect(ds.adopted).toEqual(['b@y.ie']); // adoption is REPORTED, never silent
    // The differing ring was left exactly where it was; the new one moved.
    expect(localStorage.getItem(P + 'a@x.ie')).toBe(ringJson('a@x.ie-DIFFERENT'));
    expect(localStorage.getItem(P + 'b@y.ie')).toBeNull();
    const after = await parseBundle(await unsealBundle(state.store!, 's3cret'));
    expect(after.rings.map((r) => r.address).sort()).toEqual(['a@x.ie', 'b@y.ie']);
    expect(after.rings.find((r) => r.address === 'a@x.ie')?.active).toEqual(rec('a@x.ie')); // never overwritten
  });
});

describe('a failing flush', () => {
  it('alarms once, keeps the change in memory, retries, and reports recovery', async () => {
    const { io, state } = fakeIo({ secret: 's3cret' });
    state.store = await sealedStoreWith({
      [P + 'alerts']: JSON.stringify([{ email: 'q@z.ie', at: 'then', quarantineKey: P + 'corrupt-1' }]),
      [P + 'corrupt-1']: '{broken',
    }, 's3cret');
    const goodWrite = io.writeStore;
    let broken = true;
    io.writeStore = async (c) => { if (broken) throw new Error('disk full'); await goodWrite(c); };

    const ds = await initDiskStore(io, onFlush, pgp.localRingStore, 20);
    pgp.dismissStoreAlert(P + 'corrupt-1');
    await expect(ds.flushNow()).rejects.toThrow('disk full');
    expect(flushStates).toEqual(['disk full']);
    expect(pgp.storeAlerts()).toEqual([]); // the mirror kept the change

    broken = false;
    await new Promise((r) => setTimeout(r, 120)); // let a retry land
    expect(flushStates).toEqual(['disk full', null]);
    const after = await parseBundle(await unsealBundle(state.store!, 's3cret'));
    expect(after.alerts).toEqual([]);
  });
});
