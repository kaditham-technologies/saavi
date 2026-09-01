// One store, on disk (docs/KEY-AGENT.md phase 0; docs/KEY-SYNC.md S0).
//
// In the shell, the keystore stops being webview localStorage and becomes a
// ring bundle (bundle.ts) sealed under a generated secret the OS keychain
// holds, written atomically by the shell (src-tauri/src/store.rs). pgp.ts
// is unchanged: it talks to a RingStore, and this module installs one whose
// reads are an in-memory mirror of the bundle and whose writes flush back
// to the sealed file.
//
// The rules, in order of importance:
//  - Destroying a private key is the one mistake that cannot be undone, so
//    the migration takes a backup and VERIFIES the backup opens before
//    writing anything, verifies the sealed store reads back before touching
//    localStorage, and only then removes the browser-held rings.
//  - When the store exists but cannot be opened (keychain refused, file
//    damaged), the answer is BLOCKED and loud — never a silently empty
//    keyring the user would "fix" by generating a second identity.
//  - A ring found in localStorage while a disk store exists (a key made
//    during a blocked spell, or a downgrade) is adopted if the disk store
//    has nothing for that address, and reported — never overwritten,
//    never dropped.
import * as pgp from './pgp';
import {
  bundleFromStore, parseBundle, parsesAsRing, sealBundle, serialiseBundle, storeEntries, unsealBundle,
} from './bundle';

export interface DiskIo {
  readStore(): Promise<string | null>;
  writeStore(contents: string): Promise<void>;
  writeBackup(contents: string): Promise<{ name: string; path: string }>;
  readBackup(name: string): Promise<string>;
  getSecret(): Promise<string | null>;
  setSecret(secret: string): Promise<void>;
}

export type DiskStatus =
  | { state: 'browser'; error?: string }
  | { state: 'disk'; migratedFrom?: 'browser'; backupPath?: string }
  /** `missingStore`: the keychain still holds a store secret but the store
   *  file is gone — a wiped store or a partial restore, NOT a fresh
   *  install. Opening a fresh store then needs an explicit user say-so
   *  (`acceptMissingStore`), never a silent default. */
  | { state: 'blocked'; reason: string; missingStore?: true };

/** A browser-held ring left alongside the disk store, exactly where it was:
 *  `differs` — the store holds different content for the same address;
 *  `unreadable` — the browser value does not parse as a ring, so adopting
 *  it would mean quarantining it behind the user's back. */
export interface CoexistAlert { address: string; storageKey: string; kind: 'differs' | 'unreadable' }

export interface DiskStore {
  status: DiskStatus;
  coexist: CoexistAlert[];
  /** Addresses whose browser-held rings were adopted into the disk store
   *  this boot — reported, per the design rule, never silent. */
  adopted: string[];
  /** Await the mirror's pending write, if any. Throws what the write threw. */
  flushNow(): Promise<void>;
}

const errMsg = (e: unknown): string => (e instanceof Error ? e.message : String(e));

function generateSecret(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...bytes));
}

const ringKeysOf = (s: pgp.RingStore): string[] =>
  s.keys().filter((k) => k.startsWith(pgp.STORE_PREFIX));

/** The RingStore pgp.ts gets: synchronous reads from a mirror, writes
 *  flushed to the sealed file. A failed flush retries and alarms — a write
 *  that silently fails is a generated key lost on quit. */
class Mirror implements pgp.RingStore {
  private flushing = false;
  private dirty = false;
  private hadError = false;
  private waiters: { resolve(): void; reject(e: Error): void }[] = [];

  constructor(
    private entries: Map<string, string>,
    private io: DiskIo,
    private secret: string,
    /** Called with a message when writes start failing, null when they recover. */
    private onFlushState: (message: string | null) => void,
    private retryMs = 15_000,
  ) {}

  get(key: string): string | null { return this.entries.get(key) ?? null; }
  keys(): string[] { return [...this.entries.keys()]; }
  set(key: string, value: string): void { this.entries.set(key, value); this.schedule(); }
  remove(key: string): void { this.entries.delete(key); this.schedule(); }

  private schedule(): void {
    this.dirty = true;
    if (!this.flushing) { this.flushing = true; void this.flush(); }
  }

  private async flush(): Promise<void> {
    while (this.dirty) {
      this.dirty = false;
      try {
        const bundle = await bundleFromStore(Object.fromEntries(this.entries));
        const sealed = await sealBundle(serialiseBundle(bundle), this.secret);
        await this.io.writeStore(sealed);
        if (this.hadError) { this.hadError = false; this.onFlushState(null); }
        if (!this.dirty) for (const w of this.waiters.splice(0)) w.resolve();
      } catch (e) {
        // The mirror still holds everything; keep retrying, alarm once per
        // streak, and let anyone waiting learn the outcome now — not after
        // a retry that may never succeed.
        this.dirty = true;
        if (!this.hadError) this.onFlushState(errMsg(e));
        this.hadError = true;
        const err = e instanceof Error ? e : new Error(String(e));
        for (const w of this.waiters.splice(0)) w.reject(err);
        await new Promise((r) => setTimeout(r, this.retryMs));
      }
    }
    this.flushing = false;
  }

  /** Resolves when the current changes are on disk; rejects on the first
   *  failed attempt (retries continue in the background regardless). */
  settle(): Promise<void> {
    if (!this.flushing && !this.dirty) return Promise.resolve();
    return new Promise((resolve, reject) => this.waiters.push({ resolve, reject }));
  }
}

const ALERTS_KEY = pgp.STORE_PREFIX + 'alerts';

/** Adopt browser-held store entries the disk store has no entry for; report
 *  every adoption and every conflict. Local copies are removed only once
 *  the disk provably holds them — a failed flush leaves them in place. */
async function reconcile(mirror: Mirror, local: pgp.RingStore): Promise<{ coexist: CoexistAlert[]; adopted: string[] }> {
  const coexist: CoexistAlert[] = [];
  const adoptedKeys: string[] = [];
  const adopted: string[] = [];
  for (const key of ringKeysOf(local)) {
    const localValue = local.get(key);
    if (localValue === null) continue;
    const held = mirror.get(key);
    if (held === localValue) { local.remove(key); continue; }
    const tail = key.slice(pgp.STORE_PREFIX.length);
    const isAddress = tail.includes('@') && !tail.startsWith('corrupt-');
    if (key === ALERTS_KEY) {
      // Alarm lists merge (union by quarantine key) — they are not rings
      // and must never render as "a keyring for alerts".
      try {
        const localAlerts = JSON.parse(localValue) as pgp.StoreAlert[];
        const heldAlerts = held ? (JSON.parse(held) as pgp.StoreAlert[]) : [];
        if (!Array.isArray(localAlerts)) continue;
        const seen = new Set(heldAlerts.map((a) => a.quarantineKey));
        const merged = [...heldAlerts, ...localAlerts.filter((a) => !seen.has(a.quarantineKey))];
        mirror.set(key, JSON.stringify(merged));
        adoptedKeys.push(key);
      } catch { /* unreadable local alerts list — left in place, harmless */ }
      continue;
    }
    if (held !== null) {
      // Never overwritten, and for rings: reported.
      if (isAddress) coexist.push({ address: tail, storageKey: key, kind: 'differs' });
      continue;
    }
    if (isAddress && !parsesAsRing(localValue)) {
      // Adopting this would silently quarantine it inside the bundle while
      // the mirror kept the original — report it and leave it where it is.
      coexist.push({ address: tail, storageKey: key, kind: 'unreadable' });
      continue;
    }
    mirror.set(key, localValue);
    adoptedKeys.push(key);
    if (isAddress) adopted.push(tail);
  }
  if (adoptedKeys.length) {
    try {
      await mirror.settle();
      for (const key of adoptedKeys) local.remove(key);
    } catch { /* browser copies kept — nothing lost; the flush alarm is already up */ }
  }
  return { coexist, adopted };
}

/** Round-trip proof that the OS keychain actually persists the secret —
 *  before the store is sealed under it. */
async function ensureSecret(io: DiskIo): Promise<string> {
  const existing = await io.getSecret();
  if (existing) return existing;
  const secret = generateSecret();
  await io.setSecret(secret);
  if ((await io.getSecret()) !== secret) {
    throw new Error('The OS keychain did not keep the store secret.');
  }
  return secret;
}

async function writeVerified(io: DiskIo, serialised: string, secret: string): Promise<void> {
  const wanted = await parseBundle(serialised);
  await io.writeStore(await sealBundle(serialised, secret));
  const readBack = await io.readStore();
  if (readBack === null) throw new Error('The key store did not read back after writing.');
  const got = await parseBundle(await unsealBundle(readBack, secret));
  if (got.hash !== wanted.hash) throw new Error('The key store read back different from what was written.');
}

/**
 * Open (or create, or migrate to) the sealed disk store, and install it as
 * pgp.ts's backend. On 'browser' and 'blocked' the backend is left on
 * localStorage — with 'blocked' the caller must say so, loudly.
 */
export async function initDiskStore(
  io: DiskIo,
  onFlushState: (message: string | null) => void,
  local: pgp.RingStore = pgp.localRingStore,
  retryMs?: number,
  opts?: { acceptMissingStore?: boolean },
): Promise<DiskStore> {
  // A throwing UI callback must never kill the flush loop (it would leave
  // `flushing` latched true and every later write a silent no-op).
  const notify = (m: string | null): void => { try { onFlushState(m); } catch { /* UI's problem, not the store's */ } };
  const store = (
    status: DiskStatus, mirror?: Mirror,
    found: { coexist: CoexistAlert[]; adopted: string[] } = { coexist: [], adopted: [] },
  ): DiskStore => ({
    status, ...found, flushNow: () => mirror?.settle() ?? Promise.resolve(),
  });

  let existing: string | null;
  try { existing = await io.readStore(); } catch (e) {
    return store({ state: 'blocked', reason: errMsg(e) });
  }

  if (existing !== null) {
    let secret: string | null;
    try { secret = await io.getSecret(); } catch (e) {
      return store({ state: 'blocked', reason: `The OS keychain would not answer: ${errMsg(e)}` });
    }
    if (!secret) {
      return store({
        state: 'blocked',
        reason: 'A key store exists on disk but the OS keychain holds no secret for it. Restore the keychain entry or re-import your key backups; the store file was left untouched.',
      });
    }
    let entries: Record<string, string>;
    try {
      entries = storeEntries(await parseBundle(await unsealBundle(existing, secret)));
    } catch (e) {
      return store({ state: 'blocked', reason: errMsg(e) });
    }
    const mirror = new Mirror(new Map(Object.entries(entries)), io, secret, notify, retryMs);
    const found = await reconcile(mirror, local);
    pgp.setRingStore(mirror);
    return store({ state: 'disk' }, mirror, found);
  }

  // No store file. A surviving store secret says this is NOT a fresh
  // install — it is a wiped store, a partial restore, or a reinstall over
  // surviving credentials. Writing a verified empty store here would
  // present exactly the "fresh keyring" a wiped store must never become,
  // so it takes an explicit user decision to proceed.
  if (!opts?.acceptMissingStore) {
    const orphan = await io.getSecret().catch(() => null);
    if (orphan) {
      return store({
        state: 'blocked', missingStore: true,
        reason: 'The OS keychain holds a key-store secret, but no store file was found — a previous store existed on this machine and is gone. Restore the file from a backup, or choose to start over.',
      });
    }
  }

  // Migrate what the webview holds, or start fresh.
  const localKeys = ringKeysOf(local);
  const migrating = localKeys.length > 0;
  let backupPath: string | undefined;
  try {
    const entries: Record<string, string> = {};
    for (const k of localKeys) { const v = local.get(k); if (v !== null) entries[k] = v; }
    const serialised = serialiseBundle(await bundleFromStore(entries));

    if (migrating) {
      // Backup first, and prove the backup opens before writing anything new.
      const backup = await io.writeBackup(serialised);
      backupPath = backup.path;
      const wanted = await parseBundle(serialised);
      const got = await parseBundle(await io.readBackup(backup.name));
      if (got.hash !== wanted.hash) throw new Error('The migration backup did not read back intact.');
    }

    const secret = await ensureSecret(io);
    await writeVerified(io, serialised, secret);

    // Only now — the sealed store is proven readable — clear the webview copy.
    for (const k of localKeys) local.remove(k);

    const mirror = new Mirror(
      new Map(Object.entries(storeEntries(await parseBundle(serialised)))),
      io, secret, notify, retryMs,
    );
    pgp.setRingStore(mirror);
    return store(
      migrating ? { state: 'disk', migratedFrom: 'browser', backupPath } : { state: 'disk' },
      mirror,
    );
  } catch (e) {
    // Nothing was removed unless the store verified; localStorage still rules.
    return store({ state: 'browser', error: `${migrating ? 'Moving your keys to disk storage failed' : 'Creating the disk key store failed'}: ${errMsg(e)}` });
  }
}

// ---------- the real shell IO ----------

async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  const { invoke } = await import('@tauri-apps/api/core');
  return invoke<T>(cmd, args);
}

export const shellIo: DiskIo = {
  readStore: () => call('store_read'),
  writeStore: (contents) => call('store_write', { contents }),
  writeBackup: (contents) => call('store_backup_write', { contents }),
  readBackup: (name) => call('store_backup_read', { name }),
  getSecret: () => call('keychain_store_secret_get'),
  setSecret: (secret) => call('keychain_store_secret_set', { secret }),
};
