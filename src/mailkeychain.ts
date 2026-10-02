// The Saavi keychain — one keyring across every device.
//
// The private keys in pgp.ts's store are armored and passphrase-locked
// (OpenPGP S2K); nothing readable ever leaves this device. This module ships
// that locked store to the broker as an opaque blob and pulls it back on a
// new device, where the user's passphrase — which the server never sees —
// is what opens it. The server holds ciphertext and a version number.
//
// THE TRUST BOUNDARY (cerberus V1/V2): the broker, or anyone holding a
// session, can hand this device any blob it likes. So a record's public half
// is NEVER trusted — it is derived from the private half on the way in
// (bindRecord). An attacker cannot forge that without a private key locked to
// a passphrase the victim will type, and the passphrase is proven against
// EVERY installed active key before any of them is kept. A substituted public
// key would therefore have to come with a private key the victim can unlock —
// which the attacker does not have.
//
// Sync policy, deliberately narrow:
//   - PUSH after local key events and at sign-in (rings-hash guarded, so an
//     unchanged store costs one comparison and no request).
//   - PULL only in the explicit restore ceremony. The 409 merge path adopts
//     no key material without proof — it unions fingerprints for the push and
//     leaves adoption to restore() (cerberus V7).
//   - A push never SHRINKS the ring set: a transient identity-load failure
//     must not delete an alias's keys from everyone's keychain (argus #2).
//
// Core since 2026-10-02 (Saavi 0.6.0, docs/ACCOUNT-SIGNIN.md): the webmail
// vendors this file as src/keychain.ts. Two seams keep it host-neutral —
// './server' (apiUrl/netFetch: same-origin fetch in the webmail, the Tauri
// http client in Saavi) and pgp.installRing/uninstallRing, which write
// through whichever RingStore the host installed. Change it HERE.
import * as openpgp from 'openpgp';
import * as pgp from './pgp';
import { canonicalRecoveryPhrase } from './passphrase';
import { apiUrl, netFetch } from './server';

/** One phrase-locked armor: the private key re-locked under the recovery
 *  phrase. `created` rides along so a restored record keeps its date. */
export interface EnvKey { armor: string; created: string }

/** The recovery kit's escrow envelope (ZERO-ACCESS.md "The recovery kit",
 *  Saavi KEY-SYNC.md's escrow wrapping): the account's private keys
 *  re-locked under the CSPRNG recovery phrase, so the phrase alone — never
 *  the password — recovers the ring after a reset. Public halves are NOT
 *  stored: they are derived from the private armor on open, the same
 *  bindRecord rule the rings live by. */
export interface KitEnvelope {
  createdAt: string;
  keys: Record<string, { active: EnvKey; retired: EnvKey[] }>;
}

export interface KeychainBlob {
  /** v2 adds `envelopes` and is a HARD bump: a v1 client refuses the whole
   *  blob (the honest wedge — its field whitelist would silently strip the
   *  envelopes and re-push without them, D7). A blob without envelopes is
   *  still written as v1, so kit-less accounts keep old devices working. */
  v: 1 | 2;
  exportedAt: string;
  rings: Record<string, pgp.KeyRing>;
  envelopes: Record<string, KitEnvelope>;
}

export interface KeychainStatus { exists: boolean; version: number; updatedAt: string | null }

// Same pattern as directory.useAuth: main.ts hands over the live session
// header once; before sign-in it throws and callers treat that as signed out.
let authHeader: () => string = () => '';
export function useAuth(fn: () => string): void { authHeader = fn; }

// The keychain data routes demand proof of the account secret alongside the
// bearer, because Stalwart mints a full bearer from any app password —
// scope ignored — so "interactive session" was never provable from the
// token alone (ZERO-ACCESS.md M0, P6). main.ts hands over auth.sessionSecret;
// a resumed session holds null, and sync then DEFERS (the password returns
// at the next fresh sign-in) while restore says to sign in again.
let secretProof: () => string | null = () => null;
export function useProof(fn: () => string | null): void { secretProof = fn; }

/** A stable per-device token, minted once and kept in localStorage. The
 *  broker marks a device "familiar" by this rather than by ip+ua, so a
 *  same-NAT attacker with the same browser is still a novel device and the
 *  download alarm fires (cerberus V5). Not a secret — an identifier. */
function deviceId(): string {
  let id = localStorage.getItem('kad-device-id');
  if (!id) {
    id = (crypto.randomUUID?.() ?? [...crypto.getRandomValues(new Uint8Array(16))].map((b) => b.toString(16).padStart(2, '0')).join(''));
    try { localStorage.setItem('kad-device-id', id); } catch { /* private mode — a per-session id is still better than none */ }
  }
  return id;
}
// What this device calls itself in the account's device list ("Saavi on
// macOS"). Self-reported and unverified — a label, not an identity; the
// broker falls back to a coarse browser-on-OS label from the User-Agent.
let deviceName: () => string = () => '';
export function useDeviceName(fn: () => string): void { deviceName = fn; }

function hdrs(json = false): Record<string, string> {
  const h: Record<string, string> = { Authorization: authHeader(), 'X-Device-Id': deviceId() };
  const name = deviceName().replace(/[^\x20-\x7e]/g, '').slice(0, 60);
  if (name) h['X-Device-Name'] = name;
  if (json) h['Content-Type'] = 'application/json';
  return h;
}

// A blob the server returns is not ours until proven — cap it before parsing
// so a hostile broker cannot wedge the tab with a multi-megabyte armor. Same
// ceiling the push side enforces. Raised for v2 (M5): an envelope carries a
// phrase-locked copy of the armors, so a kitted RSA-4096 multi-alias chain
// roughly doubles — the old 256 KiB cap would meet the 413 path.
const MAX_BLOB_BYTES = 393216;

/** Records per ring, active included (C4): caps the restore proof sweep an
 *  attacker-stuffed blob could force (~1s of Argon2 per record on a phone).
 *  The signed purge keeps honest rings far below it. Broker enforces the
 *  same number. */
const MAX_RING_RECORDS = 16;

// ---------------------------------------------------------------- pure core
// (exported for tests/keychain.test.ts — no storage, no network)

const ARMOR_PRIV = '-----BEGIN PGP PRIVATE KEY BLOCK-----';
const ARMOR_PUB = '-----BEGIN PGP PUBLIC KEY BLOCK-----';

function isRecord(r: unknown): r is pgp.KeyRecord {
  return !!r && typeof r === 'object'
    && typeof (r as pgp.KeyRecord).publicKey === 'string' && (r as pgp.KeyRecord).publicKey.includes(ARMOR_PUB)
    && typeof (r as pgp.KeyRecord).privateKey === 'string' && (r as pgp.KeyRecord).privateKey.includes(ARMOR_PRIV)
    && typeof (r as pgp.KeyRecord).created === 'string';
}

/** Parse and validate a blob string. Throws on anything that is not exactly
 *  the shape this module writes — a keychain is the last place to be
 *  liberal in what you accept. Only the four known fields are carried
 *  forward, so an attacker-supplied extra property cannot ride into the
 *  local store. */
function isEnvKey(k: unknown): k is EnvKey {
  return !!k && typeof k === 'object'
    && typeof (k as EnvKey).armor === 'string' && (k as EnvKey).armor.includes(ARMOR_PRIV)
    && typeof (k as EnvKey).created === 'string';
}

export function parseBlob(s: string): KeychainBlob {
  if (s.length > MAX_BLOB_BYTES) throw new Error('The keychain could not be read.');
  let parsed: unknown;
  try { parsed = JSON.parse(s); } catch { throw new Error('The keychain could not be read.'); }
  const b = parsed as KeychainBlob;
  // v1 and v2 exactly; anything else hard-fails — an unknown version is a
  // newer client's work and stripping what we don't understand would
  // destroy it on the next push (D7).
  if (!b || typeof b !== 'object' || (b.v !== 1 && b.v !== 2) || !b.rings || typeof b.rings !== 'object' || Array.isArray(b.rings)) {
    throw new Error('The keychain could not be read.');
  }
  const clean = (rec: pgp.KeyRecord): pgp.KeyRecord => ({
    publicKey: rec.publicKey,
    privateKey: rec.privateKey,
    created: rec.created,
    ...(typeof rec.revocationCertificate === 'string' ? { revocationCertificate: rec.revocationCertificate } : {}),
    // The lock epoch is attacker-writable data (C4): carried only as a
    // bounded non-negative integer; the broker additionally bounds it by
    // its version counter, so no MAX_SAFE_INTEGER pin can stick.
    ...(typeof rec.lockEpoch === 'number' && Number.isInteger(rec.lockEpoch) && rec.lockEpoch >= 0 && rec.lockEpoch <= 1_000_000
      ? { lockEpoch: rec.lockEpoch } : {}),
  });
  const rings: Record<string, pgp.KeyRing> = {};
  for (const [email, ring] of Object.entries(b.rings)) {
    if (!/^[^\s@]+@[^\s@]+$/.test(email)) throw new Error('The keychain could not be read.');
    if (!ring || typeof ring !== 'object' || !isRecord(ring.active) || !Array.isArray(ring.retired) || !ring.retired.every(isRecord)) {
      throw new Error('The keychain could not be read.');
    }
    // Records per ring are capped (C4): an attacker-stuffed ring would
    // otherwise turn restore's per-record passphrase proof into hundreds
    // of Argon2 trials and crash a restoring phone. Purge keeps honest
    // rings far below this.
    if (ring.retired.length > MAX_RING_RECORDS - 1) throw new Error('The keychain could not be read.');
    rings[email] = { active: clean(ring.active), retired: ring.retired.map(clean) };
  }
  const envelopes: Record<string, KitEnvelope> = {};
  if (b.v === 2) {
    if (!b.envelopes || typeof b.envelopes !== 'object' || Array.isArray(b.envelopes)) {
      throw new Error('The keychain could not be read.');
    }
    for (const [id, env] of Object.entries(b.envelopes)) {
      if (!/^[a-f0-9]{16,64}$/.test(id)) throw new Error('The keychain could not be read.');
      if (!env || typeof env !== 'object' || typeof env.createdAt !== 'string'
        || !env.keys || typeof env.keys !== 'object' || Array.isArray(env.keys)) {
        throw new Error('The keychain could not be read.');
      }
      const keys: KitEnvelope['keys'] = {};
      for (const [email, entry] of Object.entries(env.keys)) {
        if (!/^[^\s@]+@[^\s@]+$/.test(email)) throw new Error('The keychain could not be read.');
        if (!entry || typeof entry !== 'object' || !isEnvKey(entry.active)
          || !Array.isArray(entry.retired) || !entry.retired.every(isEnvKey)) {
          throw new Error('The keychain could not be read.');
        }
        keys[email] = {
          active: { armor: entry.active.armor, created: entry.active.created },
          retired: entry.retired.map((k) => ({ armor: k.armor, created: k.created })),
        };
      }
      envelopes[id] = { createdAt: env.createdAt, keys };
    }
  }
  return { v: b.v, exportedAt: typeof b.exportedAt === 'string' ? b.exportedAt : new Date().toISOString(), rings, envelopes };
}

/**
 * Union-merge two ring sets for a push conflict. The local ACTIVE KEY wins
 * for an address both sides know (this device is the one the human is at —
 * and rotation order, never epoch, picks the key: P2) — UNLESS the other
 * side already holds that KEY as retired (in any lock): then another device
 * moved on, and this one is stale. Letting it win is how a webmail 0.3.0 tab
 * left open pushed an account's retired key back in front (2026-09-30, v6);
 * the broker now refuses such a push, and this keeps the merge from making
 * it. `named` (the server's current key per address, most authoritative
 * first) settles it first when it names either side's key — so a healthy
 * device facing an already rolled-back blob keeps the right key in front
 * instead of agreeing with the rollback. Every armor the
 * other side has that we lack — its active included — survives as retired,
 * so mail sealed to it stays openable everywhere. The union is by ARMOR,
 * not by fingerprint: the same key under two locks is two armors, and
 * dropping either would trip the broker's multiset guard forever (the
 * post-purge stale-device wedge). Then A1: among the armors carrying the
 * active KEY, the highest lockEpoch becomes the blob's active — ties break
 * on the lowest armor hash, so two devices agree without a ping-pong — and
 * a device offline through a password change still puts the NEW lock in
 * front of every other device. Local stores adopt nothing here (V7).
 */
export async function mergeRings(
  local: Record<string, pgp.KeyRing>,
  remote: Record<string, pgp.KeyRing>,
  fprOf: (rec: pgp.KeyRecord) => Promise<string>,
  named: Record<string, string[]> = {}
): Promise<Record<string, pgp.KeyRing>> {
  const norm = (r: pgp.KeyRecord): string => r.privateKey.replace(/\r\n/g, '\n').trim();
  const out: Record<string, pgp.KeyRing> = {};
  for (const [email, ring] of Object.entries(local)) {
    out[email] = { active: ring.active, retired: [...ring.retired] };
  }
  for (const [email, theirs] of Object.entries(remote)) {
    const mine = out[email];
    if (!mine) { out[email] = { active: theirs.active, retired: [...theirs.retired] }; continue; }
    const have = new Set([mine.active, ...mine.retired].map(norm));
    for (const rec of [theirs.active, ...theirs.retired]) {
      const a = norm(rec);
      if (!have.has(a)) { mine.retired.push(rec); have.add(a); }
    }
    const mineFpr = await fprOf(mine.active).catch(() => '');
    const theirFpr = await fprOf(theirs.active).catch(() => '');
    if (mineFpr && theirFpr && mineFpr !== theirFpr) {
      const rank = (named[email] ?? []).map((f) => f.toLowerCase());
      const top = rank.find((f) => f === mineFpr || f === theirFpr);
      let theirsWin: boolean;
      if (top) theirsWin = top === theirFpr;
      else {
        theirsWin = false;
        for (const r of theirs.retired) {
          if (await fprOf(r).catch(() => '') === mineFpr) { theirsWin = true; break; }
        }
      }
      if (theirsWin) {
        const pool = [mine.active, ...mine.retired];
        const front = pool.find((r) => norm(r) === norm(theirs.active))!;
        mine.retired = pool.filter((r) => r !== front);
        mine.active = front;
      }
    }
  }
  for (const mine of Object.values(out)) {
    const activeFpr = await fprOf(mine.active);
    const pool = [mine.active, ...mine.retired];
    let best = mine.active;
    let bestHash = await sha256(norm(best));
    for (const rec of mine.retired) {
      if (await fprOf(rec) !== activeFpr) continue;
      const be = best.lockEpoch ?? 0;
      const re = rec.lockEpoch ?? 0;
      if (re < be) continue;
      const rh = await sha256(norm(rec));
      if (re > be || rh < bestHash) { best = rec; bestHash = rh; }
    }
    if (best !== mine.active) {
      mine.retired = pool.filter((r) => r !== best);
      mine.active = best;
    }
  }
  return out;
}

/**
 * Restore's guard against a keychain that was ROLLED BACK before this
 * device ever saw it (2026-09-30: v6 held the retired key active, the
 * current one retired, and every fresh restore came up on a key the
 * password no longer opened). `named` is what the server says is current
 * (zero-access key, directory key), most authoritative first. When the
 * ring's active is not the highest-ranked named key the ring holds, that
 * one goes in front, in its
 * highest-epoch lock. Null: leave as is (the active is the highest-ranked
 * named key held, nothing named is held, or nothing is named).
 * Proof still decides: the caller falls back to the blob's order when the
 * named key does not open.
 */
export async function preferNamed(ring: pgp.KeyRing, named: string[]): Promise<pgp.KeyRing | null> {
  if (!named.length) return null;
  const fprs = new Map<pgp.KeyRecord, string>();
  for (const rec of [ring.active, ...ring.retired]) {
    try { fprs.set(rec, await fprOfRecord(rec)); } catch { /* unreadable — never a candidate */ }
  }
  // The most authoritative named key this ring holds at all decides.
  const top = named.map((f) => f.toLowerCase()).find((f) => [...fprs.values()].includes(f));
  if (!top || fprs.get(ring.active) === top) return null;
  let best: pgp.KeyRecord | null = null;
  for (const rec of ring.retired) {
    if (fprs.get(rec) !== top) continue;
    if (!best || (rec.lockEpoch ?? 0) > (best.lockEpoch ?? 0)) best = rec;
  }
  if (!best) return null;
  return { active: best, retired: [ring.active, ...ring.retired].filter((r) => r !== best) };
}

/** Who the server says is current, per address — main.ts hands this over
 *  (it knows the zero-access and directory routes); fingerprints are
 *  lowercase hex, most authoritative first. Absent: restore trusts the
 *  blob's order, as before. */
let authority: (addresses: string[]) => Promise<Record<string, string[]>> = async () => ({});
export function useAuthority(fn: (addresses: string[]) => Promise<Record<string, string[]>>): void { authority = fn; }

/** Every private key in a ring must still be locked. Shipping an unlocked
 *  key would hand the server the exact thing this design exists to deny it —
 *  so this is checked by reading the armor, not by trusting the caller. */
export async function assertLocked(ring: pgp.KeyRing): Promise<void> {
  for (const rec of [ring.active, ...ring.retired]) {
    const key = await openpgp.readPrivateKey({ armoredKey: rec.privateKey });
    if (key.isDecrypted()) throw new Error('Refusing to sync: a stored key is not passphrase-locked.');
  }
}

export async function fprOfRecord(rec: pgp.KeyRecord): Promise<string> {
  return (await openpgp.readKey({ armoredKey: rec.publicKey })).getFingerprint().toLowerCase();
}

/**
 * Rebuild a record so its public half is DERIVED from its (locked) private
 * half, never taken on faith. The private key parses without the passphrase
 * (only the secret material is encrypted), so this works on a locked key and
 * is what makes a substituted public key impossible: the stored public half
 * is now, by construction, the one that belongs to this private key.
 * Rejects an unlocked private key (assertLocked's rule, per record).
 * `requireAddress` binds the derived key to the ring's address — enforced on
 * the active key so no one can file a key for an address it does not carry.
 */
export async function bindRecord(email: string, rec: pgp.KeyRecord, requireAddress: boolean): Promise<pgp.KeyRecord> {
  const priv = await openpgp.readPrivateKey({ armoredKey: rec.privateKey });
  if (priv.isDecrypted()) throw new Error('Refusing to install: a key in the keychain is not passphrase-locked.');
  const pub = priv.toPublic();
  if (requireAddress) {
    const ok = pub.users.some((u) => (u.userID?.email ?? '').toLowerCase() === email.toLowerCase());
    if (!ok) throw new Error(`A key in the keychain does not belong to ${email}.`);
  }
  return {
    publicKey: pub.armor(),
    privateKey: rec.privateKey,
    created: rec.created,
    ...(rec.revocationCertificate ? { revocationCertificate: rec.revocationCertificate } : {}),
    ...(typeof rec.lockEpoch === 'number' ? { lockEpoch: rec.lockEpoch } : {}),
  };
}

async function bindRing(email: string, ring: pgp.KeyRing): Promise<pgp.KeyRing> {
  return {
    active: await bindRecord(email, ring.active, true),
    // Retired keys were once active for this address; derive their public
    // half too, but do not reject on the UID check — an old imported key may
    // legitimately carry a different UID and its mail must still open.
    retired: await Promise.all(ring.retired.map((r) => bindRecord(email, r, false))),
  };
}

// ------------------------------------------------------------- local state

/** Through the host's RingStore (pgp.ts). Only ever called with a ring whose
 *  records have been through bindRecord, so the public half it writes is
 *  derived, not attacker-supplied. */
function installRing(email: string, ring: pgp.KeyRing): void {
  pgp.installRing(email, ring);
}

function uninstallRing(email: string): void {
  pgp.uninstallRing(email);
}

/** What this device last pushed/accepted, per signed-in account — so an
 *  unchanged store never makes a request, pushes carry the version they
 *  believe they are updating, and a push can be checked for shrinkage
 *  against the address set last known good. */
interface Marker { version: number; hash: string; emails: string[] }
const markerKey = (username: string): string => 'kad-keychain:' + username.trim().toLowerCase();
function readMarker(username: string): Marker | null {
  try {
    const m = JSON.parse(localStorage.getItem(markerKey(username)) ?? 'null');
    return m && typeof m.version === 'number' && typeof m.hash === 'string'
      ? { version: m.version, hash: m.hash, emails: Array.isArray(m.emails) ? m.emails : [] }
      : null;
  } catch { return null; }
}
/** The keychain version this device last pushed or accepted for the
 *  account — what a focus-time status check compares against. */
export function knownVersion(username: string): number | null {
  return readMarker(username)?.version ?? null;
}

/** Record that this device has seen keychain version `version` and holds
 *  nothing it needs from it — the "every key is already here" restore
 *  outcome (argus A1). Bumps ONLY the marker's version, and only when the
 *  local rings still hash to what the marker recorded and cover the same
 *  addresses: no key material is adopted, and a device whose rings changed
 *  since its last sync keeps its old version (so its next push still merges).
 *  True when the marker moved. */
export async function acceptVersion(username: string, addresses: string[], version: number): Promise<boolean> {
  const marker = readMarker(username);
  if (!marker || version <= marker.version) return false;
  const rings = await collectLocalRings(addresses);
  const emails = Object.keys(rings);
  const same = emails.length === marker.emails.length && emails.every((e) => marker.emails.includes(e));
  if (!same) return false;
  const hash = await sha256(JSON.stringify({ rings, envelopes: localEnvelopes(username) }));
  if (hash !== marker.hash) return false;
  writeMarker(username, { ...marker, version });
  return true;
}
function writeMarker(username: string, m: Marker): void {
  localStorage.setItem(markerKey(username), JSON.stringify(m));
}

async function sha256(s: string): Promise<string> {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** The locked rings this account owns on this device. Addresses are the
 *  account's own (ownAddresses), never a sweep of localStorage: on a shared
 *  browser the store can hold OTHER accounts' rings, and those are not ours
 *  to ship. Every ring is asserted locked before it can be assembled. */
async function collectLocalRings(addresses: string[]): Promise<Record<string, pgp.KeyRing>> {
  const rings: Record<string, pgp.KeyRing> = {};
  for (const a of addresses) {
    const email = a.trim().toLowerCase();
    const ring = pgp.ringFor(email);
    if (!ring) continue;
    await assertLocked(ring);
    rings[email] = ring;
  }
  return rings;
}

/** The blob string for a ring set — the wrapper carries a timestamp, but it
 *  is NOT what the change-guard hashes (that hashes rings + envelopes, so an
 *  unchanged store really does read as unchanged — argus #3). A blob with no
 *  envelopes stays v1, so an account that never made a kit never wedges its
 *  older devices; the moment a kit exists the format is v2, hard (D7). */
function blobOf(rings: Record<string, pgp.KeyRing>, envelopes: Record<string, KitEnvelope>): string {
  return Object.keys(envelopes).length
    ? JSON.stringify({ v: 2, exportedAt: new Date().toISOString(), rings, envelopes } satisfies KeychainBlob)
    : JSON.stringify({ v: 1, exportedAt: new Date().toISOString(), rings });
}

// ---------------------------------------------------- the recovery envelope

/** This device's copy of the account's kit envelopes — what sync pushes
 *  alongside the rings. Seeded at kit creation, adopted from every fetched
 *  blob (merge and restore), so a device that has ever seen the kit never
 *  pushes a blob that drops it (D7's client half; the broker enforces the
 *  same as an invariant). */
const envKey = (username: string): string => 'kad-kitenv:' + username.trim().toLowerCase();
export function localEnvelopes(username: string): Record<string, KitEnvelope> {
  try {
    const e = JSON.parse(localStorage.getItem(envKey(username)) ?? 'null');
    return e && typeof e === 'object' && !Array.isArray(e) ? e : {};
  } catch { return {}; }
}
function writeLocalEnvelopes(username: string, envs: Record<string, KitEnvelope>): void {
  try { localStorage.setItem(envKey(username), JSON.stringify(envs)); } catch { /* private mode */ }
}
function adoptEnvelopes(username: string, remote: Record<string, KitEnvelope>): Record<string, KitEnvelope> {
  const union = mergeEnvelopes(localEnvelopes(username), remote);
  writeLocalEnvelopes(username, union);
  return union;
}

/** Delete tombstoned material from THIS device (cerberus M9 gate, finding
 *  1): the broker answered "a purge already removed these", and keeping
 *  them local would re-add them on every future push. Armors are matched
 *  by the same normalized hash the server tombstones; the active record is
 *  never touched (a purge only ever drops superseded copies — an active
 *  match would mean a hostile list, and dropping the active on a server's
 *  say-so is exactly what the trust boundary forbids). */
async function pruneTombstoned(username: string, addresses: string[], t: Tombstones): Promise<void> {
  const dead = new Set(t.armors);
  for (const a of addresses) {
    const email = a.trim().toLowerCase();
    const ring = pgp.ringFor(email);
    if (!ring) continue;
    const alive: pgp.KeyRecord[] = [];
    for (const rec of ring.retired) {
      if (!dead.has(await sha256(rec.privateKey.replace(/\r\n/g, '\n').trim()))) alive.push(rec);
    }
    if (alive.length !== ring.retired.length) installRing(email, { active: ring.active, retired: alive });
  }
  if (t.envelopes.length) {
    const envs = localEnvelopes(username);
    let changed = false;
    for (const id of t.envelopes) if (envs[id]) { delete envs[id]; changed = true; }
    if (changed) writeLocalEnvelopes(username, envs);
  }
}

/** Union by id. Envelopes are immutable once minted (a replace mints a new
 *  id), so on a shared id either side serves. */
export function mergeEnvelopes(
  local: Record<string, KitEnvelope>, remote: Record<string, KitEnvelope>
): Record<string, KitEnvelope> {
  return { ...remote, ...local };
}

/** Build the escrow envelope: every own ring's armor the ring secret opens,
 *  re-locked under the canonical recovery phrase. The phrase's S2K is the
 *  default iterated-salted one, deliberately: ~103 bits is unattackable and
 *  recovery must work on a phone (the doc's "cheap S2K" rule). Retired
 *  armors wearing other locks (pre-split passphrases, prior passwords kept
 *  by the additive re-lock) are left out — the envelope covers what the
 *  CURRENT secret opens, the same partial state fold-in lives with (A3). */
export async function buildEnvelope(
  addresses: string[], ringSecret: string, phrase: string
): Promise<{ id: string; envelope: KitEnvelope }> {
  const pass = canonicalRecoveryPhrase(phrase);
  const keys: KitEnvelope['keys'] = {};
  for (const a of addresses) {
    const email = a.trim().toLowerCase();
    const ring = pgp.ringFor(email);
    if (!ring) continue;
    let active: EnvKey;
    try {
      active = { armor: await pgp.relockArmor(ring.active.privateKey, ringSecret, pass, 'legacy'), created: ring.active.created };
    } catch { continue; }             // this ring wears a different lock — not coverable
    const retired: EnvKey[] = [];
    for (const rec of ring.retired) {
      try { retired.push({ armor: await pgp.relockArmor(rec.privateKey, ringSecret, pass, 'legacy'), created: rec.created }); }
      catch { /* old lock, not in hand — stays outside the kit */ }
    }
    keys[email] = { active, retired };
  }
  if (!Object.keys(keys).length) throw new Error('No key on this device opens with the current password — the kit has nothing to protect yet.');
  const id = [...crypto.getRandomValues(new Uint8Array(16))].map((b) => b.toString(16).padStart(2, '0')).join('');
  return { id, envelope: { createdAt: new Date().toISOString(), keys } };
}

/** Open an envelope with the recovery phrase: prove the phrase on every
 *  armor, derive each public half from its private (never trust a stored
 *  public — the bindRecord rule), and hand back rings still LOCKED under
 *  the phrase for the caller to re-lock and install. Throws when the
 *  phrase opens nothing. */
export async function openEnvelope(
  env: KitEnvelope, phrase: string
): Promise<Record<string, pgp.KeyRing>> {
  const pass = canonicalRecoveryPhrase(phrase);
  const out: Record<string, pgp.KeyRing> = {};
  for (const [email, entry] of Object.entries(env.keys)) {
    const prove = async (k: EnvKey): Promise<pgp.KeyRecord | null> => {
      try {
        const priv = await openpgp.readPrivateKey({ armoredKey: k.armor });
        await openpgp.decryptKey({ privateKey: priv, passphrase: pass });   // proof only; armor stays locked
        return { publicKey: priv.toPublic().armor(), privateKey: k.armor, created: k.created };
      } catch { return null; }
    };
    const active = await prove(entry.active);
    if (!active) continue;
    const retired = (await Promise.all(entry.retired.map(prove))).filter((r): r is pgp.KeyRecord => r !== null);
    out[email] = { active, retired };
  }
  if (!Object.keys(out).length) throw new Error('That recovery phrase does not open the kit. It is the eight words shown when the kit was made.');
  return out;
}

/** What a fetched blob asks the person to open: which address's key, created
 *  WHEN, with what fingerprint. The creation date is the memory-jogger — the
 *  right passphrase is the one chosen the day that key was made, and "not
 *  the password?!" is usually someone offering a newer secret to an older
 *  key. Reads public halves only; never touches the private armor. */
export async function describeSource(
  src: { blob: string }, login: string
): Promise<{ email: string; created: string; fingerprint: string } | null> {
  try {
    const { rings } = parseBlob(src.blob);
    const email = login.trim().toLowerCase();
    const addr = rings[email] ? email : Object.keys(rings)[0];
    if (!addr) return null;
    const key = await openpgp.readKey({ armoredKey: rings[addr].active.publicKey });
    return {
      email: addr,
      created: rings[addr].active.created,
      fingerprint: key.getFingerprint().toUpperCase().replace(/(.{4})/g, '$1 ').trim(),
    };
  } catch {
    return null;
  }
}

// ------------------------------------------------------------------ broker

export async function status(): Promise<KeychainStatus> {
  const r = await netFetch(apiUrl('/signup/api/keychain'), { headers: hdrs() });
  if (!r.ok) throw new Error('Could not check the keychain.');
  const j = await r.json();
  return { exists: Boolean(j.exists), version: Number(j.version ?? 0), updatedAt: j.updatedAt ?? null };
}

async function fetchBlob(): Promise<{ blob: string; version: number }> {
  const proof = secretProof();
  if (!proof) throw new Error('Sign in again to open your keychain — restoring needs your password, and this session resumed without it.');
  const r = await netFetch(apiUrl('/signup/api/keychain/fetch'), {
    method: 'POST', headers: hdrs(true), body: JSON.stringify({ proof }),
  });
  if (r.status === 404) throw new Error('This account has no keychain yet.');
  if (r.status === 429) throw new Error('Too many attempts — wait a little and try again.');
  if (r.status === 403) throw new Error('Sign in again to open your keychain — the server wants your password confirmed.');
  if (!r.ok) throw new Error('Could not fetch the keychain.');
  const j = await r.json();
  if (typeof j.blob !== 'string' || j.blob.length > MAX_BLOB_BYTES) throw new Error('Could not fetch the keychain.');
  return { blob: j.blob, version: Number(j.version ?? 0) };
}

export interface Tombstones { armors: string[]; envelopes: string[] }

async function pushBlob(blob: string, ifVersion: number | null, force: boolean,
  extras: { replaceKit?: boolean; acceptLosingKit?: boolean; purge?: { signatures: Record<string, string> } } = {}):
  Promise<{ ok: true; version: number } | { ok: false; conflictVersion: number; tombstoned?: Tombstones }> {
  const proof = secretProof();
  // A resumed session has no password in hand; the push waits for the next
  // fresh sign-in rather than failing loudly ("deferred" is the word the
  // quiet sync path already swallows).
  if (!proof) throw new Error('keychain sync deferred: this session resumed without the password (proof required)');
  const r = await netFetch(apiUrl('/signup/api/keychain'), {
    method: 'POST',
    headers: hdrs(true),
    body: JSON.stringify({ blob, ifVersion, force, proof, ...extras }),
  });
  if (r.status === 409) {
    const j = await r.json().catch(() => ({}));
    const t = j.tombstoned;
    return {
      ok: false,
      conflictVersion: Number(j.version ?? 0),
      ...(t && Array.isArray(t.armors) && Array.isArray(t.envelopes)
        ? { tombstoned: { armors: t.armors.map(String), envelopes: t.envelopes.map(String) } }
        : {}),
    };
  }
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error ?? 'Could not sync the keychain.');
  return { ok: true, version: Number((await r.json()).version ?? 0) };
}

// ------------------------------------------------------------------- sync

export type SyncResult = 'nothing-local' | 'unchanged' | 'pushed' | 'merged' | 'exists';

/**
 * Push this device's locked rings, merging first if another device pushed
 * since we last looked. `force` replaces the server keychain outright — the
 * "start fresh" ceremony only, never sync's own idea.
 */
export async function sync(username: string, addresses: string[],
  opts: { force?: boolean; replaceKit?: boolean; acceptLosingKit?: boolean; retombstoned?: boolean;
    /** The birth push: create or stand down, NEVER merge. Two devices
     *  racing a brand-new account must not fold two identities into one
     *  blob (the doc's signup rule, argus M9 #1) — on 'exists' the caller
     *  discards its key and restores the winner's. */
    createOnly?: boolean } = {}): Promise<SyncResult> {
  // One retry after a tombstone prune, never a loop.
  const retomb = async (t: Tombstones): Promise<SyncResult> => {
    if (opts.retombstoned) throw new Error('The keychain refused this push twice over purged records.');
    await pruneTombstoned(username, addresses, t);
    return sync(username, addresses, { ...opts, retombstoned: true });
  };
  const rings = await collectLocalRings(addresses);
  const emails = Object.keys(rings);
  if (!emails.length) return 'nothing-local';
  const envelopes = localEnvelopes(username);
  const hash = await sha256(JSON.stringify({ rings, envelopes }));
  const marker = readMarker(username);
  if (marker && marker.hash === hash && !opts.force && !opts.replaceKit) return 'unchanged';

  // A push must never drop an address we are known to have pushed before —
  // that is how a one-off identity-load blip erases an alias's keys for every
  // device (argus #2). If the local view is a strict subset, defer.
  if (!opts.force && marker) {
    const dropped = marker.emails.filter((e) => !(e in rings));
    if (dropped.length) throw new Error(`keychain sync deferred: local view is missing ${dropped.join(', ')}`);
  }

  const extras = { replaceKit: opts.replaceKit, acceptLosingKit: opts.acceptLosingKit };
  const blob = blobOf(rings, envelopes);
  const first = await pushBlob(blob, opts.force ? null : marker?.version ?? null, Boolean(opts.force), extras);
  if (first.ok) { writeMarker(username, { version: first.version, hash, emails }); return 'pushed'; }
  if (first.tombstoned) return retomb(first.tombstoned);
  if (opts.createOnly) return 'exists';

  // Conflict. If the server actually holds nothing (version 0), our marker is
  // stale against an emptied store — create afresh rather than dead-ending
  // (argus #4).
  if (first.conflictVersion === 0) {
    const retry = await pushBlob(blob, null, false, extras);
    if (retry.ok) { writeMarker(username, { version: retry.version, hash, emails }); return 'pushed'; }
  }

  // Another device holds keys we may not. Fetch, union (local active wins),
  // and push the union at the server's version. Key material is NOT adopted
  // here — that is restore()'s job, with a passphrase proof (cerberus V7).
  // Envelopes ARE adopted: they are ciphertext the phrase alone opens, and a
  // device that saw the kit must never push a blob without it (D7).
  let server: { blob: string; version: number };
  try {
    server = await fetchBlob();
  } catch {
    // The keychain vanished between the conflict and the fetch — treat as a
    // fresh create on the next attempt.
    const retry = await pushBlob(blob, null, false, extras);
    if (retry.ok) { writeMarker(username, { version: retry.version, hash, emails }); return 'pushed'; }
    throw new Error('The keychain is changing on another device — will retry at next sign-in.');
  }
  const remote = parseBlob(server.blob);
  const named = await authority(addresses).catch(() => ({} as Record<string, string[]>));
  const merged = await mergeRings(rings, remote.rings, fprOfRecord, named);
  // A replace-kit push keeps the LOCAL envelope set (that is the point);
  // every ordinary sync unions, so a kit made elsewhere survives this device.
  const mergedEnvs = opts.replaceKit ? envelopes : adoptEnvelopes(username, remote.envelopes);
  const mergedBlob = blobOf(merged, mergedEnvs);
  const second = await pushBlob(mergedBlob, server.version, false, extras);
  if (!second.ok) {
    if (second.tombstoned) return retomb(second.tombstoned);
    throw new Error('The keychain is changing on another device — will retry at next sign-in.');
  }
  // The marker records what THIS device holds and can reproduce — the LOCAL
  // ring set, not the union it merely reconciled. Writing the union's
  // addresses here made the no-shrink guard fire forever on the next sync
  // (an address the device has no key for is always "dropped"), silently
  // wedging every future push (argus re-review A). Hashing the local rings
  // likewise avoids a spurious push, since the next sync hashes those —
  // envelopes included, and the adopted set IS local now, so hash that.
  writeMarker(username, {
    version: second.version,
    hash: await sha256(JSON.stringify({ rings, envelopes: mergedEnvs })),
    emails,
  });
  return 'merged';
}

/**
 * The new-device ceremony: pull the keychain, install the rings this account
 * owns — every record REBOUND so its public half is derived from its private
 * half (cerberus V1) — and PROVE the passphrase PER RING, keeping exactly the
 * rings it opens. An unproven ring never survives (cerberus V2): one the
 * passphrase does not open is uninstalled on the spot and reported back in
 * `pending`, so an account whose alias key wears a different passphrase is no
 * longer locked out of restoring its primary (argus, 2nd pass) — running
 * restore again with the other passphrase installs just the pending rings,
 * because rings already here are skipped. If NOTHING opens, everything rolls
 * back — memory included — and each cause is reported as itself rather than
 * all as "wrong passphrase" (argus #6).
 *
 * `prefetched` lets the caller's retry loop reuse one download across
 * passphrase attempts instead of hammering the fetch endpoint (argus
 * hardening) — restore itself installs and proves; only the fetch is reused.
 */
export async function restore(
  username: string,
  passphrase: string,
  addresses: string[],
  prefetched?: { blob: string; version: number },
  opts: {
    /** Rotation adoption, per address: the fingerprint (lowercase hex) the
     *  SERVER names as this address's current key. A ring already here
     *  whose active key differs takes the blob's active only when it is
     *  exactly this key — the device that rotated is elsewhere, and this
     *  one must stop sealing to the key it retired. Additive: every local
     *  record rides along retired, so mail sealed to them still opens. The
     *  usual passphrase proof decides whether it stays. */
    adopt?: Record<string, string>;
  } = {}
): Promise<{ fingerprint: string; blob: string; version: number; pending: string[] }> {
  const src = prefetched ?? await fetchBlob();
  const parsed = parseBlob(src.blob);
  const owned = new Set(addresses.map((a) => a.trim().toLowerCase()));
  const mine = Object.entries(parsed.rings).filter(([email]) => owned.has(email));
  if (!mine.length) throw new Error('The keychain holds no keys for this account’s addresses.');

  const uname = username.trim().toLowerCase();
  const installed: string[] = [];
  const kept: string[] = [];
  const pending: string[] = [];
  const displacedRings = new Map<string, pgp.KeyRing>();
  /** Blob rings put back in the server's order (preferNamed), with the
   *  order they arrived in — the fallback when the named key won't open. */
  const asShipped = new Map<string, pgp.KeyRing>();
  let unlockErr: unknown = null;
  const norm = (r: pgp.KeyRecord): string => r.privateKey.replace(/\r\n/g, '\n').trim();
  const named = await authority(addresses).catch(() => ({} as Record<string, string[]>));
  try {
    for (const [email, shipped] of mine) {
      let ring = shipped;
      const fixed = await preferNamed(shipped, named[email] ?? []).catch(() => null);
      if (fixed) { ring = fixed; asShipped.set(email, shipped); }
      const existing = pgp.ringFor(email);
      if (existing) {
        const want = opts.adopt?.[email];
        if (want) {
          try {
            const theirs = await fprOfRecord(ring.active);
            if (theirs === want.toLowerCase() && theirs !== await fprOfRecord(existing.active)) {
              // Every local KEY survives — mail sealed to it must open — but
              // not an old LOCK of a key the blob already carries: that armor
              // was purged, and carrying it would resurrect the revoked lock
              // (the swap-lock rule, cerberus M9 gate finding 1). The local
              // active rides along whatever its lock.
              const blobArmors = new Set([ring.active, ...ring.retired].map(norm));
              const blobFprs = new Set(await Promise.all([ring.active, ...ring.retired].map(fprOfRecord)));
              const keep = new Map<string, pgp.KeyRecord>();
              for (const rec of ring.retired) keep.set(norm(rec), rec);
              keep.set(norm(existing.active), existing.active);
              for (const rec of existing.retired) {
                if (blobArmors.has(norm(rec)) || !blobFprs.has(await fprOfRecord(rec))) keep.set(norm(rec), rec);
              }
              keep.delete(norm(ring.active));
              displacedRings.set(email, existing);
              installRing(email, await bindRing(email, { active: ring.active, retired: [...keep.values()] }));
              installed.push(email);
              continue;
            }
          } catch { /* unreadable record — fall through to the ordinary rules */ }
        }
        // Swap-lock mode (A1): the ring is here, but the blob's active
        // armor is the SAME key under a NEWER lock — a password change on
        // another device while this one slept. If the offered passphrase
        // proves the new armor, adopt it; the old records ride retired
        // (additive, as ever). Otherwise leave the ring exactly as it is.
        try {
          if (await fprOfRecord(ring.active) !== await fprOfRecord(existing.active)) continue;
          if ((ring.active.lockEpoch ?? 0) <= (existing.active.lockEpoch ?? 0)) continue;
          const probe = await openpgp.readPrivateKey({ armoredKey: ring.active.privateKey });
          await openpgp.decryptKey({ privateKey: probe, passphrase });     // proof only
          // Displaced LOCAL records ride along only while the server still
          // holds them: a local armor the blob lacks was purged, and
          // carrying it would resurrect the revoked lock on the next push
          // (cerberus M9 gate, finding 1).
          const blobArmors = new Set([ring.active, ...ring.retired].map(norm));
          const carried = new Map<string, pgp.KeyRecord>();
          for (const rec of ring.retired) carried.set(norm(rec), rec);
          for (const rec of [existing.active, ...existing.retired]) {
            if (blobArmors.has(norm(rec))) carried.set(norm(rec), rec);
          }
          carried.delete(norm(ring.active));
          displacedRings.set(email, existing);
          installRing(email, await bindRing(email, { active: ring.active, retired: [...carried.values()] }));
          installed.push(email);
        } catch { /* different lock or older — not this ceremony's job */ }
        continue;
      }
      installRing(email, await bindRing(email, ring));
      installed.push(email);
    }
    if (!installed.length) throw new Error('Every key in the keychain is already on this device.');
    for (const email of installed) {
      try { await pgp.unlockPrivateKey(email, passphrase); kept.push(email); continue; }
      catch (e) { unlockErr = e; }
      const shipped = asShipped.get(email);
      if (shipped && !displacedRings.has(email)) {
        // The named key did not open; the blob's own order may.
        try {
          installRing(email, await bindRing(email, shipped));
          await pgp.unlockPrivateKey(email, passphrase);
          kept.push(email);
          continue;
        } catch (e) { unlockErr = e; }
      }
      const old = displacedRings.get(email);
      if (old) installRing(email, old); else uninstallRing(email);
      pending.push(email);
    }
    if (!kept.length) throw unlockErr ?? new Error('wrong passphrase');
    // The marker records what THIS device now holds and can reproduce — the
    // LOCAL rings, re-collected after install, never the blob. Recording the
    // blob's full address set here wedged every future sync exactly the way
    // argus re-review A caught on the merge path (an address this device has
    // no ring for is forever "dropped"), and hashing the blob's rings instead
    // of the bound ones forced one spurious push per restore. The blob's
    // envelopes are adopted — this device has now seen the kit and must
    // never push without it (D7).
    const adopted = adoptEnvelopes(username, parsed.envelopes);
    const localRings = await collectLocalRings(addresses);
    writeMarker(username, { version: src.version, hash: await sha256(JSON.stringify({ rings: localRings, envelopes: adopted })), emails: Object.keys(localRings) });
    const target = kept.includes(uname) ? uname : kept[0];
    return { fingerprint: await pgp.fingerprintOf(pgp.ringFor(target)!.active.publicKey), blob: src.blob, version: src.version, pending };
  } catch (e) {
    // Roll back storage AND session memory — an uninstalled ring must not
    // linger unlocked in pgp's session map (2nd argus pass). A swap-lock
    // ring rolls back to the ring it displaced, never to nothing.
    // A displaced ring whose new armor never opened was never unlocked by
    // this ceremony: its session key is the one the user unlocked before,
    // and relocking it would strand a device that was working — the next
    // sealed send stalls behind an unlock prompt (2026-10-01).
    for (const email of installed) {
      const old = displacedRings.get(email);
      if (old) installRing(email, old); else uninstallRing(email);
      if (!old || kept.includes(email)) pgp.relockRing(email);
    }
    if (e instanceof Error && /already on this device|no keys for/.test(e.message)) throw e;
    const wrong = e instanceof Error && /passphrase|decrypt|incorrect|session key|argument/i.test(e.message);
    throw new Error(wrong
      ? 'That passphrase does not open the keychain. It is the one you chose when the key was created.'
      : 'The keychain could not be opened on this device — it may be damaged. Your key backup file is the way in.');
  }
}

/**
 * The recovery ceremony (ZERO-ACCESS.md "The recovery kit"): the password is
 * gone, the phrase is in hand. Fetch the blob, open its envelopes with the
 * phrase (newest first), re-lock every recovered armor under the CURRENT
 * ring secret (the new password's derive, in split mode) and install —
 * bound, like every install. Rings already on the device are never
 * clobbered. Returns the addresses recovered; the caller syncs after.
 */
export async function restoreWithPhrase(
  username: string,
  phrase: string,
  addresses: string[],
  newLockSecret: string,
  prefetched?: { blob: string; version: number },
  opts: { replaceExisting?: boolean } = {}
): Promise<{ recovered: string[] }> {
  const src = prefetched ?? await fetchBlob();
  const parsed = parseBlob(src.blob);
  const envs = Object.entries(parsed.envelopes)
    .sort(([, a], [, b]) => (a.createdAt < b.createdAt ? 1 : -1));
  if (!envs.length) throw new Error('This account has no recovery kit — the phrase has nothing to open.');
  const owned = new Set(addresses.map((a) => a.trim().toLowerCase()));
  const pass = canonicalRecoveryPhrase(phrase);

  let opened: Record<string, pgp.KeyRing> | null = null;
  let openErr: unknown = null;
  for (const [, env] of envs) {
    try { opened = await openEnvelope(env, phrase); break; }
    catch (e) { openErr = e; }
  }
  if (!opened) throw openErr instanceof Error ? openErr : new Error('That recovery phrase does not open the kit.');

  const installed: string[] = [];
  const displaced = new Map<string, pgp.KeyRing>();
  try {
    for (const [email, ring] of Object.entries(opened)) {
      if (!owned.has(email)) continue;
      const existing = pgp.ringFor(email);
      // Never clobber keys already here — except in the explicit
      // replace-existing lane (the password-reset case: the local ring is
      // locked under the lost password and unusable), where the old records
      // survive as retired below.
      if (existing && !opts.replaceExisting) continue;
      // The recovered lock must OUTRANK every armor the blob already holds
      // for this address — an envelope's epoch is from kit-creation time,
      // and `envelope+1` let the dead lock (under the lost password) win
      // the next merge's promotion (cerberus M9 gate, finding 4).
      const blobEpochMax = [
        ...(parsed.rings[email] ? [parsed.rings[email].active, ...parsed.rings[email].retired] : []),
        ...(existing ? [existing.active, ...existing.retired] : []),
        ring.active, ...ring.retired,
      ].reduce((m, r) => Math.max(m, r.lockEpoch ?? 0), 0);
      const relock = async (rec: pgp.KeyRecord): Promise<pgp.KeyRecord> =>
        ({ ...rec, privateKey: await pgp.relockArmor(rec.privateKey, pass, newLockSecret, 'argon2'), lockEpoch: blobEpochMax + 1 });
      // ADDITIVE, like every re-lock (C5): the blob's original records — and
      // any displaced local ones — ride along as retired, so the broker's
      // armor-multiset guard sees only growth. The dead armors leave through
      // the signed purge, never here.
      const carried = new Map<string, pgp.KeyRecord>();
      for (const rec of [
        ...(parsed.rings[email] ? [parsed.rings[email].active, ...parsed.rings[email].retired] : []),
        ...(existing ? [existing.active, ...existing.retired] : []),
      ]) carried.set(rec.privateKey.replace(/\r\n/g, '\n').trim(), rec);
      const rebuilt: pgp.KeyRing = {
        active: await relock(ring.active),
        retired: [...await Promise.all(ring.retired.map(relock)), ...carried.values()],
      };
      if (existing) displaced.set(email, existing);
      installRing(email, await bindRing(email, rebuilt));
      installed.push(email);
    }
    if (!installed.length) throw new Error('Every key in the kit is already on this device.');
    for (const email of installed) await pgp.unlockPrivateKey(email, newLockSecret);
    adoptEnvelopes(username, parsed.envelopes);
    const localRings = await collectLocalRings(addresses);
    // The marker's hash is deliberately EMPTY: this device now holds re-locked
    // armors the server has never seen, and the caller's follow-up sync must
    // actually push them (a matching hash would read as "unchanged" and the
    // recovered lock would live on this device alone). The version still
    // anchors the optimistic-concurrency chain; the emails hold the
    // no-shrink guard.
    writeMarker(username, { version: src.version, hash: '', emails: Object.keys(localRings) });
    return { recovered: installed };
  } catch (e) {
    for (const email of installed) {
      const old = displaced.get(email);
      if (old) installRing(email, old); else uninstallRing(email);
      pgp.relockRing(email);
    }
    throw e;
  }
}

/** Record a freshly minted kit envelope on this device, ahead of the sync
 *  that ships it. A replace forgets every older envelope locally — the push
 *  then carries `replaceKit`, the one sanctioned envelope drop. */
export function recordEnvelope(username: string, id: string, env: KitEnvelope, replace: boolean): void {
  writeLocalEnvelopes(username, replace ? { [id]: env } : { ...localEnvelopes(username), [id]: env });
}

// ------------------------------------------------------------- signed purge

export type PurgeResult = 'purged' | 'nothing-to-purge' | 'deferred';

/**
 * The signed purge (ZERO-ACCESS.md C2): the ONE operation that removes
 * armors — the same-key old-lock copies the additive re-locks leave behind,
 * without which the mail is as strong as the weakest password the account
 * ever had — and the broker flushes its version history in the same write.
 * Possession, not just a session, authorizes it: every ring that shrinks
 * signs the new blob, the expected version and the owner address with its
 * own ACTIVE key (per-ring, so whoever opens the weakest ring cannot
 * destroy the others — C1). A ring the secret does not unlock keeps its
 * armors, the per-ring partial state this design lives with (A3); if
 * nothing can sign, nothing is purged. `evenIfClean` runs a no-drop purge
 * purely for the history flush — the replace-kit follow-through, where the
 * dropped envelope must also leave the history.
 */
export async function purge(
  username: string,
  addresses: string[],
  ringSecret: string,
  opts: { evenIfClean?: boolean } = {}
): Promise<PurgeResult> {
  const owner = username.trim().toLowerCase();
  const local = await collectLocalRings(addresses);
  if (!Object.keys(local).length) return 'nothing-to-purge';

  // The purge blob is built from the MERGED view, never this device's
  // store alone: a local-only blob silently deleted every record other
  // devices contributed — a rotation done elsewhere, an alias ring this
  // device lacks — and flushed the history holding them in the same write
  // (cerberus M9 gate, finding 3). Fetch, union, then prune.
  let server: { blob: string; version: number };
  try { server = await fetchBlob(); } catch { return 'nothing-to-purge'; }
  const remote = parseBlob(server.blob);
  const mergedAll = await mergeRings(local, remote.rings, fprOfRecord);
  const envelopes = mergeEnvelopes(localEnvelopes(username), remote.envelopes);

  // What the additive re-locks superseded: a record carrying the SAME key
  // as the active one under a strictly OLDER lock epoch. Rotated and
  // imported keys (different fingerprints) hold old mail and stay; epoch
  // ties stay too — destruction wants certainty.
  const norm = (r: pgp.KeyRecord): string => r.privateKey.replace(/\r\n/g, '\n').trim();
  const pruned: Record<string, pgp.KeyRing> = {};
  const droppedArmors = new Set<string>();
  let dropped: string[] = [];
  for (const [email, ring] of Object.entries(mergedAll)) {
    const activeFpr = await fprOfRecord(ring.active);
    const activeEpoch = ring.active.lockEpoch ?? 0;
    const keep: pgp.KeyRecord[] = [];
    let shrank = false;
    for (const rec of ring.retired) {
      if (await fprOfRecord(rec) === activeFpr && (rec.lockEpoch ?? 0) < activeEpoch) {
        droppedArmors.add(norm(rec));
        shrank = true;
        continue;
      }
      keep.push(rec);
    }
    if (shrank) dropped.push(email);
    pruned[email] = { active: ring.active, retired: keep };
  }

  // A ring that cannot sign keeps its armors — reverted BEFORE the blob is
  // hashed, since the signature covers the blob. Signing is by the ring's
  // KEY (this session's unlocked copy); the lock the merged active wears
  // is irrelevant to the signature.
  const canSign = async (email: string): Promise<boolean> => {
    if (pgp.isUnlocked(email)) return true;
    try { await pgp.unlockPrivateKey(email, ringSecret); return true; } catch { return false; }
  };
  for (const email of [...dropped]) {
    if (!await canSign(email)) {
      pruned[email] = mergedAll[email];
      dropped = dropped.filter((e) => e !== email);
    }
  }
  let signers = dropped;
  if (!dropped.length) {
    if (!opts.evenIfClean) return 'nothing-to-purge';
    // History flush alone: one proving ring is enough — own address first.
    const candidates = [owner, ...Object.keys(pruned).filter((e) => e !== owner)];
    signers = [];
    for (const email of candidates) {
      if (pruned[email] && await canSign(email)) { signers = [email]; break; }
    }
    if (!signers.length) return 'nothing-to-purge';
  }

  const blob = blobOf(pruned, envelopes);
  const payload = `kaditham-keychain-purge-v1\n${owner}\n${server.version}\n${await sha256(blob)}`;
  const signatures: Record<string, string> = {};
  for (const email of signers) signatures[email] = await pgp.signDetached(payload, email);

  const r = await pushBlob(blob, server.version, false, { purge: { signatures } });
  if (!r.ok) return 'deferred';        // another device is mid-change; retry at the next occasion

  // This device drops exactly what the server just dropped — by armor,
  // never by guesswork — and adopts nothing else (V7 stands).
  for (const a of addresses) {
    const email = a.trim().toLowerCase();
    const ring = pgp.ringFor(email);
    if (!ring) continue;
    const alive = ring.retired.filter((rec) => !droppedArmors.has(norm(rec)));
    if (alive.length !== ring.retired.length) installRing(email, { active: ring.active, retired: alive });
  }
  adoptEnvelopes(username, remote.envelopes);
  const after = await collectLocalRings(addresses);
  writeMarker(username, {
    version: r.version,
    hash: await sha256(JSON.stringify({ rings: after, envelopes: localEnvelopes(username) })),
    emails: Object.keys(after),
  });
  return 'purged';
}

/** Fetch the keychain once, for a retry loop that reuses it. */
export async function fetchOnce(): Promise<{ blob: string; version: number }> {
  return fetchBlob();
}
