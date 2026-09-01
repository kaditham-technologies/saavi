// The ring bundle — the store as a unit (docs/KEY-SYNC.md, S0).
//
// One versioned, self-describing structure holding every ring the store
// has, serialisable as a whole and wrapped differently depending on where
// it is going: at rest on disk sealed by an OS-keychain secret (0.5.0),
// in transit to a paired device, or in escrow under a recovery phrase
// (both later phases). This module is the audited core of that plan:
// anything that touches or derives a key lives here; moving the sealed
// bytes around lives in diskstore.ts and the shell.
//
// Rules carried from the design doc:
//  - Nothing is ever silently dropped. A record that cannot be parsed is
//    carried as `quarantined`; a store key this version does not know is
//    carried verbatim in `extras`.
//  - A bundle written by a NEWER format version is refused, not guessed at.
import * as openpgp from 'openpgp';
import { STORE_PREFIX, type KeyRecord, type KeyRing, type StoreAlert } from './pgp';

export const BUNDLE_FORMAT = 'saavi-ring-bundle';
export const BUNDLE_VERSION = 1;

export interface BundleRing {
  address: string;
  active: KeyRecord;
  retired: KeyRecord[];
}

export interface RingBundle {
  format: typeof BUNDLE_FORMAT;
  version: number;
  updatedAt: string;
  rings: BundleRing[];
  /** Corruption alarms (pgp.ts `StoreAlert`), carried so they stay loud. */
  alerts: StoreAlert[];
  /** Raw records that failed to parse — parked, never destroyed. */
  quarantined: { key: string; raw: string }[];
  /** Store keys this format version does not recognise, verbatim. */
  extras: Record<string, string>;
  /** Reserved for v1.1 (KEY-SYNC.md): recipient pins travel here. */
  pins: unknown[];
  /** SHA-256 (hex) over the canonical rings serialisation — a self-check;
   *  authenticity comes from the envelope, not from this field. */
  hash: string;
}

/** Canonical rings serialisation: sorted by address, fixed field order. */
function canonicalRings(rings: BundleRing[]): string {
  const rec = (k: KeyRecord): Record<string, string> => {
    const o: Record<string, string> = { publicKey: k.publicKey, privateKey: k.privateKey, created: k.created };
    if (k.revocationCertificate !== undefined) o.revocationCertificate = k.revocationCertificate;
    return o;
  };
  return JSON.stringify([...rings]
    .sort((a, b) => (a.address < b.address ? -1 : a.address > b.address ? 1 : 0))
    .map((r) => ({ address: r.address, active: rec(r.active), retired: r.retired.map(rec) })));
}

export async function hashRings(rings: BundleRing[]): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonicalRings(rings)));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export async function makeBundle(parts: Omit<RingBundle, 'format' | 'version' | 'updatedAt' | 'hash'>): Promise<RingBundle> {
  return {
    format: BUNDLE_FORMAT,
    version: BUNDLE_VERSION,
    updatedAt: new Date().toISOString(),
    ...parts,
    hash: await hashRings(parts.rings),
  };
}

export function serialiseBundle(b: RingBundle): string {
  return JSON.stringify(b, null, 1);
}

function isRecord(v: unknown): v is KeyRecord {
  const r = v as KeyRecord;
  return !!r && typeof r === 'object'
    && typeof r.publicKey === 'string' && r.publicKey.length > 0
    && typeof r.privateKey === 'string' && r.privateKey.length > 0
    && typeof r.created === 'string'
    && (r.revocationCertificate === undefined || typeof r.revocationCertificate === 'string');
}

/** Strict parse. Throws with a reason a person can act on — a refused
 *  bundle means the caller must NOT proceed to overwrite anything. */
export async function parseBundle(text: string): Promise<RingBundle> {
  let raw: unknown;
  try { raw = JSON.parse(text); } catch { throw new Error('The key store is not readable as a bundle.'); }
  const b = raw as RingBundle;
  if (!b || typeof b !== 'object' || b.format !== BUNDLE_FORMAT) {
    throw new Error('The key store is not a Saavi ring bundle.');
  }
  if (typeof b.version !== 'number' || !Number.isInteger(b.version) || b.version < 1) {
    throw new Error('The key store carries no readable version.');
  }
  if (b.version > BUNDLE_VERSION) {
    throw new Error(`The key store was written by a newer Saavi (bundle v${b.version}); update the app rather than risk it.`);
  }
  if (!Array.isArray(b.rings)) throw new Error('The key store carries no rings list.');
  for (const r of b.rings) {
    if (!r || typeof r.address !== 'string' || !r.address.includes('@')
      || !isRecord(r.active) || !Array.isArray(r.retired) || !r.retired.every(isRecord)) {
      throw new Error('A ring in the key store is malformed.');
    }
  }
  if (!Array.isArray(b.alerts) || !Array.isArray(b.quarantined) || !Array.isArray(b.pins)
    || !b.extras || typeof b.extras !== 'object'
    || !b.quarantined.every((q) => q && typeof q.key === 'string' && typeof q.raw === 'string')) {
    throw new Error('The key store envelope is malformed.');
  }
  if (typeof b.hash !== 'string' || (await hashRings(b.rings)) !== b.hash) {
    throw new Error('The key store failed its integrity check.');
  }
  return b;
}

// ---------- the sealed envelope (at rest on a device) ----------
// OpenPGP symmetric encryption under a generated 256-bit secret the OS
// keychain holds. The private keys inside are themselves passphrase-locked;
// this envelope is the at-rest layer on top, so a copied file without the
// keychain secret is opaque.

export async function sealBundle(serialised: string, secret: string): Promise<string> {
  const message = await openpgp.createMessage({ text: serialised });
  return String(await openpgp.encrypt({ message, passwords: [secret], format: 'armored' }));
}

export async function unsealBundle(armored: string, secret: string): Promise<string> {
  const message = await openpgp.readMessage({ armoredMessage: armored });
  const { data } = await openpgp.decrypt({ message, passwords: [secret], format: 'utf8' });
  return String(data);
}

// ---------- store-entry translation ----------
// pgp.ts sees a key–value store; the disk sees a bundle. These two are the
// mapping between them, and they must never lose an entry in either
// direction — key material is the one thing this store may not drop.

const ALERTS_SUFFIX = 'alerts';
const QUARANTINE_MARK = 'corrupt-';

/** Build a bundle from every `STORE_PREFIX`-keyed entry. Records that do
 *  not parse are quarantined (with an alert), never dropped. */
export async function bundleFromStore(entries: Record<string, string>): Promise<RingBundle> {
  const rings: BundleRing[] = [];
  const alerts: StoreAlert[] = [];
  const quarantined: { key: string; raw: string }[] = [];
  const extras: Record<string, string> = {};
  for (const [key, raw] of Object.entries(entries)) {
    if (!key.startsWith(STORE_PREFIX)) { extras[key] = raw; continue; }
    const tail = key.slice(STORE_PREFIX.length);
    if (tail === ALERTS_SUFFIX) {
      try {
        const parsed = JSON.parse(raw) as StoreAlert[];
        if (Array.isArray(parsed)) { alerts.push(...parsed); continue; }
      } catch { /* fall through to extras */ }
      extras[key] = raw;
    } else if (tail.startsWith(QUARANTINE_MARK)) {
      quarantined.push({ key, raw });
    } else if (tail.includes('@')) {
      try {
        const parsed = JSON.parse(raw) as KeyRing & KeyRecord;
        if (parsed.active && isRecord(parsed.active) && Array.isArray(parsed.retired) && parsed.retired.every(isRecord)) {
          rings.push({ address: tail, active: parsed.active, retired: parsed.retired });
        } else if (isRecord(parsed)) {
          // v1 shape — a bare record — the same in-place migration pgp.ts does.
          rings.push({ address: tail, active: parsed, retired: [] });
        } else {
          throw new Error('unrecognised ring shape');
        }
      } catch {
        const qk = `${STORE_PREFIX}${QUARANTINE_MARK}${tail}-${Date.now()}`;
        quarantined.push({ key: qk, raw });
        alerts.push({ email: tail, at: new Date().toISOString(), quarantineKey: qk });
      }
    } else {
      extras[key] = raw;
    }
  }
  return makeBundle({ rings, alerts, quarantined, extras, pins: [] });
}

/** The inverse: the flat entries pgp.ts reads and writes. */
export function storeEntries(bundle: RingBundle): Record<string, string> {
  const out: Record<string, string> = {};
  for (const r of bundle.rings) {
    out[STORE_PREFIX + r.address] = JSON.stringify({ active: r.active, retired: r.retired } satisfies KeyRing);
  }
  if (bundle.alerts.length) out[STORE_PREFIX + ALERTS_SUFFIX] = JSON.stringify(bundle.alerts);
  for (const q of bundle.quarantined) out[q.key] = q.raw;
  for (const [k, v] of Object.entries(bundle.extras)) out[k] = v;
  return out;
}
