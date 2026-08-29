// Recipient key pinning — trust on first use for keys discovered over the
// network.
//
// WKD and keys.openpgp.org answer "what is the key for this address?" fresh
// on every seal, and remember nothing. Without a record of what they said
// LAST time, a legitimate rotation and a substituted key are the same event,
// and neither is ever shown to the person sealing. This module keeps that
// record: the first key seen for an address is remembered, and a later
// answer that disagrees stops the seal until a human accepts it.
//
// Policy lives here; prompts do not. resolve() returns a verdict and the app
// draws the dialog, so Saavi and the webmail's KGPG window apply identical
// rules through different UIs. The lookup chain is injected for the same
// reason — the webmail asks its own directory before WKD.
//
// A pin is PUBLIC key material and always re-derivable from the network, so
// unlike the private ring in pgp.ts an unreadable record is simply dropped
// rather than quarantined.
//
// Pins are scoped to an OWNER. On a shared machine two accounts must not
// inherit each other's trust decisions, and in the webmail the owner is the
// signed-in user; a desktop keyring with no account passes '' and gets one
// device-wide scope.
import { keyState } from './pgp';

const PIN_PREFIX = 'saavi-pin-';

/** `<prefix><owner>|<address>`. Neither half can contain a pipe, so the two
 *  never run together — and the address is stored in the record anyway. */
const keyOf = (owner: string, address: string): string =>
  `${PIN_PREFIX}${owner.trim().toLowerCase()}|${normalize(address)}`;

/** A record written before scoping existed: no owner segment in the key. */
const isLegacyKey = (k: string): boolean =>
  k.startsWith(PIN_PREFIX) && !k.slice(PIN_PREFIX.length).includes('|');

/** Where a key came from. 'directory' is the webmail's own address book. */
export type PinSource = 'wkd' | 'vks' | 'directory' | 'paste';

export interface Pin {
  address: string;
  /** Raw lowercase hex — the field every comparison is made on. */
  fingerprint: string;
  /** Armored public key, refreshed whenever the fingerprint still matches.
   *  Empty when only the fingerprint is known (see seed) — the next
   *  successful lookup fills it in. */
  publicKey: string;
  source: PinSource;
  firstSeen: string;
  lastSeen: string;
  /** Set once the owner is seen to have revoked this key; a revoked pin is
   *  never served again, including on the offline path. */
  revokedAt?: string;
}

/** What a lookup chain reports back. `status` carries WkdResult's meaning:
 *  'none' = answered, publishes nothing; 'unreachable' = nothing answered. */
export interface Lookup {
  key: string | null;
  source: PinSource;
  status: 'found' | 'none' | 'unreachable';
  detail?: string;
}

export type LookupFn = (address: string) => Promise<Lookup>;

export interface ResolveOptions {
  /**
   * Write what was decided (default true). Pass false where resolving is not
   * yet an act of trust — a mail composer re-resolves on every keystroke, and
   * merely typing an address must not record that you trust its key. Such a
   * caller commits with remember() once the user actually acts.
   */
  commit?: boolean;
}

export type Resolution =
  /** Seal to `key`. `firstContact` and `offline` are worth telling the user. */
  | { state: 'ok'; address: string; key: string; fingerprint: string; pin: Pin | null; firstContact: boolean; offline: boolean }
  /** A DIFFERENT key than the pinned one. Nothing is written until accept(). */
  | { state: 'changed'; address: string; key: string; fingerprint: string; source: PinSource; pin: Pin }
  /** Known before, and the source now answers with NO key. Withdrawn or
   *  withheld — never the same thing as "has no key yet", and never a reason
   *  to fall back to sending in the clear. */
  | { state: 'withdrawn'; address: string; pin: Pin }
  | { state: 'revoked'; address: string; fingerprint: string }
  | { state: 'unusable'; address: string; fingerprint: string; reason: string }
  | { state: 'missing'; address: string; status: 'none' | 'unreachable'; detail?: string };

export const normalize = (address: string): string => address.trim().toLowerCase();

function readAt(key: string): Pin | null {
  const raw = localStorage.getItem(key);
  if (!raw) return null;
  try {
    const p = JSON.parse(raw);
    return typeof p?.fingerprint === 'string' && typeof p?.publicKey === 'string' ? p as Pin : null;
  } catch {
    return null;
  }
}

export function pinFor(owner: string, address: string): Pin | null {
  const addr = normalize(address);
  const here = readAt(keyOf(owner, addr));
  if (here) return here;
  // Pins predate scoping. The device scope inherits them one record at a
  // time, as each is looked up — no startup sweep, and nothing to re-run.
  if (owner.trim() === '') {
    const legacyKey = PIN_PREFIX + addr;
    const legacy = readAt(legacyKey);
    if (legacy) {
      write('', legacy);
      try { localStorage.removeItem(legacyKey); } catch { /* left in place; harmless */ }
      return legacy;
    }
  }
  return null;
}

export function all(owner: string): Pin[] {
  const scope = `${PIN_PREFIX}${owner.trim().toLowerCase()}|`;
  const wantsLegacy = owner.trim() === '';
  // Addresses first: pinFor may rewrite the store as it adopts a legacy
  // record, and localStorage must not be mutated mid-scan.
  const addrs = new Set<string>();
  for (let i = 0; i < localStorage.length; i++) {
    const k = localStorage.key(i)!;
    if (k.startsWith(scope)) addrs.add(k.slice(scope.length));
    else if (wantsLegacy && isLegacyKey(k)) addrs.add(k.slice(PIN_PREFIX.length));
  }
  const out: Pin[] = [];
  for (const a of addrs) {
    const p = pinFor(owner, a);
    if (p) out.push(p);
  }
  return out.sort((a, b) => a.address.localeCompare(b.address));
}

export function forget(owner: string, address: string): void {
  localStorage.removeItem(keyOf(owner, address));
  if (owner.trim() === '') localStorage.removeItem(PIN_PREFIX + normalize(address));
}

/**
 * Write a pin. A full storage quota must never break sealing — the key is
 * already in hand and the seal is valid without a record of it — so a failed
 * write is swallowed and the in-memory Pin returned regardless.
 */
function write(owner: string, p: Pin): Pin {
  try {
    localStorage.setItem(keyOf(owner, p.address), JSON.stringify(p));
  } catch { /* quota or storage disabled — seal unpinned rather than fail */ }
  return p;
}

function markRevoked(owner: string, pin: Pin): void {
  write(owner, { ...pin, revokedAt: new Date().toISOString() });
}

/**
 * Decide which key an address should be sealed to, and what that means.
 * Writes a pin for a first contact or a confirmed match; a disagreement is
 * reported, never written — the caller must ask a human and call accept().
 */
export async function resolve(owner: string, address: string, lookup: LookupFn, opts: ResolveOptions = {}): Promise<Resolution> {
  const commit = opts.commit !== false;
  const addr = normalize(address);
  const pin = pinFor(owner, addr);
  const got = await lookup(addr);
  const now = new Date().toISOString();

  if (!got.key) {
    // A key already known to be revoked stays refused whatever the lookup does.
    if (pin?.revokedAt) return { state: 'revoked', address: addr, fingerprint: pin.fingerprint };
    // A source that could not be reached at all is a network problem, and a
    // remembered key is exactly the right answer — when we hold one.
    if (pin?.publicKey && got.status === 'unreachable') {
      return { state: 'ok', address: addr, key: pin.publicKey, fingerprint: pin.fingerprint, pin, firstContact: false, offline: true };
    }
    // A source that ANSWERED and now offers nothing has withdrawn the key.
    // Not a substitution case, and not a downgrade-to-plaintext case either.
    if (pin && got.status === 'none') return { state: 'withdrawn', address: addr, pin };
    return { state: 'missing', address: addr, status: got.status === 'found' ? 'none' : got.status, detail: got.detail };
  }

  // Revocation does NOT change a fingerprint, so a pin match would wave a
  // revoked key straight through. Check the key itself, every time.
  const st = await keyState(got.key);
  if (st.revoked) {
    if (pin && commit) markRevoked(owner, pin);
    return { state: 'revoked', address: addr, fingerprint: st.fingerprint };
  }
  if (!st.usable) return { state: 'unusable', address: addr, fingerprint: st.fingerprint, reason: st.reason };

  if (!pin) {
    const fresh = commit
      ? write(owner, { address: addr, fingerprint: st.fingerprint, publicKey: got.key, source: got.source, firstSeen: now, lastSeen: now })
      : null;
    return { state: 'ok', address: addr, key: got.key, fingerprint: st.fingerprint, pin: fresh, firstContact: true, offline: false };
  }

  if (pin.fingerprint === st.fingerprint) {
    // A revocation cannot be taken back. Once this fingerprint has been seen
    // revoked, a later copy that lacks the revocation signature is a stale or
    // rolled-back answer, never a reinstatement — so revokedAt is NEVER
    // cleared here. Only a genuinely different key (below) can replace it.
    if (pin.revokedAt) return { state: 'revoked', address: addr, fingerprint: st.fingerprint };
    // The primary fingerprint survives a rotated encryption subkey or an
    // extended expiry, so the stored armor is REPLACED, not just touched —
    // otherwise the offline path keeps serving a superseded subkey forever.
    const upd = commit ? write(owner, { ...pin, publicKey: got.key, source: got.source, lastSeen: now }) : pin;
    return { state: 'ok', address: addr, key: got.key, fingerprint: st.fingerprint, pin: upd, firstContact: false, offline: false };
  }

  return { state: 'changed', address: addr, key: got.key, fingerprint: st.fingerprint, source: got.source, pin };
}

/**
 * Record a fingerprint whose key we do not hold: verified out of band, or
 * carried over from a store that kept fingerprints only. The next successful
 * lookup fills the key in — a match refreshes the armor, a disagreement is a
 * change, exactly as for a pin that arrived complete. Never overwrites an
 * existing pin, and reports nothing it could not store.
 */
export function seed(owner: string, address: string, fingerprint: string, source: PinSource, firstSeen?: string): Pin | null {
  const addr = normalize(address);
  if (pinFor(owner, addr)) return null;
  const fpr = fingerprint.replace(/\s+/g, '').toLowerCase();
  if (!/^([0-9a-f]{40}|[0-9a-f]{64})$/.test(fpr)) return null;
  const now = new Date().toISOString();
  return write(owner, { address: addr, fingerprint: fpr, publicKey: '', source, firstSeen: firstSeen ?? now, lastSeen: now });
}

/**
 * Make a resolution durable: the user has now ACTED on this key — sent the
 * letter, read one that verified against it — which is the moment a
 * non-committing resolve() was waiting for. Keeps the address's firstSeen.
 */
export function remember(owner: string, address: string, armoredPublicKey: string, fingerprint: string, source: PinSource): Pin {
  const addr = normalize(address);
  const prior = pinFor(owner, addr);
  const now = new Date().toISOString();
  return write(owner, {
    address: addr, fingerprint: fingerprint.replace(/\s+/g, '').toLowerCase(),
    publicKey: armoredPublicKey, source,
    firstSeen: prior?.firstSeen ?? now, lastSeen: now,
  });
}

/** Commit a key change a human has accepted. firstSeen stays: it is when the
 *  address was first known, not when this key was. */
export function accept(owner: string, c: Extract<Resolution, { state: 'changed' }>): Pin {
  const now = new Date().toISOString();
  return write(owner, {
    address: c.address, fingerprint: c.fingerprint, publicKey: c.key, source: c.source,
    firstSeen: c.pin.firstSeen, lastSeen: now,
  });
}
