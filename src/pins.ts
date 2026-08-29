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
import { keyState } from './pgp';

const PIN_PREFIX = 'saavi-pin-';

/** Where a key came from. 'directory' is the webmail's own address book. */
export type PinSource = 'wkd' | 'vks' | 'directory' | 'paste';

export interface Pin {
  address: string;
  /** Raw lowercase hex — the field every comparison is made on. */
  fingerprint: string;
  /** Armored public key, refreshed whenever the fingerprint still matches. */
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

export type Resolution =
  /** Seal to `key`. `firstContact` and `offline` are worth telling the user. */
  | { state: 'ok'; address: string; key: string; pin: Pin | null; firstContact: boolean; offline: boolean }
  /** A DIFFERENT key than the pinned one. Nothing is written until accept(). */
  | { state: 'changed'; address: string; key: string; fingerprint: string; source: PinSource; pin: Pin }
  | { state: 'revoked'; address: string; fingerprint: string }
  | { state: 'unusable'; address: string; fingerprint: string; reason: string }
  | { state: 'missing'; address: string; status: 'none' | 'unreachable'; detail?: string; hadPin: boolean };

export const normalize = (address: string): string => address.trim().toLowerCase();

export function pinFor(address: string): Pin | null {
  const raw = localStorage.getItem(PIN_PREFIX + normalize(address));
  if (!raw) return null;
  try {
    const p = JSON.parse(raw);
    return typeof p?.fingerprint === 'string' && typeof p?.publicKey === 'string' ? p as Pin : null;
  } catch {
    return null;
  }
}

export function all(): Pin[] {
  const out: Pin[] = [];
  for (let i = 0; i < localStorage.length; i++) {
    const k = localStorage.key(i)!;
    if (!k.startsWith(PIN_PREFIX)) continue;
    const p = pinFor(k.slice(PIN_PREFIX.length));
    if (p) out.push(p);
  }
  return out.sort((a, b) => a.address.localeCompare(b.address));
}

export function forget(address: string): void {
  localStorage.removeItem(PIN_PREFIX + normalize(address));
}

/**
 * Write a pin. A full storage quota must never break sealing — the key is
 * already in hand and the seal is valid without a record of it — so a failed
 * write is swallowed and the in-memory Pin returned regardless.
 */
function write(p: Pin): Pin {
  try {
    localStorage.setItem(PIN_PREFIX + p.address, JSON.stringify(p));
  } catch { /* quota or storage disabled — seal unpinned rather than fail */ }
  return p;
}

function markRevoked(pin: Pin): void {
  write({ ...pin, revokedAt: new Date().toISOString() });
}

/**
 * Decide which key an address should be sealed to, and what that means.
 * Writes a pin for a first contact or a confirmed match; a disagreement is
 * reported, never written — the caller must ask a human and call accept().
 */
export async function resolve(address: string, lookup: LookupFn): Promise<Resolution> {
  const addr = normalize(address);
  const pin = pinFor(addr);
  const got = await lookup(addr);
  const now = new Date().toISOString();

  if (!got.key) {
    // A domain that could not be reached at all is a network problem, and a
    // remembered key is exactly the right answer. A domain that ANSWERED and
    // now publishes nothing has withdrawn the key — possibly because it was
    // compromised — so the pin is not a safe substitute.
    if (pin && !pin.revokedAt && got.status === 'unreachable') {
      return { state: 'ok', address: addr, key: pin.publicKey, pin, firstContact: false, offline: true };
    }
    return { state: 'missing', address: addr, status: got.status === 'found' ? 'none' : got.status, detail: got.detail, hadPin: !!pin };
  }

  // Revocation does NOT change a fingerprint, so a pin match would wave a
  // revoked key straight through. Check the key itself, every time.
  const st = await keyState(got.key);
  if (st.revoked) {
    if (pin) markRevoked(pin);
    return { state: 'revoked', address: addr, fingerprint: st.fingerprint };
  }
  if (!st.usable) return { state: 'unusable', address: addr, fingerprint: st.fingerprint, reason: st.reason };

  if (!pin) {
    const fresh = write({ address: addr, fingerprint: st.fingerprint, publicKey: got.key, source: got.source, firstSeen: now, lastSeen: now });
    return { state: 'ok', address: addr, key: got.key, pin: fresh, firstContact: true, offline: false };
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
    const upd = write({ ...pin, publicKey: got.key, source: got.source, lastSeen: now });
    return { state: 'ok', address: addr, key: got.key, pin: upd, firstContact: false, offline: false };
  }

  return { state: 'changed', address: addr, key: got.key, fingerprint: st.fingerprint, source: got.source, pin };
}

/** Commit a key change a human has accepted. firstSeen stays: it is when the
 *  address was first known, not when this key was. */
export function accept(c: Extract<Resolution, { state: 'changed' }>): Pin {
  const now = new Date().toISOString();
  return write({
    address: c.address, fingerprint: c.fingerprint, publicKey: c.key, source: c.source,
    firstSeen: c.pin.firstSeen, lastSeen: now,
  });
}
