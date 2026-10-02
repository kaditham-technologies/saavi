// The published-key match check (0.6.0, docs/ACCOUNT-SIGNIN.md, pillar 1).
// Three sources for one address's current key:
//   local    — the key unlocked on THIS device (public half derived from the
//              private half on install — the only source Saavi trusts);
//   wkd      — what the address publishes; what everyone else seals to;
//   keychain — the active key the account keychain holds, fingerprinted from
//              its PRIVATE half (a blob's public half is never believed).
// All present and equal: match. Any present pair differs: mismatch — WARN
// only (founder 2026-10-02): a rotation may still be propagating, and the
// customer may know why. Fingerprints are compared as lowercase hex.
import * as openpgp from 'openpgp';

export type Source = 'local' | 'wkd' | 'keychain';
export interface Sources { local: string | null; wkd: string | null; keychain: string | null }
export type Verdict =
  | { state: 'match'; fingerprint: string; checked: Source[] }
  | { state: 'mismatch'; differing: Source[]; sources: Sources }
  | { state: 'unpublished'; fingerprint: string }   // local (and keychain) agree; nothing on WKD
  | { state: 'unknown' };                           // nothing local to compare

const norm = (f: string | null): string | null => (f ? f.replace(/\s+/g, '').toLowerCase() : null);

export function judge(s: Sources): Verdict {
  const v: Sources = { local: norm(s.local), wkd: norm(s.wkd), keychain: norm(s.keychain) };
  if (!v.local) return { state: 'unknown' };
  const present = (Object.keys(v) as Source[]).filter((k) => v[k]);
  const differing = present.filter((k) => v[k] !== v.local);
  if (differing.length) return { state: 'mismatch', differing, sources: v };
  if (!v.wkd) return { state: 'unpublished', fingerprint: v.local };
  return { state: 'match', fingerprint: v.local, checked: present };
}

/** The fingerprint a locked private key really has. */
export async function privateFpr(armor: string): Promise<string> {
  return (await openpgp.readPrivateKey({ armoredKey: armor })).getFingerprint().toLowerCase();
}

/** The fingerprint of an armored public key. */
export async function publicFpr(armor: string): Promise<string> {
  return (await openpgp.readKey({ armoredKey: armor })).getFingerprint().toLowerCase();
}

/** 4-character groups, the way people read them aloud. */
export const showFpr = (f: string): string => f.toUpperCase().replace(/(.{4})/g, '$1 ').trim();
