// keys.openpgp.org lookup (VKS, verified-email keyserver) — the fallback
// when a recipient's domain publishes no WKD. Same rules as wkd.ts: the
// returned key must carry the address, and responses are size-capped
// while streaming.
import * as openpgp from 'openpgp';
import { readCapped } from './wkd';

async function vksFetch(url: string, init?: RequestInit): Promise<Response> {
  // Same rule as wkdFetch: an unresponsive keyserver must not stall the UI
  // for the platform's TCP timeout.
  const withTimeout = { signal: AbortSignal.timeout(10_000), ...init };
  if ('__TAURI_INTERNALS__' in window) {
    const { fetch: tauriFetch } = await import('@tauri-apps/plugin-http');
    return tauriFetch(url, withTimeout);
  }
  return fetch(url, withTimeout);
}

async function vksPost(path: string, body: unknown): Promise<Record<string, unknown>> {
  const r = await vksFetch(`https://keys.openpgp.org/vks/v1/${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const j: unknown = await r.json().catch(() => null);
  const obj = j && typeof j === 'object' ? j as Record<string, unknown> : null;
  if (!r.ok || !obj) {
    throw new Error(typeof obj?.error === 'string' ? obj.error : `keys.openpgp.org answered ${r.status}.`);
  }
  return obj;
}

/** Per-address publication state ("published" / "pending" / "unpublished" /
 *  "revoked") plus the token that can request verification mails. */
export interface VksUploadResult { fingerprint: string; status: Record<string, string>; token: string }

/** Upload a PUBLIC key. Uploading alone makes it findable by FINGERPRINT;
 *  by-email search needs the owner to click the verification link
 *  (vksRequestVerify) — the server shows no user IDs until then. */
export async function vksUpload(armoredPublicKey: string): Promise<VksUploadResult> {
  const j = await vksPost('upload', { keytext: armoredPublicKey });
  if (typeof j.key_fpr !== 'string' || typeof j.token !== 'string') throw new Error('keys.openpgp.org gave an unexpected answer.');
  return { fingerprint: j.key_fpr, status: (j.status ?? {}) as Record<string, string>, token: j.token };
}

/** Ask the keyserver to mail each address its verification link. Only ever
 *  called for the USER'S OWN addresses (a key with its secret half here) —
 *  publishing someone else's key must not trigger mail to strangers. */
export async function vksRequestVerify(token: string, addresses: string[]): Promise<Record<string, string>> {
  const j = await vksPost('request-verify', { token, addresses });
  return (j.status ?? {}) as Record<string, string>;
}

export async function vksLookup(address: string): Promise<string | null> {
  const want = address.trim().toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]{2,}$/.test(want)) return null;
  try {
    const r = await vksFetch(`https://keys.openpgp.org/vks/v1/by-email/${encodeURIComponent(want)}`);
    if (!r.ok) return null;
    const buf = await readCapped(r);
    if (!buf) return null;
    const key = await openpgp.readKey({ armoredKey: new TextDecoder().decode(buf) });
    const carries = key.getUserIDs().some((uid) => {
      const m = uid.match(/<([^>]+)>\s*$/);
      return (m ? m[1] : uid).trim().toLowerCase() === want;
    });
    return carries ? key.armor() : null;
  } catch {
    return null;
  }
}

/**
 * Look a key up by the key ID that signed a message (the unseal verdict's
 * "who is this stranger?" path). Unlike by-email there is no address to
 * check the key against — the CALLER must treat the result as an untrusted
 * candidate: good for showing "signed by <uid> (fingerprint)", never for a
 * trust decision.
 */
export async function vksLookupKeyId(keyIdHex: string): Promise<string | null> {
  const id = keyIdHex.trim().toUpperCase();
  if (!/^[0-9A-F]{16}$/.test(id)) return null;
  try {
    const r = await vksFetch(`https://keys.openpgp.org/vks/v1/by-keyid/${id}`);
    if (!r.ok) return null;
    const buf = await readCapped(r);
    if (!buf) return null;
    const key = await openpgp.readKey({ armoredKey: new TextDecoder().decode(buf) });
    const carries = key.getKeys().some((k) => k.getKeyID().toHex().toUpperCase() === id);
    return carries ? key.armor() : null;
  } catch {
    return null;
  }
}
