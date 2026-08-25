// keys.openpgp.org lookup (VKS, verified-email keyserver) — the fallback
// when a recipient's domain publishes no WKD. Same rules as wkd.ts: the
// returned key must carry the address, and responses are size-capped
// while streaming.
import * as openpgp from 'openpgp';
import { readCapped } from './wkd';

async function vksFetch(url: string): Promise<Response> {
  if ('__TAURI_INTERNALS__' in window) {
    const { fetch: tauriFetch } = await import('@tauri-apps/plugin-http');
    return tauriFetch(url);
  }
  return fetch(url);
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
