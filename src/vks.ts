// keys.openpgp.org lookup (VKS, verified-email keyserver) — the fallback
// when a recipient's domain publishes no WKD. Same rules as wkd.ts: the
// returned key must carry the address, and responses are size-capped.
import * as openpgp from 'openpgp';

const MAX_KEY_BYTES = 1 << 20;

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
    if (Number(r.headers.get('content-length') ?? 0) > MAX_KEY_BYTES) return null;
    const text = await r.text();
    if (text.length > MAX_KEY_BYTES) return null;
    const key = await openpgp.readKey({ armoredKey: text });
    const carries = key.getUserIDs().some((uid) => {
      const m = uid.match(/<([^>]+)>\s*$/);
      return (m ? m[1] : uid).trim().toLowerCase() === want;
    });
    return carries ? key.armor() : null;
  } catch {
    return null;
  }
}
