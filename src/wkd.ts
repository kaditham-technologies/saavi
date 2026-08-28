// Web Key Directory lookup (advanced then direct method, draft-koch-openpgp-webkey-service):
// hash the local part, fetch the binary key over HTTPS, re-armor it.
// No crypto here beyond SHA-1-as-address-hash, which is what the spec says.
import * as openpgp from 'openpgp';

const ZB32 = 'ybndrfg8ejkmcpqxot1uwisza345h769';

function zbase32(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ZB32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ZB32[(value << (5 - bits)) & 31];
  return out;
}

/** The two candidate URLs for an address, advanced method first. The domain
 *  must look like a hostname — it is interpolated into a URL, and a To-field
 *  author must not get to choose an arbitrary request target. */
export async function wkdUrls(address: string): Promise<string[]> {
  const [local, domain] = address.toLowerCase().split('@');
  if (!local || !domain) return [];
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(domain)) return [];
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-1', new TextEncoder().encode(local)));
  const hash = zbase32(digest);
  const l = encodeURIComponent(local);
  return [
    `https://openpgpkey.${domain}/.well-known/openpgpkey/${domain}/hu/${hash}?l=${l}`,
    `https://${domain}/.well-known/openpgpkey/hu/${hash}?l=${l}`,
  ];
}

/** Webview fetch enforces CORS like any browser, and WKD servers rarely send
 *  ACAO headers — inside the Tauri shell the request must go through the
 *  Rust-side http plugin instead. */
async function wkdFetch(url: string): Promise<Response> {
  // A domain that blackholes the request must not stall sealing for the
  // platform's TCP timeout — give each candidate URL ten seconds.
  const init = { signal: AbortSignal.timeout(10_000) };
  if ('__TAURI_INTERNALS__' in window) {
    const { fetch: tauriFetch } = await import('@tauri-apps/plugin-http');
    return tauriFetch(url, init);
  }
  return fetch(url, init);
}

/** A WKD response larger than this is not a key; refuse to buffer it. */
const MAX_KEY_BYTES = 1 << 20;

/** Read a body with the cap enforced WHILE streaming — a chunked response
 *  with no Content-Length must not get buffered before the check. */
export async function readCapped(r: Response, maxBytes = MAX_KEY_BYTES): Promise<Uint8Array | null> {
  const len = Number(r.headers.get('content-length') ?? 0);
  if (len > maxBytes) return null;
  const body = r.body;
  if (!body) {
    const buf = new Uint8Array(await r.arrayBuffer());
    return buf.byteLength > maxBytes ? null : buf;
  }
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      void reader.cancel().catch(() => { /* already refused */ });
      return null;
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let at = 0;
  for (const c of chunks) { out.set(c, at); at += c.byteLength; }
  return out;
}

/** True when one of the key's user IDs is exactly this address (the domain
 *  is authoritative for its own users, but a key server must not be able to
 *  hand back a key for someone else — GnuPG applies the same check).
 *  Exported so every other discovery source applies the same rule. */
export function keyCarriesAddress(key: openpgp.Key, address: string): boolean {
  const want = address.toLowerCase();
  return key.getUserIDs().some((uid) => {
    const m = uid.match(/<([^>]+)>\s*$/);
    return (m ? m[1] : uid).trim().toLowerCase() === want;
  });
}

export interface WkdResult {
  key: string | null;
  /** 'none': the domain answered but publishes no key for this address;
   *  'unreachable': no WKD endpoint could be reached at all (DNS, TLS,
   *  offline) — a different problem from "not published". */
  status: 'found' | 'none' | 'unreachable';
  detail?: string;
}

/**
 * Fetch an address's public key via WKD, saying why when it cannot.
 * In a plain browser a server without ACAO headers looks unreachable.
 */
export async function wkdProbe(address: string): Promise<WkdResult> {
  let answered = false;
  let lastErr = '';
  for (const url of await wkdUrls(address)) {
    try {
      const r = await wkdFetch(url);
      answered = true;
      if (!r.ok) continue;
      // Redirects are followed; the final hop must still be HTTPS.
      if (r.url && !r.url.startsWith('https://')) continue;
      const buf = await readCapped(r);
      if (!buf) continue;
      const key = await openpgp.readKey({ binaryKey: buf });
      if (!keyCarriesAddress(key, address)) continue;
      return { key: key.armor(), status: 'found' };
    } catch (e) {
      lastErr = e instanceof Error ? e.message : String(e);
      /* try the next form */
    }
  }
  return answered ? { key: null, status: 'none' } : { key: null, status: 'unreachable', detail: lastErr };
}

/** The key, or null when the domain publishes none or cannot be reached. */
export async function wkdLookup(address: string): Promise<string | null> {
  return (await wkdProbe(address)).key;
}
