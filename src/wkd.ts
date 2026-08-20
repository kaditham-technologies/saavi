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

/** The two candidate URLs for an address, advanced method first. */
export async function wkdUrls(address: string): Promise<string[]> {
  const [local, domain] = address.toLowerCase().split('@');
  if (!local || !domain) return [];
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
  if ('__TAURI_INTERNALS__' in window) {
    const { fetch: tauriFetch } = await import('@tauri-apps/plugin-http');
    return tauriFetch(url);
  }
  return fetch(url);
}

/** A WKD response larger than this is not a key; refuse to buffer it. */
const MAX_KEY_BYTES = 1 << 20;

/** True when one of the key's user IDs is exactly this address (the domain
 *  is authoritative for its own users, but a WKD server must not be able to
 *  hand back a key for someone else — GnuPG applies the same check). */
function keyCarriesAddress(key: openpgp.Key, address: string): boolean {
  const want = address.toLowerCase();
  return key.getUserIDs().some((uid) => {
    const m = uid.match(/<([^>]+)>\s*$/);
    return (m ? m[1] : uid).trim().toLowerCase() === want;
  });
}

/**
 * Fetch an address's public key via WKD. Returns the armored key, or null
 * when the domain publishes none (or, in a plain browser, when CORS blocks
 * a server that does not send ACAO headers).
 */
export async function wkdLookup(address: string): Promise<string | null> {
  for (const url of await wkdUrls(address)) {
    try {
      const r = await wkdFetch(url);
      if (!r.ok) continue;
      // Redirects are followed; the final hop must still be HTTPS.
      if (r.url && !r.url.startsWith('https://')) continue;
      const len = Number(r.headers.get('content-length') ?? 0);
      if (len > MAX_KEY_BYTES) continue;
      const buf = await r.arrayBuffer();
      if (buf.byteLength > MAX_KEY_BYTES) continue;
      const key = await openpgp.readKey({ binaryKey: new Uint8Array(buf) });
      if (!keyCarriesAddress(key, address)) continue;
      return key.armor();
    } catch {
      /* try the next form */
    }
  }
  return null;
}
