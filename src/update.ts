// Update indicator — check only, never download. On every launch (a
// once-a-day stamp used to gate this, which made "restart to check"
// silently do nothing); one GET of the static release manifest our own
// download page publishes (not GitHub, so no third party sees the app
// start). The manifest can only make Saavi *say* a newer version exists:
// installing is still the user downloading and verifying a signed release.

export const MANIFEST_URL = 'https://kaditham.ie/wp-content/uploads/saavi/latest.json';
export const DOWNLOAD_PAGE = 'https://kaditham.ie/saavi/';
const OPT_KEY = 'saavi-update-check'; // 'on' | 'off' (absent = on, the default)
const SEEN_KEY = 'saavi-update-seen'; // newest version the user was told about
const DISMISS_KEY = 'saavi-update-dismissed'; // version whose banner was dismissed

export interface UpdateInfo {
  version: string;
  published: string | null;
  /** The Linux .deb asset when the release carries one (URL resolved absolute). */
  deb: { name: string; url: string } | null;
  /** URL of the GPG-clearsigned checksum list (SHA256SUMS.asc), resolved. */
  sumsSigned: string | null;
}

// On by default: only an explicit opt-out ('off') disables the daily check.
// The one network effect is a single manifest GET; installing stays manual.
export function enabled(): boolean {
  return localStorage.getItem(OPT_KEY) !== 'off';
}
export function setEnabled(on: boolean): void {
  localStorage.setItem(OPT_KEY, on ? 'on' : 'off');
}

/** a > b for dotted numeric versions ("0.2.10" > "0.2.9"); pre-release
 *  suffixes are ignored, which is fine for our tags. */
export function isNewer(a: string, b: string): boolean {
  const pa = a.split('.').map((x) => parseInt(x, 10) || 0);
  const pb = b.split('.').map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d > 0;
  }
  return false;
}

async function get(url: string): Promise<Response> {
  if ('__TAURI_INTERNALS__' in window) {
    const { fetch: tauriFetch } = await import('@tauri-apps/plugin-http');
    return tauriFetch(url, { method: 'GET', headers: { Accept: 'application/json' } });
  }
  return fetch(url, { cache: 'no-store' });
}

/** Fetch the manifest and compare; null when current, unreachable, or
 *  malformed. */
export async function check(current: string): Promise<UpdateInfo | null> {
  try {
    const r = await get(MANIFEST_URL);
    if (!r.ok) return null;
    // A manifest is a few hundred bytes; cap the read like WKD does.
    const { readCapped } = await import('./wkd');
    const buf = await readCapped(r, 64 * 1024);
    if (!buf) return null;
    const m = JSON.parse(new TextDecoder().decode(buf)) as {
      version?: unknown; published?: unknown; checksums?: { signed?: unknown };
      assets?: { name?: unknown; url?: unknown; platform?: unknown; format?: unknown }[];
    };
    if (typeof m.version !== 'string' || !/^\d+(\.\d+){1,3}$/.test(m.version)) return null;
    if (!isNewer(m.version, current)) return null;
    // The manifest's URLs are site-relative; resolve against where it lives.
    const abs = (u: unknown): string | null => (typeof u === 'string' && u ? new URL(u, MANIFEST_URL).href : null);
    let deb: UpdateInfo['deb'] = null;
    for (const a of m.assets ?? []) {
      if (a?.platform === 'linux' && a?.format === 'deb' && typeof a.name === 'string') {
        const url = abs(a.url);
        if (url) deb = { name: a.name, url };
        break;
      }
    }
    return {
      version: m.version,
      published: typeof m.published === 'string' ? m.published : null,
      deb,
      sumsSigned: abs(m.checksums?.signed),
    };
  } catch {
    return null;
  }
}

/**
 * Parse a GPG-CLEARSIGNED checksum list (SHA256SUMS.asc), verifying the
 * signature against the pinned release key FIRST — the returned map is only
 * ever built from verified text. Throws on a bad, missing, or wrong-key
 * signature.
 */
export async function verifySignedSums(clearsigned: string, armoredKey?: string): Promise<Map<string, string>> {
  const openpgp = await import('openpgp');
  const { RELEASE_KEY } = await import('./release-key');
  const message = await openpgp.readCleartextMessage({ cleartextMessage: clearsigned });
  const key = await openpgp.readKey({ armoredKey: armoredKey ?? RELEASE_KEY });
  const { signatures } = await openpgp.verify({ message, verificationKeys: key });
  if (!signatures.length) throw new Error('The checksum list is not signed.');
  await signatures[0].verified; // rejects on a bad signature or the wrong key
  const sums = new Map<string, string>();
  for (const line of message.getText().split('\n')) {
    const m = line.match(/^([0-9a-f]{64})\s+\*?(\S.*)$/);
    if (m) sums.set(m[2].trim(), m[1]);
  }
  if (!sums.size) throw new Error('The signed checksum list is empty.');
  return sums;
}

const hexOf = (buf: ArrayBuffer): string =>
  [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');

/**
 * Download the release's .deb and return its bytes ONLY when the whole chain
 * holds: SHA256SUMS.asc verifies against the release key pinned in the app,
 * and the downloaded bytes hash to that list's entry for this file. Throws
 * on any break in the chain.
 */
export async function fetchVerifiedDeb(info: UpdateInfo): Promise<Uint8Array> {
  if (!info.deb || !info.sumsSigned) throw new Error('This release publishes no .deb.');
  const { readCapped } = await import('./wkd');
  const ascResp = await get(info.sumsSigned);
  if (!ascResp.ok) throw new Error('Could not fetch the signed checksum list.');
  const asc = await readCapped(ascResp, 64 * 1024);
  if (!asc) throw new Error('The signed checksum list is oversized.');
  const sums = await verifySignedSums(new TextDecoder().decode(asc));
  const want = sums.get(info.deb.name);
  if (!want) throw new Error(`${info.deb.name} is not in the signed checksum list.`);
  const debResp = await get(info.deb.url);
  if (!debResp.ok) throw new Error('Could not download the update.');
  const bytes = await readCapped(debResp, 256 * 1024 * 1024);
  if (!bytes) throw new Error('The update download is oversized.');
  // Copy into an owned buffer: crypto.subtle wants a plain ArrayBuffer view,
  // and the hash must be of the exact bytes that get returned.
  const owned = new Uint8Array(bytes.byteLength);
  owned.set(bytes);
  if (hexOf(await crypto.subtle.digest('SHA-256', owned)) !== want) {
    throw new Error('The downloaded update does not match its signed checksum.');
  }
  return owned;
}

export function markSeen(version: string): void { localStorage.setItem(SEEN_KEY, version); }
export function seen(): string | null { return localStorage.getItem(SEEN_KEY); }

// Banner dismissal is per-version: dismissing 0.3.0 silences its banner, but a
// later 0.4.0 shows again.
export function dismiss(version: string): void { localStorage.setItem(DISMISS_KEY, version); }
export function dismissed(): string | null { return localStorage.getItem(DISMISS_KEY); }

/** Open the download page in the system browser (Tauri) or a new tab. */
export async function openDownloadPage(): Promise<void> {
  if ('__TAURI_INTERNALS__' in window) {
    const { openUrl } = await import('@tauri-apps/plugin-opener');
    await openUrl(DOWNLOAD_PAGE);
  } else {
    window.open(DOWNLOAD_PAGE, '_blank', 'noopener');
  }
}
