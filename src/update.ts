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

export interface UpdateInfo { version: string; published: string | null; }

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
    const m = JSON.parse(new TextDecoder().decode(buf)) as { version?: unknown; published?: unknown };
    if (typeof m.version !== 'string' || !/^\d+(\.\d+){1,3}$/.test(m.version)) return null;
    if (!isNewer(m.version, current)) return null;
    return { version: m.version, published: typeof m.published === 'string' ? m.published : null };
  } catch {
    return null;
  }
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
