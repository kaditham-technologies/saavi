// "Your keychain changed on another device" (0.6.0, argus A1). The banner
// compares the keychain's version on the server with the newest version this
// device knows: the marker's (what it last pushed or accepted), or — for a
// device that has never synced and so has no marker — a baseline taken at
// the first successful status read. Every way the customer answers the banner
// (bringing the change here, or finding every key already here) moves the
// baseline, so the same version never asks twice.

export interface BannerState { banner: number | null; baseline: number | null }

export function decideBanner(remote: number | null, known: number | null, baseline: number | null): BannerState {
  if (remote === null) return { banner: null, baseline };
  const floors = [known, baseline].filter((v): v is number => v !== null);
  if (!floors.length) return { banner: null, baseline: remote };   // first look: this is where we start
  const floor = Math.max(...floors);
  return { banner: remote > floor ? remote : null, baseline };
}

const key = (user: string): string => 'saavi-kc-seen:' + user.trim().toLowerCase();

export function readBaseline(user: string): number | null {
  try {
    const v = Number(localStorage.getItem(key(user)));
    return Number.isFinite(v) && v > 0 ? v : null;
  } catch { return null; }
}

export function writeBaseline(user: string, version: number): void {
  try {
    const cur = readBaseline(user);
    if (cur === null || version > cur) localStorage.setItem(key(user), String(version));
  } catch { /* storage refused — the banner may ask once more */ }
}
