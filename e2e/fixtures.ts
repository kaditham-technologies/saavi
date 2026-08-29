import { readFileSync } from 'node:fs';
import type { BrowserContext } from '@playwright/test';

export const EMAIL = 'anjali@example.ie';
export const PASS = 'lantern-orbit-velvet-canyon-ember-tide';
export const RING_FILE = 'e2e/.artifacts/ring.json';
/** A correspondent who is NOT us: an armored public key, for the paths that
 *  must behave differently when the recipient is somebody else. */
export const OTHER_EMAIL = 'dara@example.ie';
export const OTHER_KEY_FILE = 'e2e/.artifacts/other-key.asc';
export const otherKey = (): string => readFileSync(OTHER_KEY_FILE, 'utf8');

/** Seed the app's localStorage before first load: the demo ring (unless
 *  ring:false for empty-state tests) and the update check off (unless
 *  updates:true — the update specs mock the manifest themselves). */
export async function seed(
  ctx: BrowserContext,
  opts: { ring?: boolean; updates?: boolean } = {}
): Promise<void> {
  const ring = opts.ring === false ? null : readFileSync(RING_FILE, 'utf8');
  await ctx.addInitScript(([r, email, updates]) => {
    if (!updates) localStorage.setItem('saavi-update-check', 'off');
    if (r) localStorage.setItem('saavi-ring-' + email, r);
  }, [ring, EMAIL, opts.updates === true] as const);
}
