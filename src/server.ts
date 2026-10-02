// Where the Kaditham Mail server is, and how Saavi talks to it — the seam
// mailkeychain.ts (core) and account.ts go through. The webmail has its own
// server.ts with the same two exports (same-origin fetch there); this one
// routes through the shell's Rust http client, because the page's CSP allows
// no network at all and the http capability is scoped to exactly the account
// paths on these two hosts (capabilities/default.json).

/** The servers Saavi will sign in to. Production, and the staging twin the
 *  team tests against. Anything else is refused rather than trusted. */
export const SERVERS = ['https://mail.kaditham.ie', 'https://mail.kaditham.me'] as const;
export type Server = typeof SERVERS[number];

let base: Server = SERVERS[0];

export function serverBase(): Server { return base; }

/** Point at one of the known servers (the sign-in screen's choice, or the
 *  origin a stored session belongs to). */
export function setServerBase(origin: string): void {
  const o = new URL(origin).origin;
  const hit = SERVERS.find((s) => s === o);
  if (!hit) throw new Error(`Saavi only signs in to ${SERVERS.join(' or ')}.`);
  base = hit;
}

/** Resolve an API path against the server origin. An absolute URL is only
 *  accepted when it is on that same origin (JMAP hands us absolute apiUrls). */
export function apiUrl(path: string): string {
  const u = new URL(path, base);
  if (u.origin !== base) throw new Error('Refusing a request off the mail server.');
  return u.toString();
}

export type Net = (input: string, init?: RequestInit) => Promise<Response>;

const inShell = (): boolean => typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;

let net: Net = async (input, init) => {
  if (inShell()) {
    const { fetch: tauriFetch } = await import('@tauri-apps/plugin-http');
    return tauriFetch(input, init);
  }
  return fetch(input, init);
};

/** Tests swap the transport. */
export function setNet(f: Net): void { net = f; }

/** No ambient credentials ever: every call carries its own Authorization. */
export const netFetch: Net = (input, init) => net(input, { credentials: 'omit', ...init });
