// Where the Kaditham Mail server is, and how Saavi talks to it — the seam
// mailkeychain.ts (core) and account.ts go through. The webmail has its own
// server.ts with the same two exports (same-origin fetch there); this one
// routes through the shell's Rust http client, because the page's CSP allows
// no network at all and the http capability is scoped to exactly the account
// paths on mail.kaditham.ie (capabilities/default.json).

/** The one server Saavi signs in to (product decision, 2026-10-02): production,
 *  in every build. There is no staging origin anywhere in Saavi — not even
 *  in dev builds — because the password derivation is the same everywhere,
 *  and a binary that can be pointed at a looser server can be made to send
 *  a production password there (cerberus C1). UI previews in the dev server
 *  use a faked server inside the page, never the network. */
export const PRODUCTION = 'https://mail.kaditham.ie';
export const SERVERS: readonly string[] = [PRODUCTION];

let base: string = PRODUCTION;

export function serverBase(): string { return base; }

/** The known server an origin names, or a refusal. */
export function knownServer(origin: string): string {
  const o = new URL(origin).origin;
  const hit = SERVERS.find((s) => s === o);
  if (!hit) throw new Error(`Saavi only signs in to ${SERVERS.join(' or ')}.`);
  return hit;
}

/** Point at one of the known servers (after a successful sign-in, or the
 *  origin a stored session belongs to). */
export function setServerBase(origin: string): void {
  base = knownServer(origin);
}

/** Resolve an API path against a known server origin (the current one by
 *  default). An absolute URL is only accepted on that same origin (JMAP
 *  hands us absolute apiUrls). */
export function apiUrl(path: string, on: string = base): string {
  const origin = knownServer(on);
  const u = new URL(path, origin);
  if (u.origin !== origin) throw new Error('Refusing a request off the mail server.');
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
