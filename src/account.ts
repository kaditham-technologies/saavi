// Sign in with Kaditham Mail (0.6.0, docs/ACCOUNT-SIGNIN.md). Saavi-only:
// the session, the token, and the account-side reads (identities, app
// passwords, the keychain's device list). The keychain itself is core —
// mailkeychain.ts — and this module hands it the bearer, the proof and a name.
//
// What lives where:
//   - the password and the account secret derived from it: THIS module's
//     memory, this session only. Never stored, never sent raw (the split:
//     only deriveAuthSecret's output travels).
//   - the refresh token, address and server: the OS keychain ('account:v1').
//   - the access token: memory.
import { deriveAuthSecret } from './derive';
import { apiUrl, netFetch, serverBase, setServerBase, SERVERS } from './server';
import * as mk from './mailkeychain';

export const CLIENT_ID = 'kaditham-saavi';
const RENEW_MARGIN = 120_000;
const TIMEOUT = 20_000;

const CORE = 'urn:ietf:params:jmap:core';
const SUBMISSION = 'urn:ietf:params:jmap:submission';
const STALWART = 'urn:stalwart:jmap';

/** Why a sign-in stopped — each one says what to do next. */
export type FailKind = 'denied' | 'code-denied' | 'needs-code' | 'rate' | 'offline' | 'server' | 'setup';
export class SignInError extends Error {
  constructor(public kind: FailKind, message: string) { super(message); }
}

interface Persisted { v: 1; address: string; server: string; refresh: string }

interface Session {
  address: string;
  access: string;
  expiresAt: number;
  refresh: string | null;
}

let session: Session | null = null;
// This session only (P6 proof + ring lock). Null after a resume.
let accountSecret: string | null = null;
let password: string | null = null;
let refreshing: Promise<boolean> | null = null;
const listeners = new Set<() => void>();

export function onChange(fn: () => void): () => void { listeners.add(fn); return () => listeners.delete(fn); }
const changed = (): void => { for (const fn of listeners) fn(); };

export const signedIn = (): boolean => session !== null;
export const address = (): string | null => session?.address ?? null;
/** True when this session holds the password — restore and push need it. */
export const hasSecrets = (): boolean => accountSecret !== null && password !== null;
export const server = (): string => serverBase();

const inShell = (): boolean => typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;
async function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  const { invoke: inv } = await import('@tauri-apps/api/core');
  return inv<T>(cmd, args);
}

/** A frame and a tick, so whatever says "working" is painted before a
 *  key-derivation step takes the main thread (the webmail's 7-second silent
 *  unlock, 2026-10-02). */
export const painted = (): Promise<void> =>
  new Promise((r) => (typeof requestAnimationFrame === 'function' ? requestAnimationFrame(() => setTimeout(r, 0)) : setTimeout(r, 0)));

function b64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
async function pkcePair(): Promise<{ verifier: string; challenge: string }> {
  const verifier = b64url(crypto.getRandomValues(new Uint8Array(48)));
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return { verifier, challenge: b64url(new Uint8Array(digest)) };
}

function offline(e: unknown): SignInError {
  const why = e instanceof Error ? e.message : String(e);
  return new SignInError('offline', `Could not reach ${new URL(serverBase()).host} — check the connection and try again. (${why})`);
}

async function persist(): Promise<void> {
  if (!session?.refresh || !inShell()) return;
  const rec: Persisted = { v: 1, address: session.address, server: serverBase(), refresh: session.refresh };
  try { await invoke('account_session_set', { session: JSON.stringify(rec) }); } catch { /* keychain refused — the session lasts this run */ }
}

function adopt(address: string, t: { access_token?: string; refresh_token?: string; expires_in?: number }): void {
  if (!t.access_token) throw new SignInError('server', 'The mail server did not complete the sign-in.');
  session = {
    address,
    access: t.access_token,
    expiresAt: Date.now() + (t.expires_in ?? 3600) * 1000,
    refresh: t.refresh_token ?? session?.refresh ?? null,
  };
}

export type Step = 'deriving' | 'signing-in' | 'code';

/**
 * Sign in. The password is derived on this device and only the derived
 * account secret travels. Throws SignInError with kind 'needs-code' when the
 * account has two-factor on and no code was given — call again with it.
 */
export async function signIn(addr: string, pass: string, code: string | undefined,
  opts: { server?: string; step?: (s: Step) => void } = {}): Promise<void> {
  const who = addr.trim().toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(who)) throw new SignInError('denied', 'Enter your full Kaditham Mail address, like you@yourcompany.ie.');
  if (opts.server) setServerBase(opts.server);
  opts.step?.('deriving');
  await painted();
  let secret: string;
  try { secret = await deriveAuthSecret(pass, who); } catch {
    throw new SignInError('denied', 'Enter your full Kaditham Mail address, like you@yourcompany.ie.');
  }
  opts.step?.(code ? 'code' : 'signing-in');
  const { verifier, challenge } = await pkcePair();
  let r: Response;
  try {
    r = await netFetch(apiUrl('/api/auth'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        type: 'authCode', accountName: who, accountSecret: secret,
        ...(code ? { mfaToken: code.replace(/\s+/g, '') } : {}),
        clientId: CLIENT_ID, redirectUri: apiUrl('/oauth/callback'),
        scope: 'openid offline_access',
        state: b64url(crypto.getRandomValues(new Uint8Array(12))),
        codeChallenge: challenge, codeChallengeMethod: 'S256',
      }),
      signal: AbortSignal.timeout(TIMEOUT),
    });
  } catch (e) { throw offline(e); }
  if (r.status === 429) {
    const said = await r.json().then((j) => (typeof j?.error === 'string' ? j.error : '')).catch(() => '');
    throw new SignInError('rate', said || 'Too many attempts — wait a minute and try again.');
  }
  if (r.status === 401 || r.status === 403) {
    throw code
      ? new SignInError('code-denied', 'That code or password did not work. Codes change every 30 seconds — use the newest one, and check the password.')
      : new SignInError('denied', 'Wrong address or password. It is the password you sign in to Kaditham Mail with.');
  }
  if (!r.ok) throw new SignInError('server', `The mail server could not sign you in right now (it answered ${r.status}). Try again in a moment.`);
  const j = await r.json().catch(() => ({}));
  if (j.type === 'mfaRequired') throw new SignInError('needs-code', 'Enter the 6-digit code from your authenticator app.');
  if (j.type !== 'authenticated' || !j.client_code) {
    throw code
      ? new SignInError('code-denied', 'That code or password did not work. Codes change every 30 seconds — use the newest one.')
      : new SignInError('denied', 'Wrong address or password.');
  }
  let t: Response;
  try {
    t = await netFetch(apiUrl('/auth/token'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code', code: j.client_code, code_verifier: verifier,
        client_id: CLIENT_ID, redirect_uri: apiUrl('/oauth/callback'),
      }),
      signal: AbortSignal.timeout(TIMEOUT),
    });
  } catch (e) { throw offline(e); }
  if (!t.ok) throw new SignInError('server', 'The mail server did not complete the sign-in. Try again in a moment.');
  adopt(who, await t.json());
  accountSecret = secret;
  password = pass;
  await persist();
  changed();
}

/** Hand the password back to a resumed session (restore/sync need it).
 *  Re-derived, never adopted raw; proven by the keychain's proof gate on use. */
export async function provideSecrets(pass: string): Promise<void> {
  if (!session) throw new SignInError('denied', 'Sign in first.');
  await painted();
  accountSecret = await deriveAuthSecret(pass, session.address);
  password = pass;
}

/** The password, for the ring proof. Null on a resumed session. */
export const ringSecret = (): string | null => password;

async function doRefresh(): Promise<boolean> {
  const rt = session?.refresh;
  if (!rt) return false;
  const r = await netFetch(apiUrl('/auth/token'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: rt, client_id: CLIENT_ID }),
    signal: AbortSignal.timeout(TIMEOUT),
  }).catch(() => null);
  if (!r?.ok || !session) return false;
  adopt(session.address, await r.json());
  await persist();
  return true;
}

/** Make sure the access token has life left; single-flight. */
export async function ensureFresh(): Promise<boolean> {
  if (!session) return false;
  if (Date.now() < session.expiresAt - RENEW_MARGIN) return true;
  refreshing ??= doRefresh().finally(() => { refreshing = null; });
  return refreshing;
}

/** Pick up a session stored in the OS keychain at a previous run. Offline is
 *  not an error: the session stays, and calls retry when the network is back.
 *  A refresh the server REFUSES ends the session (keys stay, as always). */
export async function resume(): Promise<boolean> {
  if (!inShell()) return false;
  let raw: string | null = null;
  try { raw = await invoke<string | null>('account_session_get'); } catch { return false; }
  if (!raw) return false;
  let rec: Persisted;
  try { rec = JSON.parse(raw); } catch { return false; }
  if (rec?.v !== 1 || typeof rec.refresh !== 'string' || typeof rec.address !== 'string') return false;
  if (!SERVERS.some((s) => s === rec.server)) return false;
  setServerBase(rec.server);
  session = { address: rec.address, access: '', expiresAt: 0, refresh: rec.refresh };
  const r = await netFetch(apiUrl('/auth/token'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: rec.refresh, client_id: CLIENT_ID }),
    signal: AbortSignal.timeout(TIMEOUT),
  }).catch(() => null);
  if (r === null) { changed(); return true; }       // offline: keep the session, try later
  if (!r.ok) { await signOut(); return false; }     // refused: the session is over
  adopt(rec.address, await r.json());
  await persist();
  changed();
  return true;
}

/** Forget the session. The keys stay on this device (founder, 2026-10-02):
 *  they are sealed by this computer's keychain and remain usable offline. */
export async function signOut(): Promise<void> {
  session = null;
  accountSecret = null;
  password = null;
  if (inShell()) { try { await invoke('account_session_delete'); } catch { /* nothing stored */ } }
  changed();
}

export function header(): string {
  if (!session?.access) throw new Error('Not signed in.');
  return 'Bearer ' + session.access;
}

/** The keychain core's three hooks. */
mk.useAuth(() => (session?.access ? 'Bearer ' + session.access : ''));
mk.useProof(() => accountSecret);
mk.useDeviceName(() => deviceLabel());

export function deviceLabel(): string {
  const ua = typeof navigator !== 'undefined' ? navigator.userAgent : '';
  const os = /Windows/i.test(ua) ? 'Windows' : /Mac OS X|Macintosh/i.test(ua) ? 'macOS' : /Linux/i.test(ua) ? 'Linux' : 'this computer';
  return `Saavi on ${os}`;
}

// ------------------------------------------------------------------ JMAP

interface JmapSession { apiUrl: string; primaryAccounts: Record<string, string>; accounts: Record<string, unknown> }
let jmap: { s: JmapSession; for: string } | null = null;

async function authed(path: string, init: RequestInit = {}): Promise<Response> {
  if (!(await ensureFresh())) throw new SignInError('denied', 'Your session has ended — sign in again.');
  const go = () => netFetch(apiUrl(path), { ...init, headers: { ...(init.headers ?? {}), Authorization: header() }, signal: AbortSignal.timeout(TIMEOUT) });
  let r: Response;
  try { r = await go(); } catch (e) { throw offline(e); }
  if (r.status === 401 && session) {
    session.expiresAt = 0;
    if (await ensureFresh()) { try { r = await go(); } catch (e) { throw offline(e); } }
  }
  return r;
}

async function jmapSession(): Promise<JmapSession> {
  if (jmap && jmap.for === session?.address) return jmap.s;
  const r = await authed('/.well-known/jmap');
  if (!r.ok) throw new SignInError('server', 'Could not read your account from the mail server.');
  const s = await r.json() as JmapSession;
  // The session document names the server's INTERNAL origin; only the path
  // is ours to use (the webmail's toOwnOrigin does the same).
  s.apiUrl = new URL(s.apiUrl, serverBase()).pathname;
  jmap = { s, for: session!.address };
  return s;
}

async function jmapCall(calls: unknown[][], using: string[]): Promise<any[]> {
  const s = await jmapSession();
  const r = await authed(s.apiUrl, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ using, methodCalls: calls }),
  });
  if (!r.ok) throw new SignInError('server', 'The mail server did not answer that request.');
  return (await r.json()).methodResponses ?? [];
}

const acct = (s: JmapSession, cap: string): string => s.primaryAccounts[cap] ?? Object.keys(s.accounts)[0];

/** Every address this account may hold keys for: the login and its send-as
 *  identities (the broker's accountAddressSet rule). */
export async function addresses(): Promise<string[]> {
  const out = new Set<string>([session!.address]);
  try {
    const s = await jmapSession();
    const rs = await jmapCall([['Identity/get', { accountId: acct(s, SUBMISSION), properties: ['email'] }, '0']], [CORE, SUBMISSION]);
    for (const i of rs[0]?.[1]?.list ?? []) if (typeof i.email === 'string') out.add(i.email.trim().toLowerCase());
  } catch { /* the login address alone is still right */ }
  return [...out];
}

export interface AppPassword { description: string; createdAt: string | null }
export async function appPasswords(): Promise<AppPassword[]> {
  const s = await jmapSession();
  const rs = await jmapCall([['x:AppPassword/get', { accountId: acct(s, STALWART), properties: ['description', 'createdAt'] }, '0']], [CORE, STALWART]);
  if (rs[0]?.[0] !== 'x:AppPassword/get') throw new SignInError('server', 'The mail server would not list app passwords.');
  return (rs[0][1].list ?? []).map((p: Record<string, unknown>) => ({
    description: typeof p.description === 'string' && p.description ? p.description : 'Unnamed app password',
    createdAt: typeof p.createdAt === 'string' ? p.createdAt : null,
  }));
}

export interface KeychainDevice { label: string; firstAt: string | null; lastAt: string | null; current: boolean }
/** Devices that have downloaded this account's keychain (broker, 0.6.0). An
 *  older broker answers 404 — report "not available yet", not an error. */
export async function devices(): Promise<KeychainDevice[] | null> {
  const r = await authed('/signup/api/keychain/devices', { headers: { 'X-Device-Id': deviceIdHint() } });
  if (r.status === 404) return null;
  if (!r.ok) throw new SignInError('server', 'Could not list the devices holding your keychain.');
  const j = await r.json();
  return (Array.isArray(j.devices) ? j.devices : []).map((d: Record<string, unknown>) => ({
    label: typeof d.label === 'string' && d.label ? d.label : 'Unnamed device',
    firstAt: typeof d.firstAt === 'string' ? d.firstAt : null,
    lastAt: typeof d.lastAt === 'string' ? d.lastAt : null,
    current: d.current === true,
  }));
}

/** The keychain core mints and keeps the device id ('kad-device-id'); read it
 *  so the device list can mark "this computer". */
function deviceIdHint(): string {
  try { return localStorage.getItem('kad-device-id') ?? ''; } catch { return ''; }
}

/** The cheap status read (version only) — the focus-time change check. */
export async function keychainVersion(): Promise<number | null> {
  if (!(await ensureFresh())) return null;
  const st = await mk.status().catch(() => null);
  return st && st.exists ? st.version : st ? 0 : null;
}
