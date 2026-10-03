// Sign in with Kaditham Mail (account.ts) against a fake mail server on the
// transport seam: the split (only the derived secret travels), two-factor,
// every named failure, the JMAP origin rewrite, and the device list's
// graceful answer on an older broker.
import { beforeEach, describe, expect, it } from 'vitest';
import { setNet, setServerBase } from '../src/server';
import * as account from '../src/account';
import { deriveAuthSecret } from '../src/derive';

const USER = 'me@example.com';
const PASS = 'correct horse battery staple';
let seen: { url: string; body: string }[] = [];
let mode: 'ok' | 'mfa' | 'deny' | 'rate' | 'down' | 'oldbroker' = 'ok';
/** What GET /signup/api/me answers: null = 404 (an older broker). */
let meAddresses: unknown = null;
/** JMAP Identity/get answers 500 (the broker still answers). */
let idsDown = false;
let tokenStatus = 200;
let tokenGate: Promise<void> | null = null;

const json = (status: number, body: unknown): Response =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

setNet(async (input, init) => {
  const url = String(input);
  const body = typeof init?.body === 'string' ? init.body : init?.body ? String(init.body) : '';
  seen.push({ url, body });
  if (mode === 'down') throw new TypeError('network down');
  const path = new URL(url).pathname;
  if (path === '/api/auth') {
    if (mode === 'rate') return json(429, { error: 'Too many attempts — wait 2 minutes.' });
    if (mode === 'deny') return json(401, {});
    const p = JSON.parse(body);
    if (p.accountSecret !== await deriveAuthSecret(PASS, USER)) return json(401, {});
    if (p.clientId !== 'kaditham-saavi') return json(400, {});
    if (mode === 'mfa' && p.mfaToken !== '123456') return json(200, { type: 'mfaRequired' });
    return json(200, { type: 'authenticated', client_code: 'C' });
  }
  if (path === '/auth/token') {
    if (body.includes('grant_type=refresh_token')) {
      if (tokenGate) await tokenGate;
      if (tokenStatus !== 200) return json(tokenStatus, { error: 'x' });
    }
    return json(200, { access_token: 'AT', refresh_token: 'RT', expires_in: 3600 });
  }
  if (path === '/.well-known/jmap') {
    return json(200, { apiUrl: 'http://stalwart-internal:8080/jmap/', primaryAccounts: { 'urn:ietf:params:jmap:submission': 'a', 'urn:stalwart:jmap': 'a' }, accounts: { a: {} } });
  }
  if (path === '/jmap/') {
    const calls = JSON.parse(body).methodCalls as [string][];
    if (calls[0][0] === 'Identity/get' && idsDown) return json(500, {});
    if (calls[0][0] === 'Identity/get') return json(200, { methodResponses: [['Identity/get', { list: [{ email: 'Me@example.com' }, { email: 'sales@example.com' }] }, '0']] });
    return json(200, { methodResponses: [['x:AppPassword/get', { list: [{ description: 'Thunderbird', createdAt: '2026-09-01T00:00:00Z' }, { description: '' }] }, '0']] });
  }
  if (path === '/signup/api/me') {
    if (meAddresses === null) return json(404, { error: 'Not found.' });
    return json(200, { email: 'me', addresses: meAddresses });
  }
  if (path === '/signup/api/keychain/devices') {
    if (mode === 'oldbroker') return json(404, { error: 'Not found.' });
    return json(200, { devices: [{ label: 'Saavi on Linux', firstAt: 'a', lastAt: 'b', current: true }] });
  }
  return json(404, {});
});

beforeEach(async () => {
  seen = [];
  mode = 'ok';
  tokenStatus = 200;
  tokenGate = null;
  meAddresses = null;
  idsDown = false;
  await account.signOut();
  setServerBase('https://mail.kaditham.ie');
});

describe('sign in', () => {
  it('sends only the derived secret, never the password', async () => {
    await account.signIn(USER, PASS, undefined);
    expect(account.signedIn()).toBe(true);
    expect(account.hasSecrets()).toBe(true);
    for (const s of seen) expect(s.body).not.toContain(PASS);
  });

  it('asks for the code when two-factor is on, then signs in with it', async () => {
    mode = 'mfa';
    await expect(account.signIn(USER, PASS, undefined)).rejects.toMatchObject({ kind: 'needs-code' });
    expect(account.signedIn()).toBe(false);
    await account.signIn(USER, PASS, '123 456');
    expect(account.signedIn()).toBe(true);
  });

  it('names a wrong password, a wrong code, a rate limit and an outage', async () => {
    mode = 'deny';
    await expect(account.signIn(USER, 'nope', undefined)).rejects.toMatchObject({ kind: 'denied' });
    await expect(account.signIn(USER, 'nope', '000000')).rejects.toMatchObject({ kind: 'code-denied' });
    mode = 'rate';
    // Fixed copy — the server's own words are never shown.
    await expect(account.signIn(USER, PASS, undefined)).rejects.toMatchObject({ kind: 'rate', message: account.RATE_LIMITED });
    mode = 'down';
    await expect(account.signIn(USER, PASS, undefined)).rejects.toMatchObject({ kind: 'offline' });
  });

  it('refuses a bare login name before deriving anything', async () => {
    await expect(account.signIn('me', PASS, undefined)).rejects.toMatchObject({ kind: 'denied' });
    expect(seen).toHaveLength(0);
  });

  it('only ever talks to mail.kaditham.ie', () => {
    expect(() => setServerBase('https://evil.example')).toThrow();
    expect(() => setServerBase('https://mail.kaditham.me')).toThrow();
  });

  it('sign-out forgets the session and the secrets', async () => {
    await account.signIn(USER, PASS, undefined);
    await account.signOut();
    expect(account.signedIn()).toBe(false);
    expect(account.ringSecret()).toBeNull();
  });
});

describe('account reads', () => {
  it('rewrites the JMAP apiUrl onto the public origin and lists identities', async () => {
    await account.signIn(USER, PASS, undefined);
    const addrs = await account.addresses();
    expect(addrs.complete).toBe(true);
    expect(addrs.list.sort()).toEqual(['me@example.com', 'sales@example.com']);
    expect(seen.some((s) => s.url.startsWith('https://mail.kaditham.ie/jmap/'))).toBe(true);
    expect(seen.some((s) => s.url.includes('stalwart-internal'))).toBe(false);
  });

  it('says when the alias list could not be read, instead of a quiet subset (argus A4)', async () => {
    await account.signIn(USER, PASS, undefined);
    mode = 'down';
    const addrs = await account.addresses();
    expect(addrs).toEqual({ list: ['me@example.com'], complete: false, primary: null, push: null });
  });

  it('brings from broker ∪ identities, primary first; pushes only what the keychain accepts', async () => {
    await account.signIn(USER, PASS, undefined);
    meAddresses = [
      { email: 'Chari@Example.com', primary: true, enabled: true },
      { email: 'old@example.com', primary: false, enabled: false },
      { email: 'not an address', primary: false, enabled: true },
    ];
    const addrs = await account.addresses();
    // A disabled alias is still brought (its ring may already be in the
    // keychain); the identity-only address is kept too (argus, 0.6.2).
    expect(addrs).toEqual({
      list: ['chari@example.com', 'old@example.com', 'me@example.com', 'sales@example.com'],
      complete: true, primary: 'chari@example.com', push: ['me@example.com', 'sales@example.com'],
    });
    expect(account.primaryAddress()).toBe('chari@example.com');
    await account.signOut();
    expect(account.primaryAddress()).toBeNull();
  });

  it('tells the main window once when the primary changes', async () => {
    await account.signIn(USER, PASS, undefined);
    let n = 0;
    const off = account.onPrimaryChange(() => { n++; });
    meAddresses = [{ email: 'chari@example.com', primary: true, enabled: true }];
    await account.addresses();
    await account.addresses();
    expect(n).toBe(1);
    await account.signOut();
    expect(n).toBe(2);
    off();
  });

  it('a broker answer without identities still brings everything, but sync waits', async () => {
    await account.signIn(USER, PASS, undefined);
    meAddresses = [{ email: 'chari@example.com', primary: true, enabled: true }];
    idsDown = true;
    const addrs = await account.addresses();
    expect(addrs).toEqual({ list: ['chari@example.com', 'me@example.com'], complete: true, primary: 'chari@example.com', push: null });
  });

  it('falls back to JMAP identities when the broker names no primary', async () => {
    await account.signIn(USER, PASS, undefined);
    meAddresses = [{ email: 'sales@example.com', primary: false, enabled: true }];
    const addrs = await account.addresses();
    expect(addrs.primary).toBeNull();
    expect(addrs.complete).toBe(true);
    expect(addrs.list.sort()).toEqual(['me@example.com', 'sales@example.com']);
    expect(addrs.push).toEqual(['me@example.com', 'sales@example.com']);
    expect(account.primaryAddress()).toBeNull();
  });

  it('lists app passwords, naming the unnamed', async () => {
    await account.signIn(USER, PASS, undefined);
    const aps = await account.appPasswords();
    expect(aps.map((a) => a.description)).toEqual(['Thunderbird', 'Unnamed app password']);
  });

  it('the device list says "not available" on an older broker instead of failing', async () => {
    await account.signIn(USER, PASS, undefined);
    expect((await account.devices())?.[0]).toMatchObject({ label: 'Saavi on Linux', current: true });
    mode = 'oldbroker';
    expect(await account.devices()).toBeNull();
  });
});

describe('refresh: only a refused grant ends the session (argus A3)', () => {
  it('classifies answers', () => {
    expect(account.classifyRefresh(200)).toBe('ok');
    for (const s of [400, 401, 403]) expect(account.classifyRefresh(s)).toBe('ended');
    for (const s of [429, 500, 502, 503]) expect(account.classifyRefresh(s)).toBe('unavailable');
    expect(account.classifyRefresh(null)).toBe('unavailable');
  });

  it('a 5xx keeps the session and says the server is away — never "ended"', async () => {
    await account.signIn(USER, PASS, undefined);
    account._expireForTest();
    tokenStatus = 503;
    await expect(account.ready()).rejects.toMatchObject({ kind: 'offline' });
    expect(account.signedIn()).toBe(true);
    tokenStatus = 200;
    await expect(account.ready()).resolves.toBeUndefined();
  });

  it('a refused grant ends it', async () => {
    await account.signIn(USER, PASS, undefined);
    account._expireForTest();
    tokenStatus = 400;
    await expect(account.ready()).rejects.toMatchObject({ kind: 'denied' });
    expect(account.signedIn()).toBe(false);
  });

  it('signing out while a refresh is in flight does not bring the session back (argus A6)', async () => {
    await account.signIn(USER, PASS, undefined);
    account._expireForTest();
    let open!: () => void;
    tokenGate = new Promise((r) => { open = r; });
    const pending = account.ensureFresh();
    await account.signOut();
    open();
    expect(await pending).toBe('ended');
    expect(account.signedIn()).toBe(false);
  });

  it('forgetSecrets drops the password but keeps the session', async () => {
    await account.signIn(USER, PASS, undefined);
    account.forgetSecrets();
    expect(account.signedIn()).toBe(true);
    expect(account.hasSecrets()).toBe(false);
    expect(account.ringSecret()).toBeNull();
  });
});
