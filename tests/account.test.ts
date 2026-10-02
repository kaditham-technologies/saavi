// Sign in with Kaditham Mail (account.ts) against a fake mail server on the
// transport seam: the split (only the derived secret travels), two-factor,
// every named failure, the JMAP origin rewrite, and the device list's
// graceful answer on an older broker.
import { beforeEach, describe, expect, it } from 'vitest';
import { setNet, setServerBase } from '../src/server';
import * as account from '../src/account';
import { deriveAuthSecret } from '../src/derive';

const USER = 'me@x.ie';
const PASS = 'correct horse battery staple';
let seen: { url: string; body: string }[] = [];
let mode: 'ok' | 'mfa' | 'deny' | 'rate' | 'down' | 'oldbroker' = 'ok';

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
  if (path === '/auth/token') return json(200, { access_token: 'AT', refresh_token: 'RT', expires_in: 3600 });
  if (path === '/.well-known/jmap') {
    return json(200, { apiUrl: 'http://stalwart-internal:8080/jmap/', primaryAccounts: { 'urn:ietf:params:jmap:submission': 'a', 'urn:stalwart:jmap': 'a' }, accounts: { a: {} } });
  }
  if (path === '/jmap/') {
    const calls = JSON.parse(body).methodCalls as [string][];
    if (calls[0][0] === 'Identity/get') return json(200, { methodResponses: [['Identity/get', { list: [{ email: 'Me@X.ie' }, { email: 'sales@x.ie' }] }, '0']] });
    return json(200, { methodResponses: [['x:AppPassword/get', { list: [{ description: 'Thunderbird', createdAt: '2026-09-01T00:00:00Z' }, { description: '' }] }, '0']] });
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
    await expect(account.signIn(USER, PASS, undefined)).rejects.toMatchObject({ kind: 'rate', message: 'Too many attempts — wait 2 minutes.' });
    mode = 'down';
    await expect(account.signIn(USER, PASS, undefined)).rejects.toMatchObject({ kind: 'offline' });
  });

  it('refuses a bare login name before deriving anything', async () => {
    await expect(account.signIn('me', PASS, undefined)).rejects.toMatchObject({ kind: 'denied' });
    expect(seen).toHaveLength(0);
  });

  it('only ever talks to the two Kaditham mail servers', () => {
    expect(() => setServerBase('https://evil.example')).toThrow();
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
    expect(addrs.sort()).toEqual(['me@x.ie', 'sales@x.ie']);
    expect(seen.some((s) => s.url.startsWith('https://mail.kaditham.ie/jmap/'))).toBe(true);
    expect(seen.some((s) => s.url.includes('stalwart-internal'))).toBe(false);
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
