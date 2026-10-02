// What the shipped binary may talk to, checked against the files the build
// reads (cerberus C1/C3, 2026-10-02). A change that widens the network
// surface has to change this test, on purpose.
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { SERVERS, PRODUCTION, apiUrl, knownServer } from '../src/server';

const root = join(__dirname, '..');
const read = (p: string): string => readFileSync(join(root, p), 'utf8');

describe('the mail server Saavi signs in to', () => {
  it('is production, and only production — in every build', () => {
    expect(SERVERS).toEqual(['https://mail.kaditham.ie']);
    expect(PRODUCTION).toBe('https://mail.kaditham.ie');
    expect(() => knownServer('https://mail.kaditham.me')).toThrow();
    expect(() => apiUrl('/api/auth', 'https://mail.kaditham.me')).toThrow();
    expect(() => apiUrl('https://evil.example/api/auth')).toThrow();
  });

  it('no source, capability or shell file names the staging server', () => {
    for (const f of ['src/server.ts', 'src/account.ts', 'src/accountui.ts', 'src/mailkeychain.ts',
      'src-tauri/capabilities/default.json', 'src-tauri/tauri.conf.json', 'src-tauri/src/main.rs']) {
      expect(read(f), f).not.toMatch(/kaditham\.me(?![\w-])(?!@)/);
    }
  });
});

describe('the shell http client', () => {
  const caps = JSON.parse(read('src-tauri/capabilities/default.json'));
  const http = caps.permissions.find((p: { identifier?: string }) => p?.identifier === 'http:default');
  const urls: string[] = http.allow.map((a: { url: string }) => a.url);

  it('reaches Kaditham Mail only on the exact account paths', () => {
    const mail = urls.filter((u) => u.includes('mail.kaditham'));
    expect(mail.every((u) => u.startsWith('https://mail.kaditham.ie/'))).toBe(true);
    expect(mail.some((u) => u.includes('*'))).toBe(false);
    // Stalwart's session apiUrl may come with or without the slash.
    expect(mail).toContain('https://mail.kaditham.ie/jmap');
    expect(mail).toContain('https://mail.kaditham.ie/jmap/');
  });

  it('checks the scope on every redirect hop (tauri-plugin-http ≥ 2.7.0, scopeRedirects)', () => {
    // 2.7.0 added `scopeRedirects` (config.rs: camelCase, deny_unknown_fields;
    // commands.rs applies the scope in the redirect policy). Below 2.7.0 the
    // key would be an error, so both the version and the flag are pinned.
    const conf = JSON.parse(read('src-tauri/tauri.conf.json'));
    expect(conf.plugins.http).toEqual({ scopeRedirects: true });
    const lock = read('src-tauri/Cargo.lock');
    const m = lock.match(/name = "tauri-plugin-http"\r?\nversion = "(\d+)\.(\d+)\.(\d+)"/);
    expect(m).not.toBeNull();
    const [maj, min] = [Number(m![1]), Number(m![2])];
    expect(maj > 2 || (maj === 2 && min >= 7)).toBe(true);
    const pkg = JSON.parse(read('package-lock.json'));
    const js = pkg.packages['node_modules/@tauri-apps/plugin-http'].version as string;
    expect(js.startsWith(`${maj}.${min}.`)).toBe(true);
  });

  it('lists the GitHub asset host the release download redirects to', () => {
    expect(urls).toContain('https://release-assets.githubusercontent.com/**');
    expect(urls).toContain('https://objects.githubusercontent.com/**');
  });
});
