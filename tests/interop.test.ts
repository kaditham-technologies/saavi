// Interop harness: our OpenPGP output must round-trip through REAL GnuPG,
// and GnuPG's output must open in our store. Runs only when a gpg binary
// is on PATH; CI without gpg just skips.
//
// GNUPGHOME lives in os.tmpdir() (not a project scratch dir): gpg-agent
// sockets cap the home path length, so it must stay short.
import { beforeEach, describe, expect, it } from 'vitest';
import { execFileSync, type ExecFileSyncOptions } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as mime from '../src/mime';
import * as pgp from '../src/pgp';

// OpenPGP text-mode literals canonicalise line endings (CRLF and LF are
// interchangeable across implementations) — compare MIME semantics, not bytes.
const norm = (s: string) => s.replace(/\r\n/g, '\n');

const PASS = 'correct horse battery staple';
const ME = 'interop@example.org';

function gpgAvailable(): boolean {
  try {
    execFileSync('gpg', ['--version'], { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

// Windows CI ships an MSYS gpg that mangles a native GNUPGHOME path
// (C:\… turns into /d/a/…/C:\…), so the throwaway keyring is never found.
// The interop guarantee is identical on every OS; proving it on Linux and
// macOS is enough, and not worth an unportable keyring dance on Windows.
const interop = gpgAvailable() && process.platform !== 'win32';

describe.skipIf(!interop)('GnuPG interop', () => {
  let home: string;
  const gpg = (args: string[], opts: ExecFileSyncOptions = {}) =>
    execFileSync('gpg', ['--batch', '--yes', '--pinentry-mode', 'loopback', ...args], {
      env: { ...process.env, GNUPGHOME: home },
      stdio: ['pipe', 'pipe', 'pipe'],
      ...opts,
    });

  beforeEach(() => {
    localStorage.clear();
    pgp.clearSession();
    home = mkdtempSync(join(tmpdir(), 'saavi-gpg-'));
    return () => {
      try { execFileSync('gpgconf', ['--kill', 'gpg-agent'], { env: { ...process.env, GNUPGHOME: home }, stdio: 'pipe' }); } catch { /* no agent ran */ }
      rmSync(home, { recursive: true, force: true });
    };
  });

  it('gpg decrypts a sealed MIME letter we built, and sees a good signature', async () => {
    const rec = await pgp.generateKeys(ME, 'Interop', PASS);
    await pgp.unlockPrivateKey(ME, PASS);
    gpg(['--passphrase', PASS, '--import'], { input: rec.privateKey });
    const inner = mime.buildMimeEntity({
      subject: 'interop subject', text: 'across implementations',
      attachments: [{ name: 'x.bin', type: 'application/octet-stream', bytes: new Uint8Array([7, 8, 9]) }],
    });
    const armored = await pgp.encryptText(inner, [rec.publicKey], ME);
    let plain = '';
    try {
      plain = String(gpg(['--passphrase', PASS, '--decrypt'], { input: armored, encoding: 'utf8' }));
    } catch (e) {
      throw new Error('gpg could not decrypt our output: ' + String((e as { stderr?: unknown }).stderr ?? e));
    }
    expect(norm(plain)).toBe(norm(inner));
    const parsed = mime.parseMimeEntity(plain);
    expect(parsed.subject).toBe('interop subject');
    expect([...parsed.attachments[0].bytes]).toEqual([7, 8, 9]);
    // signature verdict via machine-readable status lines. The plaintext is
    // written to a throwaway file in `home`, never /dev/null: gpg writes its
    // output through a sibling "<out>.part" temp, and /dev/null.part is not
    // creatable on the CI runners (Permission denied), which failed the whole
    // step even though decryption and the signature check both succeeded.
    const status = String(gpg(['--passphrase', PASS, '--status-fd', '1', '-o', join(home, 'verify.out'), '--decrypt'], { input: armored, encoding: 'utf8' }));
    expect(status).toMatch(/GOODSIG/);
  });

  it('we decrypt what gpg encrypted to our key', async () => {
    const rec = await pgp.generateKeys(ME, 'Interop', PASS);
    await pgp.unlockPrivateKey(ME, PASS);
    writeFileSync(join(home, 'pub.asc'), rec.publicKey);
    gpg(['--import', join(home, 'pub.asc')]);
    const payload = mime.buildMimeEntity({ subject: 'from gnupg', text: 'gpg made this ciphertext' });
    const armored = String(gpg(
      ['--trust-model', 'always', '--armor', '--recipient', ME, '--encrypt'],
      { input: payload, encoding: 'utf8' }
    ));
    const dec = await pgp.decryptText(armored);
    expect(norm(dec.text)).toBe(norm(payload));
    const parsed = mime.parseMimeEntity(dec.text);
    expect(parsed.subject).toBe('from gnupg');
    expect(parsed.text).toBe('gpg made this ciphertext');
  });
});
