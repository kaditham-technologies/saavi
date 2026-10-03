// The keychain's pure core: blob validation, the union merge, and the
// locked-material assertion. Each test names the property it pins.
import { describe, expect, it } from 'vitest';
import * as openpgp from 'openpgp';
import { assertLocked, bindRecord, ENGINE_FAILURE, mergeEnvelopes, mergeRings, openEnvelope, parseBlob } from '../src/mailkeychain';
import type { KitEnvelope } from '../src/mailkeychain';
import type { KeyRecord, KeyRing } from '../src/pgp';

/** A real locked key pair for the binding tests. */
async function lockedPair(email = 't@example.com', passphrase = 'a passphrase long enough') {
  const { privateKey, publicKey } = await openpgp.generateKey({
    userIDs: [{ name: 'T', email }],
    passphrase,
    type: 'ecc',
    curve: 'curve25519Legacy' as const,
    format: 'armored',
  });
  return { privateKey, publicKey, passphrase };
}

const PRIV = '-----BEGIN PGP PRIVATE KEY BLOCK-----\nxxx\n-----END PGP PRIVATE KEY BLOCK-----';
const PUB = '-----BEGIN PGP PUBLIC KEY BLOCK-----\nxxx\n-----END PGP PUBLIC KEY BLOCK-----';

const rec = (tag: string): KeyRecord => ({
  publicKey: PUB.replace('xxx', tag),
  privateKey: PRIV.replace('xxx', tag),
  created: '2026-01-01T00:00:00.000Z',
});
const ring = (active: string, ...retired: string[]): KeyRing => ({
  active: rec(active),
  retired: retired.map(rec),
});
// A fake fingerprint extractor: the tag inside the armor IS the fingerprint.
const fakeFpr = async (r: KeyRecord): Promise<string> => r.publicKey.split('\n')[1];

const blob = (rings: Record<string, KeyRing>): string =>
  JSON.stringify({ v: 1, exportedAt: '2026-01-01T00:00:00.000Z', rings });

describe('parseBlob', () => {
  it('round-trips the exact shape this module writes', () => {
    const b = parseBlob(blob({ 'a@example.com': ring('k1', 'k0') }));
    expect(Object.keys(b.rings)).toEqual(['a@example.com']);
    expect(b.rings['a@example.com'].retired).toHaveLength(1);
  });

  it.each([
    ['not JSON', 'nope'],
    ['unknown version', JSON.stringify({ v: 3, rings: {}, envelopes: {} })],
    ['rings as array', JSON.stringify({ v: 1, rings: [] })],
    ['no rings', JSON.stringify({ v: 1 })],
    ['non-address key', blob({ 'not an email': ring('k1') })],
    ['record without private armor', JSON.stringify({ v: 1, rings: { 'a@example.com': { active: { publicKey: PUB, privateKey: 'raw', created: 'x' }, retired: [] } } })],
    ['retired not an array', JSON.stringify({ v: 1, rings: { 'a@example.com': { active: rec('k'), retired: {} } } })],
    ['oversized', JSON.stringify({ v: 1, exportedAt: 'x'.repeat(400000), rings: {} })],
  ])('rejects %s', (_name, s) => {
    expect(() => parseBlob(s as string)).toThrow('could not be read');
  });

  // ---- blob v2: the recovery kit's envelopes (M5) ----

  const ENV_ID = 'ab12cd34ef56ab12cd34ef56ab12cd34';
  const envKey = (tag: string) => ({ armor: PRIV.replace('xxx', tag), created: '2026-02-01T00:00:00.000Z' });
  const v2 = (envelopes: unknown, rings: Record<string, KeyRing> = { 'a@example.com': ring('k1') }): string =>
    JSON.stringify({ v: 2, exportedAt: '2026-02-01T00:00:00.000Z', rings, envelopes });

  it('round-trips a v2 blob with an envelope', () => {
    const b = parseBlob(v2({ [ENV_ID]: { createdAt: '2026-02-01T00:00:00.000Z', keys: { 'a@example.com': { active: envKey('e1'), retired: [envKey('e0')] } } } }));
    expect(b.v).toBe(2);
    expect(Object.keys(b.envelopes)).toEqual([ENV_ID]);
    expect(b.envelopes[ENV_ID].keys['a@example.com'].retired).toHaveLength(1);
  });

  it.each([
    ['v2 without envelopes', JSON.stringify({ v: 2, rings: {} })],
    ['envelopes as array', v2([])],
    ['bad envelope id', v2({ 'NOT-HEX': { createdAt: 'x', keys: { 'a@example.com': { active: envKey('e'), retired: [] } } } })],
    ['envelope without createdAt', v2({ [ENV_ID]: { keys: { 'a@example.com': { active: envKey('e'), retired: [] } } } })],
    ['envelope key without armor marker', v2({ [ENV_ID]: { createdAt: 'x', keys: { 'a@example.com': { active: { armor: 'raw', created: 'x' }, retired: [] } } } })],
    ['envelope retired not an array', v2({ [ENV_ID]: { createdAt: 'x', keys: { 'a@example.com': { active: envKey('e'), retired: {} } } } })],
    ['envelope key for a non-address', v2({ [ENV_ID]: { createdAt: 'x', keys: { 'not an email': { active: envKey('e'), retired: [] } } } })],
  ])('rejects %s', (_name, s) => {
    expect(() => parseBlob(s)).toThrow('could not be read');
  });

  it('a v1 blob parses with no envelopes — kit-less accounts stay v1', () => {
    expect(parseBlob(blob({ 'a@example.com': ring('k1') })).envelopes).toEqual({});
  });

  it('drops attacker-supplied extra fields on the way in', () => {
    const poisoned = JSON.stringify({
      v: 1,
      rings: { 'a@example.com': { active: { ...rec('k1'), evil: 'x', __proto__: { polluted: true } }, retired: [] } },
    });
    const out = parseBlob(poisoned);
    expect((out.rings['a@example.com'].active as unknown as Record<string, unknown>).evil).toBeUndefined();
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });
});

describe('bindRecord', () => {
  it('derives the public half from the private half, ignoring the supplied one', async () => {
    const real = await lockedPair('a@example.com');
    const other = await lockedPair('a@example.com');
    // An attacker keeps the genuine locked private key but swaps in THEIR
    // public key. bindRecord must reject the substitution by re-deriving.
    const bound = await bindRecord('a@example.com', { publicKey: other.publicKey, privateKey: real.privateKey, created: 'x' }, true);
    const derivedFpr = (await openpgp.readKey({ armoredKey: bound.publicKey })).getFingerprint();
    const realFpr = (await openpgp.readKey({ armoredKey: real.publicKey })).getFingerprint();
    const otherFpr = (await openpgp.readKey({ armoredKey: other.publicKey })).getFingerprint();
    expect(derivedFpr).toBe(realFpr);
    expect(derivedFpr).not.toBe(otherFpr);
  });

  it('rejects an unlocked private key', async () => {
    const { privateKey, publicKey, passphrase } = await lockedPair('a@example.com');
    const parsed = await openpgp.readPrivateKey({ armoredKey: privateKey });
    const bare = await openpgp.decryptKey({ privateKey: parsed, passphrase });
    await expect(bindRecord('a@example.com', { publicKey, privateKey: bare.armor(), created: 'x' }, true))
      .rejects.toThrow('not passphrase-locked');
  });

  it('rejects an active key that does not carry the ring address', async () => {
    const { privateKey, publicKey } = await lockedPair('someone@example.org');
    await expect(bindRecord('victim@example.com', { publicKey, privateKey, created: 'x' }, true))
      .rejects.toThrow('does not belong to');
  });
});

describe('mergeRings', () => {
  it('keeps the local active key when both sides know the address', async () => {
    const merged = await mergeRings({ 'a@example.com': ring('mine') }, { 'a@example.com': ring('theirs') }, fakeFpr);
    expect(await fakeFpr(merged['a@example.com'].active)).toBe('mine');
  });

  it("retires the remote side's keys instead of dropping them", async () => {
    const merged = await mergeRings(
      { 'a@example.com': ring('mine', 'old1') },
      { 'a@example.com': ring('theirs', 'old2') },
      fakeFpr
    );
    const retired = await Promise.all(merged['a@example.com'].retired.map(fakeFpr));
    expect(retired.sort()).toEqual(['old1', 'old2', 'theirs']);
  });

  it('never duplicates a key both sides hold', async () => {
    const merged = await mergeRings(
      { 'a@example.com': ring('k1', 'shared') },
      { 'a@example.com': ring('shared', 'k1') },
      fakeFpr
    );
    expect(merged['a@example.com'].retired).toHaveLength(1);
  });

  it('adopts an address only the other side knows, whole', async () => {
    const merged = await mergeRings({ 'a@example.com': ring('k1') }, { 'b@example.com': ring('k2', 'k0') }, fakeFpr);
    expect(await fakeFpr(merged['b@example.com'].active)).toBe('k2');
    expect(merged['b@example.com'].retired).toHaveLength(1);
  });

  it('does not mutate its inputs', async () => {
    const local = { 'a@example.com': ring('mine') };
    await mergeRings(local, { 'a@example.com': ring('theirs') }, fakeFpr);
    expect(local['a@example.com'].retired).toHaveLength(0);
  });
});

describe('assertLocked', () => {
  it('passes a passphrase-locked key and refuses the same key unlocked', async () => {
    const { privateKey, publicKey } = await openpgp.generateKey({
      userIDs: [{ name: 'T', email: 't@example.com' }],
      passphrase: 'a passphrase long enough',
      type: 'ecc',
      curve: 'curve25519Legacy' as const,
      format: 'armored',
    });
    const locked: KeyRing = { active: { publicKey, privateKey, created: 'x' }, retired: [] };
    await expect(assertLocked(locked)).resolves.toBeUndefined();

    const parsed = await openpgp.readPrivateKey({ armoredKey: privateKey });
    const bare = await openpgp.decryptKey({ privateKey: parsed, passphrase: 'a passphrase long enough' });
    const leaked: KeyRing = { active: { publicKey, privateKey: bare.armor(), created: 'x' }, retired: [] };
    await expect(assertLocked(leaked)).rejects.toThrow('not passphrase-locked');
  });
});

describe('the recovery envelope (M5)', () => {
  it('mergeEnvelopes unions by id, local serving on a shared one', () => {
    const env = (tag: string): KitEnvelope => ({ createdAt: tag, keys: {} });
    const out = mergeEnvelopes({ aa11: env('local') } as never, { aa11: env('remote'), bb22: env('other') } as never);
    expect(Object.keys(out).sort()).toEqual(['aa11', 'bb22']);
    expect(out.aa11.createdAt).toBe('local');
  });

  it('openEnvelope proves the phrase, derives the public half, and keeps the armor locked', async () => {
    const phrase = 'apple  Brave cable DAISY eagle fable gamma habit';   // sloppy spacing/case — canonical form opens it
    const canonical = 'apple brave cable daisy eagle fable gamma habit';
    const { privateKey } = await openpgp.generateKey({
      userIDs: [{ name: 'T', email: 'a@example.com' }],
      passphrase: canonical,
      type: 'ecc', curve: 'curve25519Legacy' as const, format: 'armored',
    });
    const env: KitEnvelope = { createdAt: '2026-02-01T00:00:00.000Z', keys: { 'a@example.com': { active: { armor: privateKey, created: '2026-01-01T00:00:00.000Z' }, retired: [] } } };
    const rings = await openEnvelope(env, phrase);
    expect(Object.keys(rings)).toEqual(['a@example.com']);
    // The public half is DERIVED and the private armor stays locked.
    const pub = await openpgp.readKey({ armoredKey: rings['a@example.com'].active.publicKey });
    const priv = await openpgp.readPrivateKey({ armoredKey: rings['a@example.com'].active.privateKey });
    expect(pub.getFingerprint()).toBe(priv.getFingerprint());
    expect(priv.isDecrypted()).toBe(false);
    expect(rings['a@example.com'].active.created).toBe('2026-01-01T00:00:00.000Z');

    await expect(openEnvelope(env, 'wrong words entirely here yes eight of them')).rejects.toThrow('does not open');
  });
});

describe('lock epochs (C4/A1)', () => {
  const recAt = (fprTag: string, armorTag: string, lockEpoch?: number): KeyRecord => ({
    publicKey: PUB.replace('xxx', fprTag),
    privateKey: PRIV.replace('xxx', armorTag),
    created: '2026-01-01T00:00:00.000Z',
    ...(lockEpoch !== undefined ? { lockEpoch } : {}),
  });

  it('parseBlob carries a sane lockEpoch and strips a bogus one', () => {
    const good = parseBlob(blob({ 'a@example.com': { active: recAt('k1', 'k1-e2', 2), retired: [] } }));
    expect(good.rings['a@example.com'].active.lockEpoch).toBe(2);
    for (const bad of [-1, 2.5, 1e9, 'high' as unknown as number]) {
      const out = parseBlob(blob({ 'a@example.com': { active: recAt('k1', 'k1', bad as number), retired: [] } }));
      expect(out.rings['a@example.com'].active.lockEpoch).toBeUndefined();
    }
  });

  it('parseBlob refuses a stuffed ring (records capped at 16)', () => {
    const retired = Array.from({ length: 16 }, (_, i) => rec('r' + i));
    expect(() => parseBlob(blob({ 'a@example.com': { active: rec('k1'), retired } }))).toThrow('could not be read');
    expect(parseBlob(blob({ 'a@example.com': { active: rec('k1'), retired: retired.slice(0, 15) } }))).toBeTruthy();
  });

  it('merge keeps BOTH armors of the same key — a new lock is never dropped', async () => {
    const merged = await mergeRings(
      { 'a@example.com': { active: recAt('k1', 'k1-old', 0), retired: [] } },
      { 'a@example.com': { active: recAt('k1', 'k1-new', 1), retired: [] } },
      fakeFpr
    );
    const armors = [merged['a@example.com'].active, ...merged['a@example.com'].retired].map((r) => r.privateKey);
    expect(armors).toHaveLength(2);
  });

  it('merge promotes the higher-epoch armor of the active key (A1), key unchanged (P2)', async () => {
    const merged = await mergeRings(
      { 'a@example.com': { active: recAt('k1', 'k1-old', 0), retired: [rec('rotated')] } },
      { 'a@example.com': { active: recAt('k1', 'k1-new', 3), retired: [] } },
      fakeFpr
    );
    expect(merged['a@example.com'].active.privateKey).toContain('k1-new');
    expect(await fakeFpr(merged['a@example.com'].active)).toBe('k1');
    const retired = merged['a@example.com'].retired.map((r) => r.privateKey);
    expect(retired.some((a) => a.includes('k1-old'))).toBe(true);
    expect(retired.some((a) => a.includes('rotated'))).toBe(true);
  });

  it('an epoch tie breaks deterministically — both merge orders agree', async () => {
    const a = recAt('k1', 'k1-armA', 1);
    const b = recAt('k1', 'k1-armB', 1);
    const one = await mergeRings({ 'a@example.com': { active: a, retired: [] } }, { 'a@example.com': { active: b, retired: [] } }, fakeFpr);
    const two = await mergeRings({ 'a@example.com': { active: b, retired: [] } }, { 'a@example.com': { active: a, retired: [] } }, fakeFpr);
    expect(one['a@example.com'].active.privateKey).toBe(two['a@example.com'].active.privateKey);
  });
});

describe('an unlock-engine failure is never a wrong passphrase', () => {
  // The exact words the two webview engines gave in 0.6.0 when the CSP
  // refused Argon2's WebAssembly (reproduced in Playwright, 2026-10-03).
  const chromium = "Error decrypting private key: WebAssembly.instantiate(): Compiling or instantiating WebAssembly module violates the following Content Security policy directive because 'unsafe-eval' is not an allowed source of script in the following Content Security Policy directive: \"script-src 'self'\".";
  const webkit = "Error decrypting private key: Refused to create a WebAssembly object because 'unsafe-eval' or 'wasm-unsafe-eval' is not an allowed source of script in the following Content Security Policy directive: \"script-src 'self'\".";

  it('recognises the webview refusals as engine failures', () => {
    expect(ENGINE_FAILURE.test(chromium)).toBe(true);
    expect(ENGINE_FAILURE.test(webkit)).toBe(true);
  });

  it('leaves a real wrong passphrase to the passphrase path', () => {
    expect(ENGINE_FAILURE.test('Error decrypting private key: Incorrect key passphrase')).toBe(false);
    expect(ENGINE_FAILURE.test('Error decrypting private key: Incorrect key passphrase: Authentication tag mismatch')).toBe(false);
  });
});
