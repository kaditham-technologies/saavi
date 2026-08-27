import { beforeEach, describe, expect, it } from 'vitest';
import * as openpgp from 'openpgp';
import * as pgp from '../src/pgp';

const PASS = 'correct horse battery staple';
const ME = 'me@example.org';

beforeEach(() => {
  localStorage.clear();
  pgp.clearSession();
});

describe('keystore', () => {
  it('generates, stores locked, and lists a key', async () => {
    const rec = await pgp.generateKeys(ME, 'Me', PASS);
    expect(rec.privateKey).toContain('BEGIN PGP PRIVATE KEY BLOCK');
    const stored = await openpgp.readPrivateKey({ armoredKey: pgp.keysFor(ME)!.privateKey });
    expect(stored.isDecrypted()).toBe(false);
    const list = await pgp.listKeys(ME);
    expect(list).toHaveLength(1);
    expect(list[0]).toMatchObject({ isActive: true, unlocked: false });
    expect(list[0].fingerprint).toMatch(/^([0-9A-F]{4} ){9}[0-9A-F]{4}$/);
    expect(pgp.isUnlocked(ME)).toBe(false);
  });

  it('unlocks with the right passphrase only', async () => {
    await pgp.generateKeys(ME, 'Me', PASS);
    await expect(pgp.unlockPrivateKey(ME, 'wrong')).rejects.toThrow();
    expect(pgp.isUnlocked(ME)).toBe(false);
    expect(pgp.hasUnlockedKeys()).toBe(false);
    await pgp.unlockPrivateKey(ME, PASS);
    expect(pgp.isUnlocked(ME)).toBe(true);
    expect(pgp.hasUnlockedKeys()).toBe(true);
    pgp.clearSession(); // what Lock / the idle timer call
    expect(pgp.isUnlocked(ME)).toBe(false);
    expect(pgp.hasUnlockedKeys()).toBe(false);
  });

  it('rotating retires the old key instead of deleting it', async () => {
    const a = await pgp.generateKeys(ME, 'Me', PASS);
    const b = await pgp.generateKeys(ME, 'Me', PASS);
    const ring = pgp.ringFor(ME)!;
    expect(ring.active.publicKey).toBe(b.publicKey);
    expect(ring.retired.map((r) => r.publicKey)).toEqual([a.publicKey]);
    const list = await pgp.listKeys(ME);
    expect(list.map((k) => k.isActive)).toEqual([true, false]);
    // the active key cannot be deleted; a retired one can
    await pgp.deleteRetired(ME, list[0].fingerprint);
    expect(pgp.ringFor(ME)!.retired).toHaveLength(1);
    await pgp.deleteRetired(ME, list[1].fingerprint);
    expect(pgp.ringFor(ME)!.retired).toHaveLength(0);
    expect(pgp.keysFor(ME)!.publicKey).toBe(b.publicKey);
  });

  it('migrates a v1 bare record into a ring', async () => {
    const rec = await pgp.generateKeys('old@example.org', 'Old', PASS);
    localStorage.setItem('saavi-ring-old@example.org', JSON.stringify(rec));
    const ring = pgp.ringFor('old@example.org')!;
    expect(ring.active.publicKey).toBe(rec.publicKey);
    expect(ring.retired).toEqual([]);
    expect(JSON.parse(localStorage.getItem('saavi-ring-old@example.org')!).active).toBeDefined();
  });

  it('ignores corrupt storage rather than throwing', () => {
    localStorage.setItem('saavi-ring-' + ME, '{not json');
    expect(pgp.keysFor(ME)).toBeNull();
    localStorage.setItem('saavi-ring-' + ME, '{"nothing":1}');
    expect(pgp.keysFor(ME)).toBeNull();
  });
});

describe('import', () => {
  it('imports a locked export only with its own passphrase, and starts unlocked', async () => {
    const { privateKey, publicKey } = await openpgp.generateKey({
      userIDs: [{ name: 'Me', email: ME }], type: 'ecc', curve: 'curve25519Legacy',
      format: 'armored', passphrase: PASS,
    });
    await expect(pgp.importKey(ME, privateKey, 'wrong')).rejects.toThrow(/does not unlock/);
    expect(pgp.keysFor(ME)).toBeNull();
    await pgp.importKey(ME, `Saavi key backup\n\n${privateKey}\n\n${publicKey}\n`, PASS);
    expect(pgp.isUnlocked(ME)).toBe(true);
    expect(pgp.keysFor(ME)!.publicKey.trim()).toBe(publicKey.trim());
  });

  it('refuses a key that carries no user ID for the address', async () => {
    const rec = await pgp.generateKeys('src@example.org', 'Src', PASS);
    await expect(pgp.importKey(ME, rec.privateKey, PASS)).rejects.toThrow(/no user ID for/);
    expect(pgp.keysFor(ME)).toBeNull();
  });

  it('locks a cleartext export with the given passphrase before storing', async () => {
    const { privateKey } = await openpgp.generateKey({
      userIDs: [{ email: ME }], type: 'ecc', curve: 'curve25519Legacy', format: 'armored',
    });
    await pgp.importKey(ME, privateKey, PASS);
    const stored = await openpgp.readPrivateKey({ armoredKey: pgp.keysFor(ME)!.privateKey });
    expect(stored.isDecrypted()).toBe(false);
    await expect(openpgp.decryptKey({ privateKey: stored, passphrase: PASS })).resolves.toBeDefined();
  });

  it('rejects input with no private key block', async () => {
    const rec = await pgp.generateKeys('src@example.org', 'Src', PASS);
    await expect(pgp.importKey(ME, rec.publicKey, PASS)).rejects.toThrow(/No PGP private key/);
  });
});

describe('seal / unseal', () => {
  it('round-trips text to a recipient and reports which key a message wants', async () => {
    await pgp.generateKeys(ME, 'Me', PASS);
    const other = await pgp.generateKeys('you@example.org', 'You', PASS);
    const sealed = await pgp.encryptText('hello', [pgp.keysFor(ME)!.publicKey]);
    expect(pgp.looksEncrypted(sealed)).toBe(true);

    await expect(pgp.decryptText(sealed)).rejects.toThrow('locked');
    const need = await pgp.neededKeyFor(ME, sealed);
    expect(need).toMatchObject({ isActive: true, unlocked: false });
    expect(await pgp.neededKeyFor('you@example.org', sealed)).toBeNull();

    // only the wrong key unlocked → still 'locked', not some other error
    await pgp.unlockPrivateKey('you@example.org', PASS);
    await expect(pgp.decryptText(sealed)).rejects.toThrow('locked');

    await pgp.unlockPrivateKey(ME, PASS);
    expect((await pgp.decryptText(sealed)).text).toBe('hello');
    void other;
  });

  it('signs with the unlocked sender and the recipient can verify it', async () => {
    await pgp.generateKeys(ME, 'Me', PASS);
    await pgp.unlockPrivateKey(ME, PASS);
    const sealed = await pgp.encryptText('signed hello', [pgp.keysFor(ME)!.publicKey], ME);
    const out = await pgp.decryptText(sealed, pgp.keysFor(ME)!.publicKey);
    expect(out.text).toBe('signed hello');
    expect(out.signedBy).toBe(ME);
  });

  it('reports a tampered message as an error, not as a locked key', async () => {
    await pgp.generateKeys(ME, 'Me', PASS);
    await pgp.unlockPrivateKey(ME, PASS);
    const sealed = await pgp.encryptText('secret', [pgp.keysFor(ME)!.publicKey]);
    // flip bytes in the middle of the armored body
    const lines = sealed.split('\n');
    const mid = Math.floor(lines.length / 2);
    lines[mid] = lines[mid].replace(/[A-Za-z0-9]/g, (c) => (c === 'A' ? 'B' : 'A'));
    const tampered = lines.join('\n');
    let err: unknown;
    try { await pgp.decryptText(tampered); } catch (e) { err = e; }
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).message).not.toBe('locked');
  });

  it('decrypts to a retired key and distinguishes it from the active one', async () => {
    const old = await pgp.generateKeys(ME, 'Me', PASS);
    const sealedToOld = await pgp.encryptText('old news', [old.publicKey]);
    await pgp.generateKeys(ME, 'Me', PASS);  // rotate
    const need = (await pgp.neededKeyFor(ME, sealedToOld))!;
    expect(need.isActive).toBe(false);
    await pgp.unlockPrivateKey(ME, PASS, need.fingerprint);
    expect((await pgp.decryptText(sealedToOld)).text).toBe('old news');
    // active key is still locked
    expect(pgp.isUnlocked(ME)).toBe(false);
  });
});

describe('normalizeKeyArmor', () => {
  it('repairs a key whose newlines became spaces and leaves intact armor alone', async () => {
    const rec = await pgp.generateKeys(ME, 'Me', PASS);
    const flat = rec.publicKey.replace(/\r?\n/g, ' ');
    const fixed = pgp.normalizeKeyArmor(flat);
    expect(fixed).not.toBe(flat);
    await expect(openpgp.readKey({ armoredKey: fixed })).resolves.toBeDefined();
    expect(pgp.normalizeKeyArmor(rec.publicKey)).toBe(rec.publicKey.trim());
    expect(pgp.normalizeKeyArmor('no armor here')).toBe('no armor here');
  });
});

describe('review follow-ups', () => {
  it('refuses to lock a cleartext import with a short passphrase', async () => {
    const { privateKey } = await openpgp.generateKey({
      userIDs: [{ email: ME }], type: 'ecc', curve: 'curve25519Legacy', format: 'armored',
    });
    await expect(pgp.importKey(ME, privateKey, 'short')).rejects.toThrow(/at least 12/);
    expect(pgp.keysFor(ME)).toBeNull();
  });

  it('keeps the real creation date on import and does not retire a re-imported active key', async () => {
    const rec = await pgp.generateKeys(ME, 'Me', PASS);
    const created = (await openpgp.readKey({ armoredKey: rec.publicKey })).getCreationTime().toISOString();
    await pgp.importKey(ME, rec.privateKey, PASS);
    const ring = pgp.ringFor(ME)!;
    expect(ring.active.created).toBe(created);
    expect(ring.retired).toHaveLength(0);
    expect(await pgp.listKeys(ME)).toHaveLength(1);
  });
});

describe('clearsign / verify / files', () => {
  it('clearsigns and verifies; a tampered body is BAD; a stranger is unknown', async () => {
    await pgp.generateKeys(ME, 'Me', PASS);
    await expect(pgp.signText('hi', ME)).rejects.toThrow('locked');
    await pgp.unlockPrivateKey(ME, PASS);
    const signed = await pgp.signText('hello world', ME);
    expect(pgp.looksClearsigned(signed)).toBe(true);
    const pub = pgp.keysFor(ME)!.publicKey;
    const ok = await pgp.verifyText(signed, [pub]);
    expect(ok.status).toBe('good');
    expect(ok.text).toBe('hello world');
    expect(ok.signerUid).toContain(ME);
    const tampered = signed.replace('hello world', 'hello there');
    expect((await pgp.verifyText(tampered, [pub])).status).toBe('bad');
    const other = await pgp.generateKeys('x@example.org', 'X', PASS);
    expect((await pgp.verifyText(signed, [other.publicKey])).status).toBe('unknown-key');
  });

  it('round-trips a binary file and reports which key it wants', async () => {
    await pgp.generateKeys(ME, 'Me', PASS);
    const data = new Uint8Array(1024).map((_, i) => (i * 7) & 255);
    const sealed = await pgp.encryptBytes(data, 'blob.bin', [pgp.keysFor(ME)!.publicKey]);
    expect(sealed[0] & 0x80).toBe(0x80); // binary packet, not armor
    await expect(pgp.decryptBytes(sealed)).rejects.toThrow('locked');
    const need = await pgp.neededKeyForBytes(ME, sealed);
    expect(need?.isActive).toBe(true);
    await pgp.unlockPrivateKey(ME, PASS);
    const out = await pgp.decryptBytes(sealed);
    expect(out.filename).toBe('blob.bin');
    expect(Array.from(out.data)).toEqual(Array.from(data));
  });
});

describe('signature verdicts on unseal (audit M1)', () => {
  it('distinguishes unsigned, signed-good, and signed-unknown', async () => {
    await pgp.generateKeys(ME, 'Me', PASS);
    await pgp.unlockPrivateKey(ME, PASS);
    const pub = pgp.keysFor(ME)!.publicKey;

    const unsigned = await pgp.encryptText('u', [pub], ME, { sign: false });
    const uo = await pgp.decryptText(unsigned, pub);
    expect(uo.sigStatus).toBe('unsigned');
    expect(uo.signatures).toHaveLength(0);

    const signed = await pgp.encryptText('s', [pub], ME);
    const so = await pgp.decryptText(signed, pub);
    expect(so.sigStatus).toBe('good');
    expect(so.signedBy).toBe(ME);
    expect(so.signerFingerprint).toBeTruthy();

    // No candidate key → the signature exists but cannot be attributed.
    const uk = await pgp.decryptText(signed);
    expect(uk.sigStatus).toBe('unknown-key');
    expect(uk.signatures[0].keyId).toMatch(/^[0-9A-F]{16}$/);
  });

  it('a bad signature never hides behind the plaintext (summary is worst-first)', async () => {
    await pgp.generateKeys(ME, 'Me', PASS);
    await pgp.unlockPrivateKey(ME, PASS);
    const pub = pgp.keysFor(ME)!.publicKey;
    // A key with the SAME address but a different keypair must not verify.
    const impostor = await pgp.generateKeys('other@example.org', 'Other', PASS);
    const signed = await pgp.encryptText('m', [pub], ME);
    // Offer only the impostor as the verification key → unknown-key, not good.
    const out = await pgp.decryptText(signed, impostor.publicKey);
    expect(out.sigStatus).toBe('unknown-key');
    expect(out.signedBy).toBeNull();
  });

  it('decryptBytes now carries signature verdicts too', async () => {
    await pgp.generateKeys(ME, 'Me', PASS);
    await pgp.unlockPrivateKey(ME, PASS);
    const pub = pgp.keysFor(ME)!.publicKey;
    const data = new Uint8Array([1, 2, 3, 4]);
    const sealed = await pgp.encryptBytes(data, 'f.bin', [pub], ME);
    const out = await pgp.decryptBytes(sealed, pub);
    expect(out.sigStatus).toBe('good');
    expect(out.signedBy).toBe(ME);
    expect(Array.from(out.data)).toEqual([1, 2, 3, 4]);
  });
});

describe('import re-locks with our S2K (audit I3)', () => {
  it('a cleartext export is stored passphrase-locked', async () => {
    const gen = await openpgp.generateKey({ userIDs: [{ email: ME }], format: 'armored', type: 'ecc', curve: 'curve25519Legacy' });
    // gen.privateKey is unlocked (no passphrase). Import must lock it.
    const rec = await pgp.importKey(ME, gen.privateKey, PASS);
    const stored = await openpgp.readPrivateKey({ armoredKey: rec.privateKey });
    expect(stored.isDecrypted()).toBe(false);
    await expect(openpgp.decryptKey({ privateKey: stored, passphrase: 'wrong' })).rejects.toThrow();
    await expect(openpgp.decryptKey({ privateKey: stored, passphrase: PASS })).resolves.toBeTruthy();
  });
});

describe('corrupt store record is quarantined, not lost (audit M3)', () => {
  it('parks the bad record and raises an alert instead of vanishing', async () => {
    localStorage.setItem('saavi-ring-bad@example.org', '{ this is not json');
    expect(pgp.ringFor('bad@example.org')).toBeNull();
    const alerts = pgp.storeAlerts();
    expect(alerts).toHaveLength(1);
    expect(alerts[0].email).toBe('bad@example.org');
    // the raw bytes are preserved under the quarantine key
    expect(localStorage.getItem(alerts[0].quarantineKey)).toBe('{ this is not json');
    // and removed from the live slot so it can't keep tripping load()
    expect(localStorage.getItem('saavi-ring-bad@example.org')).toBeNull();
    pgp.dismissStoreAlert(alerts[0].quarantineKey);
    expect(pgp.storeAlerts()).toHaveLength(0);
  });
});

describe('revocation certificates', () => {
  it('is captured at generation and revokes the key when applied', async () => {
    const rec = await pgp.generateKeys(ME, 'Me', PASS);
    expect(rec.revocationCertificate).toContain('BEGIN PGP PUBLIC KEY BLOCK');
    // a captured certificate needs no unlock
    const cert = await pgp.revocationCertificate(ME);
    expect(cert).toBe(rec.revocationCertificate);
    const { publicKey } = await openpgp.revokeKey({
      key: await openpgp.readKey({ armoredKey: rec.publicKey }),
      revocationCertificate: cert,
      format: 'object',
    });
    expect(await publicKey.isRevoked()).toBe(true);
  });

  it('a record without a captured certificate derives one, but only unlocked', async () => {
    const rec = await pgp.generateKeys(ME, 'Me', PASS);
    // a pre-capture / imported record: no stored certificate
    const ring = pgp.ringFor(ME)!;
    delete ring.active.revocationCertificate;
    localStorage.setItem('saavi-ring-' + ME, JSON.stringify(ring));
    await expect(pgp.revocationCertificate(ME)).rejects.toThrow('locked');
    await pgp.unlockPrivateKey(ME, PASS);
    const cert = await pgp.revocationCertificate(ME);
    const { publicKey } = await openpgp.revokeKey({
      key: await openpgp.readKey({ armoredKey: rec.publicKey }),
      revocationCertificate: cert,
      format: 'object',
    });
    expect(await publicKey.isRevoked()).toBe(true);
  });
});

describe('explicit signing', () => {
  it('seals unsigned when asked, even with a key unlocked', async () => {
    await pgp.generateKeys(ME, 'Me', PASS);
    await pgp.unlockPrivateKey(ME, PASS);
    const pub = pgp.keysFor(ME)!.publicKey;
    const unsigned = await pgp.encryptText('x', [pub], ME, { sign: false });
    const signed = await pgp.encryptText('x', [pub], ME);
    const a = await openpgp.readMessage({ armoredMessage: unsigned });
    const b = await openpgp.readMessage({ armoredMessage: signed });
    const da = await openpgp.decrypt({ message: a, decryptionKeys: await openpgp.decryptKey({ privateKey: await openpgp.readPrivateKey({ armoredKey: pgp.keysFor(ME)!.privateKey }), passphrase: PASS }) });
    const db = await openpgp.decrypt({ message: b, decryptionKeys: await openpgp.decryptKey({ privateKey: await openpgp.readPrivateKey({ armoredKey: pgp.keysFor(ME)!.privateKey }), passphrase: PASS }) });
    expect(da.signatures.length).toBe(0);
    expect(db.signatures.length).toBe(1);
  });
});
