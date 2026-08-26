import { describe, expect, it } from 'vitest';
import * as openpgp from 'openpgp';
import { isNewer, verifySignedSums } from '../src/update';

describe('update indicator', () => {
  it('compares dotted versions numerically', () => {
    expect(isNewer('0.2.1', '0.2.0')).toBe(true);
    expect(isNewer('0.2.10', '0.2.9')).toBe(true);
    expect(isNewer('1.0.0', '0.9.9')).toBe(true);
    expect(isNewer('0.2.0', '0.2.0')).toBe(false);
    expect(isNewer('0.1.9', '0.2.0')).toBe(false);
    expect(isNewer('0.2', '0.2.0')).toBe(false);
  });

  it('builds the checksum map only from a list signed by the pinned key', async () => {
    const { privateKey, publicKey } = await openpgp.generateKey({
      userIDs: [{ name: 'Release', email: 'rel@example.org' }], format: 'object',
    });
    const sha = 'ab'.repeat(32);
    const text = `${sha}  Saavi_9.9.9_amd64.deb`;
    const signed = await openpgp.sign({
      message: await openpgp.createCleartextMessage({ text }),
      signingKeys: privateKey,
    });
    const sums = await verifySignedSums(signed, publicKey.armor());
    expect(sums.get('Saavi_9.9.9_amd64.deb')).toBe(sha);
    // a stranger's key must not verify it
    const { publicKey: stranger } = await openpgp.generateKey({
      userIDs: [{ name: 'S', email: 's@example.org' }], format: 'object',
    });
    await expect(verifySignedSums(signed, stranger.armor())).rejects.toThrow();
    // tampered content must not verify either
    await expect(verifySignedSums(signed.replace('9.9.9', '6.6.6'), publicKey.armor())).rejects.toThrow();
  });
});
