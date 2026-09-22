// Pinned vectors for the password split (webmail docs/ZERO-ACCESS.md).
// These outputs are FROZEN: both apps must derive identically forever, or
// every account's sign-in and ring lock silently diverge. A failure here
// is never fixed by updating the expected value.
import { describe, expect, it } from 'vitest';
import {
  AUTH_ITERATIONS, AUTH_REALM, authSalt, canonicalAddress,
  deriveAuthSecret, looksLikeAuthSecret, normalizePassword,
} from '../src/derive';

const hex = (u8: Uint8Array) => [...u8].map((b) => b.toString(16).padStart(2, '0')).join('');

describe('canonicalAddress', () => {
  it('NFC + ASCII lowercase + trim, keeps non-ASCII case untouched', () => {
    expect(canonicalAddress('User@Kaditham.IE ')).toBe('user@kaditham.ie');
    expect(canonicalAddress('áb@x.ie')).toBe('áb@x.ie'); // NFD → NFC, á survives
  });
  it('refuses bare logins and junk — a bare login hashes to the wrong salt (C7)', () => {
    expect(() => canonicalAddress('khree')).toThrow();
    expect(() => canonicalAddress('')).toThrow();
    expect(() => canonicalAddress('two@at@x.ie')).toThrow();
    expect(() => canonicalAddress('name@nodot')).toThrow();
  });
});

describe('normalizePassword', () => {
  it('NFKC folds composition variants, keeps deliberate spaces', () => {
    expect(normalizePassword('café')).toBe('café');
    expect(normalizePassword(' spaced ')).toBe(' spaced ');
  });
});

describe('pinned vectors', () => {
  it('constants are frozen', () => {
    expect(AUTH_REALM).toBe('kaditham-mail-auth-v1');
    expect(AUTH_ITERATIONS).toBe(600_000);
  });
  it('salt vector 1', async () => {
    expect(hex(await authSalt('User@Kaditham.IE '))).toBe(
      '1f728bddf41f65a26b2bddf80d1bcf1c7a0f5657d9ff8394df5be145db1ddb8f');
  });
  it('authSecret vector 1 — plain ASCII', async () => {
    expect(await deriveAuthSecret('correct horse battery staple', 'User@Kaditham.IE '))
      .toBe('5M0cPPJYYuzB-si5OvAYERWuef44Os4k3IzAzN-WHFY');
  });
  it('authSecret vector 2 — NFD password and NFD address both normalize', async () => {
    expect(await deriveAuthSecret('café au lait 1234', 'áb@x.ie'))
      .toBe('ZcS_UYBbNWbsn4unXDg22MgzO57CO56nKXQIjoyHQfg');
    // the composed spellings derive identically
    expect(await deriveAuthSecret('café au lait 1234', 'áb@x.ie'))
      .toBe('ZcS_UYBbNWbsn4unXDg22MgzO57CO56nKXQIjoyHQfg');
  });
  it('authSecret vector 3', async () => {
    expect(await deriveAuthSecret('pässword-with-twelve', 'khree@kaditham.me'))
      .toBe('vG9pMb1Nw2RUWsJPmEDGbZm_7CPlFHNKH78YtvEx7U4');
  });
});

describe('shape and fail-closed', () => {
  it('output always matches the broker-side shape', async () => {
    const s = await deriveAuthSecret('x'.repeat(12), 'a@b.ie');
    expect(looksLikeAuthSecret(s)).toBe(true);
    expect(s).toHaveLength(43);
  });
  it('a raw password never matches the shape', () => {
    expect(looksLikeAuthSecret('correct horse battery staple')).toBe(false);
    expect(looksLikeAuthSecret('hunter2hunter2hunter2hunter2hunter2hunter22')).toBe(true); // 43 chars CAN collide by shape — the check is a net, not proof
    expect(looksLikeAuthSecret('short')).toBe(false);
    expect(looksLikeAuthSecret('has spaces which never appear in base64url1')).toBe(false);
  });
  it('empty inputs fail closed — no derivation, no fallback', async () => {
    await expect(deriveAuthSecret('', 'a@b.ie')).rejects.toThrow();
    await expect(deriveAuthSecret('x'.repeat(12), '')).rejects.toThrow();
  });
  it('different addresses give unrelated secrets (salt separation)', async () => {
    const a = await deriveAuthSecret('same password here', 'one@kaditham.ie');
    const b = await deriveAuthSecret('same password here', 'two@kaditham.ie');
    expect(a).not.toBe(b);
  });
});
