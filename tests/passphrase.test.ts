import { describe, expect, it } from 'vitest';
import { generatePassphrase, passphraseBits, describeStrength } from '../src/passphrase';
import { EFF_LARGE } from '../src/wordlist';

describe('passphrase', () => {
  it('uses the full EFF list, unique, lower-case', () => {
    expect(EFF_LARGE.length).toBe(7776);
    expect(new Set(EFF_LARGE).size).toBe(7776);
    expect(EFF_LARGE.every((w) => /^[a-z-]+$/.test(w))).toBe(true);
  });
  it('generates N words from the list with the separator', () => {
    const p = generatePassphrase(6);
    const words = p.split(' ');
    expect(words).toHaveLength(6);
    expect(words.every((w) => EFF_LARGE.includes(w))).toBe(true);
    expect(generatePassphrase(6)).not.toBe(p);
  });
  it('reports entropy', () => {
    expect(passphraseBits(6)).toBeCloseTo(77.5, 0);
    expect(passphraseBits(7)).toBeCloseTo(90.5, 0);
  });
  it('does not call short input strong', () => {
    expect(describeStrength('short').ok).toBe(false);
    expect(describeStrength('correct-horse-battery-staple-again').ok).toBe(true);
    expect(describeStrength(generatePassphrase(6)).label).toBe('Strong passphrase');
  });
});

describe('gatePassword — the enforced floor', () => {
  it('length floor at 12, NFKC-counted', async () => {
    const { gatePassword } = await import('../src/passphrase');
    expect(gatePassword('elevenchars').ok).toBe(false);
    expect(gatePassword('twelve chars').ok).toBe(true);
  });
  it('rejects the first guesses even at length', async () => {
    const { gatePassword } = await import('../src/passphrase');
    expect(gatePassword('aaaaaaaaaaaa').ok).toBe(false);            // repetition
    expect(gatePassword('123456789012').ok).toBe(false);            // sequence
    expect(gatePassword('qwertyuiopasdf').ok).toBe(false);          // keyboard walk
    expect(gatePassword('P@ssw0rd1234!').ok).toBe(false);           // l33t common core
    expect(gatePassword('monkeymonkey').ok).toBe(false);            // doubled word
    expect(gatePassword('sunshine2024!!').ok).toBe(false);          // common core padded
  });
  it('passes honest passwords and every generated phrase', async () => {
    const { gatePassword, generatePassphrase } = await import('../src/passphrase');
    expect(gatePassword('correct horse battery staple').ok).toBe(true);
    expect(gatePassword('Tirunelveli-halwa-1998').ok).toBe(true);
    for (let i = 0; i < 20; i++) expect(gatePassword(generatePassphrase(6)).ok).toBe(true);
  });
  it('describeStrength never approves what the gate refuses', async () => {
    const { gatePassword, describeStrength } = await import('../src/passphrase');
    for (const p of ['aaaaaaaaaaaa', '123456789012', 'P@ssw0rd1234!', 'short']) {
      expect(describeStrength(p).ok).toBe(gatePassword(p).ok && p.length >= 12);
    }
  });
});

describe('recovery phrase', () => {
  it('eight EFF words, ~103 bits, already canonical', async () => {
    const { generateRecoveryPhrase, canonicalRecoveryPhrase, RECOVERY_PHRASE_WORDS, passphraseBits } = await import('../src/passphrase');
    const p = generateRecoveryPhrase();
    expect(p.split(' ')).toHaveLength(RECOVERY_PHRASE_WORDS);
    expect(passphraseBits(RECOVERY_PHRASE_WORDS)).toBeGreaterThan(100);
    expect(canonicalRecoveryPhrase(p)).toBe(p);
  });
  it('canonical form: NFC, lowercase, collapsed spaces, order kept', async () => {
    const { canonicalRecoveryPhrase } = await import('../src/passphrase');
    expect(canonicalRecoveryPhrase('  Alpha   BETA\tgamma ')).toBe('alpha beta gamma');
    expect(canonicalRecoveryPhrase('café word')).toBe('café word');
    expect(canonicalRecoveryPhrase('b a')).not.toBe(canonicalRecoveryPhrase('a b'));
  });
});
