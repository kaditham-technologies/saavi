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
