// The 2-of-3 recovery split: any two sheets rebuild the phrase, one never
// does, and a mistyped sheet is named rather than rebuilding garbage.
import { describe, expect, it } from 'vitest';
import {
  SHARE_WORDS, SPLIT_PHRASE_WORDS, ShareError,
  combineRecoveryShares, decodeShare, decodeWords, encodeWords, makeRecoverySplit, phraseOfSecret,
} from '../src/recoveryshares';
import { canonicalRecoveryPhrase } from '../src/passphrase';
import { EFF_LARGE } from '../src/wordlist';

describe('word encoding', () => {
  it('pins the encoding: zero, one, and the largest 16-byte value', () => {
    expect(encodeWords(new Uint8Array(16), 10)).toEqual(Array(10).fill(EFF_LARGE[0]));
    const one = new Uint8Array(16); one[15] = 1;
    expect(encodeWords(one, 10)).toEqual([...Array(9).fill(EFF_LARGE[0]), EFF_LARGE[1]]);
    // 2^128 - 1 in base 7776, most significant first.
    const max = encodeWords(new Uint8Array(16).fill(0xff), 10);
    let v = 0n;
    for (const w of max) v = v * 7776n + BigInt(EFF_LARGE.indexOf(w));
    expect(v).toBe((1n << 128n) - 1n);
  });

  it('round-trips random bytes and refuses values that do not fit', () => {
    for (let i = 0; i < 50; i++) {
      const b = crypto.getRandomValues(new Uint8Array(19));
      expect(decodeWords(encodeWords(b, SHARE_WORDS), 19)).toEqual(b);
    }
    // 12 words can carry more than 19 bytes: the top of that range is refused.
    expect(() => decodeWords(Array(SHARE_WORDS).fill(EFF_LARGE[7775]), 19)).toThrow(ShareError);
    expect(() => encodeWords(new Uint8Array(17).fill(0xff), 10)).toThrow();
  });

  it('names an unknown word by position', () => {
    const words = encodeWords(new Uint8Array(19), SHARE_WORDS);
    words[4] = 'notaword';
    expect(() => decodeWords(words, 19)).toThrow(/Word 5/);
  });
});

describe('makeRecoverySplit', () => {
  it('makes a 10-word phrase and three 12-word sheets; every pair rebuilds the phrase', async () => {
    const { phrase, shares } = await makeRecoverySplit();
    expect(phrase.split(' ')).toHaveLength(SPLIT_PHRASE_WORDS);
    expect(canonicalRecoveryPhrase(phrase)).toBe(phrase);
    for (const s of shares) expect(s.split(' ')).toHaveLength(SHARE_WORDS);
    expect(new Set(shares).size).toBe(3);
    for (const [a, b] of [[0, 1], [1, 0], [0, 2], [2, 0], [1, 2], [2, 1]]) {
      expect(await combineRecoveryShares(shares[a], shares[b])).toBe(phrase);
    }
  });

  it('tolerates case and spacing on a typed sheet', async () => {
    const { phrase, shares } = await makeRecoverySplit();
    const sloppy = '  ' + shares[0].toUpperCase().replace(/ /g, '   ') + '\n';
    expect(await combineRecoveryShares(sloppy, shares[2])).toBe(phrase);
  });

  it('never repeats a phrase (fresh randomness each time)', async () => {
    const seen = new Set<string>();
    for (let i = 0; i < 20; i++) seen.add((await makeRecoverySplit()).phrase);
    expect(seen.size).toBe(20);
  });
});

describe('combineRecoveryShares refuses', () => {
  it('the same sheet twice — one share is not two', async () => {
    const { shares } = await makeRecoverySplit();
    await expect(combineRecoveryShares(shares[1], shares[1])).rejects.toThrow(/same share twice/);
  });

  it('a mistyped word, naming the sheet', async () => {
    const { shares } = await makeRecoverySplit();
    const words = shares[1].split(' ');
    words[3] = EFF_LARGE[(EFF_LARGE.indexOf(words[3]) + 1) % 7776];
    const err = await combineRecoveryShares(shares[0], words.join(' ')).catch((e) => e);
    expect(err).toBeInstanceOf(ShareError);
    expect(err.which).toBe(1);
    expect(err.message).toMatch(/does not check out/);
  });

  it('swapped words (order matters)', async () => {
    const { shares } = await makeRecoverySplit();
    const w = shares[0].split(' ');
    [w[0], w[1]] = [w[1], w[0]];
    if (w.join(' ') === shares[0]) return;   // identical words: nothing to swap
    await expect(decodeShare(w.join(' '))).rejects.toThrow(ShareError);
  });

  it('a sheet of the wrong length', async () => {
    const { shares } = await makeRecoverySplit();
    await expect(combineRecoveryShares(shares[0], shares[1].split(' ').slice(0, 11).join(' '))).rejects.toThrow(/12 words/);
  });
});

describe('one share alone', () => {
  it('cannot be combined — the provider\'s share by itself rebuilds nothing', async () => {
    const { shares } = await makeRecoverySplit();
    const { combine } = await import('shamir-secret-sharing');
    for (const s of shares) await expect(combine([await decodeShare(s)])).rejects.toThrow();
  });
});
