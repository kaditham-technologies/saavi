// Passphrase generation — because humans are bad at this. Diceware over
// the EFF large list: 6 words ≈ 77.5 bits, 7 ≈ 90.5, drawn with the
// platform CSPRNG and rejection sampling (no modulo bias).
import { EFF_LARGE } from './wordlist';

const N = EFF_LARGE.length; // 7776

function uniform(bound: number): number {
  // Largest multiple of `bound` below 2^32; reject above it.
  const limit = Math.floor(0x1_0000_0000 / bound) * bound;
  const buf = new Uint32Array(1);
  for (;;) {
    crypto.getRandomValues(buf);
    if (buf[0] < limit) return buf[0] % bound;
  }
}

export function generatePassphrase(words = 6, separator = ' '): string {
  const out: string[] = [];
  for (let i = 0; i < words; i++) out.push(EFF_LARGE[uniform(N)]);
  return out.join(separator);
}

/** Entropy in bits for a passphrase of `words` diceware words. */
export function passphraseBits(words: number): number {
  return Math.round(words * Math.log2(N) * 10) / 10;
}

/** A rough strength read for anything the user types instead. Not a
 *  cracker model — a floor: length-based, with a bonus for diceware shape. */
export function describeStrength(p: string): { label: string; ok: boolean } {
  const n = p.length;
  if (n === 0) return { label: '', ok: false };
  const wordsLike = p.split(/[\s\-_.]+/).filter((w) => w.length >= 3).length;
  if (n < 12) return { label: `${n}/12 characters — keep going`, ok: false };
  if (wordsLike >= 5 || n >= 24) return { label: 'Strong passphrase', ok: true };
  if (n >= 16) return { label: 'Acceptable — longer is stronger', ok: true };
  return { label: 'Minimum — consider a generated passphrase', ok: true };
}
