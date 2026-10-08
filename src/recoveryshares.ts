// The 2-of-3 recovery split. A second recovery envelope sits beside the
// recovery kit: the account's keys locked under a random SPLIT PHRASE that
// nobody is ever shown. The phrase's 128-bit secret is cut into three
// shares with Shamir's scheme (threshold two) — one for the owner, one for
// a trusted adviser, one held by the mail provider. Any two rebuild the
// phrase; any one alone reveals nothing about it (Shamir's scheme is
// information-theoretically hiding below the threshold), so the provider's
// share can never open the mail by itself.
//
// Shamir is Privy's audited shamir-secret-sharing (GF(256), zero
// dependencies). This module only adds the pieces around it: a random
// secret, its phrase, and shares written as EFF words with a checksum, so a
// mistyped sheet is caught by name instead of silently rebuilding garbage.
import { split, combine } from 'shamir-secret-sharing';
import { EFF_LARGE } from './wordlist';

export const SPLIT_SHARES = 3;
export const SPLIT_THRESHOLD = 2;
/** 16 bytes of secret: 128 bits, the floor for anything an offline attacker
 *  holding the keychain blob may grind forever. */
const SECRET_BYTES = 16;
/** 10 EFF words carry 129.2 bits ≥ 128. */
export const SPLIT_PHRASE_WORDS = 10;
/** A share is the library's 17 bytes (16 y + the x coordinate) plus a
 *  two-byte checksum: 152 bits, carried by 12 words (155.1 bits). */
export const SHARE_WORDS = 12;
const SHARE_BYTES = SECRET_BYTES + 1;
const CHECK_BYTES = 2;
const CHECK_LABEL = 'kaditham-recovery-share-v1\n';

const N = BigInt(EFF_LARGE.length); // 7776
const INDEX = new Map<string, number>(EFF_LARGE.map((w, i) => [w, i]));

export class ShareError extends Error {
  /** Which of the two sheets offered (0 or 1) is at fault, when known. */
  constructor(message: string, readonly which?: 0 | 1) { super(message); }
}

/** Big-endian bytes → exactly `n` words, most significant first. */
export function encodeWords(bytes: Uint8Array, n: number): string[] {
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  if (v >= N ** BigInt(n)) throw new Error('too many bytes for that many words');
  const out: string[] = new Array(n);
  for (let i = n - 1; i >= 0; i--) { out[i] = EFF_LARGE[Number(v % N)]; v /= N; }
  return out;
}

/** Exactly `n` words → `nBytes` big-endian bytes; throws on an unknown word
 *  (naming its position) or a value that does not fit. */
export function decodeWords(words: string[], nBytes: number): Uint8Array {
  let v = 0n;
  words.forEach((w, i) => {
    const d = INDEX.get(w);
    if (d === undefined) throw new ShareError(`Word ${i + 1} (“${w}”) is not on the word list — check the spelling.`);
    v = v * N + BigInt(d);
  });
  if (v >= 1n << BigInt(8 * nBytes)) throw new ShareError('Those words do not make a valid sheet.');
  const out = new Uint8Array(nBytes);
  for (let i = nBytes - 1; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}

/** The same canonical form the recovery phrase uses: NFC, lowercase,
 *  whitespace collapsed, order-significant. */
function wordsOf(text: string): string[] {
  const t = text.normalize('NFC').toLowerCase().trim();
  return t ? t.split(/\s+/) : [];
}

async function checksum(share: Uint8Array): Promise<Uint8Array> {
  const label = new TextEncoder().encode(CHECK_LABEL);
  const buf = new Uint8Array(label.length + share.length);
  buf.set(label); buf.set(share, label.length);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', buf)).slice(0, CHECK_BYTES);
}

async function encodeShare(share: Uint8Array): Promise<string> {
  if (share.length !== SHARE_BYTES) throw new Error('unexpected share length');
  const full = new Uint8Array(SHARE_BYTES + CHECK_BYTES);
  full.set(share); full.set(await checksum(share), SHARE_BYTES);
  return encodeWords(full, SHARE_WORDS).join(' ');
}

/** Read one share sheet back: twelve list words whose checksum holds. */
export async function decodeShare(text: string, which?: 0 | 1): Promise<Uint8Array> {
  const words = wordsOf(text);
  if (words.length !== SHARE_WORDS) {
    throw new ShareError(`A recovery share is ${SHARE_WORDS} words — this one has ${words.length}.`, which);
  }
  let full: Uint8Array;
  try { full = decodeWords(words, SHARE_BYTES + CHECK_BYTES); }
  catch (e) { throw new ShareError(e instanceof Error ? e.message : String(e), which); }
  const share = full.slice(0, SHARE_BYTES);
  const want = await checksum(share);
  if (want[0] !== full[SHARE_BYTES] || want[1] !== full[SHARE_BYTES + 1]) {
    throw new ShareError('This share does not check out — a word is probably mistyped or out of order.', which);
  }
  return share;
}

/** The split phrase a secret stands for: ten list words, canonical form. */
export function phraseOfSecret(secret: Uint8Array): string {
  if (secret.length !== SECRET_BYTES) throw new Error('unexpected secret length');
  return encodeWords(secret, SPLIT_PHRASE_WORDS).join(' ');
}

export interface RecoverySplit {
  /** Lock the second envelope with this; show it to nobody, store it nowhere. */
  phrase: string;
  /** Three sheets, any two of which rebuild `phrase`. Order carries no
   *  meaning — the caller assigns owner / adviser / provider. */
  shares: [string, string, string];
}

/** A fresh split: a random secret, its phrase, and three share sheets. */
export async function makeRecoverySplit(): Promise<RecoverySplit> {
  const secret = crypto.getRandomValues(new Uint8Array(SECRET_BYTES));
  const raw = await split(secret, SPLIT_SHARES, SPLIT_THRESHOLD);
  const shares = await Promise.all(raw.map(encodeShare));
  // Prove the round trip before anyone is handed a sheet: every pair must
  // rebuild the phrase, or the split is thrown away, never printed.
  const phrase = phraseOfSecret(secret);
  for (const [a, b] of [[0, 1], [0, 2], [1, 2]] as const) {
    if (await combineRecoveryShares(shares[a], shares[b]) !== phrase) throw new Error('recovery split failed its own check');
  }
  return { phrase, shares: shares as [string, string, string] };
}

/** Two share sheets → the split phrase. A bad sheet is named; the same
 *  sheet offered twice is refused (it is one share, not two). */
export async function combineRecoveryShares(a: string, b: string): Promise<string> {
  const sa = await decodeShare(a, 0);
  const sb = await decodeShare(b, 1);
  if (sa[SHARE_BYTES - 1] === sb[SHARE_BYTES - 1]) {
    throw new ShareError('Those are the same share twice — two different sheets are needed.');
  }
  return phraseOfSecret(await combine([sa, sb]));
}
