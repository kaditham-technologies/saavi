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
  if (!gatePassword(p).ok) return { label: gatePassword(p).reason, ok: false };
  const wordsLike = p.split(/[\s\-_.]+/).filter((w) => w.length >= 3).length;
  if (wordsLike >= 5 || n >= 24) return { label: 'Strong passphrase', ok: true };
  if (n >= 16) return { label: 'Acceptable — longer is stronger', ok: true };
  return { label: 'Minimum — consider a generated passphrase', ok: true };
}

// ---- the enforced floor (webmail docs/ZERO-ACCESS.md, "the password gate")
//
// Under the password split the login password IS the ring lock, so a weak
// password is weak cryptography, and this floor is enforced — not nudged —
// at every password-choosing moment in both apps. NIST 800-63B shape:
// length over composition rules, plus a small blocklist of the passwords
// everyone reaches for. A floor, not a cracker model: the generator above
// is always the better answer, and the UI keeps it one tap away.

/** The passwords everyone reaches for, folded (lowercase, l33t undone,
 *  edge digits/symbols stripped) before comparison. Short list on purpose:
 *  the 12-char minimum already excludes most of every leaked top-1000, so
 *  what is left to catch is a common core padded out to length. */
const BLOCKED_CORES = new Set([
  'password', 'passwort', 'motdepasse', 'contrasena', 'qwerty', 'azerty',
  'letmein', 'welcome', 'iloveyou', 'sunshine', 'monkey', 'dragon',
  'football', 'baseball', 'superman', 'batman', 'trustno', 'whatever',
  'princess', 'freedom', 'shadow', 'master', 'michael', 'jennifer',
  'computer', 'internet', 'starwars', 'pokemon', 'minecraft', 'kaditham',
  'admin', 'administrator', 'root', 'secret', 'changeme', 'default',
]);

const KEYBOARD_WALKS = [
  'qwertyuiopasdfghjklzxcvbnm', 'mnbvcxzlkjhgfdsapoiuytrewq',
  'azertyuiopqsdfghjklmwxcvbn', '1234567890', '0987654321',
  'abcdefghijklmnopqrstuvwxyz', 'zyxwvutsrqponmlkjihgfedcba',
];

function fold(p: string): string {
  return p.normalize('NFKC').toLowerCase()
    .replace(/[013457@$!]/g, (c) => ({ '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', $: 's', '!': 'i' }[c] as string))
    .replace(/[^a-z]+/g, ' ').trim();
}

/** The floor itself: ok, or the reason shown beside the field. Enforced at
 *  signup, password change, migration fold-in and the passphrase override —
 *  never retroactively at sign-in. The server cannot re-check this (it only
 *  ever sees the derived authSecret), so this function is the whole gate. */
export function gatePassword(p: string): { ok: boolean; reason: string } {
  const n = p.normalize('NFKC').length;
  if (n < 12) return { ok: false, reason: `${n}/12 characters — keep going` };
  const low = p.normalize('NFKC').toLowerCase();
  if (new Set(low).size <= 3) return { ok: false, reason: 'Too repetitive — this is one of the first guesses.' };
  const compact = low.replace(/[^a-z0-9]/g, '');
  // Reject a password that IS a keyboard walk or sequence (modulo case and
  // separators) — not one that merely contains a fragment of one.
  if (compact.length >= 8 && KEYBOARD_WALKS.some((walk) => (walk + walk).includes(compact))) {
    return { ok: false, reason: 'Keyboard rows and sequences are the first guesses — try the generator.' };
  }
  for (const word of fold(p).split(' ')) {
    if (word.length >= 5 && (BLOCKED_CORES.has(word) || [...BLOCKED_CORES].some((core) => word.startsWith(core)))) {
      return { ok: false, reason: 'Built on a very common password — try the generator.' };
    }
  }
  const half = compact.slice(0, Math.floor(compact.length / 2));
  if (half.length >= 6 && compact === half + half) {
    return { ok: false, reason: 'A doubled word is still one guess — try the generator.' };
  }
  return { ok: true, reason: '' };
}

// ---- the recovery phrase (ZERO-ACCESS.md, "The recovery kit")

/** Eight EFF words ≈ 103 bits — unattackable offline, which is the whole
 *  job: any holder of the keychain blob may grind this envelope forever.
 *  Never user-chosen, never editable. */
export const RECOVERY_PHRASE_WORDS = 8;

export function generateRecoveryPhrase(): string {
  return generatePassphrase(RECOVERY_PHRASE_WORDS);
}

/** The pinned canonical form both ends derive from: NFC, lowercase,
 *  whitespace collapsed to single spaces, order-significant. Typing
 *  "Word  word" recovers; rearranging the words never does. */
export function canonicalRecoveryPhrase(phrase: string): string {
  return phrase.normalize('NFC').toLowerCase().trim().replace(/\s+/g, ' ');
}
