// The password split (webmail docs/ZERO-ACCESS.md): one password, two
// derived secrets, split on the device before anything is sent.
//
//   password ─┬─ PBKDF2-HMAC-SHA256(salt, 600k) → authSecret → the server
//             └─ Argon2id S2K (pgp.ts)          → locks the ring, never leaves
//
// authSecret is the only branch that ever travels; it opens nothing
// cryptographic. The salt is DETERMINISTIC — SHA-256(realm ‖ canonical
// primary address) — because a served salt was shown to be an enumeration
// surface, a timing oracle, a login-denial lever and a bricking lever
// (ZERO-ACCESS.md D8), while buying nothing an address-derived salt does
// not. The realm names the SERVICE, not just a version (P4): another
// Kaditham property adopting this scheme must use its own realm, or a
// credential leak there is a working mail credential.
//
// Normalization is pinned (C7): the password is NFKC (NIST 800-63B — the
// same secret typed on macOS/NFD and Windows/NFC must derive alike); the
// address is NFC + ASCII-only lowercase (never locale lowercasing), and
// must be the full canonical primary address — aliases and bare logins
// hash to different salts and are not derivable inputs. Everything here
// fails closed: no input, no derivation, never a raw-password fallback.
//
// Both apps must give the same answer to the same password forever; the
// vectors in tests/derive.test.ts are pinned and must never change.

/** Service-bound derivation realm. Changing it strands every account. */
export const AUTH_REALM = 'kaditham-mail-auth-v1';

/** PBKDF2-HMAC-SHA256 iterations for the auth branch (OWASP 2023 floor). */
export const AUTH_ITERATIONS = 600_000;

/** The derived secret: 32 bytes, base64url, no padding — always 43 chars.
 *  The broker rejects anything else on a split-mode password path (D10),
 *  so a raw password can never be silently stored where authSecret goes. */
export const AUTH_SECRET_SHAPE = /^[A-Za-z0-9_-]{43}$/;

/** The canonical form both derivations and the broker agree on:
 *  NFC, trimmed, ASCII-lowercased. Throws unless it looks like a full
 *  address — the salt must come from the primary address, never a bare
 *  login or alias spelling (C7). */
export function canonicalAddress(address: string): string {
  const a = address.normalize('NFC').trim().replace(/[A-Z]/g, (c) => c.toLowerCase());
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(a)) {
    throw new Error('Derivation needs the full account address (name@domain).');
  }
  return a;
}

/** NFKC, as NIST 800-63B requires of memorized secrets. Not trimmed:
 *  leading/trailing spaces are part of a password if the user typed them. */
export function normalizePassword(password: string): string {
  return password.normalize('NFKC');
}

const utf8 = (s: string) => new TextEncoder().encode(s);
const b64url = (buf: ArrayBuffer) =>
  btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

/** The deterministic per-account salt: SHA-256(realm ‖ canonical address). */
export async function authSalt(address: string): Promise<Uint8Array> {
  const canon = canonicalAddress(address);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', utf8(AUTH_REALM + canon)));
}

/** The auth branch: what the server is given as the account password.
 *  It cannot be reversed to the password and unlocks nothing. */
export async function deriveAuthSecret(password: string, address: string): Promise<string> {
  if (!password) throw new Error('Derivation needs the password.'); // fail closed, never ''
  const salt = await authSalt(address);
  const km = await crypto.subtle.importKey(
    'raw', utf8(normalizePassword(password)), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: salt as BufferSource, iterations: AUTH_ITERATIONS }, km, 256);
  return b64url(bits);
}

/** True when a stored secret has authSecret's exact shape — the server-side
 *  check that keeps a raw password out of a split-mode credential slot. */
export function looksLikeAuthSecret(secret: string): boolean {
  return AUTH_SECRET_SHAPE.test(secret);
}
