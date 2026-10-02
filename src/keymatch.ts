// What Saavi can honestly say about an address's key (0.6.0; design in
// docs/ACCOUNT-SIGNIN.md, "The key check"). Four vantage points, each
// proving one thing and no more:
//
//   local     the key this computer holds and opened. The reference: its
//             public half is derived from the private half on install, so
//             no server chose it.
//   domain    what <domain> served THIS computer just now over WKD. Proves
//             what the domain answered here; it cannot prove that everyone
//             else is served the same key.
//   keychain  the active key in the account keychain, fingerprinted from
//             its PRIVATE half (a blob's public half is never believed).
//             Proves what your other devices will treat as current.
//   vks       keys.openpgp.org — a directory Kaditham does not run, holding
//             only keys whose owner confirmed the address by mail. An
//             independent vantage point: agreement there is evidence the
//             domain is not quietly serving a different key to you.
//
// Each leg is compared with `local` and lands in one of five states. A leg
// that is absent or unreachable is NEVER a mismatch — it is "nothing to
// compare", said as such. Only a present, different fingerprint differs.
// Warn only, never block (product decision, 2026-10-02).
import * as openpgp from 'openpgp';

export type Leg = 'domain' | 'keychain' | 'vks';
export type LegState = 'agrees' | 'differs' | 'absent' | 'unreachable' | 'not-read';

/** What was fetched for one leg. `fpr` null with `reached` true = the leg
 *  answered and holds no key for the address. `read: false` = not asked. */
export interface LegInput { fpr: string | null; reached: boolean; read?: boolean }

export interface LegResult { state: LegState; fpr: string | null }

export type Summary =
  | 'consistent'     // the domain agrees; the keychain agrees or was not read
  | 'differs'        // the domain or the keychain holds a different key
  | 'unpublished'    // the domain answered: no key for this address
  | 'unchecked'      // the domain could not be reached
  | 'no-local-key';  // nothing on this computer to compare against

export interface Assessment {
  local: string | null;
  legs: Record<Leg, LegResult>;
  summary: Summary;
  /** keys.openpgp.org, read separately: it never changes `summary` — it adds
   *  (or withholds) independent evidence beside it. */
  independent: LegState;
}

const norm = (f: string | null | undefined): string | null => (f ? f.replace(/\s+/g, '').toLowerCase() : null);

function legState(local: string | null, leg: LegInput): LegResult {
  if (leg.read === false) return { state: 'not-read', fpr: null };
  if (!leg.reached) return { state: 'unreachable', fpr: null };
  const f = norm(leg.fpr);
  if (!f) return { state: 'absent', fpr: null };
  return { state: f === local ? 'agrees' : 'differs', fpr: f };
}

export function assess(input: { local: string | null; domain: LegInput; keychain: LegInput; vks: LegInput }): Assessment {
  const local = norm(input.local);
  const legs: Record<Leg, LegResult> = {
    domain: legState(local, input.domain),
    keychain: legState(local, input.keychain),
    vks: legState(local, input.vks),
  };
  if (!local) return { local, legs, summary: 'no-local-key', independent: legs.vks.state };
  let summary: Summary;
  if (legs.domain.state === 'differs' || legs.keychain.state === 'differs') summary = 'differs';
  else if (legs.domain.state === 'unreachable') summary = 'unchecked';
  else if (legs.domain.state === 'absent') summary = 'unpublished';
  else summary = 'consistent';
  return { local, legs, summary, independent: legs.vks.state };
}

/** The fingerprint a locked private key really has. */
export async function privateFpr(armor: string): Promise<string> {
  return (await openpgp.readPrivateKey({ armoredKey: armor })).getFingerprint().toLowerCase();
}

/** The fingerprint of an armored public key. */
export async function publicFpr(armor: string): Promise<string> {
  return (await openpgp.readKey({ armoredKey: armor })).getFingerprint().toLowerCase();
}

/** 4-character groups, the way people read them aloud. */
export const showFpr = (f: string): string => f.toUpperCase().replace(/(.{4})/g, '$1 ').trim();
