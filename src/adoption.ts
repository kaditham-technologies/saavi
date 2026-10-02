// Bringing a different current key onto this computer (0.6.0; design in
// docs/ACCOUNT-SIGNIN.md, "Adoption"). When an address already has a ring
// here and another source names a different key as current — the domain's
// published key, or (on the customer's explicit choice) the keychain's —
// restore swaps the active key only for addresses in an adoption plan.
// This module builds that plan and puts one rule in front of it:
//
//   A key this computer has RETIRED is never made current again without the
//   customer saying so, for that address, knowing what it means.
//
// Retiring is a decision: usually a rotation, sometimes because the key was
// exposed. A source naming a retired key as current is either a device that
// slept through the rotation, a stale directory, or someone trying to roll
// the account back to a key they hold. Saavi cannot tell those apart, so it
// asks — and the default answer is no.
export type AdoptionSource = 'published' | 'keychain';

export interface AdoptionInput {
  address: string;
  /** Fingerprint of this computer's current key. */
  current: string;
  /** Fingerprints this computer holds as retired for the address. */
  retired: string[];
  /** The key the source names as current, or null when it names none. */
  target: string | null;
  source: AdoptionSource;
}

export interface AdoptionStep {
  address: string;
  target: string;
  source: AdoptionSource;
  /** True when the target is a key this computer retired. */
  reactivates: boolean;
}

const n = (f: string): string => f.replace(/\s+/g, '').toLowerCase();

/** Which addresses would change key, and which of those would bring back a
 *  retired one. An address whose source agrees with this computer, or names
 *  nothing, is not in the plan. */
export function planAdoption(inputs: AdoptionInput[]): AdoptionStep[] {
  const out: AdoptionStep[] = [];
  for (const i of inputs) {
    if (!i.target) continue;
    const t = n(i.target);
    if (t === n(i.current)) continue;
    out.push({ address: i.address.toLowerCase(), target: t, source: i.source, reactivates: i.retired.map(n).includes(t) });
  }
  return out;
}

/** The plan restore receives (address → fingerprint). A step that would
 *  bring back a retired key is kept ONLY when `confirm` answers yes for it;
 *  every other step passes. `confirm` is asked once per such address. */
export async function confirmAdoption(plan: AdoptionStep[], confirm: (step: AdoptionStep) => Promise<boolean>): Promise<Record<string, string>> {
  const out: Record<string, string> = {};
  for (const step of plan) {
    if (step.reactivates && !(await confirm(step))) continue;
    out[step.address] = step.target;
  }
  return out;
}
