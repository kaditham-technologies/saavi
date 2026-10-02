import { describe, expect, it } from 'vitest';
import { assess } from '../src/keymatch';
import { confirmAdoption, planAdoption } from '../src/adoption';

const A = 'AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555';
const B = 'ffff1111bbbb2222cccc3333dddd4444eeee5555';
const a = A.toLowerCase();
const got = (fpr: string | null) => ({ fpr, reached: true });
const away = { fpr: null, reached: false };
const unread = { fpr: null, reached: true, read: false };

describe('the key check: what each leg proves', () => {
  it('consistent when the domain agrees, case and spacing aside', () => {
    const r = assess({ local: A, domain: got(a), keychain: got('aaaa 1111 bbbb 2222 cccc 3333 dddd 4444 eeee 5555'), vks: got(A) });
    expect(r.summary).toBe('consistent');
    expect(r.legs.domain.state).toBe('agrees');
    expect(r.legs.keychain.state).toBe('agrees');
    expect(r.independent).toBe('agrees');
  });

  it('a different key on the domain or in the keychain differs; each leg says which', () => {
    expect(assess({ local: A, domain: got(B), keychain: got(A), vks: got(null) })).toMatchObject({ summary: 'differs', legs: { domain: { state: 'differs' }, keychain: { state: 'agrees' } } });
    expect(assess({ local: A, domain: got(A), keychain: got(B), vks: got(null) }).summary).toBe('differs');
  });

  it('absent or unreachable is never a mismatch', () => {
    expect(assess({ local: A, domain: got(null), keychain: got(A), vks: away }).summary).toBe('unpublished');
    expect(assess({ local: A, domain: away, keychain: got(A), vks: got(null) }).summary).toBe('unchecked');
    const r = assess({ local: A, domain: got(A), keychain: unread, vks: away });
    expect(r.summary).toBe('consistent');
    expect(r.legs.keychain.state).toBe('not-read');
    expect(r.independent).toBe('unreachable');
  });

  it('keys.openpgp.org is independent evidence: it never changes the summary', () => {
    const differsThere = assess({ local: A, domain: got(A), keychain: got(A), vks: got(B) });
    expect(differsThere.summary).toBe('consistent');
    expect(differsThere.independent).toBe('differs');
    expect(assess({ local: A, domain: got(B), keychain: got(A), vks: got(A) }).summary).toBe('differs');
  });

  it('without a local key there is nothing this computer can vouch for', () => {
    expect(assess({ local: null, domain: got(A), keychain: got(A), vks: got(A) }).summary).toBe('no-local-key');
  });
});

describe('adoption: a retired key never comes back unasked', () => {
  const OLD = 'cccc0000cccc0000cccc0000cccc0000cccc0000';
  const NEW = 'dddd0000dddd0000dddd0000dddd0000dddd0000';

  it('plans only real changes, and flags a retired target', () => {
    const plan = planAdoption([
      { address: 'Me@example.com', current: NEW, retired: [OLD], target: OLD.toUpperCase(), source: 'published' },
      { address: 'b@example.com', current: OLD, retired: [], target: NEW, source: 'keychain' },
      { address: 'c@example.com', current: NEW, retired: [], target: NEW, source: 'published' },
      { address: 'd@example.com', current: NEW, retired: [], target: null, source: 'published' },
    ]);
    expect(plan).toEqual([
      { address: 'me@example.com', target: OLD, source: 'published', reactivates: true },
      { address: 'b@example.com', target: NEW, source: 'keychain', reactivates: false },
    ]);
  });

  it('a reactivation is kept only on an explicit yes; ordinary changes pass without asking', async () => {
    const plan = planAdoption([
      { address: 'me@example.com', current: NEW, retired: [OLD], target: OLD, source: 'published' },
      { address: 'b@example.com', current: OLD, retired: [], target: NEW, source: 'keychain' },
    ]);
    const asked: string[] = [];
    const no = await confirmAdoption(plan, async (s) => { asked.push(s.address); return false; });
    expect(no).toEqual({ 'b@example.com': NEW });
    expect(asked).toEqual(['me@example.com']);
    const yes = await confirmAdoption(plan, async () => true);
    expect(yes).toEqual({ 'me@example.com': OLD, 'b@example.com': NEW });
  });
});
