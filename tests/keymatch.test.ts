import { describe, expect, it } from 'vitest';
import { judge } from '../src/keymatch';

const A = 'AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555';
const B = 'ffff1111bbbb2222cccc3333dddd4444eeee5555';

describe('the published-key match check', () => {
  it('matches when every present source agrees, case and spacing aside', () => {
    expect(judge({ local: A, wkd: A.toLowerCase(), keychain: 'aaaa 1111 bbbb 2222 cccc 3333 dddd 4444 eeee 5555' }))
      .toEqual({ state: 'match', fingerprint: A.toLowerCase(), checked: ['local', 'wkd', 'keychain'] });
  });

  it('names exactly the sources that disagree with this device', () => {
    expect(judge({ local: A, wkd: B, keychain: A })).toMatchObject({ state: 'mismatch', differing: ['wkd'] });
    expect(judge({ local: A, wkd: B, keychain: B })).toMatchObject({ state: 'mismatch', differing: ['wkd', 'keychain'] });
  });

  it('a key that is not published is said plainly, not called a mismatch', () => {
    expect(judge({ local: A, wkd: null, keychain: A })).toEqual({ state: 'unpublished', fingerprint: A.toLowerCase() });
  });

  it('without a local key there is nothing this device can vouch for', () => {
    expect(judge({ local: null, wkd: A, keychain: A })).toEqual({ state: 'unknown' });
  });

  it('matches on two sources when the keychain was not read this session', () => {
    expect(judge({ local: A, wkd: A, keychain: null })).toMatchObject({ state: 'match', checked: ['local', 'wkd'] });
  });
});
