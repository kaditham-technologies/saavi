import { describe, expect, it } from 'vitest';
import { isNewer } from '../src/update';

describe('update indicator', () => {
  it('compares dotted versions numerically', () => {
    expect(isNewer('0.2.1', '0.2.0')).toBe(true);
    expect(isNewer('0.2.10', '0.2.9')).toBe(true);
    expect(isNewer('1.0.0', '0.9.9')).toBe(true);
    expect(isNewer('0.2.0', '0.2.0')).toBe(false);
    expect(isNewer('0.1.9', '0.2.0')).toBe(false);
    expect(isNewer('0.2', '0.2.0')).toBe(false);
  });
});
