import { describe, expect, it } from 'vitest';
import { decideBanner, readBaseline, writeBaseline } from '../src/changes';

describe('the "changed on another device" banner (argus A1)', () => {
  it('a device with no marker takes its first look as the baseline — no banner', () => {
    expect(decideBanner(4, null, null)).toEqual({ banner: null, baseline: 4 });
  });

  it('asks when the server is ahead of what this device knows', () => {
    expect(decideBanner(5, null, 4)).toEqual({ banner: 5, baseline: 4 });
    expect(decideBanner(5, 4, null)).toEqual({ banner: 5, baseline: null });
  });

  it('the higher of marker and baseline wins, so an answered version never asks again', () => {
    expect(decideBanner(5, 3, 5)).toEqual({ banner: null, baseline: 5 });
    expect(decideBanner(5, 5, 2)).toEqual({ banner: null, baseline: 2 });
  });

  it('no answer from the server changes nothing', () => {
    expect(decideBanner(null, 3, 2)).toEqual({ banner: null, baseline: 2 });
  });

  it('the stored baseline only moves forward', () => {
    writeBaseline('Me@example.com', 4);
    writeBaseline('me@example.com', 2);
    expect(readBaseline('me@example.com')).toBe(4);
    writeBaseline('me@example.com', 6);
    expect(readBaseline('ME@example.com')).toBe(6);
  });
});
