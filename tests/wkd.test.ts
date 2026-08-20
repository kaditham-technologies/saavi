import { afterEach, describe, expect, it, vi } from 'vitest';
import * as openpgp from 'openpgp';
import { wkdLookup, wkdUrls } from '../src/wkd';

async function binaryKeyFor(email: string): Promise<Uint8Array> {
  const { publicKey } = await openpgp.generateKey({
    userIDs: [{ name: 'T', email }], type: 'ecc', curve: 'curve25519Legacy', format: 'binary',
  });
  return publicKey;
}

function mockFetch(handler: (url: string) => Response | Promise<Response>): void {
  vi.stubGlobal('fetch', vi.fn((u: string) => Promise.resolve(handler(u))));
}
const notFound = () => new Response(null, { status: 404 });

afterEach(() => vi.unstubAllGlobals());

describe('wkdUrls', () => {
  it('matches the draft-koch test vector (Joe.Doe@Example.ORG)', async () => {
    const urls = await wkdUrls('Joe.Doe@Example.ORG');
    expect(urls).toEqual([
      'https://openpgpkey.example.org/.well-known/openpgpkey/example.org/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=joe.doe',
      'https://example.org/.well-known/openpgpkey/hu/iy9q119eutrkn8s1mk4r39qejnbu3n5q?l=joe.doe',
    ]);
  });
  it('rejects things that are not addresses', async () => {
    expect(await wkdUrls('nobody')).toEqual([]);
    expect(await wkdUrls('@x.org')).toEqual([]);
  });
});

describe('wkdLookup', () => {
  it('returns the armored key when the domain publishes one for that address', async () => {
    const bin = await binaryKeyFor('ada@example.org');
    mockFetch((u) => (u.startsWith('https://example.org/') ? new Response(bin) : notFound()));
    const armored = await wkdLookup('ada@example.org');
    expect(armored).toContain('-----BEGIN PGP PUBLIC KEY BLOCK-----');
    const key = await openpgp.readKey({ armoredKey: armored! });
    expect(key.getUserIDs()[0]).toContain('ada@example.org');
  });

  it('refuses a key that does not carry the looked-up address', async () => {
    const bin = await binaryKeyFor('mallory@example.org');
    mockFetch(() => new Response(bin));
    expect(await wkdLookup('ada@example.org')).toBeNull();
  });

  it('matches user IDs case-insensitively and with a display name', async () => {
    const bin = await binaryKeyFor('Ada.Lovelace@Example.org');
    mockFetch(() => new Response(bin));
    expect(await wkdLookup('ada.lovelace@example.org')).not.toBeNull();
  });

  it('refuses oversized responses', async () => {
    mockFetch(() => new Response(new Uint8Array(2 * 1024 * 1024)));
    expect(await wkdLookup('ada@example.org')).toBeNull();
  });

  it('returns null when nothing is published or the body is garbage', async () => {
    mockFetch(notFound);
    expect(await wkdLookup('ada@example.org')).toBeNull();
    mockFetch(() => new Response(new TextEncoder().encode('not a key')));
    expect(await wkdLookup('ada@example.org')).toBeNull();
  });
});

describe('wkdLookup redirects', () => {
  it('refuses a result whose final URL is not https', async () => {
    const bin = await binaryKeyFor('ada@example.org');
    mockFetch(() => {
      const r = new Response(bin);
      Object.defineProperty(r, 'url', { value: 'http://example.org/key' });
      return r;
    });
    expect(await wkdLookup('ada@example.org')).toBeNull();
  });
});
