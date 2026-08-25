import { beforeEach, describe, expect, it } from 'vitest';
import * as mime from '../src/mime';
import * as pgp from '../src/pgp';

const PASS = 'correct horse battery staple';
const ME = 'me@example.org';

beforeEach(() => {
  localStorage.clear();
  pgp.clearSession();
});

describe('build → parse round trip', () => {
  it('plain text with a protected subject', () => {
    const raw = mime.buildMimeEntity({ subject: 'Q3 figures', text: 'Numbers attached.\nBest,\nA' });
    expect(raw).toContain('protected-headers="v1"');
    const out = mime.parseMimeEntity(raw);
    expect(out.subject).toBe('Q3 figures');
    expect(out.text).toBe('Numbers attached.\nBest,\nA');
    expect(out.html).toBeNull();
    expect(out.attachments).toEqual([]);
  });

  it('text + html + attachments, unicode intact', () => {
    const bytes = new Uint8Array([0, 1, 2, 255, 254, 128, 10, 13]);
    const raw = mime.buildMimeEntity({
      subject: 'Résumé — naïve π',
      text: 'plain — π ≈ 3.14159',
      html: '<p>rich — <b>π</b></p>',
      attachments: [
        { name: 'report.pdf', type: 'application/pdf', bytes },
        { name: 'facture n°7 — août.bin', type: 'application/octet-stream', bytes },
      ],
    });
    const out = mime.parseMimeEntity(raw);
    expect(out.subject).toBe('Résumé — naïve π');
    expect(out.text).toBe('plain — π ≈ 3.14159');
    expect(out.html).toBe('<p>rich — <b>π</b></p>');
    expect(out.attachments.map((a) => a.name)).toEqual(['report.pdf', 'facture n°7 — août.bin']);
    expect(out.attachments.map((a) => a.type)).toEqual(['application/pdf', 'application/octet-stream']);
    for (const a of out.attachments) expect([...a.bytes]).toEqual([...bytes]);
  });

  it('subject header never smuggles extra headers', () => {
    const raw = mime.buildMimeEntity({ subject: 'hi\r\nBcc: evil@x.org', text: 'body' });
    const out = mime.parseMimeEntity(raw);
    expect(out.subject).toBe('hi Bcc: evil@x.org');
    expect(raw).not.toMatch(/^Bcc:/m);
  });

  it('a large binary attachment survives base64 wrapping', () => {
    const big = new Uint8Array(70_000);
    for (let i = 0; i < big.length; i++) big[i] = i % 251;
    const raw = mime.buildMimeEntity({ text: 'big', attachments: [{ name: 'blob.bin', type: 'application/octet-stream', bytes: big }] });
    // RFC 2045: encoded lines stay within 76 chars
    for (const line of raw.split(/\r\n/)) expect(line.length).toBeLessThanOrEqual(78);
    const out = mime.parseMimeEntity(raw);
    expect(out.attachments[0].bytes).toHaveLength(70_000);
    expect([...out.attachments[0].bytes.slice(0, 5)]).toEqual([0, 1, 2, 3, 4]);
  });
});

describe('parsing foreign mail (what other clients send)', () => {
  it('quoted-printable text, quoted filename, LF-only lines', () => {
    const foreign = [
      'Content-Type: multipart/mixed; boundary="XYZ"',
      '',
      '--XYZ',
      'Content-Type: text/plain; charset=iso-8859-1',
      'Content-Transfer-Encoding: quoted-printable',
      '',
      'caf=E9 au lait =',
      'joined',
      '--XYZ',
      'Content-Type: application/pdf; name="fallback.pdf"',
      'Content-Transfer-Encoding: base64',
      'Content-Disposition: attachment; filename="q3 report.pdf"',
      '',
      'AAEC',
      '--XYZ--',
      '',
    ].join('\n');
    const out = mime.parseMimeEntity(foreign);
    expect(out.text).toBe('café au lait joined');
    expect(out.attachments[0].name).toBe('q3 report.pdf');
    expect([...out.attachments[0].bytes]).toEqual([0, 1, 2]);
  });

  it('RFC 2047 encoded-word and RFC 2231 extended filenames decode', () => {
    const a = mime.parseMimeEntity([
      'Content-Type: application/pdf',
      'Content-Disposition: attachment; filename="=?utf-8?B?w6l0w6kucGRm?="',
      'Content-Transfer-Encoding: base64',
      '',
      'AAEC',
    ].join('\r\n'));
    expect(a.attachments[0].name).toBe('été.pdf');
    const b = mime.parseMimeEntity([
      "Content-Type: application/pdf",
      "Content-Disposition: attachment; filename*=utf-8''%C3%A9t%C3%A9%202026.pdf",
      'Content-Transfer-Encoding: base64',
      '',
      'AAEC',
    ].join('\r\n'));
    expect(b.attachments[0].name).toBe('été 2026.pdf');
  });

  it('nested alternative inside mixed picks text AND html', () => {
    const raw = mime.buildMimeEntity({
      text: 't', html: '<p>h</p>',
      attachments: [{ name: 'x.bin', type: 'application/octet-stream', bytes: new Uint8Array([9]) }],
    });
    const out = mime.parseMimeEntity(raw);
    expect(out.text).toBe('t');
    expect(out.html).toBe('<p>h</p>');
    expect(out.attachments).toHaveLength(1);
  });
});

describe('parser hardening (audit + review findings)', () => {
  it('an empty text part does not swallow the real body (argus #2)', () => {
    const raw = [
      'Content-Type: multipart/mixed; boundary="B"',
      '',
      '--B',
      'Content-Type: text/plain; charset=utf-8',
      '',
      '',                       // empty leading text part (Apple inline layout)
      '--B',
      'Content-Type: text/plain; charset=utf-8',
      'Content-Transfer-Encoding: base64',
      '',
      Buffer.from('the actual message').toString('base64'),
      '--B--',
      '',
    ].join('\r\n');
    const out = mime.parseMimeEntity(raw);
    expect(out.text).toBe('the actual message');
    expect(out.attachments).toHaveLength(0);
  });

  it('a child boundary that prefixes the parent does not split the parent (argus #7)', () => {
    const raw = [
      'Content-Type: multipart/mixed; boundary="B"',
      '',
      '--B',
      'Content-Type: multipart/related; boundary="B_rel"',
      '',
      '--B_rel',
      'Content-Type: text/html; charset=utf-8',
      'Content-Transfer-Encoding: base64',
      '',
      Buffer.from('<p>the real body</p>').toString('base64'),
      '--B_rel--',
      '--B--',
      '',
    ].join('\r\n');
    const out = mime.parseMimeEntity(raw);
    expect(out.html).toBe('<p>the real body</p>');
  });

  it('a protected Subject is honoured ONLY at top level with protected-headers=v1 (cerberus V3 / argus #9)', () => {
    // A Subject on a nested part must NOT be adopted.
    const nested = [
      'Content-Type: multipart/mixed; boundary="B"',
      '',
      '--B',
      'Content-Type: text/plain; protected-headers="v1"',
      'Subject: injected subject',
      '',
      'body',
      '--B--',
      '',
    ].join('\r\n');
    expect(mime.parseMimeEntity(nested).subject).toBeNull();
    // Top-level single part WITH the marker is honoured.
    const top = mime.buildMimeEntity({ subject: 'real', text: 'body' });
    expect(mime.parseMimeEntity(top).subject).toBe('real');
  });

  it('strips bidi overrides from a spoofed attachment filename (cerberus V9)', () => {
    const raw = mime.buildMimeEntity({
      text: 'x',
      attachments: [{ name: 'invoice‮mth.exe', type: 'application/octet-stream', bytes: new Uint8Array([1]) }],
    });
    const name = mime.parseMimeEntity(raw).attachments[0].name;
    expect(name).not.toContain('‮');
    expect(name).toBe('invoicemth.exe');
  });

  it('caps a runaway part count instead of hanging (cerberus V8)', () => {
    const parts = Array.from({ length: 5000 }, () => '--B\r\nContent-Type: text/plain\r\n\r\nx').join('\r\n');
    const raw = `Content-Type: multipart/mixed; boundary="B"\r\n\r\n${parts}\r\n--B--\r\n`;
    // must return, not spin; attachment count is bounded
    const out = mime.parseMimeEntity(raw);
    expect(out.attachments.length).toBeLessThanOrEqual(128);
  });
});

describe('outgoing header safety (cerberus V6, argus #4)', () => {
  const armored = '-----BEGIN PGP MESSAGE-----\nabc\n-----END PGP MESSAGE-----\n';

  it('a CRLF-laced address is dropped from the header, never injected', () => {
    const raw = mime.buildEncryptedMessage({
      from: { email: 'me@example.ie' },
      to: [{ email: 'ok@example.org' }, { email: 'evil@x.org\r\nBcc: victim@x.org' }],
      subject: '...', armored,
    });
    expect(raw).not.toMatch(/^Bcc:/mi);
    expect(raw).toContain('To: ok@example.org');
    expect(raw).not.toContain('evil@x.org');
  });

  it('a malformed In-Reply-To id cannot add a header line', () => {
    const raw = mime.buildEncryptedMessage({
      from: { email: 'me@example.ie' }, to: [{ email: 'a@b.org' }], subject: '...', armored,
      inReplyTo: ['good@x.org', 'bad\r\nX-Injected: 1@x.org'],
    });
    expect(raw).not.toMatch(/^X-Injected:/mi);
    expect(raw).toContain('In-Reply-To: <good@x.org>');
  });

  it('folds long recipient and References headers under 998 octets', () => {
    const to = Array.from({ length: 60 }, (_, i) => ({ email: `person.number.${i}@some-longish-domain.example.com` }));
    const refs = Array.from({ length: 30 }, (_, i) => `CAF0abcdefghij.longish.local.part.${i}@mail.example.com`);
    const raw = mime.buildEncryptedMessage({ from: { email: 'me@example.ie' }, to, subject: '...', armored, references: refs });
    for (const line of raw.split('\r\n')) expect(line.length).toBeLessThanOrEqual(998);
    // References is capped (first + last ~20), not emitted whole
    const refLines = raw.split('\r\n\r\n')[0].split('\r\n');
    expect(refLines.some((l) => l.startsWith('References:'))).toBe(true);
  });

  it('an attacker-derived attachment content-type cannot break the part', () => {
    const raw = mime.buildMimeEntity({
      text: 'x',
      attachments: [{ name: 'a.bin', type: 'application/pdf\r\nX-Evil: 1', bytes: new Uint8Array([1]) }],
    });
    expect(raw).not.toMatch(/^X-Evil:/mi);
    expect(raw).toContain('Content-Type: application/octet-stream');
  });
});

describe('looksLikeMimeEntity', () => {
  it('accepts built entities, rejects legacy bare payloads', () => {
    expect(mime.looksLikeMimeEntity(mime.buildMimeEntity({ text: 'x' }))).toBe(true);
    expect(mime.looksLikeMimeEntity('just some sealed text')).toBe(false);
    expect(mime.looksLikeMimeEntity('<p>legacy sealed html</p>')).toBe(false);
    // a letter that merely TALKS about headers is not an entity
    expect(mime.looksLikeMimeEntity('Note: set Content-Type: text/html in your config')).toBe(false);
  });
});

describe('buildEncryptedMessage (outer RFC 3156 shell)', () => {
  it('emits a well-formed multipart/encrypted message', () => {
    const raw = mime.buildEncryptedMessage({
      from: { name: 'Aoife Ní Bhriain', email: 'aoife@example.ie' },
      to: [{ email: 'bob@example.org' }, { name: 'C. Ó Dálaigh', email: 'c@example.ie' }],
      cc: [{ email: 'cc@example.org' }],
      subject: '...',
      armored: '-----BEGIN PGP MESSAGE-----\nabc\n-----END PGP MESSAGE-----\n',
      date: new Date('2026-08-25T12:00:00Z'),
      inReplyTo: ['prev@example.org'],
    });
    expect(raw).toMatch(/^From: =\?utf-8\?B\?/m);                    // non-ASCII name encoded
    expect(raw).toContain('Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"');
    expect(raw).toContain('Version: 1');
    expect(raw).toContain('Date: Tue, 25 Aug 2026 12:00:00 +0000');
    expect(raw).toContain('In-Reply-To: <prev@example.org>');
    expect(raw).not.toMatch(/^Bcc:/m);
    // headers end before the body; every line break is CRLF
    expect(raw.split('\r\n\r\n')[0]).toContain('MIME-Version: 1.0');
    expect(raw).not.toMatch(/[^\r]\n/);
    // our own parser can dig the ciphertext back out (it lands as the
    // octet-stream attachment)
    const outer = mime.parseMimeEntity(raw);
    const asc = outer.attachments.find((a) => a.name === 'encrypted.asc');
    expect(asc).toBeDefined();
    expect(new TextDecoder().decode(asc!.bytes)).toContain('BEGIN PGP MESSAGE');
  });

  it('full loop: inner entity → seal → wrap → unwrap → unseal → parse', async () => {
    const rec = await pgp.generateKeys(ME, 'Me', PASS);
    await pgp.unlockPrivateKey(ME, PASS);
    const inner = mime.buildMimeEntity({
      subject: 'the real subject', text: 'sealed body',
      attachments: [{ name: 'p.bin', type: 'application/octet-stream', bytes: new Uint8Array([4, 5]) }],
    });
    const armored = await pgp.encryptText(inner, [rec.publicKey], ME);
    const wire = mime.buildEncryptedMessage({
      from: { email: ME }, to: [{ email: ME }], subject: '...', armored,
    });
    const outer = mime.parseMimeEntity(wire);
    // The outer "..." is a plain header on a non-protected entity, so the
    // parser must NOT surface it as the entity subject (protected-headers
    // scoping) — the real subject lives inside the ciphertext.
    expect(outer.subject).toBeNull();
    expect(wire).toContain('Subject: ...');
    const asc = new TextDecoder().decode(outer.attachments.find((a) => a.name === 'encrypted.asc')!.bytes);
    const dec = await pgp.decryptText(asc, rec.publicKey);
    const got = mime.parseMimeEntity(dec.text);
    expect(got.subject).toBe('the real subject');
    expect(got.text).toBe('sealed body');
    expect([...got.attachments[0].bytes]).toEqual([4, 5]);
  });
});

describe('sealed MIME through the OpenPGP layer', () => {
  it('build → encrypt → decrypt → parse keeps everything', async () => {
    const rec = await pgp.generateKeys(ME, 'Me', PASS);
    await pgp.unlockPrivateKey(ME, PASS);
    const bytes = new Uint8Array([1, 2, 3]);
    const inner = mime.buildMimeEntity({
      subject: 'secret subject', text: 'secret body', html: '<p>secret body</p>',
      attachments: [{ name: 'a.bin', type: 'application/octet-stream', bytes }],
    });
    const armored = await pgp.encryptText(inner, [rec.publicKey], ME);
    const dec = await pgp.decryptText(armored, rec.publicKey);
    expect(dec.signedBy).toBe(ME);
    expect(mime.looksLikeMimeEntity(dec.text)).toBe(true);
    const out = mime.parseMimeEntity(dec.text);
    expect(out.subject).toBe('secret subject');
    expect(out.text).toBe('secret body');
    expect(out.html).toBe('<p>secret body</p>');
    expect([...out.attachments[0].bytes]).toEqual([1, 2, 3]);
  });
});
