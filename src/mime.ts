// The MIME layer under PGP/MIME (RFC 3156): builds and parses the INNER
// entity — the thing that gets encrypted. The outer multipart/encrypted
// shell is transport-specific (webmail assembles it as JMAP bodyStructure;
// an .eml export would assemble it as text) and deliberately lives with the
// transport, not here.
//
// Built entities carry the real Subject as a protected header on the inner
// part (Content-Type ...; protected-headers="v1" — the Thunderbird/LAMPS
// convention), so the outer, visible subject can be a plain "...".
// Every leaf part is base64-encoded: it is ciphertext-bound anyway, and
// base64 sidesteps all line-length and 8-bit transport doubt.

const CRLF = '\r\n';

export interface MimeAttachment {
  name: string;
  type: string;        // MIME type, e.g. application/pdf
  bytes: Uint8Array;
}

export interface MimeEntity {
  subject: string | null;
  text: string | null;
  html: string | null;
  attachments: MimeAttachment[];
}

// ---------- base64 / quoted-printable ----------

function b64encode(bytes: Uint8Array): string {
  let bin = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    bin += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(bin);
}

function b64decode(text: string): Uint8Array {
  const bin = atob(text.replace(/[^A-Za-z0-9+/=]/g, ''));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Base64 wrapped at 76 columns, per RFC 2045. */
function b64lines(bytes: Uint8Array): string {
  return b64encode(bytes).replace(/(.{76})/g, '$1' + CRLF);
}

function qpDecode(text: string): Uint8Array {
  const src = text.replace(/=\r?\n/g, '');   // soft line breaks
  const out: number[] = [];
  for (let i = 0; i < src.length; i++) {
    if (src[i] === '=' && /^[0-9a-fA-F]{2}$/.test(src.slice(i + 1, i + 3))) {
      out.push(parseInt(src.slice(i + 1, i + 3), 16));
      i += 2;
    } else {
      out.push(src.charCodeAt(i) & 0xff);
    }
  }
  return new Uint8Array(out);
}

// ---------- header plumbing ----------

interface Headers { [lower: string]: string }

/** Split one MIME entity into its (unfolded) headers and raw body. */
function splitEntity(raw: string): { headers: Headers; body: string } {
  const m = raw.match(/\r?\n\r?\n/);
  const headBlock = m ? raw.slice(0, m.index) : raw;
  const body = m ? raw.slice((m.index ?? 0) + m[0].length) : '';
  const headers: Headers = {};
  const unfolded = headBlock.replace(/\r?\n[ \t]+/g, ' ');
  for (const line of unfolded.split(/\r?\n/)) {
    const c = line.indexOf(':');
    if (c > 0) headers[line.slice(0, c).trim().toLowerCase()] = line.slice(c + 1).trim();
  }
  return { headers, body };
}

/** "type/sub; a=b; c="d e"" → value + params (quoted or RFC 2231 encoded). */
function parseParams(header: string | undefined): { value: string; params: Record<string, string> } {
  if (!header) return { value: '', params: {} };
  const parts = header.split(/;(?=(?:[^"]*"[^"]*")*[^"]*$)/);
  const value = (parts.shift() ?? '').trim().toLowerCase();
  const params: Record<string, string> = {};
  const continuations: Record<string, string[]> = {};
  for (const p of parts) {
    const eq = p.indexOf('=');
    if (eq < 0) continue;
    let name = p.slice(0, eq).trim().toLowerCase();
    let val = p.slice(eq + 1).trim().replace(/^"(.*)"$/s, '$1');
    // RFC 2231: filename*=utf-8''..., possibly split filename*0*=/filename*1*=
    const cont = name.match(/^(.+?)\*(\d+)\*?$/);
    if (cont) {
      (continuations[cont[1]] ??= [])[Number(cont[2])] = val;
      continue;
    }
    if (name.endsWith('*')) {
      name = name.slice(0, -1);
      val = decodeExtValue(val);
    }
    params[name] ??= val;
  }
  for (const [name, pieces] of Object.entries(continuations)) {
    params[name] ??= decodeExtValue(pieces.join(''));
  }
  return { value, params };
}

/** RFC 2231 extended value: charset'lang'percent-encoded. */
function decodeExtValue(val: string): string {
  const m = val.match(/^([^']*)'[^']*'([\s\S]*)$/);
  if (!m) return val;
  try {
    const bytes = new Uint8Array([...m[2].matchAll(/%([0-9a-fA-F]{2})|(.)/g)]
      .flatMap((h) => h[1] ? [parseInt(h[1], 16)] : [...new TextEncoder().encode(h[2])]));
    return new TextDecoder(m[1] || 'utf-8').decode(bytes);
  } catch {
    return m[2];
  }
}

/** Minimal RFC 2047 encoded-word decoding (=?utf-8?B?...?=) for filenames. */
function decodeWords(src: string): string {
  return src.replace(/=\?([^?]+)\?([bBqQ])\?([^?]*)\?=/g, (_, cs, enc, data) => {
    try {
      const bytes = /b/i.test(enc)
        ? b64decode(data)
        : qpDecode(data.replace(/_/g, ' '));
      return new TextDecoder(cs).decode(bytes);
    } catch {
      return _;
    }
  });
}

function decodeCharset(bytes: Uint8Array, charset: string | undefined): string {
  try {
    return new TextDecoder(charset || 'utf-8').decode(bytes);
  } catch {
    return new TextDecoder('utf-8').decode(bytes);
  }
}

/** Decode one leaf part's body to bytes, honouring its transfer encoding. */
function decodeBody(body: string, cte: string | undefined): Uint8Array {
  switch ((cte ?? '7bit').trim().toLowerCase()) {
    case 'base64': return b64decode(body);
    case 'quoted-printable': return qpDecode(body);
    default: return new TextEncoder().encode(body.replace(/\r?\n$/, ''));
  }
}

// ---------- build ----------

function boundary(): string {
  const r = new Uint8Array(12);
  crypto.getRandomValues(r);
  return '----=_saavi_' + [...r].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function textPart(type: string, content: string): string {
  return [
    `Content-Type: ${type}; charset=utf-8`,
    'Content-Transfer-Encoding: base64',
    '',
    b64lines(new TextEncoder().encode(content)),
  ].join(CRLF);
}

function attachmentPart(a: MimeAttachment): string {
  const ascii = /^[\x20-\x7e]*$/.test(a.name) && !a.name.includes('"');
  const nameParam = ascii
    ? `filename="${a.name}"`
    : `filename*=utf-8''${[...new TextEncoder().encode(a.name)]
        .map((b) => (b > 0x20 && b < 0x7f && !'%\'";'.includes(String.fromCharCode(b))
          ? String.fromCharCode(b) : '%' + b.toString(16).padStart(2, '0').toUpperCase())).join('')}`;
  return [
    `Content-Type: ${a.type || 'application/octet-stream'}`,
    'Content-Transfer-Encoding: base64',
    `Content-Disposition: attachment; ${nameParam}`,
    '',
    b64lines(a.bytes),
  ].join(CRLF);
}

function multipart(sub: 'mixed' | 'alternative', parts: string[], extraHeaders: string[] = []): string {
  const b = boundary();
  return [
    `Content-Type: multipart/${sub}; boundary="${b}"${extraHeaders.length ? '; protected-headers="v1"' : ''}`,
    ...extraHeaders,
    '',
    ...parts.flatMap((p) => [`--${b}`, p]),
    `--${b}--`,
    '',
  ].join(CRLF);
}

/**
 * Build the inner MIME entity to encrypt. The subject rides INSIDE as a
 * protected header; the transport's visible subject should be "...".
 */
export function buildMimeEntity(src: {
  subject?: string;
  text: string;
  html?: string | null;
  attachments?: MimeAttachment[];
}): string {
  const protectedHeaders = src.subject !== undefined ? [`Subject: ${src.subject.replace(/[\r\n]+/g, ' ')}`] : [];
  const bodyEntity = src.html
    ? multipart('alternative', [textPart('text/plain', src.text), textPart('text/html', src.html)])
    : textPart('text/plain', src.text);
  if (src.attachments?.length) {
    return multipart('mixed', [bodyEntity, ...src.attachments.map(attachmentPart)], protectedHeaders);
  }
  if (!protectedHeaders.length) return bodyEntity;
  // A single body part still needs the protected Subject on its own headers.
  const { headers, body } = splitEntity(bodyEntity);
  const ct = headers['content-type'] ?? 'text/plain; charset=utf-8';
  const rebuilt = [
    `Content-Type: ${ct}; protected-headers="v1"`,
    ...(headers['content-transfer-encoding'] ? [`Content-Transfer-Encoding: ${headers['content-transfer-encoding']}`] : []),
    ...protectedHeaders,
    '',
    body,
  ].join(CRLF);
  return rebuilt;
}

// ---------- parse ----------

/** True when a decrypted payload looks like a MIME entity rather than the
 *  legacy bare text/HTML the older sealer produced. */
export function looksLikeMimeEntity(payload: string): boolean {
  const head = payload.slice(0, 2048);
  return /^(?:[!-9;-~]+:[^\n]*\r?\n)+/.test(head) && /^content-type:/im.test(head);
}

function walk(raw: string, out: MimeEntity, depth: number): void {
  if (depth > 10) return;   // malformed nesting — stop, keep what we have
  const { headers, body } = splitEntity(raw);
  const ct = parseParams(headers['content-type'] ?? 'text/plain; charset=us-ascii');
  if (headers['subject'] !== undefined && out.subject === null) {
    out.subject = decodeWords(headers['subject']);
  }
  if (ct.value.startsWith('multipart/')) {
    const b = ct.params['boundary'];
    if (!b) return;
    const chunks = body.split(new RegExp(`(?:^|\\r?\\n)--${b.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`));
    for (const chunk of chunks.slice(1)) {
      if (/^--/.test(chunk)) break;   // closing delimiter
      walk(chunk.replace(/^[^\n]*\r?\n/, ''), out, depth + 1);
    }
    return;
  }
  const disp = parseParams(headers['content-disposition']);
  const bytes = decodeBody(body, headers['content-transfer-encoding']);
  const isAttachment = disp.value === 'attachment'
    || (!ct.value.startsWith('text/') && !ct.value.startsWith('multipart/'));
  if (!isAttachment && ct.value === 'text/plain' && out.text === null) {
    out.text = decodeCharset(bytes, ct.params['charset']);
  } else if (!isAttachment && ct.value === 'text/html' && out.html === null) {
    out.html = decodeCharset(bytes, ct.params['charset']);
  } else {
    const name = disp.params['filename'] ?? ct.params['name'] ?? 'attachment';
    out.attachments.push({ name: decodeWords(name), type: ct.value || 'application/octet-stream', bytes });
  }
}

/** Parse a decrypted inner entity back into subject / text / html / files. */
export function parseMimeEntity(raw: string): MimeEntity {
  const out: MimeEntity = { subject: null, text: null, html: null, attachments: [] };
  walk(raw, out, 0);
  return out;
}

// ---------- the outer RFC 3156 message ----------

export interface MailAddress { name?: string | null; email: string }

/** RFC 2047 B-encode a header word when it isn't plain ASCII. */
function headerWord(src: string): string {
  return /^[\x20-\x7e]*$/.test(src) ? src : `=?utf-8?B?${b64encode(new TextEncoder().encode(src))}?=`;
}

function addrList(list: MailAddress[]): string {
  return list.map((a) => {
    const clean = a.name?.replace(/[\r\n"]+/g, ' ').trim();
    if (!clean) return a.email;
    // An encoded word must stand bare — never inside quotes (RFC 2047 §5).
    if (!/^[\x20-\x7e]*$/.test(clean)) return `${headerWord(clean)} <${a.email}>`;
    return /^[\w .-]*$/.test(clean) ? `${clean} <${a.email}>` : `"${clean.replace(/\\/g, '')}" <${a.email}>`;
  }).join(', ');
}

function rfc5322Date(d: Date): string {
  const day = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'][d.getUTCDay()];
  const mon = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'][d.getUTCMonth()];
  const p = (n: number) => String(n).padStart(2, '0');
  return `${day}, ${p(d.getUTCDate())} ${mon} ${d.getUTCFullYear()} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())} +0000`;
}

/**
 * Assemble the complete RFC 5322 + RFC 3156 message around an armored
 * ciphertext — the exact bytes to put on the wire (webmail imports and
 * submits it; a desktop export writes it as .eml). The subject given here
 * is the OUTER, visible one: pass "..." when the real subject rides inside
 * as a protected header. Bcc is deliberately never a header — the caller's
 * submission envelope carries those recipients.
 */
export function buildEncryptedMessage(opts: {
  from: MailAddress;
  to: MailAddress[];
  cc?: MailAddress[];
  subject: string;
  armored: string;
  date?: Date;
  messageId?: string;
  inReplyTo?: string[];
  references?: string[];
}): string {
  const b = boundary();
  const domain = opts.from.email.split('@')[1] ?? 'localhost';
  const r = new Uint8Array(16);
  crypto.getRandomValues(r);
  const msgId = opts.messageId ?? `<${[...r].map((x) => x.toString(16).padStart(2, '0')).join('')}@${domain}>`;
  const headers = [
    `From: ${addrList([opts.from])}`,
    `To: ${addrList(opts.to)}`,
    ...(opts.cc?.length ? [`Cc: ${addrList(opts.cc)}`] : []),
    `Subject: ${headerWord(opts.subject.replace(/[\r\n]+/g, ' '))}`,
    `Date: ${rfc5322Date(opts.date ?? new Date())}`,
    `Message-ID: ${msgId}`,
    ...(opts.inReplyTo?.length ? [`In-Reply-To: ${opts.inReplyTo.map((i) => `<${i.replace(/^<|>$/g, '')}>`).join(' ')}`] : []),
    ...(opts.references?.length ? [`References: ${opts.references.map((i) => `<${i.replace(/^<|>$/g, '')}>`).join(' ')}`] : []),
    'MIME-Version: 1.0',
    `Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary="${b}"`,
  ];
  return [
    ...headers,
    '',
    'This is an OpenPGP/MIME encrypted message (RFC 3156).',
    `--${b}`,
    'Content-Type: application/pgp-encrypted',
    'Content-Description: PGP/MIME version identification',
    '',
    'Version: 1',
    '',
    `--${b}`,
    'Content-Type: application/octet-stream; name="encrypted.asc"',
    'Content-Description: OpenPGP encrypted message',
    'Content-Disposition: inline; filename="encrypted.asc"',
    '',
    opts.armored.replace(/\r?\n/g, CRLF).replace(/\r?\n$/, ''),
    `--${b}--`,
    '',
  ].join(CRLF);
}
