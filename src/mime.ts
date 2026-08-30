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
  /** Protected headers (H2). Present only when the top-level entity declared
   *  protected-headers="v1" AND carried them; null means "this message does
   *  not say", which a reader must treat as *cannot check* — never as forged,
   *  since every message sent before H2 shipped is in that state.
   *
   *  Addresses only: display names are deliberately not parsed, because these
   *  values exist to be COMPARED against the visible headers, never to be
   *  shown. `null` (absent header) and `[]` (present but empty) are different
   *  answers and callers must distinguish them. */
  from: string | null;
  to: string[] | null;
  cc: string[] | null;
  date: Date | null;
  messageId: string | null;
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
      // The RFC 2231 extended form is authoritative — it wins over a plain
      // ASCII fallback regardless of header order (Thunderbird/Outlook emit
      // both filename= and filename*=).
      name = name.slice(0, -1);
      params[name] = decodeExtValue(val);
    } else {
      params[name] ??= val;
    }
  }
  for (const [name, pieces] of Object.entries(continuations)) {
    params[name] = decodeExtValue(pieces.join(''));
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

/** A content-type this side controls; anything odd collapses to octet-stream
 *  so an attacker-derived `type` (forwarded from inbound JMAP) can never
 *  smuggle a header break or extra parameters onto the wire. */
function safeType(type: string): string {
  return /^[\w.+-]+\/[\w.+-]+$/.test(type) ? type : 'application/octet-stream';
}

function attachmentPart(a: MimeAttachment): string {
  // RFC 2231 always — no quoted ASCII branch, so a name containing " or \
  // can never break out of the parameter.
  const nameParam = `filename*=utf-8''${[...new TextEncoder().encode(a.name)]
    .map((b) => (b > 0x20 && b < 0x7f && !"%'\";\\".includes(String.fromCharCode(b))
      ? String.fromCharCode(b) : '%' + b.toString(16).padStart(2, '0').toUpperCase())).join('')}`;
  return [
    `Content-Type: ${safeType(a.type)}`,
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
 *
 * From/To/Cc/Date/Message-ID ride inside too, and for a different reason than
 * the Subject. The Subject is protected to keep it PRIVATE. These are
 * protected to make them TRUE: outside the signature they are attacker-
 * writable, so a signed payload can be lifted out of its envelope and
 * re-delivered under headers that name a different sender, recipient or day —
 * and a reader with nothing but the visible headers cannot tell. Signing them
 * is what lets a reader say "signed by X, to you, on this date" and mean it.
 *
 * The caller must pass the SAME values it will put on the outer message, and
 * must therefore decide the Date and Message-ID before calling this — see
 * buildEncryptedMessage, which will otherwise generate its own and leave the
 * two copies disagreeing, which is indistinguishable from an attack.
 */
export function buildMimeEntity(src: {
  subject?: string;
  from?: MailAddress;
  to?: MailAddress[];
  cc?: MailAddress[];
  date?: Date;
  messageId?: string;
  text: string;
  html?: string | null;
  attachments?: MimeAttachment[];
}): string {
  // RFC 5322 order, so the block reads like the header it mirrors.
  const protectedHeaders: string[] = [];
  if (src.from) {
    const f = addrList([src.from]);
    if (f) protectedHeaders.push(foldHeader('From', f, ', '));
  }
  if (src.to?.length) {
    const t = addrList(src.to);
    if (t) protectedHeaders.push(foldHeader('To', t, ', '));
  }
  if (src.cc?.length) {
    const c = addrList(src.cc);
    if (c) protectedHeaders.push(foldHeader('Cc', c, ', '));
  }
  // Bcc is never emitted, here or outside: the submission envelope carries
  // those recipients and no header ever does.
  if (src.date) protectedHeaders.push(`Date: ${rfc5322Date(src.date)}`);
  if (src.messageId) {
    const id = safeMsgId(src.messageId);
    if (id) protectedHeaders.push(`Message-ID: ${id}`);
  }
  if (src.subject !== undefined) protectedHeaders.push(`Subject: ${src.subject.replace(/[\r\n]+/g, ' ')}`);
  const bodyEntity = src.html
    ? multipart('alternative', [textPart('text/plain', src.text), textPart('text/html', src.html)])
    : textPart('text/plain', src.text);
  if (src.attachments?.length) {
    return multipart('mixed', [bodyEntity, ...src.attachments.map(attachmentPart)], protectedHeaders);
  }
  if (!protectedHeaders.length) return bodyEntity;
  // A single body part still needs the protected headers on its own headers.
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

/** Bounds so a hostile decrypted payload cannot hang or OOM the reader:
 *  an attacker can encrypt anything to a published key, and OpenPGP
 *  decompresses with no ceiling. */
const MAX_ENTITY_BYTES = 40 * 1024 * 1024;
const MAX_PARTS = 512;
const MAX_ATTACHMENTS = 128;

/** Strip bidi overrides and control characters that let a filename or a
 *  protected subject read as something other than what it is. */
function sanitizeText(s: string, max = 20_000): string {
  let out = '';
  for (const ch of s) {
    const c = ch.codePointAt(0)!;
    const control = (c < 0x20 && c !== 0x09) || (c >= 0x7f && c <= 0x9f);
    const bidi = c === 0x200e || c === 0x200f || (c >= 0x202a && c <= 0x202e) || (c >= 0x2066 && c <= 0x2069);
    if (!control && !bidi) out += ch;
    if (out.length >= max) break;
  }
  return out;
}

interface WalkState { parts: number }

function walk(raw: string, out: MimeEntity, depth: number, st: WalkState): void {
  if (depth > 10 || st.parts > MAX_PARTS) return;   // malformed/hostile nesting
  if (!raw.trim()) return;                           // an empty chunk is not a part
  st.parts++;
  const { headers, body } = splitEntity(raw);
  const ct = parseParams(headers['content-type'] ?? 'text/plain; charset=us-ascii');
  // A protected header is only trustworthy on the TOP-LEVEL entity that
  // actually declares protected-headers="v1" (the LAMPS convention) — never
  // adopted from an arbitrary nested part an attacker can add. Every field
  // below shares that guard; relaxing it for any one of them would hand an
  // attacker the ability to choose what the reader believes.
  if (depth === 0 && ct.params['protected-headers'] === 'v1') {
    if (out.subject === null && headers['subject'] !== undefined) {
      out.subject = sanitizeText(decodeWords(headers['subject']));
    }
    if (out.from === null && headers['from'] !== undefined) {
      // One sender or none: a From naming several addresses is not something
      // to reason about, so it is treated as absent.
      const f = addrSpecs(headers['from']);
      if (f.length === 1) out.from = f[0];
    }
    if (out.to === null && headers['to'] !== undefined) out.to = addrSpecs(headers['to']);
    if (out.cc === null && headers['cc'] !== undefined) out.cc = addrSpecs(headers['cc']);
    if (out.date === null && headers['date'] !== undefined) {
      const d = new Date(headers['date']);
      if (!Number.isNaN(d.getTime())) out.date = d;
    }
    if (out.messageId === null && headers['message-id'] !== undefined) {
      out.messageId = safeMsgId(headers['message-id']);
    }
  }
  if (ct.value.startsWith('multipart/')) {
    const b = ct.params['boundary'];
    if (!b) return;
    // The delimiter must END the line — otherwise a child boundary that has
    // the parent's as a prefix (Exchange/Apple "_000_ABC_" vs "_000_ABC__2")
    // would split the parent too.
    const esc = b.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const chunks = body.split(new RegExp(`(?:^|\\r?\\n)--${esc}(?=[ \\t]*(?:\\r?\\n|--|$))`));
    for (const chunk of chunks.slice(1)) {
      if (/^--/.test(chunk)) break;   // closing delimiter
      if (st.parts > MAX_PARTS) break;
      walk(chunk.replace(/^[^\n]*\r?\n/, ''), out, depth + 1, st);
    }
    return;
  }
  const disp = parseParams(headers['content-disposition']);
  const bytes = decodeBody(body, headers['content-transfer-encoding']);
  const isAttachment = disp.value === 'attachment'
    || (!ct.value.startsWith('text/') && !ct.value.startsWith('multipart/'));
  // Gate on emptiness, not nullness: an empty text/plain part (Apple inline
  // layouts, phantom fragments) must not claim the body slot and shunt the
  // real body into a nameless attachment. Siblings concatenate.
  if (!isAttachment && ct.value === 'text/plain') {
    const t = decodeCharset(bytes, ct.params['charset']);
    if (t) out.text = (out.text ?? '') + t;
  } else if (!isAttachment && ct.value === 'text/html') {
    const h = decodeCharset(bytes, ct.params['charset']);
    if (h) out.html = (out.html ?? '') + h;
  } else if (out.attachments.length < MAX_ATTACHMENTS) {
    const name = disp.params['filename'] ?? ct.params['name'] ?? 'attachment';
    out.attachments.push({
      name: sanitizeText(decodeWords(name), 255) || 'attachment',
      type: /^[\w.+-]+\/[\w.+-]+$/.test(ct.value) ? ct.value : 'application/octet-stream',
      bytes,
    });
  }
}

/** Parse a decrypted inner entity back into its protected headers, text,
 *  html and files. */
export function parseMimeEntity(raw: string): MimeEntity {
  const out: MimeEntity = {
    subject: null, from: null, to: null, cc: null, date: null, messageId: null,
    text: null, html: null, attachments: [],
  };
  if (raw.length > MAX_ENTITY_BYTES) return out;   // refuse a decompression bomb
  walk(raw, out, 0, { parts: 0 });
  return out;
}

// ---------- the outer RFC 3156 message ----------

export interface MailAddress { name?: string | null; email: string }

/** RFC 2047 B-encode a header word when it isn't plain ASCII. */
function headerWord(src: string): string {
  return /^[\x20-\x7e]*$/.test(src) ? src : `=?utf-8?B?${b64encode(new TextEncoder().encode(src))}?=`;
}

/** The addr-specs in a header value, lowercased and de-duplicated, display
 *  names discarded. Used ONLY to compare protected headers against visible
 *  ones, so it errs strict: quoted display names are removed before the scan
 *  (an attacker must not smuggle an address into one), each comma-separated
 *  item yields at most one address, an angle-bracketed form wins over a bare
 *  one, and anything safeEmail refuses is dropped rather than repaired. */
function addrSpecs(header: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const stripped = header.replace(/"(?:[^"\\]|\\.)*"/g, '""');
  for (const item of stripped.split(',')) {
    const m = /<([^<>]*)>/.exec(item);
    const e = safeEmail((m ? m[1] : item).trim());
    if (!e) continue;
    const low = e.toLowerCase();
    if (seen.has(low)) continue;
    seen.add(low);
    out.push(low);
  }
  return out;
}

/** A syntactically safe addr-spec, or null. The address is emitted RAW into
 *  a header (and used as an envelope recipient), so anything that isn't a
 *  plain addr-spec — CR/LF, spaces, angle brackets, commas — is refused
 *  rather than sanitised. */
function safeEmail(email: string): string | null {
  const e = email.trim();
  return /^[^\s<>(),:;@"\\]+@[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i.test(e) ? e : null;
}

function addrList(list: MailAddress[]): string {
  return list.map((a) => {
    const email = safeEmail(a.email);
    if (!email) return '';   // dropped from the header; caller validated rcptTo
    const clean = a.name?.replace(/[\r\n"]+/g, ' ').trim();
    if (!clean) return email;
    // An encoded word must stand bare — never inside quotes (RFC 2047 §5).
    if (!/^[\x20-\x7e]*$/.test(clean)) return `${headerWord(clean)} <${email}>`;
    return /^[\w .-]*$/.test(clean) ? `${clean} <${email}>` : `"${clean.replace(/\\/g, '')}" <${email}>`;
  }).filter(Boolean).join(', ');
}

/** A safe Message-ID token (`<...>` with no header-breaking characters). */
function safeMsgId(raw: string): string | null {
  const id = raw.replace(/^<|>$/g, '').trim();
  return /^[^\s<>]+$/.test(id) ? `<${id}>` : null;
}

/** Fold a header value onto continuation lines so no line exceeds RFC 5322's
 *  998-octet limit; breaks only at the given separator (", " or " "). */
function foldHeader(name: string, value: string, sep: string): string {
  const items = value.split(sep);
  const lines: string[] = [];
  let cur = `${name}:`;
  for (const item of items) {
    const piece = (cur.endsWith(':') ? ' ' : sep) + item;
    if (cur.length + piece.length > 76 && !cur.endsWith(':')) {
      lines.push(cur);
      cur = ' ' + item;
    } else {
      cur += piece;
    }
  }
  lines.push(cur);
  return lines.join(CRLF);
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
  const fromEmail = safeEmail(opts.from.email);
  if (!fromEmail) throw new Error('The From address is not a valid email address.');
  const domain = fromEmail.split('@')[1];
  const r = new Uint8Array(16);
  crypto.getRandomValues(r);
  const generatedId = `<${[...r].map((x) => x.toString(16).padStart(2, '0')).join('')}@${domain}>`;
  const msgId = (opts.messageId ? safeMsgId(opts.messageId) : null) ?? generatedId;
  // Message-id lists come from inbound headers (attacker-written) — keep only
  // syntactically valid ids, and cap References the way RFC 5322 §3.6.4
  // recommends (first plus the most recent) so a long thread can't blow the
  // header past the line limit.
  const inReplyTo = (opts.inReplyTo ?? []).map(safeMsgId).filter((x): x is string => Boolean(x));
  let references = (opts.references ?? []).map(safeMsgId).filter((x): x is string => Boolean(x));
  if (references.length > 21) references = [references[0], ...references.slice(-20)];
  const headers = [
    foldHeader('From', addrList([opts.from]), ', '),
    foldHeader('To', addrList(opts.to), ', '),
    ...(opts.cc?.length ? [foldHeader('Cc', addrList(opts.cc), ', ')] : []),
    `Subject: ${headerWord(sanitizeText(opts.subject.replace(/[\r\n]+/g, ' ')))}`,
    `Date: ${rfc5322Date(opts.date ?? new Date())}`,
    `Message-ID: ${msgId}`,
    ...(inReplyTo.length ? [foldHeader('In-Reply-To', inReplyTo.join(' '), ' ')] : []),
    ...(references.length ? [foldHeader('References', references.join(' '), ' ')] : []),
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
