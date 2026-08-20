// Saavi keystore + OpenPGP operations. OpenPGP.js only: keys are generated
// on this device and the private key never leaves it unencrypted. There is
// no server; the webmail that vendors this file (see docs/PARITY.md) adds
// its own directory on top.
//
// Model — a keyring per address:
//  - ONE active key: it is what signs, what gets published, and what new
//    messages are encrypted to.
//  - Rotating (generate or import while a key exists) RETIRES the old key
//    instead of destroying it: retired private keys stay on the device so
//    messages encrypted to them still open. Each key keeps its own passphrase.
//  - localStorage is device-bound; backups are per-key files. Private keys
//    are stored passphrase-locked (OpenPGP S2K); unlocked keys live only in
//    `sessionKeys`, in process memory.
import * as openpgp from 'openpgp';

const STORE_PREFIX = 'saavi-ring-';

export interface KeyRecord {
  publicKey: string;
  privateKey: string;   // armored, passphrase-encrypted
  created: string;
}

export interface KeyRing {
  active: KeyRecord;
  retired: KeyRecord[];
}

export interface KeyInfo {
  fingerprint: string;   // formatted, 4-char groups
  created: string;
  isActive: boolean;
  unlocked: boolean;
}

// Unlocked private keys for this session, by raw (unformatted) fingerprint.
const sessionKeys = new Map<string, openpgp.PrivateKey>();
let activeSessionFpr: string | null = null;
// Which unlocked fingerprint is the ACTIVE key of which address — so a
// multi-identity account signs with the From address's key, not whichever
// ring was unlocked last.
const activeByEmail = new Map<string, string>();

export function clearSession(): void {
  sessionKeys.clear();
  activeSessionFpr = null;
  activeByEmail.clear();
}

function load(email: string): KeyRing | null {
  const raw = localStorage.getItem(STORE_PREFIX + email.toLowerCase());
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    if (parsed.active) return parsed as KeyRing;
    if (parsed.publicKey) {
      // v1 shape (a bare record) — migrate in place.
      const ring: KeyRing = { active: parsed as KeyRecord, retired: [] };
      save(email, ring);
      return ring;
    }
    return null;
  } catch {
    return null;
  }
}

function save(email: string, ring: KeyRing): void {
  localStorage.setItem(STORE_PREFIX + email.toLowerCase(), JSON.stringify(ring));
}

/** The ACTIVE key record (what signs and what the registry holds). */
export function keysFor(email: string): KeyRecord | null {
  return load(email)?.active ?? null;
}

export function ringFor(email: string): KeyRing | null {
  return load(email);
}

function fmtFpr(raw: string): string {
  return raw.toUpperCase().replace(/(.{4})/g, '$1 ').trim();
}

async function rawFingerprint(rec: KeyRecord): Promise<string> {
  return (await openpgp.readKey({ armoredKey: rec.publicKey })).getFingerprint();
}

/** Formatted fingerprint (4-char groups) for out-of-band verification. */
export async function fingerprintOf(armoredPublicKey: string): Promise<string> {
  const key = await openpgp.readKey({ armoredKey: armoredPublicKey });
  return fmtFpr(key.getFingerprint());
}

/** Adopt a new active record, retiring any current active key. Re-adopting
 *  the key that is already active (restoring a backup "to be safe") replaces
 *  it in place rather than retiring a copy of itself. */
async function adopt(email: string, rec: KeyRecord, fpr?: string): Promise<void> {
  const ring = load(email);
  if (!ring) return save(email, { active: rec, retired: [] });
  const newFpr = fpr ?? await rawFingerprint(rec);
  if ((await rawFingerprint(ring.active)) === newFpr) return save(email, { active: rec, retired: ring.retired });
  const retired: KeyRecord[] = [ring.active];
  for (const r of ring.retired) if ((await rawFingerprint(r)) !== newFpr) retired.push(r);
  save(email, { active: rec, retired });
}

export type KeyAlgo = 'curve25519' | 'rsa4096';

export async function generateKeys(
  email: string,
  name: string,
  passphrase: string,
  algo: KeyAlgo = 'curve25519'
): Promise<KeyRecord> {
  const base = {
    userIDs: [{ name: name || email, email }],
    passphrase,
    format: 'armored' as const,
  };
  const { privateKey, publicKey } =
    algo === 'rsa4096'
      ? await openpgp.generateKey({ ...base, type: 'rsa' as const, rsaBits: 4096 })
      : await openpgp.generateKey({ ...base, type: 'ecc' as const, curve: 'curve25519Legacy' as const });
  const rec: KeyRecord = { publicKey, privateKey, created: new Date().toISOString() };
  await adopt(email, rec);
  return rec;
}

/**
 * Import an existing key — a Saavi backup file or any ASCII-armored GPG
 * private key export — as the NEW ACTIVE key. The passphrase must be the one
 * that unlocks that key (we verify by actually unlocking before anything is
 * stored); a cleartext export is locked with the given passphrase first.
 * A previously active key is retired, not destroyed.
 */
export async function importKey(email: string, armoredSource: string, passphrase: string): Promise<KeyRecord> {
  const block = armoredSource.match(
    /-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----/
  );
  if (!block) {
    throw new Error('No PGP private key found. Paste an ASCII-armored export (gpg --export-secret-keys --armor) or a Saavi backup file.');
  }
  const parsed = await openpgp.readPrivateKey({ armoredKey: block[0] });
  let unlocked: openpgp.PrivateKey;
  let storedArmor: string;
  if (parsed.isDecrypted()) {
    // A cleartext export gets locked with the passphrase typed here, so it
    // must meet the same floor as a generated key's.
    if (passphrase.length < 12) throw new Error('This key has no passphrase yet. Choose one of at least 12 characters to lock it with.');
    unlocked = parsed;
    storedArmor = (await openpgp.encryptKey({ privateKey: parsed, passphrase })).armor();
  } else {
    try {
      unlocked = await openpgp.decryptKey({ privateKey: parsed, passphrase });
    } catch {
      throw new Error('That passphrase does not unlock this key.');
    }
    storedArmor = block[0];
  }
  const rec: KeyRecord = {
    publicKey: unlocked.toPublic().armor(),
    privateKey: storedArmor,
    created: unlocked.getCreationTime().toISOString(),
  };
  const fpr = unlocked.getFingerprint();
  await adopt(email, rec, fpr);
  sessionKeys.set(fpr, unlocked);   // verified above — starts unlocked
  activeSessionFpr = fpr;
  activeByEmail.set(email.toLowerCase(), fpr);
  return rec;
}



/**
 * Unlock a private key for this session. Default: the active key. Pass a
 * (formatted or raw) fingerprint to unlock a specific — e.g. retired — key.
 */
export async function unlockPrivateKey(email: string, passphrase: string, fingerprint?: string): Promise<void> {
  const ring = load(email);
  if (!ring) throw new Error('No encryption keys on this device.');
  const want = fingerprint?.replace(/\s+/g, '').toLowerCase() ?? null;
  const candidates = [ring.active, ...ring.retired];
  let target: KeyRecord | null = null;
  if (want) {
    for (const rec of candidates) {
      if ((await rawFingerprint(rec)).toLowerCase() === want) { target = rec; break; }
    }
    if (!target) throw new Error('That key is not on this device.');
  } else {
    target = ring.active;
  }
  const locked = await openpgp.readPrivateKey({ armoredKey: target.privateKey });
  const unlocked = await openpgp.decryptKey({ privateKey: locked, passphrase });
  const fpr = unlocked.getFingerprint();
  sessionKeys.set(fpr, unlocked);
  if (target === ring.active) {
    activeSessionFpr = fpr;
    activeByEmail.set(email.toLowerCase(), fpr);
  }
}

/** True when the ACTIVE key is unlocked — for a specific address when given,
 *  else for whichever ring was unlocked most recently. */
export function isUnlocked(email?: string): boolean {
  if (email) {
    const fpr = activeByEmail.get(email.toLowerCase());
    return fpr !== undefined && sessionKeys.has(fpr);
  }
  return activeSessionFpr !== null && sessionKeys.has(activeSessionFpr);
}

/** Encrypt — signed with the given address's active key when it is unlocked
 *  (falls back to the most recently unlocked key). */
export async function encryptText(text: string, armoredPublicKeys: string[], signerEmail?: string, opts: { sign?: boolean } = {}): Promise<string> {
  const encryptionKeys = await Promise.all(armoredPublicKeys.map((k) => openpgp.readKey({ armoredKey: k })));
  const message = await openpgp.createMessage({ text });
  const signerFpr = (signerEmail ? activeByEmail.get(signerEmail.toLowerCase()) : null) ?? activeSessionFpr;
  // sign defaults to true for callers that rely on it (the webmail); pass
  // { sign: false } to seal without vouching for authorship.
  const signer = opts.sign === false ? null : signerFpr ? sessionKeys.get(signerFpr) : null;
  return String(await openpgp.encrypt({
    message,
    encryptionKeys,
    ...(signer ? { signingKeys: signer } : {}),
  }));
}

export function looksEncrypted(text: string): boolean {
  return text.includes('-----BEGIN PGP MESSAGE-----');
}

/** Repair a public-key armor whose newlines were flattened to spaces —
 *  what browsers do when a multi-line key is pasted into a single-line
 *  input. Untouched when the armor still has its newlines. */
export function normalizeKeyArmor(src: string): string {
  const m = src.match(/-----BEGIN PGP PUBLIC KEY BLOCK-----([\s\S]*?)-----END PGP PUBLIC KEY BLOCK-----/);
  if (!m) return src;
  let body = m[1];
  if (!body.includes('\n')) {
    body = '\n\n' + body.trim().split(/\s+/).join('\n') + '\n';
  }
  return `-----BEGIN PGP PUBLIC KEY BLOCK-----${body}-----END PGP PUBLIC KEY BLOCK-----`;
}

export interface DecryptResult {
  text: string;
  signedBy: string | null;   // email of a VERIFIED signer, else null
}

/** Decrypt with whichever session key fits; throws Error('locked') when the
 *  needed key is on the device but not unlocked (see neededKeyFor). */
export async function decryptText(armored: string, senderPublicKey?: string | null): Promise<DecryptResult> {
  if (!sessionKeys.size) throw new Error('locked');
  const message = await openpgp.readMessage({ armoredMessage: armored.trim() });
  const verificationKeys = senderPublicKey ? [await openpgp.readKey({ armoredKey: senderPublicKey })] : undefined;
  let data: unknown;
  let signatures: Awaited<ReturnType<typeof openpgp.decrypt>>['signatures'] | undefined;
  try {
    ({ data, signatures } = await openpgp.decrypt({
      message,
      decryptionKeys: [...sessionKeys.values()],
      ...(verificationKeys ? { verificationKeys } : {}),
    }));
  } catch (e) {
    // Only a missing/locked key is 'locked'. Anything else — a tampered
    // message (MDC/AEAD failure), a malformed packet — must surface as-is,
    // never be mistaken for "try another passphrase".
    const msg = e instanceof Error ? e.message : String(e);
    if (/session key|decryption key|no private key|not decrypted/i.test(msg)) throw new Error('locked');
    throw e;
  }
  let signedBy: string | null = null;
  if (signatures?.length && verificationKeys) {
    try {
      await signatures[0].verified;
      signedBy = verificationKeys[0].users[0]?.userID?.email ?? 'verified';
    } catch { signedBy = null; }
  }
  return { text: String(data), signedBy };
}

/**
 * Which stored key does this ciphertext want? Matches the message's
 * encryption key IDs against every key (and subkey) on the ring. Null when
 * no stored key fits (encrypted to someone else / a lost key).
 */
export async function neededKeyFor(email: string, armored: string): Promise<KeyInfo | null> {
  const ring = load(email);
  if (!ring) return null;
  let wanted: string[];
  try {
    const message = await openpgp.readMessage({ armoredMessage: armored.trim() });
    wanted = message.getEncryptionKeyIDs().map((id) => id.toHex().toLowerCase());
  } catch {
    return null;
  }
  const candidates = [ring.active, ...ring.retired];
  for (const rec of candidates) {
    const key = await openpgp.readKey({ armoredKey: rec.publicKey });
    const ids = key.getKeys().map((k) => k.getKeyID().toHex().toLowerCase());
    if (ids.some((id) => wanted.includes(id))) {
      const fpr = key.getFingerprint();
      return {
        fingerprint: fmtFpr(fpr),
        created: rec.created,
        isActive: rec === ring.active,
        unlocked: sessionKeys.has(fpr),
      };
    }
  }
  return null;
}

/** Every key on the ring, active first — for the settings manager. */
export async function listKeys(email: string): Promise<KeyInfo[]> {
  const ring = load(email);
  if (!ring) return [];
  const out: KeyInfo[] = [];
  for (const [i, rec] of [ring.active, ...ring.retired].entries()) {
    const fpr = await rawFingerprint(rec);
    out.push({
      fingerprint: fmtFpr(fpr),
      created: rec.created,
      isActive: i === 0,
      unlocked: sessionKeys.has(fpr),
    });
  }
  return out;
}

/** Remove a RETIRED key from this device (the active key cannot be deleted). */
export async function deleteRetired(email: string, fingerprint: string): Promise<void> {
  const ring = load(email);
  if (!ring) return;
  const want = fingerprint.replace(/\s+/g, '').toLowerCase();
  const keep: KeyRecord[] = [];
  for (const rec of ring.retired) {
    if ((await rawFingerprint(rec)).toLowerCase() !== want) keep.push(rec);
  }
  save(email, { active: ring.active, retired: keep });
}

/** Save a (passphrase-encrypted) private key as a backup file — the active
 *  key by default, or any key on the ring by fingerprint. Inside the Tauri
 *  shell this opens a real save dialog (blob-anchor downloads are inert in
 *  the webview); in a plain browser it falls back to an anchor download.
 *  Returns the saved path, '' for a browser download, or null if cancelled. */
export async function saveBackup(email: string, fingerprint?: string): Promise<string | null> {
  const ring = load(email);
  if (!ring) return null;
  let rec: KeyRecord | null = fingerprint ? null : ring.active;
  if (fingerprint) {
    const want = fingerprint.replace(/\s+/g, '').toLowerCase();
    for (const r of [ring.active, ...ring.retired]) {
      if ((await rawFingerprint(r)).toLowerCase() === want) { rec = r; break; }
    }
  }
  if (!rec) return null;
  const text = `Saavi key backup — ${email}\nKeep this file and your passphrase somewhere safe. Without both, encrypted letters cannot be read.\n\n${rec.privateKey}\n\n${rec.publicKey}\n`;
  const filename = `saavi-key-backup-${email.replace(/[^a-z0-9.@-]/gi, '_')}.txt`;
  if ('__TAURI_INTERNALS__' in window) {
    const { save } = await import('@tauri-apps/plugin-dialog');
    const { writeTextFile } = await import('@tauri-apps/plugin-fs');
    const path = await save({ defaultPath: filename, filters: [{ name: 'Saavi key backup', extensions: ['txt'] }] });
    if (!path) return null;
    await writeTextFile(path, text);
    return path;
  }
  const blob = new Blob([text], { type: 'text/plain' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
  return '';
}

// ---------- signing & verification (cleartext), files ----------

/** Clearsign text with the given address's unlocked active key. */
export async function signText(text: string, signerEmail: string): Promise<string> {
  const fpr = activeByEmail.get(signerEmail.toLowerCase());
  const key = fpr ? sessionKeys.get(fpr) : null;
  if (!key) throw new Error('locked');
  const message = await openpgp.createCleartextMessage({ text });
  return String(await openpgp.sign({ message, signingKeys: key }));
}

export interface VerifyResult {
  text: string;
  /** 'good' | 'bad' | 'unknown-key' */
  status: 'good' | 'bad' | 'unknown-key';
  signerFingerprint: string | null;
  signerUid: string | null;
}

/** Verify a clearsigned message against candidate public keys. */
export async function verifyText(armored: string, armoredPublicKeys: string[]): Promise<VerifyResult> {
  const message = await openpgp.readCleartextMessage({ cleartextMessage: armored.trim() });
  const text = message.getText();
  const wanted = message.getSigningKeyIDs().map((id) => id.toHex().toLowerCase());
  const keys = await Promise.all(armoredPublicKeys.map((k) => openpgp.readKey({ armoredKey: k })));
  const candidates = keys.filter((k) => k.getKeys().some((sk) => wanted.includes(sk.getKeyID().toHex().toLowerCase())));
  if (!candidates.length) return { text, status: 'unknown-key', signerFingerprint: null, signerUid: null };
  const { signatures } = await openpgp.verify({ message, verificationKeys: candidates });
  for (const sig of signatures) {
    const key = candidates.find((k) => k.getKeys().some((sk) => sk.getKeyID().equals(sig.keyID)));
    const fpr = key ? fmtFpr(key.getFingerprint()) : null;
    const uid = key?.users[0]?.userID?.userID ?? null;
    try {
      await sig.verified;
      return { text, status: 'good', signerFingerprint: fpr, signerUid: uid };
    } catch {
      return { text, status: 'bad', signerFingerprint: fpr, signerUid: uid };
    }
  }
  return { text, status: 'unknown-key', signerFingerprint: null, signerUid: null };
}

export function looksClearsigned(text: string): boolean {
  return text.includes('-----BEGIN PGP SIGNED MESSAGE-----');
}

/** Encrypt bytes (a file) to public keys; binary OpenPGP output (.gpg). */
export async function encryptBytes(data: Uint8Array, filename: string, armoredPublicKeys: string[], signerEmail?: string): Promise<Uint8Array> {
  const encryptionKeys = await Promise.all(armoredPublicKeys.map((k) => openpgp.readKey({ armoredKey: k })));
  const message = await openpgp.createMessage({ binary: data, filename });
  const signerFpr = (signerEmail ? activeByEmail.get(signerEmail.toLowerCase()) : null) ?? null;
  const signer = signerFpr ? sessionKeys.get(signerFpr) : null;
  return (await openpgp.encrypt({
    message, encryptionKeys, format: 'binary',
    ...(signer ? { signingKeys: signer } : {}),
  })) as Uint8Array;
}

/** Decrypt a binary or armored OpenPGP file with whichever session key fits. */
export async function decryptBytes(data: Uint8Array): Promise<{ data: Uint8Array; filename: string | null }> {
  if (!sessionKeys.size) throw new Error('locked');
  const head = new TextDecoder().decode(data.subarray(0, 64));
  const message = head.includes('-----BEGIN PGP')
    ? await openpgp.readMessage({ armoredMessage: new TextDecoder().decode(data) })
    : await openpgp.readMessage({ binaryMessage: data });
  try {
    const out = await openpgp.decrypt({ message, decryptionKeys: [...sessionKeys.values()], format: 'binary' });
    return { data: out.data as Uint8Array, filename: out.filename || null };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (/session key|decryption key|no private key|not decrypted/i.test(msg)) throw new Error('locked');
    throw e;
  }
}

/** Key IDs a binary/armored file is encrypted to (for the unlock prompt). */
export async function neededKeyForBytes(email: string, data: Uint8Array): Promise<KeyInfo | null> {
  const head = new TextDecoder().decode(data.subarray(0, 64));
  const armored = head.includes('-----BEGIN PGP') ? new TextDecoder().decode(data) : null;
  const ring = load(email);
  if (!ring) return null;
  let wanted: string[];
  try {
    const message = armored ? await openpgp.readMessage({ armoredMessage: armored }) : await openpgp.readMessage({ binaryMessage: data });
    wanted = message.getEncryptionKeyIDs().map((id) => id.toHex().toLowerCase());
  } catch {
    return null;
  }
  for (const rec of [ring.active, ...ring.retired]) {
    const key = await openpgp.readKey({ armoredKey: rec.publicKey });
    const ids = key.getKeys().map((k) => k.getKeyID().toHex().toLowerCase());
    if (ids.some((id) => wanted.includes(id))) {
      const fpr = key.getFingerprint();
      return { fingerprint: fmtFpr(fpr), created: rec.created, isActive: rec === ring.active, unlocked: sessionKeys.has(fpr) };
    }
  }
  return null;
}
