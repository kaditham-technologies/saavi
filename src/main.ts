// Saavi — the app. Two faces, KGpg heritage: −k (the keyring table) and
// −d (the sealer). Two keyring sources: Saavi's own store (pgp.ts,
// OpenPGP.js, works anywhere) and the system GnuPG keyring (gpg.ts, the
// user's own gpg binary, shell only). All crypto lives in those two modules;
// WKD lookup for the Saavi store in wkd.ts.
import './style.css';
import * as pgp from './pgp';
import * as gpg from './gpg';
import { wkdLookup } from './wkd';

const $ = <T extends HTMLElement = HTMLElement>(id: string): T =>
  document.getElementById(id) as T;

const ICONS: Record<string, string> = {
  plus: '<path d="M8 3.5v9M3.5 8h9"/>',
  import: '<path d="M8 2.4v7.2"/><path d="M5.6 7.2 8 9.6l2.4-2.4"/><path d="M2.8 10.4v1.8a1.2 1.2 0 0 0 1.2 1.2h8a1.2 1.2 0 0 0 1.2-1.2v-1.8"/>',
  save: '<rect x="2.6" y="2.6" width="10.8" height="10.8" rx="1.2"/><path d="M5.2 2.6v3.6h5.6V2.6"/><path d="M5.2 13.4V9.2h5.6v4.2"/>',
  trash: '<path d="M2.8 4.3h10.4"/><path d="M5.6 4.3v-1a1 1 0 0 1 1-1h2.8a1 1 0 0 1 1 1v1"/><path d="m4.3 4.3.6 8.2a1.1 1.1 0 0 0 1.1 1h4a1.1 1.1 0 0 0 1.1-1l.6-8.2"/>',
  refresh: '<path d="M13.5 8a5.5 5.5 0 1 1-1.6-3.9"/><path d="M13.5 1.5v3h-3"/>',
};

for (const holder of document.querySelectorAll<HTMLElement>('[data-ico]')) {
  holder.innerHTML = `<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[holder.dataset.ico!] ?? ''}</svg>`;
}

function el(tag: string, cls?: string, text?: string): HTMLElement {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}

const errMsg = (e: unknown): string => (e instanceof Error ? e.message : String(e));

/** Every address with a ring in the Saavi store. */
function ringAddresses(): string[] {
  const out: string[] = [];
  for (let i = 0; i < localStorage.length; i++) {
    const k = localStorage.key(i)!;
    if (k.startsWith('saavi-ring-')) out.push(k.slice('saavi-ring-'.length));
  }
  return out.sort();
}

/** Save text through the shell's dialog (browser: anchor download).
 *  Returns the path, '' for a browser download, null if cancelled. */
async function saveTextFile(filename: string, text: string): Promise<string | null> {
  if (gpg.inShell()) {
    const { save } = await import('@tauri-apps/plugin-dialog');
    const { writeTextFile } = await import('@tauri-apps/plugin-fs');
    const path = await save({ defaultPath: filename, filters: [{ name: 'OpenPGP key', extensions: ['asc', 'txt'] }] });
    if (!path) return null;
    await writeTextFile(path, text);
    return path;
  }
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
  return '';
}

// ---------- themes (shared palette family with Kaditham Mail) ----------
const THEME_NAMES = ['paper', 'aurora', 'solarium', 'ink', 'nocturne', 'phosphor'];
function applyTheme(name: string): void {
  for (const t of THEME_NAMES) document.body.classList.toggle(`theme-${t}`, t === name);
  localStorage.setItem('saavi-theme', name);
  ($('theme') as HTMLSelectElement).value = name;
}
{
  const saved = localStorage.getItem('saavi-theme') ?? 'system';
  if (THEME_NAMES.includes(saved)) applyTheme(saved);
  $('theme').addEventListener('change', () => {
    const v = ($('theme') as HTMLSelectElement).value;
    if (v === 'system') {
      for (const t of THEME_NAMES) document.body.classList.remove(`theme-${t}`);
      localStorage.setItem('saavi-theme', 'system');
    } else applyTheme(v);
  });
}

// ---------- tabs ----------
function selectTab(which: 'keys' | 'seal'): void {
  $('tab-keys').classList.toggle('on', which === 'keys');
  $('tab-seal').classList.toggle('on', which === 'seal');
  $('tab-keys').setAttribute('aria-selected', String(which === 'keys'));
  $('tab-seal').setAttribute('aria-selected', String(which === 'seal'));
  $('view-keys').hidden = which !== 'keys';
  $('view-seal').hidden = which !== 'seal';
}
$('tab-keys').addEventListener('click', () => selectTab('keys'));
$('tab-seal').addEventListener('click', () => selectTab('seal'));

// ---------- keyring source ----------
type Source = 'saavi' | 'system';
let source: Source = 'saavi';
let gpgInfo: gpg.GpgInfo | null = null;
let systemKeys: gpg.SystemKey[] = [];

function setSource(s: Source): void {
  source = s;
  localStorage.setItem('saavi-source', s);
  ($('ring-src') as HTMLSelectElement).value = s;
  document.body.classList.toggle('src-system', s === 'system');
  $('col-status').textContent = s === 'system' ? 'Trust' : 'Status';
  $('seal-sign-fld').hidden = s !== 'system';
  $('seal-to-label').textContent = s === 'system'
    ? 'To (addresses or fingerprints in your GnuPG keyring — WKD for unknown addresses — or paste a public key)'
    : 'To (addresses — keys found via WKD — or paste a public key)';
  sel = null;
  void refreshKeys();
}

async function detectGpg(): Promise<void> {
  const note = $('ring-note');
  if (!gpg.inShell()) {
    $('ring-src-wrap').hidden = true;
    return;
  }
  try {
    gpgInfo = await gpg.info();
  } catch (e) {
    gpgInfo = null;
    note.textContent = `GnuPG check failed: ${errMsg(e)}`;
  }
  const opt = $('ring-src').querySelector<HTMLOptionElement>('option[value=system]')!;
  if (gpgInfo?.found) {
    opt.disabled = false;
    note.textContent = `GnuPG ${gpgInfo.version ?? ''} · ${gpgInfo.homedir ?? gpgInfo.path ?? ''}`;
    note.title = gpgInfo.path ?? '';
    const saved = localStorage.getItem('saavi-source');
    if (saved === 'system') setSource('system');
  } else {
    opt.disabled = true;
    note.textContent = 'System keyring needs GnuPG: Gpg4win (Windows), GPG Suite or Homebrew (macOS), your package manager (Linux).';
  }
}
$('ring-src').addEventListener('change', () => {
  const v = ($('ring-src') as HTMLSelectElement).value as Source;
  if (v === 'system' && !gpgInfo?.found) {
    ($('ring-src') as HTMLSelectElement).value = 'saavi';
    return;
  }
  setSource(v);
});

// ---------- the keyring table (−k) ----------
type Sel =
  | { kind: 'saavi'; email: string; fpr: string; isActive: boolean }
  | { kind: 'system'; fpr: string; email: string; hasSecret: boolean };
let sel: Sel | null = null;

function syncTools(): void {
  ($('act-backup') as HTMLButtonElement).disabled = !sel;
  ($('act-delete') as HTMLButtonElement).disabled =
    !sel || (sel.kind === 'saavi' ? sel.isActive : sel.hasSecret);
  ($('act-backup').querySelector('span:last-child') as HTMLElement).textContent =
    sel?.kind === 'system' && !sel.hasSecret ? 'Export' : 'Backup';
  ($('act-delete') as HTMLButtonElement).title =
    sel?.kind === 'system' && sel.hasSecret
      ? 'Saavi does not delete secret keys from the GnuPG keyring — use gpg or Kleopatra.'
      : sel?.kind === 'saavi' && sel.isActive ? 'The active key cannot be deleted; rotate first.' : '';
}

function rowFor(cells: { dot: boolean; dotTitle: string; addr: string; id: string; date: string; chip: string; chipOn: boolean; title: string; dead?: boolean }): HTMLElement {
  const row = el('button', 'row' + (cells.dead ? ' dead' : ''));
  row.setAttribute('role', 'option');
  const dot = el('span', 'dot' + (cells.dot ? ' dot-open' : ''));
  dot.title = cells.dotTitle;
  row.append(dot);
  row.append(el('span', 'c-addr', cells.addr));
  row.append(el('span', 'c-id', cells.id));
  row.append(el('span', 'c-date', cells.date));
  row.append(el('span', 'chip c-end' + (cells.chipOn ? ' chip-on' : ''), cells.chip));
  row.title = cells.title;
  return row;
}

const fmtDate = (iso: string | null): string =>
  iso ? new Date(iso).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' }) : '—';

function markSelected(rows: HTMLElement, row: HTMLElement): void {
  for (const r of rows.querySelectorAll('.row')) r.classList.toggle('sel', r === row);
  syncTools();
}

async function refreshKeys(): Promise<void> {
  const rows = $('rows');
  rows.replaceChildren(el('p', 'loading', 'Reading the keyring…'));
  const go = source;
  if (go === 'system') return refreshSystemKeys(rows);

  const flat: { email: string; info: pgp.KeyInfo }[] = [];
  for (const email of ringAddresses()) {
    for (const info of await pgp.listKeys(email).catch(() => [] as pgp.KeyInfo[])) {
      flat.push({ email, info });
    }
  }
  if (source !== go) return;
  rows.replaceChildren();
  if (!flat.length) {
    const empty = el('div', 'empty');
    empty.append(el('p', undefined, 'No keys yet. This is a fresh keyring.'));
    const b = el('button', 'primary', 'Generate your first key');
    b.addEventListener('click', () => openModal('generate'));
    empty.append(b);
    rows.append(empty);
  }
  for (const { email, info } of flat) {
    const row = rowFor({
      dot: info.unlocked, dotTitle: info.unlocked ? 'Unlocked this session' : 'Locked',
      addr: email,
      id: '…' + info.fingerprint.replace(/\s+/g, '').slice(-8).toUpperCase(),
      date: fmtDate(info.created),
      chip: info.isActive ? 'active' : 'retired', chipOn: info.isActive,
      title: info.fingerprint,
    });
    if (sel?.kind === 'saavi' && sel.fpr === info.fingerprint) row.classList.add('sel');
    row.addEventListener('click', () => {
      sel = { kind: 'saavi', email, fpr: info.fingerprint, isActive: info.isActive };
      markSelected(rows, row);
    });
    rows.append(row);
  }
  const unlocked = flat.filter((f) => f.info.unlocked).length;
  const n = ringAddresses().length;
  $('status').textContent =
    `Saavi store · ${flat.length} key${flat.length === 1 ? '' : 's'} · ${n} address${n === 1 ? '' : 'es'} · ${unlocked} unlocked this session`;
  syncTools();
}

async function refreshSystemKeys(rows: HTMLElement): Promise<void> {
  try {
    systemKeys = await gpg.listKeys();
  } catch (e) {
    rows.replaceChildren(el('p', 'empty', `Could not read the GnuPG keyring: ${errMsg(e)}`));
    $('status').textContent = 'System GnuPG keyring · unavailable';
    return;
  }
  if (source !== 'system') return;
  // Secret keys first, then by primary user ID.
  const label = (k: gpg.SystemKey): string => k.uids[0]?.email || k.uids[0]?.name || k.key_id;
  systemKeys.sort((a, b) => Number(b.has_secret) - Number(a.has_secret) || label(a).localeCompare(label(b)));
  rows.replaceChildren();
  if (!systemKeys.length) {
    const empty = el('div', 'empty');
    empty.append(el('p', undefined, `The GnuPG keyring at ${gpgInfo?.homedir ?? '~/.gnupg'} is empty.`));
    const b = el('button', 'primary', 'Generate a key with gpg');
    b.addEventListener('click', () => openModal('generate'));
    empty.append(b);
    rows.append(empty);
  }
  for (const k of systemKeys) {
    const dead = k.revoked || k.expired || k.disabled;
    const state = k.revoked ? 'revoked' : k.expired ? 'expired' : k.disabled ? 'disabled' : k.validity;
    const row = rowFor({
      dot: k.has_secret, dotTitle: k.has_secret ? 'Secret key in your keyring' : 'Public key only',
      addr: label(k) + (k.uids.length > 1 ? ` +${k.uids.length - 1}` : ''),
      id: '…' + k.fingerprint.slice(-8),
      date: fmtDate(k.created),
      chip: state, chipOn: !dead && (k.validity === 'ultimate' || k.validity === 'full'),
      title: `${gpg.fmtFpr(k.fingerprint)}\n${k.algo}${k.expires ? ` · expires ${k.expires}` : ''}\n${k.uids.map((u) => u.uid).join('\n')}`,
      dead,
    });
    if (sel?.kind === 'system' && sel.fpr === k.fingerprint) row.classList.add('sel');
    row.addEventListener('click', () => {
      sel = { kind: 'system', fpr: k.fingerprint, email: k.uids[0]?.email ?? '', hasSecret: k.has_secret };
      markSelected(rows, row);
    });
    rows.append(row);
  }
  const secret = systemKeys.filter((k) => k.has_secret).length;
  $('status').textContent =
    `System GnuPG keyring · ${systemKeys.length} key${systemKeys.length === 1 ? '' : 's'} · ${secret} with a secret key · trust is gpg's`;
  // Sign-as choices for the sealer.
  const sign = $('seal-sign') as HTMLSelectElement;
  const prev = sign.value;
  sign.replaceChildren(new Option("Don't sign", ''));
  for (const k of systemKeys.filter((k) => k.has_secret && k.can_sign && !(k.revoked || k.expired || k.disabled))) {
    sign.append(new Option(`${label(k)} (…${k.fingerprint.slice(-8)})`, k.fingerprint));
  }
  if ([...sign.options].some((o) => o.value === prev)) sign.value = prev;
  syncTools();
}

$('act-refresh').addEventListener('click', () => void refreshKeys());
$('act-new').addEventListener('click', () => openModal('generate'));
$('act-import').addEventListener('click', () => openModal('import'));
$('act-backup').addEventListener('click', async () => {
  if (!sel) return;
  try {
    if (sel.kind === 'saavi') {
      const path = await pgp.saveBackup(sel.email, sel.fpr);
      if (path !== null) $('status').textContent = path ? `Backup saved to ${path}` : 'Backup downloaded.';
      return;
    }
    const armored = sel.hasSecret ? await gpg.exportSecret(sel.fpr) : await gpg.exportPublic(sel.fpr);
    const base = (sel.email || sel.fpr.slice(-16)).replace(/[^a-z0-9.@-]/gi, '_');
    const path = await saveTextFile(`${base}${sel.hasSecret ? '-secret' : ''}.asc`, armored);
    if (path !== null) {
      $('status').textContent = path
        ? `${sel.hasSecret ? 'Secret key (passphrase-protected by gpg)' : 'Public key'} saved to ${path}`
        : 'Key downloaded.';
    }
  } catch (e) {
    $('status').textContent = `NOT saved: ${errMsg(e)}`;
  }
});
$('act-delete').addEventListener('click', async () => {
  if (!sel) return;
  try {
    if (sel.kind === 'saavi') {
      if (sel.isActive) return;
      if (!confirm(`Delete this retired key for ${sel.email} from this device?\n\nAnything sealed to it becomes unreadable here unless its backup is re-imported.`)) return;
      await pgp.deleteRetired(sel.email, sel.fpr);
    } else {
      if (sel.hasSecret) return;
      if (!confirm(`Remove the public key ${gpg.fmtFpr(sel.fpr)}${sel.email ? ` (${sel.email})` : ''} from your GnuPG keyring?`)) return;
      await gpg.deletePublic(sel.fpr);
    }
    sel = null;
    void refreshKeys();
  } catch (e) {
    $('status').textContent = `Not deleted: ${errMsg(e)}`;
  }
});

// ---------- the modal (generate / import / unlock) ----------
type ModalMode = 'generate' | 'import' | 'unlock';
let modalMode: ModalMode = 'generate';
let unlockFor: { email: string; fingerprint?: string; then: () => void } | null = null;
// When set, the modal is on the "key ready" step: a Saavi address, or a
// system fingerprint.
let doneFor: { kind: Source; ref: string } | null = null;

function setSrc(src: 'generate' | 'import'): void {
  modalMode = src;
  for (const b of $('modal-src').querySelectorAll('button')) {
    b.classList.toggle('on', b.dataset.src === src);
  }
  const sys = source === 'system';
  $('f-gen').hidden = src !== 'generate';
  $('f-imp').hidden = src !== 'import';
  $('f-email2').hidden = sys;
  $('f-pass').hidden = sys;
  $('f-pass2').hidden = sys || src !== 'generate';
  $('m-import-label').textContent = sys
    ? 'Armored public or secret key (gpg --export / --export-secret-keys --armor)'
    : 'Armored private key or Saavi backup file';
}
$('modal-src').addEventListener('click', (e) => {
  const b = (e.target as HTMLElement).closest('button');
  if (b?.dataset.src) setSrc(b.dataset.src as 'generate' | 'import');
});

function openModal(mode: ModalMode, unlock?: { email: string; fingerprint?: string; then: () => void }): void {
  modalMode = mode;
  unlockFor = mode === 'unlock' ? unlock ?? null : null;
  doneFor = null;
  ($('modal-form') as HTMLFormElement).reset();
  $('m-err').hidden = true;
  $('m-strength').textContent = '';
  $('f-done').hidden = true;
  $('f-pass').hidden = false;
  $('f-email2').hidden = false;
  ($('m-cancel') as HTMLButtonElement).hidden = false;
  $('m-go').textContent = 'Continue';
  $('modal-src').hidden = mode === 'unlock';
  $('f-gen').hidden = mode !== 'generate';
  $('f-imp').hidden = mode !== 'import';
  $('f-pass2').hidden = mode !== 'generate';
  const sys = source === 'system' && mode !== 'unlock';
  $('modal-title').textContent =
    mode === 'unlock' ? 'Unlock key' : mode === 'import' ? (sys ? 'Import into GnuPG' : 'Import a key') : (sys ? 'New key in GnuPG' : 'New key');
  $('modal-sub').textContent = mode === 'unlock'
    ? `Enter the passphrase for ${unlock?.email ?? 'this key'}.`
    : sys
      ? 'gpg creates and stores the key in your GnuPG keyring and asks for the passphrase itself (pinentry). Saavi never sees it.'
      : 'Created and stored on this device only, locked with your passphrase. Keep the backup file and the passphrase safe; there is no recovery without both.';
  if (mode !== 'unlock') setSrc(mode);
  $('modal').hidden = false;
  (mode === 'generate' ? $('m-name') : mode === 'import' ? $('m-import') : $('m-pass')).focus();
}

function closeModal(): void {
  $('modal').hidden = true;
  if (doneFor) {
    doneFor = null;
    void refreshKeys();
  }
}

$('m-cancel').addEventListener('click', closeModal);

$('m-save-backup').addEventListener('click', async () => {
  if (!doneFor) return;
  const b = $('m-save-backup') as HTMLButtonElement;
  b.disabled = true;
  try {
    const path = doneFor.kind === 'saavi'
      ? await pgp.saveBackup(doneFor.ref)
      : await saveTextFile(`${doneFor.ref.slice(-16)}-secret.asc`, await gpg.exportSecret(doneFor.ref));
    $('done-saved').textContent =
      path === null ? 'Not saved yet — choose a location for the backup.'
      : path === '' ? 'Backup downloaded.'
      : `Backup saved to ${path}`;
  } catch (e2) {
    $('done-saved').textContent = `Could not save: ${errMsg(e2)}`;
  } finally {
    b.disabled = false;
  }
});
$('m-pass').addEventListener('input', () => {
  const n = ($('m-pass') as HTMLInputElement).value.length;
  $('m-strength').textContent =
    n === 0 ? '' : n < 12 ? `${n}/12 characters — keep going` : n < 20 ? 'Acceptable — longer is stronger' : 'Strong passphrase';
});

function showDone(fingerprint: string, sub: string): void {
  $('modal-title').textContent = 'Your key is ready';
  $('modal-sub').textContent = sub;
  $('modal-src').hidden = true;
  $('f-gen').hidden = true;
  $('f-pass').hidden = true;
  $('f-pass2').hidden = true;
  $('m-strength').textContent = '';
  $('done-fpr').textContent = fingerprint;
  $('done-saved').textContent = '';
  $('f-done').hidden = false;
  ($('m-cancel') as HTMLButtonElement).hidden = true;
}

const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]{2,}$/;

$('modal-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (doneFor) return closeModal();
  const err = $('m-err');
  err.hidden = true;
  const pass = ($('m-pass') as HTMLInputElement).value;
  const go = $('m-go') as HTMLButtonElement;
  go.disabled = true;
  go.textContent = source === 'system' && modalMode !== 'unlock' ? 'Waiting for gpg…' : 'Working…';
  try {
    if (modalMode === 'unlock' && unlockFor) {
      await pgp.unlockPrivateKey(unlockFor.email, pass, unlockFor.fingerprint);
      $('modal').hidden = true;
      const then = unlockFor.then;
      unlockFor = null;
      then();
    } else if (modalMode === 'import') {
      const src = ($('m-import') as HTMLTextAreaElement).value.trim();
      if (!src) throw new Error('Paste the key first.');
      if (source === 'system') {
        const r = await gpg.importKey(src);
        $('modal').hidden = true;
        $('status').textContent =
          `gpg imported ${r.imported} new key${r.imported === 1 ? '' : 's'}` +
          (r.secret_imported ? ` (${r.secret_imported} secret)` : '') +
          (r.unchanged ? `, ${r.unchanged} unchanged` : '') + '.';
      } else {
        const email = ($('m-email2') as HTMLInputElement).value.trim().toLowerCase();
        if (!EMAIL_RE.test(email)) throw new Error('Give the address this key belongs to.');
        await pgp.importKey(email, src, pass);
        $('modal').hidden = true;
      }
    } else {
      const email = ($('m-email') as HTMLInputElement).value.trim().toLowerCase();
      if (!EMAIL_RE.test(email)) throw new Error('That does not look like an email address.');
      const name = ($('m-name') as HTMLInputElement).value.trim();
      const algo = ($('m-algo') as HTMLSelectElement).value as pgp.KeyAlgo;
      if (source === 'system') {
        const fpr = await gpg.generate(name, email, algo);
        doneFor = { kind: 'system', ref: fpr };
        showDone(gpg.fmtFpr(fpr), 'Stored in your GnuPG keyring with ultimate trust. A backup is the secret key as gpg exports it — still locked with the passphrase you gave pinentry.');
      } else {
        if (pass !== ($('m-pass2') as HTMLInputElement).value) throw new Error('The passphrases do not match.');
        if (pass.length < 12) throw new Error('Use at least 12 characters — this passphrase is the whole lock.');
        const rec = await pgp.generateKeys(email, name, pass, algo);
        await pgp.unlockPrivateKey(email, pass);
        doneFor = { kind: 'saavi', ref: email };
        showDone(await pgp.fingerprintOf(rec.publicKey), '');
      }
    }
    void refreshKeys();
  } catch (e2) {
    err.textContent = errMsg(e2);
    err.hidden = false;
  } finally {
    go.disabled = false;
    go.textContent = doneFor ? 'Done' : 'Continue';
  }
});

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && !$('modal').hidden) return closeModal();
  const mod = e.metaKey || e.ctrlKey;
  if (!mod || !$('modal').hidden) return;
  if (e.key === '1') { e.preventDefault(); selectTab('keys'); }
  else if (e.key === '2') { e.preventDefault(); selectTab('seal'); }
  else if (e.key === 'Enter' && !$('view-seal').hidden) { e.preventDefault(); $('seal-enc').click(); }
});

// ---------- the sealer (−d) ----------
const sealErr = $('seal-err');
function sealFail(msg: string): void {
  sealErr.textContent = msg;
  sealErr.hidden = false;
}
function sealShow(label: string, text: string, sigs?: gpg.SignatureInfo[] | null): void {
  $('seal-out-label').textContent = label;
  ($('seal-out') as HTMLTextAreaElement).value = text;
  $('seal-out-fld').hidden = false;
  $('seal-copy').hidden = false;
  const sig = $('seal-sig');
  sig.replaceChildren();
  if (sigs === undefined) { sig.hidden = true; return; }
  sig.hidden = false;
  if (!sigs || !sigs.length) {
    sig.append(el('span', 'sig sig-none', 'Unsigned — nothing vouches for who wrote this.'));
    return;
  }
  for (const s of sigs) {
    sig.append(el('span', `sig sig-${s.status === 'good' && (s.trust === 'ultimate' || s.trust === 'full') ? 'good' : s.status === 'bad' ? 'bad' : 'warn'}`, gpg.describeSignature(s)));
  }
}

async function sealWithSystem(text: string, toRaw: string): Promise<void> {
  const recipients: string[] = [];
  if (toRaw.includes('BEGIN PGP PUBLIC KEY BLOCK')) {
    // gpg can only encrypt to keys in its keyring: import the pasted key
    // (as gpg would), then address it by fingerprint.
    const r = await gpg.importKey(pgp.normalizeKeyArmor(toRaw));
    recipients.push(...r.fingerprints);
    $('status').textContent = `Pasted key imported into GnuPG: ${r.fingerprints.map(gpg.fmtFpr).join(', ')}`;
  } else {
    recipients.push(...toRaw.split(',').map((s) => s.trim()).filter(Boolean));
  }
  const signWith = ($('seal-sign') as HTMLSelectElement).value || null;
  let r = await gpg.encrypt(text, recipients, { signWith });
  if (!r.armored && r.untrusted.length && !r.missing.length) {
    const ok = confirm(
      `gpg does not trust the key${r.untrusted.length === 1 ? '' : 's'} for:\n  ${r.untrusted.join('\n  ')}\n\n` +
      'Nobody you trust has certified it, and you have not verified its fingerprint. ' +
      'Encrypt to it anyway, this once?');
    if (!ok) return sealFail('Not sealed — verify the fingerprint (gpg --fingerprint) and sign the key, then try again.');
    r = await gpg.encrypt(text, recipients, { signWith, trustAll: true });
  }
  if (!r.armored) {
    return sealFail(
      r.missing.length
        ? `No usable key in your GnuPG keyring (or via WKD) for: ${r.missing.join(', ')}. Import their public key first.`
        : 'gpg could not encrypt.');
  }
  sealShow(signWith ? 'Sealed and signed message' : 'Sealed message', r.armored);
}

$('seal-enc').addEventListener('click', async () => {
  sealErr.hidden = true;
  $('seal-out-fld').hidden = true;
  $('seal-sig').hidden = true;
  const text = ($('seal-in') as HTMLTextAreaElement).value;
  if (!text.trim()) return sealFail('There is nothing to seal yet.');
  const toRaw = ($('seal-to') as HTMLInputElement).value.trim();
  if (!toRaw) return sealFail('Name at least one recipient — an address, or a pasted public key.');
  try {
    if (source === 'system') return await sealWithSystem(text, toRaw);
    const keys: string[] = [];
    const missing: string[] = [];
    if (toRaw.includes('BEGIN PGP PUBLIC KEY BLOCK')) {
      keys.push(pgp.normalizeKeyArmor(toRaw));
    } else {
      for (const addr of toRaw.split(',').map((s) => s.trim().toLowerCase()).filter(Boolean)) {
        const own = pgp.keysFor(addr);
        const found = own?.publicKey ?? await wkdLookup(addr);
        if (found) keys.push(found);
        else missing.push(addr);
      }
    }
    if (missing.length) return sealFail(`No key discoverable for: ${missing.join(', ')}. Their domain publishes no WKD entry — ask them for their public key and paste it instead.`);
    sealShow('Sealed message', await pgp.encryptText(text, keys));
  } catch (e2) {
    sealFail(errMsg(e2));
  }
});

$('seal-dec').addEventListener('click', async () => {
  sealErr.hidden = true;
  $('seal-out-fld').hidden = true;
  $('seal-sig').hidden = true;
  const text = ($('seal-in') as HTMLTextAreaElement).value.trim();
  if (!pgp.looksEncrypted(text)) return sealFail('That is not an armored PGP message.');
  if (source === 'system') {
    try {
      const out = await gpg.decrypt(text);
      sealShow('Unsealed text', out.text, out.signatures);
    } catch (e2) {
      sealFail(errMsg(e2));
    }
    return;
  }
  const attempt = async (): Promise<void> => {
    try {
      const out = await pgp.decryptText(text);
      sealShow('Unsealed text', out.text);
    } catch (e) {
      if (!(e instanceof Error && e.message === 'locked')) {
        return sealFail(`Could not unseal: ${errMsg(e)}`);
      }
      for (const email of ringAddresses()) {
        const need = await pgp.neededKeyFor(email, text).catch(() => null);
        if (!need) continue;
        if (need.unlocked) {
          return sealFail(`This message names the key for ${email}, but that key cannot open it. The message may be damaged.`);
        }
        openModal('unlock', { email, fingerprint: need.fingerprint, then: () => void attempt() });
        return;
      }
      sealFail('None of the keys on this device fit this message.');
    }
  };
  await attempt();
});

$('seal-copy').addEventListener('click', () => {
  void navigator.clipboard.writeText(($('seal-out') as HTMLTextAreaElement).value);
});

// ---------- boot ----------
void refreshKeys();
void detectGpg();
