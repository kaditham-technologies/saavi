// Saavi — the app. Two faces, KGpg heritage: −k (the keyring table) and
// −d (the sealer). Two keyring sources: Saavi's own store (pgp.ts,
// OpenPGP.js, works anywhere) and the system GnuPG keyring (gpg.ts, the
// user's own gpg binary, shell only). All crypto lives in those two modules;
// recipient lookup in wkd.ts / vks.ts; dialogs in ui.ts.
import './style.css';
import * as pgp from './pgp';
import * as gpg from './gpg';
import * as keychain from './keychain';
import { wkdProbe } from './wkd';
import { vksLookup, vksLookupKeyId } from './vks';
import { ask, confirmBox, notice } from './ui';
import { generatePassphrase, passphraseBits, describeStrength } from './passphrase';
import * as update from './update';

const $ = <T extends HTMLElement = HTMLElement>(id: string): T =>
  document.getElementById(id) as T;

const ICONS: Record<string, string> = {
  plus: '<path d="M8 3.5v9M3.5 8h9"/>',
  import: '<path d="M8 2.4v7.2"/><path d="M5.6 7.2 8 9.6l2.4-2.4"/><path d="M2.8 10.4v1.8a1.2 1.2 0 0 0 1.2 1.2h8a1.2 1.2 0 0 0 1.2-1.2v-1.8"/>',
  save: '<rect x="2.6" y="2.6" width="10.8" height="10.8" rx="1.2"/><path d="M5.2 2.6v3.6h5.6V2.6"/><path d="M5.2 13.4V9.2h5.6v4.2"/>',
  trash: '<path d="M2.8 4.3h10.4"/><path d="M5.6 4.3v-1a1 1 0 0 1 1-1h2.8a1 1 0 0 1 1 1v1"/><path d="m4.3 4.3.6 8.2a1.1 1.1 0 0 0 1.1 1h4a1.1 1.1 0 0 0 1.1-1l.6-8.2"/>',
  refresh: '<path d="M13.5 8a5.5 5.5 0 1 1-1.6-3.9"/><path d="M13.5 1.5v3h-3"/>',
  info: '<circle cx="8" cy="8" r="5.6"/><path d="M8 7.2v3.6"/><path d="M8 5.2v.2"/>',
  lock: '<rect x="3.4" y="7" width="9.2" height="6.4" rx="1.2"/><path d="M5.4 7V5.2a2.6 2.6 0 0 1 5.2 0V7"/><path d="M8 9.6v1.6"/>',
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
const status = (msg: string): void => { $('status').textContent = msg; };

/** Every address with a ring in the Saavi store. */
function ringAddresses(): string[] {
  const out: string[] = [];
  for (let i = 0; i < localStorage.length; i++) {
    const k = localStorage.key(i)!;
    if (k.startsWith('saavi-ring-')) out.push(k.slice('saavi-ring-'.length));
  }
  return out.sort();
}

// ---------- OS keychain (Saavi store) ----------
let keychainOk = false;
void keychain.available().then((ok) => { keychainOk = ok; });

/** Raw fingerprint of a Saavi-store key (active by default). */
async function saaviFpr(email: string, fingerprint?: string): Promise<string | null> {
  if (fingerprint) return fingerprint.replace(/\s+/g, '').toLowerCase();
  const k = pgp.keysFor(email);
  return k ? (await pgp.fingerprintOf(k.publicKey)).replace(/\s+/g, '').toLowerCase() : null;
}

/** Unlock from the keychain without asking, if the user chose to remember. */
async function tryKeychainUnlock(email: string, fingerprint?: string): Promise<boolean> {
  if (!keychainOk) return false;
  try {
    const fpr = await saaviFpr(email, fingerprint);
    if (!fpr) return false;
    const pass = await keychain.get(fpr);
    if (!pass) return false;
    await pgp.unlockPrivateKey(email, pass, fingerprint);
    return true;
  } catch {
    return false;
  }
}

async function rememberInKeychain(email: string, pass: string, fingerprint?: string): Promise<void> {
  const fpr = await saaviFpr(email, fingerprint);
  if (fpr) await keychain.set(fpr, pass);
}

// ---------- auto-lock (Saavi store) ----------
// Unlocked keys live only in memory; drop them after IDLE_MS without input,
// or on demand. Keys remembered in the OS keychain reopen silently the next
// time they are needed, so the timeout costs nothing for those; for the
// rest it bounds how long a walked-away-from machine holds open keys.
const IDLE_MS = 15 * 60 * 1000;
let idleTimer: ReturnType<typeof setTimeout> | undefined;
let lastArm = 0;

function lockAll(why: 'idle' | 'manual'): void {
  pgp.clearSession();
  const msg = why === 'idle' ? 'Locked: no input for 15 minutes.' : 'Locked: unlocked keys forgotten.';
  if (source === 'saavi' && $('modal').hidden) {
    void refreshKeys().then(() => status(msg));
  } else {
    status(msg);
  }
}

function armIdle(): void {
  const now = Date.now();
  if (now - lastArm < 1000) return; // mousemove fires constantly; cheap reset
  lastArm = now;
  clearTimeout(idleTimer);
  idleTimer = setTimeout(() => { if (pgp.hasUnlockedKeys()) lockAll('idle'); else armIdle(); }, IDLE_MS);
}
// A hidden window is a walked-away-from window: lock after a third of the
// idle allowance out of sight, regardless of the last input.
const HIDDEN_MS = IDLE_MS / 3;
let hiddenTimer: ReturnType<typeof setTimeout> | undefined;
document.addEventListener('visibilitychange', () => {
  clearTimeout(hiddenTimer);
  if (document.hidden && pgp.hasUnlockedKeys()) {
    hiddenTimer = setTimeout(() => { if (document.hidden && pgp.hasUnlockedKeys()) lockAll('idle'); }, HIDDEN_MS);
  }
});
for (const ev of ['pointerdown', 'keydown', 'mousemove', 'wheel', 'focus'] as const) {
  window.addEventListener(ev, armIdle, { passive: true, capture: true });
}
armIdle();

// ---------- update indicator (on by default, check-only) ----------
const updateOpt = $('update-opt') as HTMLInputElement;
const updatePill = $('update-pill') as HTMLButtonElement;
const updateBanner = $('update-banner');
const updateBannerText = $('update-banner-text');
let offeredVersion: string | null = null;
async function runUpdateCheck(force = false): Promise<void> {
  if (!update.enabled()) return;
  const info = await update.check(__APP_VERSION__, force);
  if (!info) { if (force) status(`Saavi ${__APP_VERSION__} is the latest version.`); return; }
  offeredVersion = info.version;
  updatePill.textContent = `Saavi ${info.version} available`;
  updatePill.title = `You have ${__APP_VERSION__}. Opens the download page; install it the usual way and verify the signature.`;
  updatePill.hidden = false;
  // The loud banner, unless the user has already dismissed this exact version.
  if (update.dismissed() !== info.version) {
    updateBannerText.textContent =
      `Saavi ${info.version} is available — you have ${__APP_VERSION__}.`;
    updateBanner.hidden = false;
  }
  if (update.seen() !== info.version) { update.markSeen(info.version); status(`Saavi ${info.version} is available — see the download page.`); }
}
updateOpt.checked = update.enabled();
updateOpt.addEventListener('change', () => {
  update.setEnabled(updateOpt.checked);
  if (updateOpt.checked) void runUpdateCheck(true);
  else { updatePill.hidden = true; updateBanner.hidden = true; }
});
const openDownload = () => { void update.openDownloadPage().catch((e) => status(`Could not open the browser: ${errMsg(e)}`)); };
updatePill.addEventListener('click', openDownload);
$('update-banner-get').addEventListener('click', openDownload);
$('update-banner-x').addEventListener('click', () => {
  updateBanner.hidden = true;
  if (offeredVersion) update.dismiss(offeredVersion); // the pill stays as the quiet reminder
});
void runUpdateCheck();

// ---------- files through the shell ----------
async function saveTextFile(filename: string, text: string): Promise<string | null> {
  if (gpg.inShell()) {
    const { save } = await import('@tauri-apps/plugin-dialog');
    const { writeTextFile } = await import('@tauri-apps/plugin-fs');
    const path = await save({ defaultPath: filename, filters: [{ name: 'OpenPGP', extensions: ['asc', 'txt'] }] });
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
async function pickFile(title: string): Promise<string | null> {
  const { open } = await import('@tauri-apps/plugin-dialog');
  const p = await open({ title, multiple: false, directory: false });
  return typeof p === 'string' ? p : null;
}
async function pickSave(defaultPath: string): Promise<string | null> {
  const { save } = await import('@tauri-apps/plugin-dialog');
  return save({ defaultPath });
}
const baseName = (p: string): string => p.split(/[\\/]/).pop() ?? p;
const dirName = (p: string): string => p.slice(0, p.length - baseName(p).length);

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
  $('seal-to-label').textContent = s === 'system'
    ? 'To (addresses or fingerprints in your GnuPG keyring — WKD for unknown addresses — or paste a public key)'
    : 'To (addresses — found via WKD or keys.openpgp.org — or paste a public key)';
  $('files').hidden = !gpg.inShell();
  sel = null;
  void refreshKeys();
}

async function detectGpg(): Promise<void> {
  const note = $('ring-note');
  $('files').hidden = !gpg.inShell();
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
    if (localStorage.getItem('saavi-source') === 'system') setSource('system');
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
  ($('act-details') as HTMLButtonElement).disabled = !sel;
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
  row.append(dot, el('span', 'c-addr', cells.addr), el('span', 'c-id', cells.id), el('span', 'c-date', cells.date),
    el('span', 'chip c-end' + (cells.chipOn ? ' chip-on' : ''), cells.chip));
  row.title = cells.title;
  row.addEventListener('dblclick', () => void openDetails());
  return row;
}

const fmtDate = (iso: string | null): string =>
  iso ? new Date(iso).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' }) : '—';

function markSelected(rows: HTMLElement, row: HTMLElement): void {
  for (const r of rows.querySelectorAll('.row')) r.classList.toggle('sel', r === row);
  syncTools();
}

const keyLabel = (k: gpg.SystemKey): string => k.uids[0]?.email || k.uids[0]?.name || k.key_id;
const dead = (k: gpg.SystemKey): boolean => k.revoked || k.expired || k.disabled;

async function refreshKeys(): Promise<void> {
  const rows = $('rows');
  rows.replaceChildren(el('p', 'loading', 'Reading the keyring…'));
  const go = source;
  if (go === 'system') return refreshSystemKeys(rows);

  // Keychain-remembered keys unlock LAZILY (ensureUnlocked / the unseal
  // attempt), never here — otherwise every refresh would undo Lock and the
  // idle timer, and remembered keys would sit decrypted all session.
  const flat: { email: string; info: pgp.KeyInfo; remembered: boolean }[] = [];
  for (const email of ringAddresses()) {
    for (const info of await pgp.listKeys(email).catch(() => [] as pgp.KeyInfo[])) {
      let remembered = false;
      if (keychainOk && !info.unlocked) {
        remembered = await keychain.get(info.fingerprint.replace(/\s+/g, '').toLowerCase())
          .then((p) => !!p).catch(() => false);
      }
      flat.push({ email, info, remembered });
    }
  }
  if (source !== go) return;
  rows.replaceChildren();
  // A store record that failed to parse was quarantined, not destroyed —
  // and that must be LOUD, not a silently shorter key list.
  for (const alert of pgp.storeAlerts()) {
    const bar = el('div', 'alert-bar');
    bar.append(el('strong', undefined, `A stored key record for ${alert.email} could not be read. `));
    bar.append(el('span', undefined,
      'It was preserved, not deleted. Re-import that key’s backup file; the damaged record is kept in browser storage under “'
      + alert.quarantineKey + '”.'));
    const ok = el('button', 'ghost', 'Dismiss');
    ok.addEventListener('click', () => { pgp.dismissStoreAlert(alert.quarantineKey); void refreshKeys(); });
    bar.append(ok);
    rows.append(bar);
  }
  if (!flat.length) {
    const empty = el('div', 'empty');
    empty.append(el('p', undefined, 'No keys yet. This is a fresh keyring.'));
    const b = el('button', 'primary', 'Generate your first key');
    b.addEventListener('click', () => openModal('generate'));
    empty.append(b);
    rows.append(empty);
  }
  for (const { email, info, remembered } of flat) {
    const row = rowFor({
      dot: info.unlocked,
      dotTitle: info.unlocked ? 'Unlocked this session'
        : remembered ? 'Locked — remembered in the OS keychain, unlocks when needed' : 'Locked',
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
  status(`Saavi store · ${flat.length} key${flat.length === 1 ? '' : 's'} · ${n} address${n === 1 ? '' : 'es'} · ${unlocked} unlocked this session`);
  // Sign-as: own addresses (unlock is prompted when needed).
  const sign = $('seal-sign') as HTMLSelectElement;
  const prev = sign.value;
  sign.replaceChildren(new Option("Don't sign", ''));
  for (const email of ringAddresses()) sign.append(new Option(email, email));
  if ([...sign.options].some((o) => o.value === prev)) sign.value = prev;
  syncTools();
}

async function refreshSystemKeys(rows: HTMLElement): Promise<void> {
  try {
    systemKeys = await gpg.listKeys();
  } catch (e) {
    rows.replaceChildren(el('p', 'empty', `Could not read the GnuPG keyring: ${errMsg(e)}`));
    status('System GnuPG keyring · unavailable');
    return;
  }
  if (source !== 'system') return;
  systemKeys.sort((a, b) => Number(b.has_secret) - Number(a.has_secret) || keyLabel(a).localeCompare(keyLabel(b)));
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
    const state = k.revoked ? 'revoked' : k.expired ? 'expired' : k.disabled ? 'disabled' : k.validity;
    const row = rowFor({
      dot: k.has_secret, dotTitle: k.has_secret ? 'Secret key in your keyring' : 'Public key only',
      addr: keyLabel(k) + (k.uids.length > 1 ? ` +${k.uids.length - 1}` : ''),
      id: '…' + k.fingerprint.slice(-8),
      date: fmtDate(k.created),
      chip: state, chipOn: !dead(k) && (k.validity === 'ultimate' || k.validity === 'full'),
      title: `${gpg.fmtFpr(k.fingerprint)}\n${k.algo}${k.expires ? ` · expires ${k.expires}` : ''}\n${k.uids.map((u) => u.uid).join('\n')}`,
      dead: dead(k),
    });
    if (sel?.kind === 'system' && sel.fpr === k.fingerprint) row.classList.add('sel');
    row.addEventListener('click', () => {
      sel = { kind: 'system', fpr: k.fingerprint, email: k.uids[0]?.email ?? '', hasSecret: k.has_secret };
      markSelected(rows, row);
    });
    rows.append(row);
  }
  const secret = systemKeys.filter((k) => k.has_secret).length;
  status(`System GnuPG keyring · ${systemKeys.length} key${systemKeys.length === 1 ? '' : 's'} · ${secret} with a secret key · trust is gpg's`);
  const sign = $('seal-sign') as HTMLSelectElement;
  const prev = sign.value;
  sign.replaceChildren(new Option("Don't sign", ''));
  for (const k of signingKeys()) sign.append(new Option(`${keyLabel(k)} (…${k.fingerprint.slice(-8)})`, k.fingerprint));
  if ([...sign.options].some((o) => o.value === prev)) sign.value = prev;
  syncTools();
}
const signingKeys = (): gpg.SystemKey[] => systemKeys.filter((k) => k.has_secret && k.can_sign && !dead(k));

$('act-refresh').addEventListener('click', () => void refreshKeys());
$('act-lock').addEventListener('click', () => lockAll('manual'));
$('act-new').addEventListener('click', () => openModal('generate'));
$('act-import').addEventListener('click', () => openModal('import'));
$('act-details').addEventListener('click', () => void openDetails());
$('act-backup').addEventListener('click', async () => {
  if (!sel) return;
  try {
    if (sel.kind === 'saavi') {
      const path = await pgp.saveBackup(sel.email, sel.fpr);
      if (path !== null) status(path ? `Backup saved to ${path}` : 'Backup downloaded.');
      return;
    }
    const armored = sel.hasSecret ? await gpg.exportSecret(sel.fpr) : await gpg.exportPublic(sel.fpr);
    const base = (sel.email || sel.fpr.slice(-16)).replace(/[^a-z0-9.@-]/gi, '_');
    const path = await saveTextFile(`${base}${sel.hasSecret ? '-secret' : ''}.asc`, armored);
    if (path !== null) status(path ? `${sel.hasSecret ? 'Secret key (as gpg exports it — protected only if the key has a passphrase)' : 'Public key'} saved to ${path}` : 'Key downloaded.');
  } catch (e) {
    status(`NOT saved: ${errMsg(e)}`);
  }
});
$('act-delete').addEventListener('click', async () => {
  if (!sel) return;
  try {
    if (sel.kind === 'saavi') {
      if (sel.isActive) return;
      if (!await confirmBox('Delete retired key?', `Delete this retired key for ${sel.email} from this device? Anything sealed to it becomes unreadable here unless its backup is re-imported.`, 'Delete', true, sel.fpr)) return;
      await pgp.deleteRetired(sel.email, sel.fpr);
    } else {
      if (sel.hasSecret) return;
      if (!await confirmBox('Remove public key?', `Remove this public key${sel.email ? ` (${sel.email})` : ''} from your GnuPG keyring?`, 'Remove', true, gpg.fmtFpr(sel.fpr))) return;
      await gpg.deletePublic(sel.fpr);
    }
    sel = null;
    void refreshKeys();
  } catch (e) {
    status(`Not deleted: ${errMsg(e)}`);
  }
});

// ---------- key details (double-click / Details) ----------
function detailRow(grid: HTMLElement, k: string, v: string, mono = false): void {
  grid.append(el('dt', undefined, k), el('dd', mono ? 'mono' : undefined, v));
}

async function openDetails(): Promise<void> {
  if (!sel) return;
  const veil = $('details');
  const body = $('details-body');
  const acts = $('details-acts');
  body.replaceChildren();
  acts.replaceChildren();
  const action = (label: string, fn: () => Promise<void>, cls = ''): void => {
    const b = el('button', cls, label);
    b.addEventListener('click', async () => {
      (b as HTMLButtonElement).disabled = true;
      try { await fn(); } catch (e) { await notice('Not done', errMsg(e)); } finally { (b as HTMLButtonElement).disabled = false; }
    });
    acts.append(b);
  };
  const copyFpr = (fpr: string) => async (): Promise<void> => { await navigator.clipboard.writeText(fpr); status('Fingerprint copied.'); };

  if (sel.kind === 'saavi') {
    const s = sel;
    const ring = pgp.ringFor(s.email);
    const want = s.fpr.replace(/\s+/g, '').toLowerCase();
    let rec: pgp.KeyRecord | null = null;
    for (const r of ring ? [ring.active, ...ring.retired] : []) {
      if ((await pgp.fingerprintOf(r.publicKey)).replace(/\s+/g, '').toLowerCase() === want) { rec = r; break; }
    }
    $('details-title').textContent = s.email;
    const grid = el('dl', 'kv');
    detailRow(grid, 'Fingerprint', s.fpr, true);
    detailRow(grid, 'Created', rec ? fmtDate(rec.created) : '—');
    detailRow(grid, 'Status', s.isActive ? 'active — signs and receives new messages' : 'retired — still opens old messages');
    detailRow(grid, 'Unlocked', pgp.isUnlocked(s.email) && s.isActive ? 'yes, this session' : 'no');
    detailRow(grid, 'Store', 'Saavi (OpenPGP.js), passphrase-locked on this device');
    const raw = s.fpr.replace(/\s+/g, '').toLowerCase();
    const remembered = keychainOk ? await keychain.get(raw).then((p) => !!p).catch(() => false) : false;
    if (keychainOk) detailRow(grid, 'OS keychain', remembered ? 'passphrase remembered — unlocks without asking' : 'not remembered');
    body.append(grid);
    action('Copy fingerprint', copyFpr(s.fpr));
    if (remembered) {
      action('Forget in keychain', async () => {
        await keychain.forget(raw);
        status('Keychain entry removed; the passphrase will be asked again.');
        await openDetails();
      });
    }
    if (rec) {
      const pub = rec.publicKey;
      action('Export public key…', async () => {
        const p = await saveTextFile(`${s.email}-public.asc`, pub);
        if (p !== null) status(p ? `Public key saved to ${p}` : 'Public key downloaded.');
      });
      action('Show public key', async () => { await notice('Public key', 'Share this freely — it is what others seal to.', pub); });
    }
  } else {
    const s = sel;
    const k = systemKeys.find((x) => x.fingerprint === s.fpr);
    if (!k) return;
    $('details-title').textContent = keyLabel(k);
    const grid = el('dl', 'kv');
    detailRow(grid, 'Fingerprint', gpg.fmtFpr(k.fingerprint), true);
    detailRow(grid, 'Algorithm', k.algo);
    detailRow(grid, 'Created', fmtDate(k.created));
    detailRow(grid, 'Expires', k.expires ? fmtDate(k.expires) : 'never');
    detailRow(grid, 'Validity', k.revoked ? 'revoked' : k.expired ? 'expired' : k.validity);
    detailRow(grid, 'Owner trust', k.owner_trust);
    detailRow(grid, 'Secret key', k.has_secret ? 'in your keyring' : 'no — public only');
    detailRow(grid, 'Can', [k.can_encrypt && 'encrypt', k.can_sign && 'sign'].filter(Boolean).join(', ') || '—');
    body.append(grid);
    const uids = el('div', 'sub');
    uids.append(el('h3', undefined, 'User IDs'));
    for (const u of k.uids) uids.append(el('div', 'uid', `${u.uid}  ·  ${u.validity}`));
    body.append(uids);
    if (k.subkeys.length) {
      const subs = el('div', 'sub');
      subs.append(el('h3', undefined, 'Subkeys'));
      for (const sk of k.subkeys) {
        subs.append(el('div', 'uid mono', `${gpg.fmtFpr(sk.fingerprint)}  ${sk.algo}  [${sk.caps.toUpperCase()}]${sk.expires ? `  expires ${sk.expires}` : ''}${sk.revoked ? '  REVOKED' : sk.expired ? '  EXPIRED' : ''}`));
      }
      body.append(subs);
    }
    action('Copy fingerprint', copyFpr(gpg.fmtFpr(k.fingerprint)));
    action('Export public key…', async () => {
      const p = await saveTextFile(`${(k.uids[0]?.email || k.key_id).replace(/[^a-z0-9.@-]/gi, '_')}-public.asc`, await gpg.exportPublic(k.fingerprint));
      if (p !== null) status(p ? `Public key saved to ${p}` : 'Public key downloaded.');
    });
    action('Owner trust…', async () => {
      const r = await ask({
        title: 'Owner trust', message: 'How much do you trust this person to certify OTHER people\'s keys? This is gpg\'s web-of-trust setting, not whether the key is theirs.',
        fields: [{ name: 'level', label: 'Trust', type: 'select', value: { unknown: '2', never: '3', marginal: '4', full: '5', ultimate: '6' }[k.owner_trust] ?? '2',
          options: [{ value: '2', label: 'Unknown' }, { value: '3', label: 'Never' }, { value: '4', label: 'Marginal' }, { value: '5', label: 'Full' }, { value: '6', label: 'Ultimate (my own key)' }] }],
        ok: 'Set',
      });
      if (!r) return;
      await gpg.setOwnertrust(k.fingerprint, Number(r.level));
      status('Owner trust updated.');
      await refreshKeys(); await openDetails();
    });
    const signers = signingKeys().filter((x) => x.fingerprint !== k.fingerprint);
    if (signers.length) {
      action('Certify…', async () => {
        const r = await ask({
          title: 'Certify this key', message: 'Sign this key with yours to say "I verified this fingerprint belongs to this person". Compare the fingerprint out of band first.',
          code: gpg.fmtFpr(k.fingerprint),
          fields: [
            { name: 'signer', label: 'With my key', type: 'select', options: signers.map((x) => ({ value: x.fingerprint, label: `${keyLabel(x)} (…${x.fingerprint.slice(-8)})` })) },
            { name: 'scope', label: 'Scope', type: 'select', value: 'local', options: [{ value: 'local', label: 'Local — only my keyring (lsign)' }, { value: 'export', label: 'Exportable — others may rely on it' }] },
          ],
          ok: 'Certify',
        });
        if (!r) return;
        await gpg.signKey(k.fingerprint, r.signer, r.scope === 'local');
        status('Key certified.');
        await refreshKeys(); await openDetails();
      });
    }
    if (k.has_secret) {
      action('Set expiry…', async () => {
        const r = await ask({
          title: 'Key expiry', message: 'An expiry is a safety net: a lost key stops being valid on its own. You can extend it any time before (or after) it passes.',
          fields: [{ name: 'expire', label: 'Expires', value: '2y', hint: '0 = never · 2y · 18m · 90d · or a date 2030-01-31' }],
          ok: 'Set',
        });
        if (!r) return;
        await gpg.setExpire(k.fingerprint, r.expire);
        status('Expiry updated.');
        await refreshKeys(); await openDetails();
      });
      action('Change passphrase…', async () => {
        await gpg.passwd(k.fingerprint);
        status('Passphrase changed (through pinentry).');
      });
      action('Add user ID…', async () => {
        const r = await ask({ title: 'Add a user ID', message: 'Another name/address this key speaks for.',
          fields: [{ name: 'name', label: 'Name' }, { name: 'email', label: 'Email address', type: 'email' }], ok: 'Add' });
        if (!r) return;
        await gpg.addUid(k.fingerprint, r.name, r.email);
        status('User ID added.');
        await refreshKeys(); await openDetails();
      });
      if (k.uids.length > 1) {
        action('Revoke user ID…', async () => {
          const r = await ask({ title: 'Revoke a user ID', message: 'Marks the name/address as no longer valid for this key. Cannot be undone; the key itself stays.',
            fields: [{ name: 'uid', label: 'User ID', type: 'select', options: k.uids.map((u) => ({ value: u.uid, label: u.uid })) }], ok: 'Revoke', danger: true });
          if (!r) return;
          await gpg.revokeUid(k.fingerprint, r.uid);
          status('User ID revoked.');
          await refreshKeys(); await openDetails();
        });
      }
    }
  }
  veil.hidden = false;
  $('details-close').focus();
}
$('details-close').addEventListener('click', () => { $('details').hidden = true; });

// ---------- the modal (generate / import / unlock) ----------
type ModalMode = 'generate' | 'import' | 'unlock';
let modalMode: ModalMode = 'generate';
let unlockFor: { email: string; fingerprint?: string; then: () => void; cancel?: () => void } | null = null;
let doneFor: { kind: Source; ref: string } | null = null;

function setSrc(src: 'generate' | 'import'): void {
  modalMode = src;
  for (const b of $('modal-src').querySelectorAll('button')) b.classList.toggle('on', b.dataset.src === src);
  const sys = source === 'system';
  $('f-gen').hidden = src !== 'generate';
  $('f-imp').hidden = src !== 'import';
  $('f-email2').hidden = sys;
  $('f-pass').hidden = sys;
  $('f-pass2').hidden = sys || src !== 'generate';
  $('f-suggest').hidden = sys || src !== 'generate';
  $('f-fpr').hidden = !sys || src !== 'import';
  $('f-remember').hidden = sys || src !== 'generate' || !keychainOk;
  $('m-import-label').textContent = sys
    ? 'Armored public or secret key (gpg --export / --export-secret-keys --armor)'
    : 'Armored private key or Saavi backup file';
}
$('modal-src').addEventListener('click', (e) => {
  const b = (e.target as HTMLElement).closest('button');
  if (b?.dataset.src) setSrc(b.dataset.src as 'generate' | 'import');
});

function openModal(mode: ModalMode, unlock?: { email: string; fingerprint?: string; then: () => void; cancel?: () => void }): void {
  modalMode = mode;
  unlockFor = mode === 'unlock' ? unlock ?? null : null;
  doneFor = null;
  ($('modal-form') as HTMLFormElement).reset();
  ($('m-pass') as HTMLInputElement).type = 'password';
  ($('m-pass2') as HTMLInputElement).type = 'password';
  $('m-err').hidden = true;
  $('m-strength').textContent = '';
  $('f-done').hidden = true;
  $('f-pass').hidden = false;
  $('f-email2').hidden = false;
  $('f-suggest').hidden = true;
  $('f-fpr').hidden = true;
  $('f-remember').hidden = !(keychainOk && source === 'saavi' && mode !== 'import');
  ($('m-remember') as HTMLInputElement).checked = false;
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
  // Humans are bad at inventing passphrases: a new Saavi-store key starts
  // with six generated words already filled in and shown in clear; "Use my
  // own" is the opt-out. The keychain box starts ticked where a store
  // exists, so the words are typed essentially never.
  if (mode === 'generate' && source === 'saavi') {
    suggestPassphrase();
    ($('m-remember') as HTMLInputElement).checked = keychainOk;
  }
  $('modal').hidden = false;
  (mode === 'generate' ? $('m-name') : mode === 'import' ? $('m-import') : $('m-pass')).focus();
}

function closeModal(): void {
  $('modal').hidden = true;
  if (unlockFor?.cancel) { const c = unlockFor.cancel; unlockFor = null; c(); }
  if (doneFor) { doneFor = null; void refreshKeys(); }
}
$('m-cancel').addEventListener('click', closeModal);

// Generated passphrase: diceware, shown in clear so it can be written down
// or copied into a password manager — the right home for it.
let suggested = '';
function suggestPassphrase(): void {
  suggested = generatePassphrase(6);
  for (const id of ['m-pass', 'm-pass2']) {
    const i = $(id) as HTMLInputElement;
    i.value = suggested;
    i.type = 'text';
  }
  $('m-strength').textContent = `Six random words, ≈${passphraseBits(6)} bits. Write them down or save them in a password manager before you continue.`;
}
$('m-suggest').addEventListener('click', suggestPassphrase);
$('m-own-pass').addEventListener('click', () => {
  suggested = '';
  for (const id of ['m-pass', 'm-pass2']) {
    const i = $(id) as HTMLInputElement;
    i.value = '';
    i.type = 'password';
  }
  $('m-strength').textContent = 'At least 12 characters; a sentence you will remember beats a short jumble.';
  $('m-pass').focus();
});
// Copy, then clear the clipboard after 30 s — only if it still holds the
// passphrase, so something the user copied meanwhile is left alone.
$('m-copy-pass').addEventListener('click', async () => {
  const p = ($('m-pass') as HTMLInputElement).value;
  if (!p) return;
  try {
    await navigator.clipboard.writeText(p);
    $('m-strength').textContent = 'Copied. The clipboard is cleared in 30 seconds — paste it into your password manager now.';
    setTimeout(async () => {
      try {
        const now = await navigator.clipboard.readText().catch(() => null);
        if (now === null || now === p) await navigator.clipboard.writeText('');
      } catch { /* clipboard gone or denied — nothing to clear */ }
    }, 30_000);
  } catch (e) {
    $('m-strength').textContent = `Could not copy: ${errMsg(e)}`;
  }
});
$('m-pass-show').addEventListener('click', () => {
  const i = $('m-pass') as HTMLInputElement;
  const j = $('m-pass2') as HTMLInputElement;
  const t = i.type === 'password' ? 'text' : 'password';
  i.type = t; j.type = t;
});
$('m-pass').addEventListener('input', () => {
  $('m-strength').textContent = describeStrength(($('m-pass') as HTMLInputElement).value).label;
});

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
      : path === '' ? 'Backup downloaded.' : `Backup saved to ${path}`;
  } catch (e2) {
    $('done-saved').textContent = `Could not save: ${errMsg(e2)}`;
  } finally {
    b.disabled = false;
  }
});

function showDone(fingerprint: string, sub: string): void {
  $('modal-title').textContent = 'Your key is ready';
  $('modal-sub').textContent = sub;
  for (const id of ['modal-src', 'f-gen', 'f-pass', 'f-pass2', 'f-suggest']) $(id).hidden = true;
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
      if (($('m-remember') as HTMLInputElement).checked) {
        await rememberInKeychain(unlockFor.email, pass, unlockFor.fingerprint).catch((e) => status(`Unlocked, but not remembered: ${errMsg(e)}`));
      }
      $('modal').hidden = true;
      const then = unlockFor.then;
      unlockFor = null;
      then();
    } else if (modalMode === 'import') {
      const src = ($('m-import') as HTMLTextAreaElement).value.trim();
      const fpr = ($('m-fpr') as HTMLInputElement).value.trim();
      if (source === 'system') {
        if (!src && !fpr) throw new Error('Paste a key, or give a fingerprint to fetch.');
        const r = src ? await gpg.importKey(src) : await gpg.recvKey(fpr);
        $('modal').hidden = true;
        status(`gpg imported ${r.imported} new key${r.imported === 1 ? '' : 's'}` +
          (r.secret_imported ? ` (${r.secret_imported} secret)` : '') + (r.unchanged ? `, ${r.unchanged} unchanged` : '') + '.');
      } else {
        if (!src) throw new Error('Paste the key first.');
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
        if (pass.length < 12) throw new Error('Use at least 12 characters — this passphrase is the whole lock. "Suggest one" makes a strong one for you.');
        const rec = await pgp.generateKeys(email, name, pass, algo);
        await pgp.unlockPrivateKey(email, pass);
        if (($('m-remember') as HTMLInputElement).checked) {
          await rememberInKeychain(email, pass).catch((e) => status(`Created, but not remembered: ${errMsg(e)}`));
        }
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
  if (e.key === 'Escape') {
    if (!$('details').hidden) { $('details').hidden = true; return; }
    if (!$('modal').hidden) return closeModal();
  }
  const mod = e.metaKey || e.ctrlKey;
  if (!mod || !$('modal').hidden) return;
  if (e.key === '1') { e.preventDefault(); selectTab('keys'); }
  else if (e.key === '2') { e.preventDefault(); selectTab('seal'); }
  else if (e.key === 'l' || e.key === 'L') { e.preventDefault(); lockAll('manual'); }
  else if (e.key === 'Enter' && !$('view-seal').hidden) { e.preventDefault(); $('seal-enc').click(); }
});

// ---------- the sealer (−d) ----------
const sealErr = $('seal-err');
function sealFail(msg: string): void { sealErr.textContent = msg; sealErr.hidden = false; }
function sealReset(): void { sealErr.hidden = true; $('seal-out-fld').hidden = true; $('seal-sig').hidden = true; }
function sealShow(label: string, text: string, sigs?: gpg.SignatureInfo[] | null): void {
  $('seal-out-label').textContent = label;
  ($('seal-out') as HTMLTextAreaElement).value = text;
  $('seal-out-fld').hidden = false;
  $('seal-copy').hidden = false;
  const sig = $('seal-sig');
  sig.replaceChildren();
  if (sigs === undefined) { sig.hidden = true; return; }
  sig.hidden = false;
  if (!sigs || !sigs.length) { sig.append(el('span', 'sig sig-none', 'Unsigned — nothing vouches for who wrote this.')); return; }
  for (const s of sigs) {
    const cls = s.status === 'good' && (s.trust === 'ultimate' || s.trust === 'full') ? 'good' : s.status === 'bad' ? 'bad' : 'warn';
    sig.append(el('span', `sig sig-${cls}`, gpg.describeSignature(s)));
  }
}
const recipientsRaw = (): string => ($('seal-to') as HTMLInputElement).value.trim();
const signAs = (): string => ($('seal-sign') as HTMLSelectElement).value;

/** Every fingerprint on this device's rings (active AND retired), raw hex.
 *  THE own-key test: trust badges compare fingerprints, never UID strings —
 *  a user ID is attacker-chosen text. */
async function ownFingerprints(): Promise<Set<string>> {
  const fprs = new Set<string>();
  for (const email of ringAddresses()) {
    for (const k of await pgp.listKeys(email).catch(() => [] as pgp.KeyInfo[])) {
      fprs.add(k.fingerprint.replace(/\s+/g, '').toUpperCase());
    }
  }
  return fprs;
}

/** Map core signature verdicts onto the signature strip's row format. */
function verdictInfos(verdicts: pgp.SigVerdict[], ownFprs: Set<string>): gpg.SignatureInfo[] {
  return verdicts.map((v) => {
    const raw = v.fingerprint?.replace(/\s+/g, '').toUpperCase() ?? '';
    return {
      status: v.status === 'unsigned' ? 'error' : v.status,
      fingerprint: raw,
      key_id: v.keyId,
      uid: v.signedBy ?? '',
      trust: v.status === 'good' && raw && ownFprs.has(raw) ? 'ultimate' : '',
    };
  });
}

/** Candidate verification keys for an unseal: every own key plus whatever
 *  the To field names (a pasted key, or lookups for its addresses). */
async function unsealCandidates(toRaw: string): Promise<string[]> {
  const cands: string[] = [];
  for (const email of ringAddresses()) {
    const k = pgp.keysFor(email);
    if (k) cands.push(k.publicKey);
  }
  if (toRaw) {
    const { keys } = await resolveSaaviRecipients(toRaw);
    cands.push(...keys);
  }
  return cands;
}

/** Saavi store: resolve the To field to armored public keys. */
/** Split a To field: commas, semicolons, whitespace and newlines all separate addresses. */
function splitAddresses(raw: string): string[] {
  return raw.split(/[\s,;]+/).map((s) => s.trim().toLowerCase().replace(/^<|>$/g, '')).filter(Boolean);
}

async function resolveSaaviRecipients(toRaw: string): Promise<{ keys: string[]; missing: string[]; why: string[] }> {
  const keys: string[] = [];
  const missing: string[] = [];
  const why: string[] = [];
  if (toRaw.includes('BEGIN PGP PUBLIC KEY BLOCK')) {
    keys.push(pgp.normalizeKeyArmor(toRaw));
    return { keys, missing, why };
  }
  for (const addr of splitAddresses(toRaw)) {
    const own = pgp.keysFor(addr)?.publicKey;
    if (own) { keys.push(own); continue; }
    const w = await wkdProbe(addr);
    if (w.key) { keys.push(w.key); continue; }
    const v = await vksLookup(addr);
    if (v) { keys.push(v); continue; }
    missing.push(addr);
    const domain = addr.split('@')[1] ?? '';
    why.push(w.status === 'unreachable'
      ? `${addr}: ${domain} could not be reached for WKD${w.detail ? ` (${w.detail})` : ''} — check the connection`
      : `${addr}: ${domain} publishes no key for this address (WKD), and none is on keys.openpgp.org`);
  }
  return { keys, missing, why };
}

/** Make sure the Saavi signing key is unlocked; prompts if not. Resolves false if the user bails. */
async function ensureUnlocked(email: string): Promise<boolean> {
  if (pgp.isUnlocked(email)) return true;
  if (await tryKeychainUnlock(email)) return true;
  return new Promise((resolve) => {
    openModal('unlock', { email, then: () => resolve(true), cancel: () => resolve(false) });
  });
}

/** System: resolve To (pasted key → import) to gpg recipients. */
async function resolveSystemRecipients(toRaw: string): Promise<string[]> {
  if (toRaw.includes('BEGIN PGP PUBLIC KEY BLOCK')) {
    const r = await gpg.importKey(pgp.normalizeKeyArmor(toRaw));
    status(`Pasted key imported into GnuPG: ${r.fingerprints.map(gpg.fmtFpr).join(', ')}`);
    return r.fingerprints;
  }
  return splitAddresses(toRaw);
}

async function untrustedOk(untrusted: string[]): Promise<boolean> {
  return confirmBox('gpg does not trust this key',
    `Nobody you trust has certified the key${untrusted.length === 1 ? '' : 's'} for:\n${untrusted.join(', ')}\n\nand you have not verified the fingerprint. Encrypt to it anyway, this once?`,
    'Encrypt anyway');
}

async function sealWithSystem(text: string, toRaw: string): Promise<void> {
  const recipients = await resolveSystemRecipients(toRaw);
  const signWith = signAs() || null;
  let r = await gpg.encrypt(text, recipients, { signWith });
  if (!r.armored && r.untrusted.length && !r.missing.length) {
    if (!await untrustedOk(r.untrusted)) return sealFail('Not sealed — verify the fingerprint and certify the key (Details → Certify), then try again.');
    r = await gpg.encrypt(text, recipients, { signWith, trustAll: true });
  }
  if (!r.armored) {
    return sealFail(r.missing.length
      ? `No usable key in your GnuPG keyring (or via WKD) for: ${r.missing.join(', ')}. Import their public key first.`
      : 'gpg could not encrypt.');
  }
  sealShow(signWith ? 'Sealed and signed message' : 'Sealed message', r.armored);
}

$('seal-enc').addEventListener('click', async () => {
  sealReset();
  const text = ($('seal-in') as HTMLTextAreaElement).value;
  if (!text.trim()) return sealFail('There is nothing to seal yet.');
  const toRaw = recipientsRaw();
  if (!toRaw) return sealFail('Name at least one recipient — an address, or a pasted public key.');
  try {
    if (source === 'system') return await sealWithSystem(text, toRaw);
    const { keys, missing, why } = await resolveSaaviRecipients(toRaw);
    if (missing.length) return sealFail(`No key found. ${why.join('. ')}. Ask them for their public key and paste it into To instead.`);
    const signer = signAs();
    if (signer && !await ensureUnlocked(signer)) return sealFail('Not sealed — the signing key stayed locked.');
    // Also seal to the signing identity's own key, so the sender keeps a
    // readable record of what they sent (copy-paste sealers lose it otherwise).
    const self = signer ? pgp.keysFor(signer)?.publicKey : null;
    if (self) keys.push(self);
    sealShow(signer ? 'Sealed and signed message (also readable by you)' : 'Sealed message', await pgp.encryptText(text, keys, signer || undefined, { sign: !!signer }));
  } catch (e2) {
    sealFail(errMsg(e2));
  }
});

$('seal-sign-btn').addEventListener('click', async () => {
  sealReset();
  const text = ($('seal-in') as HTMLTextAreaElement).value;
  if (!text.trim()) return sealFail('There is nothing to sign yet.');
  const signer = signAs();
  if (!signer) return sealFail('Choose a key under "Sign as" first.');
  try {
    if (source === 'system') return sealShow('Clearsigned text', await gpg.clearsign(text, signer));
    if (!await ensureUnlocked(signer)) return sealFail('Not signed — the key stayed locked.');
    sealShow('Clearsigned text', await pgp.signText(text, signer));
  } catch (e2) {
    sealFail(errMsg(e2));
  }
});

$('seal-verify').addEventListener('click', async () => {
  sealReset();
  const text = ($('seal-in') as HTMLTextAreaElement).value.trim();
  if (!pgp.looksClearsigned(text)) return sealFail('Paste a clearsigned message (-----BEGIN PGP SIGNED MESSAGE-----) to verify.');
  try {
    if (source === 'system') {
      const out = await gpg.decrypt(text);
      return sealShow('Verified text', out.text, out.signatures);
    }
    // Saavi store: candidates are own keys, a pasted key in To, and lookups for addresses in To.
    const toRaw = recipientsRaw();
    const cands: string[] = [];
    for (const email of ringAddresses()) { const k = pgp.keysFor(email); if (k) cands.push(k.publicKey); }
    if (toRaw) cands.push(...(await resolveSaaviRecipients(toRaw)).keys);
    const v = await pgp.verifyText(text, cands);
    // "Your key" is a FINGERPRINT comparison — never a match on the UID
    // string, which the key's author writes and can embed your address in.
    const own = !!v.signerFingerprint
      && (await ownFingerprints()).has(v.signerFingerprint.replace(/\s+/g, '').toUpperCase());
    const sig: gpg.SignatureInfo = {
      status: v.status, fingerprint: v.signerFingerprint?.replace(/\s+/g, '') ?? '', key_id: '', uid: v.signerUid ?? '',
      trust: v.status === 'good' && own ? 'ultimate' : '',
    };
    sealShow('Verified text', v.text, [sig]);
    if (v.status === 'unknown-key') $('seal-sig').append(el('span', 'hint', 'Put the signer\'s address (or their pasted key) in the To field to look their key up.'));
  } catch (e2) {
    sealFail(errMsg(e2));
  }
});

$('seal-dec').addEventListener('click', async () => {
  sealReset();
  const text = ($('seal-in') as HTMLTextAreaElement).value.trim();
  if (pgp.looksClearsigned(text)) return $('seal-verify').click();
  if (!pgp.looksEncrypted(text)) return sealFail('That is not an armored PGP message.');
  if (source === 'system') {
    try {
      const out = await gpg.decrypt(text);
      sealShow('Unsealed text', out.text, out.signatures);
    } catch (e2) { sealFail(errMsg(e2)); }
    return;
  }
  const attempt = async (): Promise<void> => {
    try {
      // Verify against own keys + anything the To field names; a signer we
      // still don't know is looked up by key ID (an untrusted candidate —
      // it can name the signer, never vouch for them).
      const cands = await unsealCandidates(recipientsRaw());
      let out = await pgp.decryptText(text, cands);
      const unknown = out.signatures.filter((s) => s.status === 'unknown-key');
      if (unknown.length) {
        const found = (await Promise.all(unknown.map((s) => vksLookupKeyId(s.keyId).catch(() => null))))
          .filter((k): k is string => Boolean(k));
        if (found.length) out = await pgp.decryptText(text, [...cands, ...found]);
      }
      sealShow('Unsealed text', out.text, verdictInfos(out.signatures, await ownFingerprints()));
    } catch (e) {
      if (!(e instanceof Error && e.message === 'locked')) return sealFail(`Could not unseal: ${errMsg(e)}`);
      for (const email of ringAddresses()) {
        const need = await pgp.neededKeyFor(email, text).catch(() => null);
        if (!need) continue;
        if (need.unlocked) return sealFail(`This message names the key for ${email}, but that key cannot open it. The message may be damaged.`);
        if (await tryKeychainUnlock(email, need.fingerprint)) return attempt();
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

// ---------- files (shell only) ----------
const SEALED_EXT = /\.(gpg|pgp|asc)$/i;
function fileStatus(msg: string, sigs?: gpg.SignatureInfo[]): void {
  const out = $('file-out');
  out.replaceChildren(el('span', undefined, msg));
  for (const s of sigs ?? []) {
    const cls = s.status === 'good' && (s.trust === 'ultimate' || s.trust === 'full') ? 'good' : s.status === 'bad' ? 'bad' : 'warn';
    out.append(el('span', `sig sig-${cls}`, gpg.describeSignature(s)));
  }
  out.hidden = false;
}

/** A filename from inside a sealed file is sender-controlled: basename only,
 *  no control characters, never a path. */
function safeName(name: string | null, fallback: string): string {
  const base = (name ?? '').split(/[\\/]/).pop()?.replace(/[\u0000-\u001f\u007f]/g, '').trim() ?? '';
  return base && base !== '.' && base !== '..' ? base : fallback;
}

async function askRecipients(forWhat: string): Promise<string | null> {
  const have = recipientsRaw();
  if (have) return have;
  const r = await ask({ title: 'Seal — to whom?', message: forWhat,
    fields: [{ name: 'to', label: source === 'system' ? 'Addresses or fingerprints' : 'Addresses', placeholder: 'ada@example.org, grace@proton.me' }], ok: 'Seal' });
  if (!r?.to.trim()) return null;
  ($('seal-to') as HTMLInputElement).value = r.to.trim();
  return r.to.trim();
}

/** input === null → the shell (system) / a dialog (Saavi) picks the file. */
async function sealFile(input: string | null): Promise<void> {
  const toRaw = await askRecipients(input ? baseName(input) : 'Choose the file next.');
  if (!toRaw) return;
  const signWith = signAs() || null;
  if (source === 'system') {
    // Paths are chosen by native dialogs on the Rust side; the webview never names the output.
    const recipients = await resolveSystemRecipients(toRaw);
    let r = await gpg.encryptFile(input, recipients, { signWith });
    if (!r.output && r.untrusted.length && !r.missing.length) {
      if (!await untrustedOk(r.untrusted)) return fileStatus('Not sealed.');
      r = await gpg.encryptFile(r.input, recipients, { signWith, trustAll: true });
    }
    if (!r.output) return fileStatus(r.missing.length ? `No usable key for: ${r.missing.join(', ')}.` : r.input ? 'Not sealed.' : '');
    return fileStatus(`Sealed${signWith ? ' and signed' : ''} → ${r.output}`);
  }
  const path = input ?? await pickFile('Choose a file to seal');
  if (!path) return;
  const { keys, missing, why } = await resolveSaaviRecipients(toRaw);
  if (missing.length) return fileStatus(`No key found. ${why.join('. ')}.`);
  if (signWith && !await ensureUnlocked(signWith)) return fileStatus('Not sealed — the signing key stayed locked.');
  const output = await pickSave(`${path}.gpg`);
  if (!output) return;
  const { readFile, writeFile } = await import('@tauri-apps/plugin-fs');
  const data = await readFile(path);
  const sealed = await pgp.encryptBytes(data, baseName(path), keys, signWith || undefined);
  await writeFile(output, sealed);
  fileStatus(`Sealed${signWith ? ' and signed' : ''} → ${output}`);
}

async function unsealFile(input: string | null): Promise<void> {
  if (source === 'system') {
    const r = await gpg.decryptFile(input);
    if (!r.output) return fileStatus(r.input ? 'Not unsealed.' : '');
    return fileStatus(`Unsealed → ${r.output}`, r.signatures);
  }
  const path = input ?? await pickFile('Choose a sealed file');
  if (!path) return;
  const suggested = SEALED_EXT.test(baseName(path)) ? baseName(path).replace(SEALED_EXT, '') : `${baseName(path)}.out`;
  const { readFile, writeFile } = await import('@tauri-apps/plugin-fs');
  const data = await readFile(path);
  const attempt = async (): Promise<void> => {
    try {
      const out = await pgp.decryptBytes(data);
      const output = await pickSave(dirName(path) + safeName(out.filename, suggested));
      if (!output) return;
      await writeFile(output, out.data);
      fileStatus(`Unsealed → ${output}`);
    } catch (e) {
      if (!(e instanceof Error && e.message === 'locked')) return fileStatus(`Could not unseal: ${errMsg(e)}`);
      for (const email of ringAddresses()) {
        const need = await pgp.neededKeyForBytes(email, data).catch(() => null);
        if (!need) continue;
        if (need.unlocked) return fileStatus(`The key for ${email} cannot open this file; it may be damaged.`);
        if (await tryKeychainUnlock(email, need.fingerprint)) return attempt();
        openModal('unlock', { email, fingerprint: need.fingerprint, then: () => void attempt() });
        return;
      }
      fileStatus('None of the keys on this device fit this file.');
    }
  };
  await attempt();
}

// One file flow at a time: dialogs and the unlock modal are singletons.
let fileQueue: Promise<void> = Promise.resolve();
function handleFile(path: string | null, mode?: 'seal' | 'unseal'): Promise<void> {
  const m = mode ?? (path && SEALED_EXT.test(path) ? 'unseal' : 'seal');
  fileQueue = fileQueue.then(async () => {
    try {
      await (m === 'seal' ? sealFile(path) : unsealFile(path));
    } catch (e) {
      fileStatus(`${m === 'seal' ? 'Seal' : 'Unseal'} failed: ${errMsg(e)}`);
    }
  });
  return fileQueue;
}
$('file-seal').addEventListener('click', () => void handleFile(null, 'seal'));
$('file-unseal').addEventListener('click', () => void handleFile(null, 'unseal'));

async function wireDragDrop(): Promise<void> {
  if (!gpg.inShell()) return;
  const { getCurrentWebview } = await import('@tauri-apps/api/webview');
  await getCurrentWebview().onDragDropEvent((e) => {
    const zone = $('dropzone');
    if (e.payload.type === 'enter' || e.payload.type === 'over') zone.classList.add('over');
    else zone.classList.remove('over');
    if (e.payload.type === 'drop') {
      selectTab('seal');
      for (const p of e.payload.paths) void handleFile(p);
    }
  });
}

// ---------- boot ----------
void refreshKeys();
void detectGpg();
void wireDragDrop();
