// Saavi — the app. Two faces, KGpg heritage: −k (the keyring table) and
// −d (the sealer). Two keyring sources: Saavi's own store (pgp.ts,
// OpenPGP.js, works anywhere) and the system GnuPG keyring (gpg.ts, the
// user's own gpg binary, shell only). All crypto lives in those two modules;
// recipient lookup in wkd.ts / vks.ts; dialogs in ui.ts.
import './style.css';
import * as pgp from './pgp';
import * as gpg from './gpg';
import * as keychain from './keychain';
import * as diskstore from './diskstore';
import { wkdProbe } from './wkd';
import * as pins from './pins';

// Pins are scoped to an owner so two accounts on one machine cannot inherit
// each other's trust decisions. The desktop app has no signed-in account —
// its keyring IS the device — so everything here shares one empty scope.
const PIN_OWNER = '';
import { vksLookup, vksLookupKeyId, vksUpload, vksRequestVerify } from './vks';
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

/** Every address with a ring in the Saavi store (whichever backend rules). */
const ringAddresses = pgp.ringAddresses;

// ---------- the sealed disk store (shell only) ----------
// In the shell the Saavi store lives on disk as a sealed bundle, not in
// webview storage; diskstore.ts installs the backend at boot. Whatever it
// reports — a migration, a blocked store, failing writes — is rendered as
// alert bars by refreshKeys, never swallowed.
let diskHandle: diskstore.DiskStore | null = null;
let diskStatus: diskstore.DiskStatus | null = null;
let diskCoexist: diskstore.CoexistAlert[] = [];
let diskAdopted: string[] = [];
let storeFlushError: string | null = null;
let storeInitBusy = false;

// No keychain.available() gate here: initDiskStore itself answers a
// refusing or absent keychain, and BLOCKED must be reachable — bailing
// early would show a migrated user the "fresh keyring" invitation while
// their real keys sit sealed on disk.
async function initStore(acceptMissingStore = false): Promise<void> {
  if (!keychain.inShell() || storeInitBusy) return;
  storeInitBusy = true;
  try {
    const ds = await diskstore.initDiskStore(diskstore.shellIo, (message) => {
      storeFlushError = message;
      void refreshKeys();
    }, undefined, undefined, { acceptMissingStore });
    diskHandle = ds;
    diskStatus = ds.status;
    diskCoexist = ds.coexist;
    diskAdopted = ds.adopted;
    if (ds.status.state === 'disk' && ds.status.migratedFrom === 'browser') {
      status('Your keys moved to disk storage, sealed by the OS keychain.'
        + (ds.status.backupPath ? ` A verified backup was kept at ${ds.status.backupPath}.` : ''));
    }
  } finally {
    storeInitBusy = false;
  }
}

function renderStoreBars(rows: HTMLElement): void {
  const bar = (head: string, body: string): HTMLElement => {
    const b = el('div', 'alert-bar');
    b.append(el('strong', undefined, head), el('span', undefined, body));
    rows.append(b);
    return b;
  };
  if (diskStatus?.state === 'blocked') {
    const b = bar('Your keys are on disk, but the store could not be opened. ',
      diskStatus.reason + ' Nothing was changed. A key generated now would live in browser storage until the store opens again.');
    if (diskStatus.missingStore) {
      const fresh = el('button', 'ghost', 'Start over with a fresh store');
      fresh.addEventListener('click', () => {
        void (async () => {
          if (!await confirmBox('Start a fresh key store?',
            'This writes a new, empty key store. If your old store file still exists in a backup somewhere, restore it INSTEAD — a fresh store cannot read your old sealed mail.',
            'Start fresh', true)) return;
          await initStore(true);
          void refreshKeys();
        })();
      });
      b.append(fresh);
    }
    const retry = el('button', 'ghost', 'Retry');
    retry.addEventListener('click', () => { void initStore().then(() => refreshKeys()); });
    b.append(retry);
  }
  if (diskStatus?.state === 'browser' && diskStatus.error) {
    bar('Disk key storage is not active. ',
      diskStatus.error + ' Your keys remain in browser storage, unchanged.');
  }
  if (storeFlushError !== null) {
    bar('Key store writes are failing. ',
      `${storeFlushError} — changes are held in memory and retried. Do not quit Saavi until this clears, and keep backup files of your keys.`);
  }
  if (diskAdopted.length) {
    const b = bar(`Browser-held keys were moved into your disk store: ${diskAdopted.join(', ')}. `,
      'They were found in browser storage at start-up (usually a key made while the disk store was unavailable) and are now part of the sealed store. If you did not expect them, check their fingerprints in Details.');
    const ok = el('button', 'ghost', 'Dismiss');
    ok.addEventListener('click', () => { diskAdopted = []; void refreshKeys(); });
    b.append(ok);
  }
  for (const c of diskCoexist) {
    if (c.kind === 'differs') {
      bar(`A browser-held keyring for ${c.address} sits alongside your disk store. `,
        `It was left untouched in browser storage under “${c.storageKey}”; the disk store’s ring is the one in use. Export/import a key backup to reconcile, then remove the browser copy.`);
    } else {
      bar(`A browser-held record for ${c.address} could not be read. `,
        `It was left untouched in browser storage under “${c.storageKey}”, not moved into the disk store. Re-import that key’s backup file if it is one of yours.`);
    }
  }
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
$('app-version').textContent = `v${__APP_VERSION__}`;
$('app-version').title = `This install is Saavi ${__APP_VERSION__}.`;
const updateOpt = $('update-opt') as HTMLInputElement;
const updatePill = $('update-pill') as HTMLButtonElement;
const updateBanner = $('update-banner');
const updateBannerText = $('update-banner-text');
let offeredVersion: string | null = null;
async function checkForUpdate(force: boolean): Promise<void> {
  if (!update.enabled()) return;
  const info = await update.check(__APP_VERSION__);
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
  void tryAutoUpdate(info);
}

/* The check used to run once, at launch, and nowhere else — so an app left
 * open for days never learned that a release existed. That is not a corner
 * case: it is what happens to anyone who keeps Saavi open, which is the point
 * of a desktop app. (Seen on Linux, 0.4.2, the day 0.4.3 shipped.)
 *
 * So it now also runs hourly, and when the window comes back to the front —
 * the contract the webmail has had for a while. Both share one in-flight
 * promise, because a tick and a focus arriving together must not become two
 * requests, and the front-of-window check is rate-limited so that alt-tabbing
 * does not poll the site. A manual check ignores the rate limit but still
 * joins a run already under way rather than starting a second. */
const UPDATE_EVERY = 60 * 60 * 1000;
const UPDATE_FOCUS_AFTER = 30 * 60 * 1000;
let updateInFlight: Promise<void> | null = null;
let lastUpdateCheck = 0;

function runUpdateCheck(force = false): Promise<void> {
  if (updateInFlight) return updateInFlight;
  updateInFlight = checkForUpdate(force).finally(() => {
    updateInFlight = null;
    lastUpdateCheck = Date.now();
  });
  return updateInFlight;
}

setInterval(() => void runUpdateCheck(), UPDATE_EVERY);
window.addEventListener('focus', () => {
  if (Date.now() - lastUpdateCheck >= UPDATE_FOCUS_AFTER) void runUpdateCheck();
});

// One-click update: the package is downloaded up front and verified before
// anything installs — the user still clicks. Two verified paths: the Tauri
// updater (minisign key baked into THIS binary; AppImage/Windows/macOS),
// and the .deb path (GPG chain against the pinned release key, then dpkg
// through polkit). A plain browser keeps the open-the-download-page button.
let installReady: (() => Promise<void>) | null = null;
async function tryAutoUpdate(info: update.UpdateInfo): Promise<void> {
  if (!('__TAURI_INTERNALS__' in window)) return;
  const btn = $('update-banner-get') as HTMLButtonElement;
  try {
    let upd: Awaited<ReturnType<typeof import('@tauri-apps/plugin-updater')['check']>> = null;
    try {
      const { check } = await import('@tauri-apps/plugin-updater');
      upd = await check();
    } catch { upd = null; /* endpoint missing or unsupported install — the .deb path may still fit */ }
    if (!upd) return await tryDebUpdate(info, btn);
    btn.disabled = true;
    btn.textContent = 'Downloading…';
    let total = 0, got = 0;
    await upd.download((e) => {
      if (e.event === 'Started') total = e.data.contentLength ?? 0;
      else if (e.event === 'Progress' && total) {
        got += e.data.chunkLength;
        btn.textContent = `Downloading… ${Math.min(99, Math.round((got / total) * 100))}%`;
      }
    });
    installReady = async () => {
      btn.disabled = true;
      btn.textContent = 'Installing…';
      await upd.install();
      const { relaunch } = await import('@tauri-apps/plugin-process');
      await relaunch();
    };
    btn.textContent = 'Install & restart';
    btn.disabled = false;
    updatePill.textContent = `Saavi ${upd.version} ready to install`;
    status(`Saavi ${upd.version} downloaded and verified — install when ready.`);
  } catch (e) {
    // A failed download or a signature that does not verify must never
    // brick the banner — fall back to the manual, browser flow.
    installReady = null;
    btn.disabled = false;
    btn.textContent = 'Download update';
    status(`In-app update unavailable (${errMsg(e)}) — the download page still works.`);
  }
}

// The .deb self-update: verify the GPG chain (SHA256SUMS.asc against the
// release key pinned in the app, then the file's sha256), stage the file
// under $TEMP, and let dpkg install it through polkit's own authentication
// dialog on the user's click. Errors bubble to tryAutoUpdate's fallback.
async function tryDebUpdate(info: update.UpdateInfo, btn: HTMLButtonElement): Promise<void> {
  const { invoke } = await import('@tauri-apps/api/core');
  if (!await invoke<boolean>('deb_capable').catch(() => false)) return;
  if (!info.deb || !info.sumsSigned) return;
  btn.disabled = true;
  btn.textContent = 'Downloading…';
  const bytes = await update.fetchVerifiedDeb(info);
  const { mkdir, writeFile, BaseDirectory } = await import('@tauri-apps/plugin-fs');
  await mkdir('saavi-update', { baseDir: BaseDirectory.Temp, recursive: true }).catch(() => { /* already there */ });
  await writeFile('saavi-update/saavi-update.deb', bytes, { baseDir: BaseDirectory.Temp });
  installReady = async () => {
    btn.disabled = true;
    btn.textContent = 'Installing…';
    await invoke('deb_install');
    const { relaunch } = await import('@tauri-apps/plugin-process');
    await relaunch();
  };
  btn.textContent = 'Install & restart';
  btn.disabled = false;
  updatePill.textContent = `Saavi ${info.version} ready to install`;
  status(`Saavi ${info.version} downloaded and verified — install when ready.`);
}
updateOpt.checked = update.enabled();
updateOpt.addEventListener('change', () => {
  update.setEnabled(updateOpt.checked);
  if (updateOpt.checked) void runUpdateCheck(true);
  else { updatePill.hidden = true; updateBanner.hidden = true; }
});
const openDownload = () => {
  if (installReady) { void installReady().catch((e) => status(`Install failed: ${errMsg(e)} — the download page still works.`)); return; }
  void update.openDownloadPage().catch((e) => status(`Could not open the browser: ${errMsg(e)}`));
};
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
/* A recipient is given either as an address to look up or as a whole pasted
 * public key. Those are different shapes of answer, and a one-line input was
 * the wrong container for the second. */
type ToMode = 'addr' | 'key';
let toMode: ToMode = 'addr';
let gpgInfo: gpg.GpgInfo | null = null;
let systemKeys: gpg.SystemKey[] = [];

function setSource(s: Source): void {
  source = s;
  localStorage.setItem('saavi-source', s);
  ($('ring-src') as HTMLSelectElement).value = s;
  document.body.classList.toggle('src-system', s === 'system');
  $('col-status').textContent = s === 'system' ? 'Trust' : 'Status';
  $('seal-to-label').textContent = toLabel();
  $('files').hidden = !gpg.inShell();
  sel = null;
  void refreshKeys();
}

function toLabel(): string {
  if (toMode === 'key') return 'To (their public key — paste the whole block)';
  return source === 'system'
    ? 'To (addresses or fingerprints in your GnuPG keyring — WKD for unknown addresses)'
    : 'To (addresses — found via WKD or keys.openpgp.org)';
}

function setToMode(m: ToMode): void {
  toMode = m;
  for (const b of $('seal-to-mode').querySelectorAll<HTMLButtonElement>('button')) {
    const on = b.dataset.to === m;
    b.classList.toggle('on', on);
    b.setAttribute('aria-pressed', String(on));
  }
  ($('seal-to').parentElement as HTMLElement).hidden = m !== 'addr';
  $('seal-to-key').hidden = m !== 'key';
  $('seal-to-label').textContent = toLabel();
  $('seal-to-label').setAttribute('for', m === 'key' ? 'seal-to-key' : 'seal-to');
  closeToMenu();
  (m === 'key' ? $('seal-to-key') : $('seal-to')).focus();
}

$('seal-to-mode').addEventListener('click', (e) => {
  const b = (e.target as HTMLElement).closest<HTMLButtonElement>('button[data-to]');
  if (b?.dataset.to) setToMode(b.dataset.to as ToMode);
});

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
  // A chevron that opens an empty list is worse than no chevron.
  $('seal-to-pick').hidden = !knownRecipients().length;
  if ($('seal-to-pick').hidden) closeToMenu();
}

function rowFor(cells: { dot: boolean; dotTitle: string; addr: string; id: string; date: string; chip: string; chipOn: boolean; title: string; dead?: boolean }): HTMLElement {
  const row = el('button', 'row' + (cells.dead ? ' dead' : ''));
  row.setAttribute('role', 'option');
  const dot = el('span', 'dot' + (cells.dot ? ' dot-open' : ''));
  dot.title = cells.dotTitle;
  row.append(dot, el('span', 'c-addr', cells.addr), el('span', 'c-id', cells.id), el('span', 'c-date', cells.date),
    el('span', 'chip c-end' + (cells.chipOn ? ' chip-on' : ''), cells.chip));
  row.title = cells.title;
  return row;
}

const fmtDate = (iso: string | null): string =>
  iso ? new Date(iso).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' }) : '—';

const SOURCE_NAME: Record<pins.PinSource, string> = {
  wkd: 'the domain (WKD)', vks: 'keys.openpgp.org', directory: 'the Kaditham directory', paste: 'a pasted key',
};

/** A remembered recipient key. Deliberately NOT selectable: the Backup /
 *  Details / Delete tools act on keys you hold, and a pin is someone else's
 *  public key. Forgetting one is the only thing you can do to it here. */
function pinRow(p: pins.Pin): HTMLElement {
  // Its own class, not .row: the key table's row selector (and markSelected)
  // must keep meaning "a key you hold".
  const row = el('div', 'prow' + (p.revokedAt ? ' prow-dead' : ''));
  const dot = el('span', 'dot');
  dot.title = p.revokedAt ? 'Revoked by its owner' : `Remembered from ${SOURCE_NAME[p.source]}`;
  const end = el('span', 'c-end pin-end');
  end.append(el('span', 'chip', p.revokedAt ? 'revoked' : p.source));
  const forget = el('button', 'ghost pin-forget', 'Forget');
  forget.title = `Forget the key remembered for ${p.address}. The next seal to that address is treated as a first contact again.`;
  forget.addEventListener('click', () => { pins.forget(PIN_OWNER, p.address); void refreshKeys(); });
  end.append(forget);
  row.append(dot, el('span', 'c-addr', p.address), el('span', 'c-id', '…' + p.fingerprint.slice(-8).toUpperCase()),
    el('span', 'c-date', fmtDate(p.firstSeen)), end);
  row.title = `${pgp.fmtFpr(p.fingerprint)}\nfrom ${SOURCE_NAME[p.source]}\nfirst seen ${fmtDate(p.firstSeen)} · last confirmed ${fmtDate(p.lastSeen)}`;
  return row;
}

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
  renderStoreBars(rows);
  // A store record that failed to parse was quarantined, not destroyed —
  // and that must be LOUD, not a silently shorter key list.
  for (const alert of pgp.storeAlerts()) {
    const bar = el('div', 'alert-bar');
    bar.append(el('strong', undefined, `A stored key record for ${alert.email} could not be read. `));
    bar.append(el('span', undefined,
      'It was preserved, not deleted. Re-import that key’s backup file; the damaged record is kept in the key store under “'
      + alert.quarantineKey + '”.'));
    const ok = el('button', 'ghost', 'Dismiss');
    ok.addEventListener('click', () => { pgp.dismissStoreAlert(alert.quarantineKey); void refreshKeys(); });
    bar.append(ok);
    rows.append(bar);
  }
  // While the disk store is blocked, an empty list means "unopened", not
  // "fresh" — inviting a generate here would mint a second identity.
  if (!flat.length && diskStatus?.state !== 'blocked') {
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
      void openDetails();
    });
    rows.append(row);
  }
  // Keys REMEMBERED for other people — the record that makes a changed key
  // detectable. Not keys you hold, so they sit below your own.
  const pinned = pins.all(PIN_OWNER);
  if (pinned.length) {
    const head = el('div', 'pin-head');
    head.append(el('span', 'pin-head-t', `Known addresses · ${pinned.length}`));
    head.append(el('span', 'hint', 'Keys remembered for people you seal to. Saavi stops and asks if one of them ever changes.'));
    rows.append(head);
    for (const p of pinned) rows.append(pinRow(p));
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
    // The store bars must survive every render path — a blocked store or a
    // failing flush stays visible on the System tab too.
    rows.replaceChildren();
    renderStoreBars(rows);
    rows.append(el('p', 'empty', `Could not read the GnuPG keyring: ${errMsg(e)}`));
    status('System GnuPG keyring · unavailable');
    return;
  }
  if (source !== 'system') return;
  systemKeys.sort((a, b) => Number(b.has_secret) - Number(a.has_secret) || keyLabel(a).localeCompare(keyLabel(b)));
  rows.replaceChildren();
  renderStoreBars(rows);
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
      void openDetails();
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
      if (s.isActive) {
        action('Publish key…', async () => {
          const go = await ask({
            title: 'Publish for discovery',
            message: `Uploads the PUBLIC key for ${s.email} to keys.openpgp.org — and, if ${s.email.split('@')[1] ?? 'its domain'} is served by Kaditham key discovery, publishes it there for WKD too. Each service mails ${s.email} its own confirmation link; the key becomes findable once clicked (and by fingerprint right away on the keyserver).`,
            ok: 'Publish',
          });
          if (!go) return;
          const kad = await kadithamWkdPublish(s.email, pub);
          const up = await vksUpload(pub);
          const st = Object.entries(up.status).find(([a]) => a.toLowerCase() === s.email.toLowerCase())?.[1];
          const kadLine = kad.state === 'sent'
            ? `\n\nKaditham WKD: a confirmation mail is on its way to ${s.email} as well — its link makes the key discoverable at your own domain.`
            : kad.state === 'failed'
              ? `\n\nKaditham WKD: NOT published — ${kad.why}. The keyserver upload above is unaffected; try Publish again to retry just this part.`
              : '';
          if (st === 'published') return notice('Published', `${s.email} is verified on keys.openpgp.org — the key is findable by email.${kadLine}`);
          await vksRequestVerify(up.token, [s.email]);
          await notice('One step left', `Uploaded. A verification message from keys.openpgp.org is on its way to ${s.email} — click its link to make the key findable by email. It is findable by fingerprint already.\n\nCheck the spam folder if it does not arrive: these are automated mails from a keyserver, and filters treat them accordingly.${kadLine}`);
        });
      }
      action('Revocation certificate…', async () => {
        const go = await ask({
          title: 'Revocation certificate',
          message: 'A signed "this key is no longer valid" note. Keep the file somewhere safe, SEPARATE from the key backup — anyone holding it can retire your key. If the key is ever lost or compromised, importing and publishing this certificate revokes it everywhere.',
          ok: 'Save…',
        });
        if (!go) return;
        const saveCert = async (): Promise<void> => {
          const cert = await pgp.revocationCertificate(s.email, s.fpr);
          const p = await saveTextFile(`${s.email}-revocation-certificate.asc`, cert);
          if (p !== null) status(p ? `Revocation certificate saved to ${p}` : 'Revocation certificate downloaded.');
        };
        try { await saveCert(); } catch (e) {
          // Keys from before certificates were captured at generation (and
          // imported ones) derive the certificate from the unlocked key.
          if (errMsg(e) !== 'locked') throw e;
          if (await tryKeychainUnlock(s.email, s.fpr)) return saveCert();
          openModal('unlock', { email: s.email, fingerprint: s.fpr, then: () => { void saveCert().catch((e2) => notice('Not done', errMsg(e2))); } });
        }
      });
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
      action('Publish key…', async () => {
        const emails = [...new Set(k.uids.map((u) => u.email).filter(Boolean))];
        const go = await ask({
          title: 'Publish to keys.openpgp.org',
          message: emails.length
            ? `Uploads this PUBLIC key. The keyserver mails each of its addresses (${emails.join(', ')}) a verification link — the key becomes findable by email once confirmed, and by fingerprint right away.`
            : 'Uploads this PUBLIC key. It carries no email address, so it will be findable by fingerprint only.',
          ok: 'Publish',
        });
        if (!go) return;
        const up = await vksUpload(await gpg.exportPublic(k.fingerprint));
        const pending = emails.filter((e) => Object.entries(up.status).find(([a]) => a.toLowerCase() === e.toLowerCase())?.[1] !== 'published');
        if (!emails.length) return notice('Published', 'Uploaded — findable by fingerprint.');
        if (!pending.length) return notice('Published', 'Every address on this key is verified — it is findable by email.');
        await vksRequestVerify(up.token, pending);
        await notice('One step left', `Uploaded. Verification messages are on their way to ${pending.join(', ')} — the key is findable by fingerprint already, by email once confirmed.\n\nCheck the spam folder if one does not arrive: these are automated mails from a keyserver, and filters treat them accordingly.`);
      });
      action('Revocation certificate…', async () => {
        const go = await ask({
          title: 'Revocation certificate',
          message: 'A signed "this key is no longer valid" note; gpg will ask for the key\'s passphrase. Keep the file somewhere safe, SEPARATE from any key backup — anyone holding it can retire the key. If the key is ever lost or compromised, importing and publishing it revokes the key everywhere.',
          ok: 'Create…',
        });
        if (!go) return;
        const cert = await gpg.genRevoke(k.fingerprint);
        const p = await saveTextFile(`${(k.uids[0]?.email || k.key_id).replace(/[^a-z0-9.@-]/gi, '_')}-revocation-certificate.asc`, cert);
        if (p !== null) status(p ? `Revocation certificate saved to ${p}` : 'Revocation certificate downloaded.');
      });
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

// The fingerprint is shown so it can be read to someone or filed with the
// backup — both of which start with getting it out of the window.
$('done-fpr-copy').addEventListener('click', async () => {
  const b = $('done-fpr-copy');
  try {
    await navigator.clipboard.writeText($('done-fpr').textContent ?? '');
    b.textContent = 'Copied';
  } catch {
    const r = document.createRange();
    r.selectNodeContents($('done-fpr'));
    const sel = window.getSelection();
    sel?.removeAllRanges();
    sel?.addRange(r);
    b.textContent = 'Selected';
  }
  setTimeout(() => { b.textContent = 'Copy'; }, 1600);
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
    if (!$('seal-to-menu').hidden) { closeToMenu(); $('seal-to-pick').focus(); return; }
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
  copyDone(false);
  // On a wide window the result is already beside the input. On a narrow one
  // the panes stack, and a letter you just unsealed would otherwise appear
  // below the fold — the reader has to know it worked without hunting.
  $('seal-out-label').scrollIntoView({ block: 'nearest', behavior: 'smooth' });
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
const recipientsRaw = (): string =>
  (toMode === 'key'
    ? ($('seal-to-key') as HTMLTextAreaElement).value
    : ($('seal-to') as HTMLInputElement).value).trim();
const signAs = (): string => ($('seal-sign') as HTMLSelectElement).value;

/* ---------- who you can already seal to ----------
 * The addresses this device holds a key for are sitting in the store; making
 * someone retype one from memory is the app forgetting on their behalf. In
 * the GnuPG ring that is every key that can encrypt; in the Saavi store it is
 * the addresses pinned from earlier seals, plus your own. Typing an unknown
 * address still works — this only removes the need to when it is known. */
interface Known { value: string; label: string; id: string; group: string }

function knownRecipients(): Known[] {
  if (source === 'system') {
    return systemKeys
      .filter((k) => k.can_encrypt && !dead(k) && (k.uids[0]?.email || k.fingerprint))
      // Other people first: sealing to yourself is the rarer errand.
      .sort((a, b) => Number(a.has_secret) - Number(b.has_secret) || keyLabel(a).localeCompare(keyLabel(b)))
      .map((k) => ({
        value: k.uids[0]?.email || k.fingerprint,
        label: keyLabel(k),
        id: '…' + k.fingerprint.slice(-8),
        group: k.has_secret ? 'Your own keys' : 'In your GnuPG keyring',
      }));
  }
  const theirs: Known[] = pins.all(PIN_OWNER).filter((p) => !p.revokedAt).map((p) => ({
    value: p.address,
    label: p.address,
    id: '…' + p.fingerprint.replace(/\s+/g, '').slice(-8).toUpperCase(),
    group: 'Keys you have remembered',
  }));
  const mine: Known[] = ringAddresses().sort().map((a) => ({
    value: a, label: a, id: '', group: 'Your own addresses',
  }));
  const seen = new Set<string>();
  return [...theirs, ...mine].filter((k) => {
    const v = k.value.toLowerCase();
    if (seen.has(v)) return false;
    seen.add(v);
    return true;
  });
}

/** The To field is a comma list; what is already in it should not be offered
 *  again as if it were missing. */
const recipientsListed = (): string[] =>
  recipientsRaw().split(/[,\n;]+/).map((r) => r.trim().toLowerCase()).filter(Boolean);

function addRecipient(value: string): void {
  if (toMode !== 'addr') setToMode('addr');
  const inp = $('seal-to') as HTMLInputElement;
  if (!recipientsListed().includes(value.trim().toLowerCase())) {
    const raw = inp.value.replace(/[,\s]+$/, '');
    inp.value = raw ? `${raw}, ${value}` : value;
  }
  inp.focus();
}

function closeToMenu(): void {
  $('seal-to-menu').hidden = true;
  $('seal-to-pick').setAttribute('aria-expanded', 'false');
}

function openToMenu(): void {
  const menu = $('seal-to-menu');
  const known = knownRecipients();
  const have = new Set(recipientsListed());
  menu.replaceChildren();
  if (!known.length) {
    menu.append(el('p', 'pick-empty', 'No keys held yet. Seal to an address once and its key is remembered here.'));
  }
  let group = '';
  for (const k of known) {
    if (k.group !== group) { group = k.group; menu.append(el('div', 'pick-head', group)); }
    const picked = have.has(k.value.toLowerCase());
    const item = el('button', 'pick-item' + (picked ? ' picked' : ''));
    item.setAttribute('type', 'button');
    item.setAttribute('role', 'option');
    item.setAttribute('aria-selected', String(picked));
    item.append(el('span', undefined, k.label));
    if (k.id) item.append(el('span', 'pick-id', k.id));
    item.addEventListener('click', () => { addRecipient(k.value); closeToMenu(); });
    menu.append(item);
  }
  menu.hidden = false;
  $('seal-to-pick').setAttribute('aria-expanded', 'true');
}

$('seal-to-pick').addEventListener('click', (e) => {
  e.stopPropagation();
  if ($('seal-to-menu').hidden) openToMenu(); else closeToMenu();
});

// Arrow keys walk the list; the field keeps the caret, so opening the menu
// never costs the typist their place.
$('seal-to-menu').addEventListener('keydown', (e) => {
  if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
  e.preventDefault();
  const items = [...$('seal-to-menu').querySelectorAll<HTMLElement>('.pick-item')];
  if (!items.length) return;
  const at = items.indexOf(document.activeElement as HTMLElement);
  const next = e.key === 'ArrowDown' ? (at + 1) % items.length : (at <= 0 ? items.length : at) - 1;
  items[next]?.focus();
});
$('seal-to-pick').addEventListener('keydown', (e) => {
  if (e.key !== 'ArrowDown') return;
  e.preventDefault();
  if ($('seal-to-menu').hidden) openToMenu();
  $('seal-to-menu').querySelector<HTMLElement>('.pick-item')?.focus();
});

document.addEventListener('click', (e) => {
  const menu = $('seal-to-menu');
  if (!menu.hidden && !menu.contains(e.target as Node)) closeToMenu();
});

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
/** Kaditham-hosted WKD publish (deliberately app-layer, not shared core:
 *  the publish endpoint is a Kaditham service feature). Ownership proof is
 *  a mail to the address itself; only domains Kaditham serves accept.
 *  Browser builds hit CORS here — the shell's Rust-side http client is the
 *  supported path, matching wkd.ts. */
const KADITHAM_WKD_PUBLISH = 'https://mail.kaditham.ie/signup/api/wkd/publish';
type WkdPublish =
  | { state: 'sent' }
  | { state: 'unsupported' }              // domain not served — not an error
  | { state: 'failed'; why: string };
async function kadithamWkdPublish(address: string, publicKey: string): Promise<WkdPublish> {
  try {
    const init: RequestInit = {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ address, publicKey }),
      signal: AbortSignal.timeout(15_000),
    };
    const r = '__TAURI_INTERNALS__' in window
      ? await (await import('@tauri-apps/plugin-http')).fetch(KADITHAM_WKD_PUBLISH, init)
      : await fetch(KADITHAM_WKD_PUBLISH, init);
    if (r.ok) return { state: 'sent' };
    if (r.status === 403) return { state: 'unsupported' };
    // The endpoint explains itself — rate limits, a key that carries no user
    // ID for this address, mail being down. Discarding that and saying
    // nothing at all was the old behaviour, and it left people believing
    // their key was published at their own domain when it was not.
    const said = await r.json().catch(() => null) as { error?: string } | null;
    return { state: 'failed', why: said?.error ?? `the server answered ${r.status}` };
  } catch (e) {
    return { state: 'failed', why: errMsg(e) };
  }
}

/**
 * Public keys a signature may be checked against: own keys, every pinned
 * recipient, and whatever the To field names.
 *
 * Verifying is NOT a trust decision — a verdict reports a fingerprint, it
 * does not authorise sending anything to it — so lookups here never write a
 * pin and never interrupt with a key-change question. Sealing is the only
 * path that pins.
 */
async function verifyCandidates(toRaw: string): Promise<string[]> {
  const cands: string[] = [];
  for (const email of ringAddresses()) {
    const k = pgp.keysFor(email);
    if (k) cands.push(k.publicKey);
  }
  for (const p of pins.all(PIN_OWNER)) cands.push(p.publicKey);
  if (!toRaw) return cands;
  // Keys and addresses both count, and a pasted key no longer stops the rest
  // of the field from being looked up.
  const { keys: pasted, rest } = pgp.splitKeyArmor(toRaw);
  cands.push(...pasted);
  for (const addr of splitAddresses(rest)) {
    if (pins.pinFor(PIN_OWNER, addr)) continue;
    const got = await discover(addr);
    if (got.key) cands.push(got.key);
  }
  return cands;
}

/** Split a To field: commas, semicolons, whitespace and newlines all separate addresses. */
function splitAddresses(raw: string): string[] {
  return raw.split(/[\s,;]+/).map((s) => s.trim().toLowerCase().replace(/^<|>$/g, '')).filter(Boolean);
}

/** The discovery chain: the domain's own WKD first, then the verifying
 *  keyserver. The webmail injects its directory ahead of both. */
async function discover(address: string): Promise<pins.Lookup> {
  const w = await wkdProbe(address);
  if (w.key) return { key: w.key, source: 'wkd', status: 'found' };
  const v = await vksLookup(address);
  if (v) return { key: v, source: 'vks', status: 'found' };
  return { key: null, source: 'wkd', status: w.status, detail: w.detail };
}

function missingWhy(r: Extract<pins.Resolution, { state: 'missing' }>): string {
  const domain = r.address.split('@')[1] ?? '';
  return r.status === 'unreachable'
    ? `${r.address}: ${domain} could not be reached for WKD${r.detail ? ` (${r.detail})` : ''} — check the connection`
    : `${r.address}: ${domain} publishes no key for this address (WKD), and none is on keys.openpgp.org`;
}

/** One question for every recipient whose key changed, not one each. */
async function acceptKeyChanges(cs: Extract<pins.Resolution, { state: 'changed' }>[]): Promise<boolean> {
  const one = cs.length === 1;
  const detail = cs.map((c) =>
    `${c.address}\n  was  ${pgp.fmtFpr(c.pin.fingerprint)}\n       ${SOURCE_NAME[c.pin.source]}, first seen ${fmtDate(c.pin.firstSeen)}\n  now  ${pgp.fmtFpr(c.fingerprint)}\n       ${SOURCE_NAME[c.source]}`,
  ).join('\n\n');
  return confirmBox(
    one ? `The key for ${cs[0].address} has changed` : `${cs.length} recipient keys have changed`,
    'This is normal after a key rotation. It is also exactly what an attacker substituting their own key looks like.\n\n'
    + `Confirm the new fingerprint${one ? '' : 's'} with ${one ? 'them' : 'each of them'} over some channel that is not this one before accepting.`,
    one ? 'Accept the new key' : 'Accept the new keys', true, detail);
}

interface Recipients { keys: string[]; missing: string[]; why: string[]; notes: string[] }

/** Turn resolutions into keys to seal to, reasons not to, and things the
 *  user should be told about keys that WERE accepted. */
async function settle(rs: pins.Resolution[]): Promise<Recipients> {
  const out: Recipients = { keys: [], missing: [], why: [], notes: [] };
  const changed = rs.filter((r): r is Extract<pins.Resolution, { state: 'changed' }> => r.state === 'changed');
  const accepted = changed.length ? await acceptKeyChanges(changed) : false;
  for (const r of rs) {
    switch (r.state) {
      case 'ok':
        out.keys.push(r.key);
        // Trust on first use is only trustworthy if the first use is VISIBLE:
        // this is the one moment the fingerprint can still be checked.
        if (r.firstContact && r.pin) {
          out.notes.push(`First time sealing to ${r.address} — its key is ${pgp.fmtFpr(r.pin.fingerprint)}, now remembered. Confirm that with them out of band.`);
        } else if (r.offline && r.pin) {
          out.notes.push(`${r.address} could not be looked up; sealed to the key remembered since ${fmtDate(r.pin.firstSeen)}.`);
        }
        break;
      case 'changed':
        if (accepted) { pins.accept(PIN_OWNER, r); out.keys.push(r.key); }
        else { out.missing.push(r.address); out.why.push(`${r.address}: the published key changed and was not accepted`); }
        break;
      case 'withdrawn':
        // Known before, offered by nobody now. Saying "no key found" would
        // invite pasting one; the point is that a key was taken away.
        out.missing.push(r.address);
        out.why.push(`${r.address}: the key remembered since ${fmtDate(r.pin.firstSeen)} is no longer published anywhere, and a remembered key is not a safe substitute for one that was withdrawn — ask them directly`);
        break;
      case 'revoked':
        out.missing.push(r.address);
        out.why.push(`${r.address}: that key has been REVOKED by its owner (${pgp.fmtFpr(r.fingerprint)}) — ask them for the replacement`);
        break;
      case 'unusable':
        out.missing.push(r.address);
        out.why.push(`${r.address}: the published key cannot encrypt — ${r.reason}`);
        break;
      case 'missing':
        out.missing.push(r.address);
        out.why.push(missingWhy(r));
        break;
    }
  }
  return out;
}

/** Saavi store: resolve the To field to armored public keys, applying the
 *  pinning policy in pins.ts to everything discovered over the network. */
async function resolveSaaviRecipients(toRaw: string): Promise<Recipients> {
  // Keys and addresses can share the field, and there can be several of
  // each. Every one is resolved; none is quietly dropped.
  const { keys: pasted, rest } = pgp.splitKeyArmor(toRaw);
  const direct: string[] = [];   // used exactly as given, nothing to pin against
  const looked: pins.Resolution[] = [];
  let anonymous = 0;
  for (const armored of pasted) {
    // A pasted key is pinned under its PRIMARY address only. Pinning every
    // address in its user IDs would let a key that also claims a colleague's
    // address quietly become the remembered key for that colleague.
    const addr = await pgp.primaryAddressOf(armored).catch(() => null);
    if (!addr) { direct.push(armored); anonymous++; continue; }
    looked.push(await pins.resolve(PIN_OWNER, addr, async () => ({ key: armored, source: 'paste', status: 'found' })));
  }
  for (const addr of splitAddresses(rest)) {
    // Your own ring IS the pin for your own addresses.
    const mine = pgp.keysFor(addr)?.publicKey;
    if (mine) { direct.push(mine); continue; }
    looked.push(await pins.resolve(PIN_OWNER, addr, discover));
  }
  const out = await settle(looked);
  out.keys.unshift(...direct);
  if (anonymous) {
    out.notes.push(anonymous === 1
      ? 'Sealed to a pasted key that names no address — nothing was remembered.'
      : `Sealed to ${anonymous} pasted keys that name no address — nothing was remembered.`);
  }
  return out;
}

/**
 * Your own copy of what you send. Sealing only to the recipient leaves the
 * sender holding ciphertext they cannot open, and for a copy-paste sealer
 * that loss is permanent — there is no Sent folder to fall back on. So every
 * seal also goes to one of your own keys.
 *
 * Which one: the signing identity when there is one, your only address when
 * you hold one, and otherwise the first — never all of them. Sealing to
 * every identity you own would tell the recipient, and anyone who sees the
 * ciphertext, that those addresses belong to the same person.
 */
function selfCopy(signer: string | null): { key: string; email: string } | null {
  const email = signer || ringAddresses()[0];
  if (!email) return null;
  const key = pgp.keysFor(email)?.publicKey;
  return key ? { key, email } : null;
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
  const { keys: pasted, rest } = pgp.splitKeyArmor(toRaw);
  const out = splitAddresses(rest);
  if (pasted.length) {
    // gpg imports a concatenated blob in one go, so several pasted keys cost
    // one call — and addresses beside them are still recipients.
    const r = await gpg.importKey(pasted.join('\n'));
    status(`Pasted key${pasted.length === 1 ? '' : 's'} imported into GnuPG: ${r.fingerprints.map(gpg.fmtFpr).join(', ')}`);
    out.push(...r.fingerprints);
  }
  return out;
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
  // Key discovery goes to the network (WKD, then a keyserver) and can take
  // seconds — the button must say so, and a second click must not race the
  // first.
  const btn = $('seal-enc') as HTMLButtonElement;
  const label = btn.textContent;
  btn.disabled = true;
  btn.textContent = 'Looking up keys…';
  try {
    if (source === 'system') return await sealWithSystem(text, toRaw);
    const { keys, missing, why, notes } = await resolveSaaviRecipients(toRaw);
    btn.textContent = label;
    // Nothing is sealed while ANY recipient is unresolved: a partial send
    // reaches some people and silently drops the rest.
    if (missing.length) return sealFail(`Not sealed. ${why.join('. ')}.`);
    const signer = signAs();
    if (signer && !await ensureUnlocked(signer)) return sealFail('Not sealed — the signing key stayed locked.');
    const self = selfCopy(signer);
    // Already a recipient when you sealed to your own address; encrypting to
    // the same key twice is visible in the packet and buys nothing.
    if (self && !keys.includes(self.key)) keys.push(self.key);
    // Which key took the copy is only obvious when there was no choice.
    if (self && !signer && ringAddresses().length > 1) {
      notes.push(`A copy was sealed to your ${self.email} key, so this stays readable to you.`);
    }
    sealShow(signer ? 'Sealed and signed message (also readable by you)' : 'Sealed message (also readable by you)', await pgp.encryptText(text, keys, signer || undefined, { sign: !!signer }));
    // sealShow hides the verdict strip when there are no signatures to
    // report; a first-contact fingerprint has to bring it back.
    if (notes.length) {
      const strip = $('seal-sig');
      strip.hidden = false;
      strip.append(...notes.map((n) => el('span', 'sig sig-warn', n)));
    }
  } catch (e2) {
    sealFail(errMsg(e2));
  } finally {
    btn.disabled = false;
    btn.textContent = label;
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
    const cands = await verifyCandidates(toRaw);
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
      const cands = await verifyCandidates(recipientsRaw());
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

/* A clipboard write is silent, and the glyph sits on the block rather than in
 * a header — so it has to answer in place, and go back to offering. */
let copyTimer: ReturnType<typeof setTimeout> | undefined;
function copyDone(done: boolean, word = 'Copied'): void {
  const b = $('seal-copy');
  clearTimeout(copyTimer);
  const txt = b.querySelector('.box-copy-txt');
  if (txt) txt.textContent = word;
  b.classList.toggle('done', done);
  b.setAttribute('aria-label', done ? word : 'Copy');
  b.title = done ? word : 'Copy';
  if (done) copyTimer = setTimeout(() => copyDone(false), 1600);
}

$('seal-copy').addEventListener('click', async () => {
  const out = $('seal-out') as HTMLTextAreaElement;
  try {
    await navigator.clipboard.writeText(out.value);
    copyDone(true);
  } catch {
    // Refused clipboards are a fact of webviews: leave it selected instead.
    out.focus();
    out.select();
    copyDone(true, 'Selected');
  }
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
  setToMode('addr');
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
  // A sealed file you cannot open is worse than a sealed message: the
  // plaintext is usually deleted once the .gpg exists.
  const self = selfCopy(signWith);
  if (self && !keys.includes(self.key)) keys.push(self.key);
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
// The store backend must be settled before the first read: in the shell,
// keys live in the sealed disk store, and reading localStorage first would
// briefly show a keyring that is about to be swapped out underneath.
void (async () => {
  try { await initStore(); } catch (e) {
    diskStatus = { state: 'browser', error: `Disk key storage failed to start: ${errMsg(e)}` };
  }
  void refreshKeys();
  void detectGpg();
  void wireDragDrop();
  // Persistence is write-behind now, so closing must wait for the mirror:
  // kill the window mid-flush and a just-generated key would exist nowhere.
  if (keychain.inShell()) {
    try {
      const { getCurrentWindow } = await import('@tauri-apps/api/window');
      const win = getCurrentWindow();
      let closing = false;
      await win.onCloseRequested((e) => {
        if (closing || !diskHandle) return;
        e.preventDefault();
        void (async () => {
          try {
            await diskHandle!.flushNow();
          } catch {
            if (!await confirmBox('Quit without saving keys?',
              'Your last key change could not be written to the key store — it exists only in this window’s memory. Quitting now loses it.',
              'Quit anyway', true)) return;
          }
          closing = true;
          await win.destroy();
        })();
      });
    } catch { /* no window API (plain browser) — nothing to guard */ }
  }
})();
