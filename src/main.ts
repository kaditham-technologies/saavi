// Saavi — the app. Two faces, KGpg heritage: −k (the keyring table) and
// −d (the sealer). All crypto lives in pgp.ts; WKD lookup in wkd.ts.
import './style.css';
import * as pgp from './pgp';
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

/** Every address with a ring in the keystore. */
function ringAddresses(): string[] {
  const out: string[] = [];
  for (let i = 0; i < localStorage.length; i++) {
    const k = localStorage.key(i)!;
    if (k.startsWith('saavi-ring-')) out.push(k.slice('saavi-ring-'.length));
  }
  return out.sort();
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

// ---------- the keyring table (−k) ----------
let sel: { email: string; fpr: string; isActive: boolean } | null = null;

function syncTools(): void {
  ($('act-backup') as HTMLButtonElement).disabled = !sel;
  ($('act-delete') as HTMLButtonElement).disabled = !sel || sel.isActive;
}

async function refreshKeys(): Promise<void> {
  const rows = $('rows');
  rows.replaceChildren(el('p', 'loading', 'Reading the keyring…'));
  const flat: { email: string; info: pgp.KeyInfo }[] = [];
  for (const email of ringAddresses()) {
    for (const info of await pgp.listKeys(email).catch(() => [] as pgp.KeyInfo[])) {
      flat.push({ email, info });
    }
  }
  rows.replaceChildren();
  if (!flat.length) {
    const empty = el('div', 'empty');
    empty.append(el('p', undefined, 'No keys yet. This is a fresh keyring.'));
    const go = el('button', 'primary', 'Generate your first key');
    go.addEventListener('click', () => openModal('generate'));
    empty.append(go);
    rows.append(empty);
  }
  for (const { email, info } of flat) {
    const row = el('button', 'row');
    row.setAttribute('role', 'option');
    const dot = el('span', 'dot' + (info.unlocked ? ' dot-open' : ''));
    dot.title = info.unlocked ? 'Unlocked this session' : 'Locked';
    row.append(dot);
    row.append(el('span', 'c-addr', email));
    row.append(el('span', 'c-id', '…' + info.fingerprint.replace(/\s+/g, '').slice(-8).toUpperCase()));
    row.append(el('span', 'c-date',
      new Date(info.created).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' })));
    row.append(el('span', 'chip c-end' + (info.isActive ? ' chip-on' : ''), info.isActive ? 'active' : 'retired'));
    row.title = info.fingerprint;
    if (sel?.fpr === info.fingerprint) row.classList.add('sel');
    row.addEventListener('click', () => {
      sel = { email, fpr: info.fingerprint, isActive: info.isActive };
      for (const r of rows.querySelectorAll('.row')) r.classList.toggle('sel', r === row);
      syncTools();
    });
    rows.append(row);
  }
  const unlocked = flat.filter((f) => f.info.unlocked).length;
  $('status').textContent =
    `${flat.length} key${flat.length === 1 ? '' : 's'} · ${ringAddresses().length} address${ringAddresses().length === 1 ? '' : 'es'} · ${unlocked} unlocked this session`;
  syncTools();
}

$('act-refresh').addEventListener('click', () => void refreshKeys());
$('act-new').addEventListener('click', () => openModal('generate'));
$('act-import').addEventListener('click', () => openModal('import'));
$('act-backup').addEventListener('click', async () => {
  if (!sel) return;
  const path = await pgp.saveBackup(sel.email, sel.fpr).catch(() => null);
  if (path !== null) $('status').textContent = path ? `Backup saved to ${path}` : 'Backup downloaded.';
});
$('act-delete').addEventListener('click', async () => {
  if (!sel || sel.isActive) return;
  if (!confirm(`Delete this retired key for ${sel.email} from this device?\n\nAnything sealed to it becomes unreadable here unless its backup is re-imported.`)) return;
  await pgp.deleteRetired(sel.email, sel.fpr);
  sel = null;
  void refreshKeys();
});

// ---------- the modal (generate / import / unlock) ----------
type ModalMode = 'generate' | 'import' | 'unlock';
let modalMode: ModalMode = 'generate';
let unlockFor: { email: string; fingerprint?: string; then: () => void } | null = null;
// When set, the modal is on the "key ready" step for this address.
let doneFor: string | null = null;

function setSrc(src: 'generate' | 'import'): void {
  modalMode = src;
  for (const b of $('modal-src').querySelectorAll('button')) {
    b.classList.toggle('on', b.dataset.src === src);
  }
  $('f-gen').hidden = src !== 'generate';
  $('f-imp').hidden = src !== 'import';
  $('f-pass2').hidden = src !== 'generate';
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
  ($('m-cancel') as HTMLButtonElement).hidden = false;
  $('m-go').textContent = 'Continue';
  $('modal-src').hidden = mode === 'unlock';
  $('f-gen').hidden = mode !== 'generate';
  $('f-imp').hidden = mode !== 'import';
  $('f-pass2').hidden = mode !== 'generate';
  $('modal-title').textContent =
    mode === 'unlock' ? 'Unlock key' : mode === 'import' ? 'Import a key' : 'New key';
  $('modal-sub').textContent = mode === 'unlock'
    ? `Enter the passphrase for ${unlock?.email ?? 'this key'}.`
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
    const path = await pgp.saveBackup(doneFor);
    $('done-saved').textContent =
      path === null ? 'Not saved yet — choose a location for the backup.'
      : path === '' ? 'Backup downloaded.'
      : `Backup saved to ${path}`;
  } catch (e2) {
    $('done-saved').textContent = `Could not save: ${e2 instanceof Error ? e2.message : String(e2)}`;
  } finally {
    b.disabled = false;
  }
});
$('m-pass').addEventListener('input', () => {
  const n = ($('m-pass') as HTMLInputElement).value.length;
  $('m-strength').textContent =
    n === 0 ? '' : n < 12 ? `${n}/12 characters — keep going` : n < 20 ? 'Acceptable — longer is stronger' : 'Strong passphrase';
});

$('modal-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (doneFor) return closeModal();
  const err = $('m-err');
  err.hidden = true;
  const pass = ($('m-pass') as HTMLInputElement).value;
  const go = $('m-go') as HTMLButtonElement;
  go.disabled = true;
  go.textContent = 'Working…';
  try {
    if (modalMode === 'unlock' && unlockFor) {
      await pgp.unlockPrivateKey(unlockFor.email, pass, unlockFor.fingerprint);
      $('modal').hidden = true;
      const then = unlockFor.then;
      unlockFor = null;
      then();
    } else if (modalMode === 'import') {
      const email = ($('m-email2') as HTMLInputElement).value.trim().toLowerCase();
      if (!/^[^@\s]+@[^@\s]+\.[^@\s]{2,}$/.test(email)) throw new Error('Give the address this key belongs to.');
      const src = ($('m-import') as HTMLTextAreaElement).value.trim();
      if (!src) throw new Error('Paste the key first.');
      await pgp.importKey(email, src, pass);
      $('modal').hidden = true;
    } else {
      const email = ($('m-email') as HTMLInputElement).value.trim().toLowerCase();
      if (!/^[^@\s]+@[^@\s]+\.[^@\s]{2,}$/.test(email)) throw new Error('That does not look like an email address.');
      if (pass !== ($('m-pass2') as HTMLInputElement).value) throw new Error('The passphrases do not match.');
      if (pass.length < 12) throw new Error('Use at least 12 characters — this passphrase is the whole lock.');
      const algo = ($('m-algo') as HTMLSelectElement).value as pgp.KeyAlgo;
      const rec = await pgp.generateKeys(email, ($('m-name') as HTMLInputElement).value.trim(), pass, algo);
      await pgp.unlockPrivateKey(email, pass);
      doneFor = email;
      $('modal-title').textContent = 'Your key is ready';
      $('modal-sub').textContent = '';
      $('modal-src').hidden = true;
      $('f-gen').hidden = true;
      $('f-pass').hidden = true;
      $('f-pass2').hidden = true;
      $('m-strength').textContent = '';
      $('done-fpr').textContent = await pgp.fingerprintOf(rec.publicKey);
      $('done-saved').textContent = '';
      $('f-done').hidden = false;
      ($('m-cancel') as HTMLButtonElement).hidden = true;
    }
    void refreshKeys();
  } catch (e2) {
    err.textContent = e2 instanceof Error ? e2.message : String(e2);
    err.hidden = false;
  } finally {
    go.disabled = false;
    go.textContent = doneFor ? 'Done' : 'Continue';
  }
});

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && !$('modal').hidden) closeModal();
});

// ---------- the sealer (−d) ----------
const sealErr = $('seal-err');
function sealFail(msg: string): void {
  sealErr.textContent = msg;
  sealErr.hidden = false;
}
function sealShow(label: string, text: string): void {
  $('seal-out-label').textContent = label;
  ($('seal-out') as HTMLTextAreaElement).value = text;
  $('seal-out-fld').hidden = false;
  $('seal-copy').hidden = false;
}

$('seal-enc').addEventListener('click', async () => {
  sealErr.hidden = true;
  $('seal-out-fld').hidden = true;
  const text = ($('seal-in') as HTMLTextAreaElement).value;
  if (!text.trim()) return sealFail('There is nothing to seal yet.');
  const toRaw = ($('seal-to') as HTMLInputElement).value.trim();
  if (!toRaw) return sealFail('Name at least one recipient — an address, or a pasted public key.');
  const keys: string[] = [];
  const missing: string[] = [];
  if (toRaw.includes('BEGIN PGP PUBLIC KEY BLOCK')) {
    keys.push(toRaw);
  } else {
    for (const addr of toRaw.split(',').map((s) => s.trim().toLowerCase()).filter(Boolean)) {
      const own = pgp.keysFor(addr);
      const found = own?.publicKey ?? await wkdLookup(addr);
      if (found) keys.push(found);
      else missing.push(addr);
    }
  }
  if (missing.length) return sealFail(`No key discoverable for: ${missing.join(', ')}. Their domain publishes no WKD entry — ask them for their public key and paste it instead.`);
  try {
    sealShow('Sealed message', await pgp.encryptText(text, keys));
  } catch (e2) {
    sealFail(e2 instanceof Error ? e2.message : String(e2));
  }
});

$('seal-dec').addEventListener('click', async () => {
  sealErr.hidden = true;
  $('seal-out-fld').hidden = true;
  const text = ($('seal-in') as HTMLTextAreaElement).value.trim();
  if (!pgp.looksEncrypted(text)) return sealFail('That is not an armored PGP message.');
  const attempt = async (): Promise<void> => {
    try {
      const out = await pgp.decryptText(text);
      sealShow('Unsealed text', out.text);
    } catch {
      for (const email of ringAddresses()) {
        const need = await pgp.neededKeyFor(email, text).catch(() => null);
        if (need) {
          openModal('unlock', { email, fingerprint: need.fingerprint, then: () => void attempt() });
          return;
        }
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
