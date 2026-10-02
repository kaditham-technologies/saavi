// The account face of Saavi 0.6.0 (docs/ACCOUNT-SIGNIN.md): the header
// button, the first-run offer, the narrated sign-in, the account panel (the
// published-key match, where your keys live, app passwords) and the
// "changed on another device" prompt. Crypto and protocol live elsewhere —
// account.ts (session), mailkeychain.ts (core keychain), keymatch.ts.
import * as account from './account';
import { SignInError } from './account';
import * as mk from './mailkeychain';
import * as pgp from './pgp';
import { SERVERS } from './server';
import { wkdProbe } from './wkd';
import { judge, privateFpr, publicFpr, showFpr, type Verdict } from './keymatch';
import { ask, confirmBox } from './ui';

export interface Hooks {
  refreshKeys: () => void;
  /** Wait until the store has the change on disk (sealed store). */
  flush: () => Promise<void>;
  status: (msg: string) => void;
}

let hooks: Hooks;
/** This session's copy of the keychain blob, for the keychain column of the
 *  match check. Memory only; it is ciphertext either way. */
let lastBlob: string | null = null;
let remoteNewer: number | null = null;
const OFFER_KEY = 'saavi-account-offer';

function el<K extends keyof HTMLElementTagNameMap>(tag: K, cls?: string, text?: string): HTMLElementTagNameMap[K] {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}
const host = (): string => new URL(account.server()).host;
const errText = (e: unknown): string => (e instanceof Error ? e.message : String(e));
const when = (iso: string | null): string => {
  if (!iso) return '—';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString(undefined, { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
};

// ------------------------------------------------------------------ shell

let veil: HTMLElement | null = null;
function openCard(build: (card: HTMLElement) => void, wide = false): HTMLElement {
  closeCard();
  veil = el('div', 'veil acct-veil');
  const card = el('div', 'card acct-card' + (wide ? ' acct-wide' : ''));
  card.setAttribute('role', 'dialog');
  card.setAttribute('aria-modal', 'true');
  veil.append(card);
  veil.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !card.classList.contains('busy')) closeCard(); });
  document.body.append(veil);
  build(card);
  card.querySelector<HTMLElement>('input, button.primary')?.focus();
  return card;
}
function closeCard(): void { veil?.remove(); veil = null; }

// ------------------------------------------------------------------ header

let btn: HTMLButtonElement;
let banner: HTMLElement;

function renderButton(): void {
  const a = account.address();
  btn.replaceChildren();
  btn.classList.toggle('signed', Boolean(a));
  if (a) {
    btn.append(el('span', 'acct-dot', a[0].toUpperCase()), el('span', 'acct-name', a));
    btn.title = `Signed in to Kaditham Mail as ${a}`;
  } else {
    btn.append(el('span', undefined, 'Sign in'));
    btn.title = 'Sign in with Kaditham Mail — bring your mail keys to this computer';
  }
  if (remoteNewer !== null) btn.append(el('span', 'acct-alert'));
  banner.hidden = remoteNewer === null || !a;
}

// ------------------------------------------------------------- first run

function shouldOffer(): boolean {
  try { return !localStorage.getItem(OFFER_KEY); } catch { return false; }
}
function offerDone(): void { try { localStorage.setItem(OFFER_KEY, new Date().toISOString()); } catch { /* fine */ } }

function showOffer(): void {
  openCard((card) => {
    card.append(
      el('h2', undefined, 'Have a Kaditham Mail account?'),
      el('p', 'hint', 'Sign in and the encryption keys you already use in Kaditham Mail come to this computer — every one, so old sealed mail opens here too. They are sealed by this computer’s keychain, and Saavi needs no network after that.'),
      el('p', 'hint', 'Or skip it: Saavi works fully on its own, and the Sign in button stays at the top.'),
    );
    const acts = el('div', 'card-acts');
    const skip = el('button', undefined, 'Use Saavi on its own');
    skip.type = 'button';
    skip.addEventListener('click', () => { offerDone(); closeCard(); });
    const go = el('button', 'primary', 'Sign in');
    go.type = 'button';
    go.addEventListener('click', () => { offerDone(); showSignIn(); });
    acts.append(skip, go);
    card.append(acts);
  });
}

// ---------------------------------------------------------------- steps

type StepState = 'pending' | 'active' | 'done' | 'fail' | 'skip';
interface StepRow { li: HTMLElement; label: HTMLElement; note: HTMLElement }
function stepList(labels: [string, string][]): { ol: HTMLElement; set: (id: string, s: StepState, label?: string, note?: string) => void } {
  const ol = el('ol', 'acct-steps');
  ol.setAttribute('aria-live', 'polite');
  const rows = new Map<string, StepRow>();
  for (const [id, text] of labels) {
    const li = el('li', 'pending');
    const label = el('span', 'acct-step-label', text);
    const note = el('span', 'acct-step-note');
    li.append(el('span', 'acct-step-mark'), label, note);
    ol.append(li);
    rows.set(id, { li, label, note });
  }
  return {
    ol,
    set: (id, s, label, note) => {
      const r = rows.get(id);
      if (!r) return;
      r.li.className = s;
      if (label !== undefined) r.label.textContent = label;
      r.note.textContent = note ?? '';
    },
  };
}

// --------------------------------------------------------------- sign in

function showSignIn(prefill = ''): void {
  openCard((card) => {
    const form = el('form', 'acct-form');
    form.noValidate = true;
    form.append(
      el('h2', undefined, 'Sign in with Kaditham Mail'),
      el('p', 'hint', 'Your password stays on this computer — only a value derived from it is sent. It also unlocks your keys, so it is the only thing you type.'),
    );
    const mk1 = (label: string, type: string, auto: string): { wrap: HTMLElement; input: HTMLInputElement } => {
      const wrap = el('label', 'fld');
      const input = el('input');
      input.type = type; input.autocomplete = auto as AutoFill; input.spellcheck = false;
      wrap.append(el('span', undefined, label), input);
      return { wrap, input };
    };
    const addr = mk1('Email address', 'email', 'username');
    addr.input.value = prefill;
    const pass = mk1('Password', 'password', 'current-password');
    const code = mk1('Two-factor code', 'text', 'one-time-code');
    code.input.inputMode = 'numeric';
    code.wrap.hidden = true;
    const adv = el('details', 'acct-adv');
    const advSum = el('summary', undefined, 'Server');
    const pick = el('select');
    for (const s of SERVERS) { const o = el('option', undefined, new URL(s).host); o.value = s; pick.append(o); }
    pick.value = account.server();
    adv.append(advSum, pick, el('span', 'hint', ' mail.kaditham.me is the staging server the team tests on.'));
    const err = el('p', 'error');
    err.setAttribute('role', 'alert');
    err.hidden = true;
    const steps = stepList([
      ['derive', 'Checking your password'],
      ['auth', 'Signing in'],
      ['fetch', 'Fetching your keychain'],
      ['unlock', 'Unlocking your keys'],
      ['seal', 'Sealing them to this computer'],
      ['match', 'Checking your published key'],
    ]);
    steps.ol.hidden = true;
    const acts = el('div', 'card-acts');
    const cancel = el('button', undefined, 'Cancel');
    cancel.type = 'button';
    cancel.addEventListener('click', closeCard);
    const go = el('button', 'primary', 'Sign in');
    go.type = 'submit';
    acts.append(cancel, go);
    form.append(addr.wrap, pass.wrap, code.wrap, adv, steps.ol, err, acts);
    card.append(form);

    const fail = (msg: string, info = false): void => { err.textContent = msg; err.className = info ? 'hint acct-info' : 'error'; err.hidden = false; };
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      if (card.classList.contains('busy')) return;
      err.hidden = true;
      if (!addr.input.value.trim() || !pass.input.value) { fail('Enter your address and password.'); return; }
      void (async () => {
        card.classList.add('busy');
        go.disabled = true; cancel.disabled = true;
        for (const i of [addr.input, pass.input, code.input, pick]) i.disabled = true;
        steps.ol.hidden = false;
        try {
          await account.signIn(addr.input.value, pass.input.value, code.wrap.hidden ? undefined : code.input.value, {
            server: pick.value,
            step: (s) => {
              if (s === 'deriving') steps.set('derive', 'active');
              else { steps.set('derive', 'done'); steps.set('auth', 'active', `Signing in to ${host()}`); }
            },
          });
          steps.set('auth', 'done', `Signed in to ${host()}`);
          await bringKeys(steps.set, pass.input.value);
          card.classList.remove('busy');
          closeCard();
          void showPanel();
        } catch (e) {
          card.classList.remove('busy');
          go.disabled = false; cancel.disabled = false;
          for (const i of [addr.input, pass.input, code.input, pick]) i.disabled = false;
          if (e instanceof SignInError) {
            steps.set('derive', 'done');
            if (e.kind === 'needs-code') {
              steps.set('auth', 'pending', 'Signing in', 'two-factor is on');
              code.wrap.hidden = false;
              code.input.focus();
              go.textContent = 'Continue';
              fail('Two-factor is on for this account — enter the 6-digit code from your authenticator app.', true);
              return;
            }
            steps.set('auth', 'fail');
            fail(e.message);
            (e.kind === 'code-denied' ? code.input : e.kind === 'denied' ? pass.input : go).focus();
            return;
          }
          fail(errText(e));
        }
      })();
    });
  });
}

/**
 * Fetch → unlock (proof) → seal → match, each step narrated, each failure
 * named. Throws only for failures the sign-in form should show; a missing
 * keychain is not a failure — it says what to do and carries on.
 */
async function bringKeys(set: (id: string, s: StepState, label?: string, note?: string) => void, password: string,
  opts: { adoptFromKeychain?: boolean } = {}): Promise<void> {
  const user = account.address()!;
  const addrs = await account.addresses();
  set('fetch', 'active');
  let src: { blob: string; version: number };
  try {
    src = await mk.fetchOnce();
  } catch (e) {
    const m = errText(e);
    if (/no keychain yet/i.test(m)) {
      set('fetch', 'skip', 'No keychain on this account yet', 'keys made here back up with Sync now');
      set('unlock', 'skip'); set('seal', 'skip');
      await matchStep(set, addrs);
      return;
    }
    set('fetch', 'fail', undefined, m);
    throw new Error(`${m} You are signed in; your keys can be fetched later from the account panel with Sync now.`);
  }
  lastBlob = src.blob;
  set('fetch', 'done', `Fetched your keychain (version ${src.version})`);
  let n = 0;
  try {
    const parsed = mk.parseBlob(src.blob);
    for (const a of addrs) { const r = parsed.rings[a]; if (r) n += 1 + r.retired.length; }
  } catch { /* restore names a damaged blob itself */ }
  set('unlock', 'active', `Unlocking ${n} key${n === 1 ? '' : 's'}`);
  await account.painted();
  const adopt = await adoptionMap(addrs, src.blob, opts.adoptFromKeychain === true);
  let pending: string[] = [];
  try {
    const r = await mk.restore(user, password, addrs, src, { adopt });
    pending = r.pending;
    set('unlock', 'done', `Unlocked ${n} key${n === 1 ? '' : 's'}`, pending.length ? `${pending.length} wear an older passphrase` : '');
  } catch (e) {
    const m = errText(e);
    if (/already on this device/.test(m)) {
      set('unlock', 'done', 'Your keys were already on this computer');
    } else if (/passphrase does not open/.test(m)) {
      // Every ring wears a passphrase other than the sign-in password (keys
      // made before the password split). Ask for it, reuse the same blob.
      set('unlock', 'active', 'Your keys wear an older passphrase');
      pending = addrs.filter((a) => (() => { try { return Boolean(mk.parseBlob(src.blob).rings[a]); } catch { return false; } })());
    } else {
      set('unlock', 'fail', undefined, 'nothing was installed and nothing was lost');
      throw new Error(`${m} Nothing was installed and nothing on this computer changed.`);
    }
  }
  for (const a of pending) {
    for (;;) {
      const got = await ask({
        title: `The key for ${a}`,
        message: `This key is locked with a passphrase other than your sign-in password — the one you chose when it was made (before Kaditham Mail moved to one password). Enter it to bring this key here, or skip it for now.`,
        fields: [{ name: 'p', label: 'Passphrase', type: 'password' }],
        ok: 'Unlock', cancel: 'Skip this key',
      });
      if (!got) break;
      set('unlock', 'active', `Unlocking the key for ${a}`);
      await account.painted();
      try { await mk.restore(user, got.p, [a], src); break; } catch (e) {
        const m = errText(e);
        if (/already on this device/.test(m)) break;
        if (!(await confirmBox('That passphrase did not open it', `${m}\n\nTry another passphrase?`, 'Try again'))) break;
      }
    }
  }
  set('unlock', 'done');
  set('seal', 'active');
  try {
    await hooks.flush();
    set('seal', 'done', 'Sealed to this computer’s keychain');
  } catch (e) {
    set('seal', 'fail', undefined, 'the keys are open in this window but not yet on disk');
    throw new Error(`The keys came in, but the key store refused the write: ${errText(e)} Keep Saavi open and try Sync now; closing will ask before discarding anything.`);
  }
  hooks.refreshKeys();
  await matchStep(set, addrs);
}

/** Which key each address should end up with when this device already has
 *  a different one: the key the address PUBLISHES (the server-named current
 *  key, never the blob's order alone) — or, on an explicit "use the
 *  account's key", the keychain's active key (still proof-gated). */
async function adoptionMap(addrs: string[], blob: string, fromKeychain: boolean): Promise<Record<string, string>> {
  const out: Record<string, string> = {};
  let parsed: ReturnType<typeof mk.parseBlob> | null = null;
  try { parsed = mk.parseBlob(blob); } catch { return out; }
  for (const a of addrs) {
    const local = pgp.ringFor(a);
    const remote = parsed.rings[a];
    if (!local || !remote) continue;
    const want = fromKeychain ? await privateFpr(remote.active.privateKey).catch(() => null) : await wkdFpr(a);
    if (want) out[a] = want;
  }
  return out;
}

async function wkdFpr(address: string): Promise<string | null> {
  try {
    const r = await wkdProbe(address);
    return r.key ? await publicFpr(r.key) : null;
  } catch { return null; }
}

// -------------------------------------------------------- the match check

interface AddrVerdict { address: string; verdict: Verdict; wkdState: 'found' | 'none' | 'unreachable' }
let verdicts: AddrVerdict[] = [];

async function computeVerdicts(addrs: string[]): Promise<AddrVerdict[]> {
  let parsed: ReturnType<typeof mk.parseBlob> | null = null;
  if (lastBlob) { try { parsed = mk.parseBlob(lastBlob); } catch { parsed = null; } }
  const out: AddrVerdict[] = [];
  for (const a of addrs) {
    const ring = pgp.ringFor(a);
    const local = ring ? await publicFpr(ring.active.publicKey).catch(() => null) : null;
    const w = await wkdProbe(a).catch(() => ({ key: null, status: 'unreachable' as const }));
    const wkd = w.key ? await publicFpr(w.key).catch(() => null) : null;
    const remote = parsed?.rings[a];
    const keychain = remote ? await privateFpr(remote.active.privateKey).catch(() => null) : null;
    out.push({ address: a, verdict: judge({ local, wkd, keychain }), wkdState: w.status });
  }
  return out;
}

async function matchStep(set: (id: string, s: StepState, label?: string, note?: string) => void, addrs: string[]): Promise<void> {
  set('match', 'active');
  verdicts = await computeVerdicts(addrs);
  const bad = verdicts.filter((v) => v.verdict.state === 'mismatch');
  const good = verdicts.filter((v) => v.verdict.state === 'match');
  if (bad.length) set('match', 'fail', 'Your published key does not match', 'see the account panel');
  else if (good.length) set('match', 'done', 'Your published key matches this computer');
  else set('match', 'skip', 'Nothing published to compare yet');
}

function verdictBlock(v: AddrVerdict): HTMLElement {
  const box = el('div', 'acct-match');
  const head = el('div', 'acct-match-head');
  head.append(el('b', undefined, v.address));
  const d = v.verdict;
  if (d.state === 'match') {
    box.classList.add('ok');
    head.append(el('span', 'acct-badge ok', 'Your published key matches this computer ✓'));
    box.append(head, el('p', 'fpr', showFpr(d.fingerprint)),
      el('p', 'hint', `Checked: this computer${d.checked.includes('wkd') ? ' · what ' + v.address.split('@')[1] + ' publishes' : ''}${d.checked.includes('keychain') ? ' · your account keychain' : ''}. Anyone sealing mail to you uses this key, and only this computer’s copy opens it.`));
  } else if (d.state === 'mismatch') {
    box.classList.add('warn');
    head.append(el('span', 'acct-badge warn', 'These do not match'));
    const g = el('dl', 'kv');
    const row = (k: string, f: string | null, odd: boolean, missing = 'not found') => {
      g.append(el('dt', undefined, k));
      const dd = el('dd', 'mono' + (odd ? ' acct-odd' : ''), f ? showFpr(f) : missing);
      g.append(dd);
    };
    row('This computer', d.sources.local, false);
    row(`Published (${v.address.split('@')[1]})`, d.sources.wkd, d.differing.includes('wkd'));
    row('Account keychain', d.sources.keychain, d.differing.includes('keychain'), lastBlob ? 'no key for this address' : 'not read this session');
    box.append(head, g, el('p', 'hint',
      d.differing.includes('wkd')
        ? 'People who seal mail to you are using a different key from the one this computer holds. The usual reason is harmless: a key was just changed on another device and the published copy has not caught up (give it a few minutes, then Check again). If you changed nothing, treat it as serious — the published key decides who can read mail sent to you. Sealing is not blocked; you decide.'
        : 'Your account keychain names a different current key than this computer uses — another device probably made a new key. Bring it here from the banner (your password proves it first), or keep this one.'));
  } else if (d.state === 'unpublished') {
    head.append(el('span', 'acct-badge', 'Not published yet'));
    box.append(head, el('p', 'fpr', showFpr(d.fingerprint)),
      el('p', 'hint', v.wkdState === 'unreachable'
        ? 'Could not reach the published-key directory just now, so nothing was compared. Check again when online.'
        : 'This address publishes no key yet, so people cannot find it to seal mail to you. Publishing happens from Kaditham Mail, or from Details → Publish.'));
  } else {
    head.append(el('span', 'acct-badge', 'No key here for this address'));
    box.append(head);
  }
  return box;
}

// ---------------------------------------------------------------- panel

export async function showPanel(): Promise<void> {
  if (!account.signedIn()) { showSignIn(); return; }
  const card = openCard((c) => c.append(el('h2', undefined, 'Kaditham Mail'), el('p', 'hint', 'Loading your account…')), true);
  const user = account.address()!;
  const addrs = await account.addresses().catch(() => [user]);
  const st = await mk.status().catch(() => null);
  const [devs, aps] = await Promise.all([
    account.devices().then((d) => ({ ok: true as const, d }), (e) => ({ ok: false as const, e: errText(e) })),
    account.appPasswords().then((a) => ({ ok: true as const, a }), (e) => ({ ok: false as const, e: errText(e) })),
  ]);
  if (!verdicts.length || verdicts.some((v) => !addrs.includes(v.address))) verdicts = await computeVerdicts(addrs);
  if (!veil?.contains(card)) return;   // closed meanwhile
  card.replaceChildren();

  const who = el('div', 'acct-who');
  who.append(el('span', 'acct-dot big', user[0].toUpperCase()));
  const lines = el('div');
  lines.append(el('b', undefined, user), el('span', 'hint', ` · ${host()}`));
  who.append(lines);
  card.append(who);

  if (remoteNewer !== null) card.append(changeBlock());

  // Keychain
  const kc = el('section', 'acct-sec');
  kc.append(el('h3', undefined, 'Your keychain'));
  kc.append(el('p', 'hint', st
    ? st.exists ? `Version ${st.version} · last changed ${when(st.updatedAt)}. Your keys are locked with your password inside it; the server cannot open them.`
      : 'No keychain yet. Sync now backs up the keys this computer holds for your addresses.'
    : 'Could not reach the keychain just now — your keys here keep working offline.'));
  const sync = el('button', 'mini', 'Sync now');
  sync.type = 'button';
  sync.addEventListener('click', () => void syncNow(sync));
  const syncNote = el('span', 'hint acct-sync-note');
  const kcActs = el('div', 'acct-row');
  kcActs.append(sync, syncNote);
  kc.append(kcActs);
  card.append(kc);

  // Match
  const ms = el('section', 'acct-sec');
  const mh = el('h3', undefined, 'Your published key');
  ms.append(mh);
  for (const v of verdicts) ms.append(verdictBlock(v));
  const again = el('button', 'mini', 'Check again');
  again.type = 'button';
  again.addEventListener('click', async () => {
    again.disabled = true; again.textContent = 'Checking…';
    verdicts = await computeVerdicts(addrs);
    void showPanel();
  });
  ms.append(again);
  card.append(ms);

  // Where your keys live
  const dv = el('section', 'acct-sec');
  dv.append(el('h3', undefined, 'Where your keys live'));
  if (!devs.ok) dv.append(el('p', 'error', devs.e));
  else if (devs.d === null) dv.append(el('p', 'hint', 'The device list arrives with the next server update.'));
  else if (!devs.d.length) dv.append(el('p', 'hint', 'No device has downloaded your keychain yet.'));
  else {
    const ul = el('ul', 'acct-list');
    for (const d of devs.d) {
      const li = el('li');
      li.append(el('span', undefined, d.label + (d.current ? ' — this computer' : '')), el('span', 'hint', `first ${when(d.firstAt)} · last ${when(d.lastAt)}`));
      ul.append(li);
    }
    dv.append(ul, el('p', 'hint', 'Devices that downloaded your keychain in the last 90 days, as they named themselves. Each download from a new device was announced by email. Removing a device needs a new key to mean anything — that arrives in a later release.'));
  }
  card.append(dv);

  const ap = el('section', 'acct-sec');
  ap.append(el('h3', undefined, 'App passwords'));
  if (!aps.ok) ap.append(el('p', 'error', aps.e));
  else if (!aps.a.length) ap.append(el('p', 'hint', 'None. Mail apps like Thunderbird or your phone’s Mail sign in with one.'));
  else {
    const ul = el('ul', 'acct-list');
    for (const p of aps.a) { const li = el('li'); li.append(el('span', undefined, p.description), el('span', 'hint', `created ${when(p.createdAt)}`)); ul.append(li); }
    ap.append(ul, el('p', 'hint', 'Mail apps signed in to your account. They read and send mail but cannot reach your keychain. Remove one in Kaditham Mail → Settings.'));
  }
  card.append(ap);

  const acts = el('div', 'card-acts');
  const out = el('button', undefined, 'Sign out');
  out.type = 'button';
  out.addEventListener('click', async () => {
    if (!(await confirmBox('Sign out of Kaditham Mail?', 'Your keys stay on this computer, sealed by its keychain, and keep working offline. Signing out only forgets the session; sign in again any time to sync.', 'Sign out'))) return;
    await account.signOut();
    lastBlob = null; verdicts = []; remoteNewer = null;
    closeCard();
    hooks.status('Signed out of Kaditham Mail. Your keys are still here.');
  });
  const close = el('button', 'primary', 'Close');
  close.type = 'button';
  close.addEventListener('click', closeCard);
  acts.append(out, close);
  card.append(acts);
}

/** Ask for the password when this session resumed without it. */
async function needPassword(why: string): Promise<boolean> {
  if (account.hasSecrets()) return true;
  const got = await ask({
    title: 'Confirm your password',
    message: `${why} Saavi keeps your password in memory only, so after a restart it asks once.`,
    fields: [{ name: 'p', label: 'Password', type: 'password' }],
    ok: 'Continue',
  });
  if (!got) return false;
  await account.provideSecrets(got.p);
  return true;
}

async function syncNow(b: HTMLButtonElement): Promise<void> {
  const note = b.parentElement?.querySelector('.acct-sync-note');
  const say = (t: string): void => { if (note) note.textContent = t; };
  if (!(await needPassword('Syncing proves your password to the keychain.'))) return;
  b.disabled = true;
  try {
    const user = account.address()!;
    const addrs = await account.addresses();
    say('Checking for changes…');
    if (await localDiffersFromAccount(addrs)) {
      say('');
      await notice2('This computer and your account disagree',
        'For at least one address, this computer’s current key is not the one your account uses. Syncing now would make this computer’s key the current one on every device. Review “Your published key” below first; to take the account’s key instead, use “Bring it here”.');
      return;
    }
    const r = await mk.sync(user, addrs);
    say(r === 'unchanged' ? 'Already in step.' : r === 'nothing-local' ? 'Nothing here to back up yet.' : r === 'exists' ? 'Your account already has a keychain — bring it here first.' : `Synced (${r}).`);
    remoteNewer = null;
    renderButton();
  } catch (e) {
    const m = errText(e);
    say(/proof|password confirmed/i.test(m) ? 'The server did not accept that password. Sign out and in again.' : m);
  } finally { b.disabled = false; }
}

async function notice2(title: string, message: string): Promise<void> {
  await confirmBox(title, message, 'OK');
}

/** Would a push replace the account's current key for some address? */
async function localDiffersFromAccount(addrs: string[]): Promise<boolean> {
  if (!lastBlob) {
    try { lastBlob = (await mk.fetchOnce()).blob; } catch { return false; }
  }
  let parsed: ReturnType<typeof mk.parseBlob>;
  try { parsed = mk.parseBlob(lastBlob); } catch { return false; }
  for (const a of addrs) {
    const local = pgp.ringFor(a);
    const remote = parsed.rings[a];
    if (!local || !remote) continue;
    const lf = await publicFpr(local.active.publicKey).catch(() => '');
    const rf = await privateFpr(remote.active.privateKey).catch(() => '');
    if (lf && rf && lf !== rf) return true;
  }
  return false;
}

// ------------------------------------------- changes from other devices

function changeBlock(): HTMLElement {
  const box = el('div', 'acct-change');
  box.append(el('b', undefined, 'Your keychain changed on another device'),
    el('p', 'hint', 'A key was made, changed or added elsewhere. Bring it here: your password proves every key before anything on this computer changes.'));
  const go = el('button', 'primary', 'Bring it here');
  go.type = 'button';
  go.addEventListener('click', () => void adoptChange());
  box.append(go);
  return box;
}

async function adoptChange(): Promise<void> {
  if (!(await needPassword('Bringing keys here proves them with your password.'))) return;
  const pass = account.ringSecret()!;
  openCard((card) => {
    card.classList.add('busy');
    card.append(el('h2', undefined, 'Bringing your keychain here'));
    const steps = stepList([
      ['fetch', 'Fetching your keychain'], ['unlock', 'Unlocking your keys'],
      ['seal', 'Sealing them to this computer'], ['match', 'Checking your published key'],
    ]);
    const err = el('p', 'error'); err.hidden = true;
    const acts = el('div', 'card-acts');
    const close = el('button', 'primary', 'Done'); close.type = 'button'; close.disabled = true;
    close.addEventListener('click', () => { closeCard(); void showPanel(); });
    acts.append(close);
    card.append(steps.ol, err, acts);
    void (async () => {
      try {
        let fromKeychain = false;
        // When the published key has not caught up with the keychain, say so
        // and let the customer choose — never silently trust the blob's order.
        try {
          const src = await mk.fetchOnce();
          lastBlob = src.blob;
          const addrs = await account.addresses();
          const parsed = mk.parseBlob(src.blob);
          for (const a of addrs) {
            const remote = parsed.rings[a];
            if (!remote) continue;
            const rf = await privateFpr(remote.active.privateKey).catch(() => null);
            const wf = await wkdFpr(a);
            if (rf && wf && rf !== wf) {
              fromKeychain = await confirmBox('Your published key has not caught up',
                `Your keychain names a new current key for ${a} (${showFpr(rf)}), but what ${a.split('@')[1]} publishes is still ${showFpr(wf)}. If you just changed it on another device, take the new one. If you did not, keep this computer’s key and check your account.`,
                'Take the new key');
              break;
            }
          }
        } catch { /* bringKeys reports fetch problems itself */ }
        await bringKeys(steps.set, pass, { adoptFromKeychain: fromKeychain });
        remoteNewer = null;
        renderButton();
      } catch (e) {
        err.textContent = errText(e); err.hidden = false;
      } finally {
        card.classList.remove('busy');
        close.disabled = false;
        close.focus();
      }
    })();
  });
}

let lastFocusCheck = 0;
let focusInFlight: Promise<void> | null = null;
async function focusCheck(): Promise<void> {
  if (!account.signedIn() || Date.now() - lastFocusCheck < 60_000) return;
  lastFocusCheck = Date.now();
  focusInFlight ??= (async () => {
    try {
      const user = account.address()!;
      const v = await account.keychainVersion();
      const known = mk.knownVersion(user);
      remoteNewer = v !== null && known !== null && v > known ? v : null;
      renderButton();
    } catch { /* offline — next focus */ } finally { focusInFlight = null; }
  })();
  await focusInFlight;
}

/** Saavi made or imported a key for some address. If it is one of the
 *  account's and the session can push, offer to back it up — explicit, since
 *  pushing makes it the current key on every device. */
export async function keysChanged(email: string, passUsed: string): Promise<void> {
  if (!account.signedIn()) return;
  const addrs = await account.addresses().catch(() => [] as string[]);
  if (!addrs.includes(email.toLowerCase())) return;
  if (!(await confirmBox('Use this key on all your devices?',
    `${email} belongs to your Kaditham Mail account. Back this key up to your keychain and make it the current key everywhere? Older keys stay, so old mail still opens.`,
    'Back it up'))) return;
  if (!(await needPassword('Backing up proves your password to the keychain.'))) return;
  try {
    // Account keys are locked with the account password (the split), so
    // every device — the webmail included — opens them with what it already
    // holds. Re-lock additively: the passphrase-locked armor is retired,
    // never dropped.
    const pw = account.ringSecret()!;
    if (passUsed !== pw) {
      await account.painted();
      await pgp.relockActive(email, passUsed, pw);
      await hooks.flush();
    }
    const r = await mk.sync(account.address()!, addrs);
    hooks.status(r === 'exists' ? 'Your account already has a keychain — open the account panel to bring it here first.' : 'Backed up to your Kaditham Mail keychain.');
  } catch (e) { hooks.status(`Could not back it up: ${errText(e)}`); }
}

// ----------------------------------------------------------------- boot

export async function initAccountUi(h: Hooks): Promise<void> {
  hooks = h;
  // Restore's authority: the key each address PUBLISHES is the server-named
  // current key (a keychain rolled back by a stale device must not hand this
  // computer a retired key).
  mk.useAuthority(async (addrs) => {
    const out: Record<string, string[]> = {};
    for (const a of addrs) { const f = await wkdFpr(a); if (f) out[a.toLowerCase()] = [f]; }
    return out;
  });
  btn = el('button', 'acct-btn');
  btn.type = 'button';
  btn.addEventListener('click', () => void (account.signedIn() ? showPanel() : showSignIn()));
  banner = el('div', 'update-banner acct-banner');
  banner.setAttribute('role', 'status');
  banner.hidden = true;
  const bt = el('span', 'ub-text', 'Your keychain changed on another device.');
  const bg = el('button', 'ub-get', 'Bring it here');
  bg.type = 'button';
  bg.addEventListener('click', () => void adoptChange());
  banner.append(el('span', 'ub-dot'), bt, bg);
  const bar = document.querySelector('.bar');
  bar?.append(btn);
  bar?.after(banner);
  account.onChange(renderButton);
  renderButton();
  // The browser build cannot reach the server (no http capability). The
  // dev server may preview the flows against a faked server; production
  // builds strip this branch.
  const preview = import.meta.env.DEV && localStorage.getItem('saavi-account-preview') === '1';
  if (!('__TAURI_INTERNALS__' in window) && !preview) { btn.hidden = true; return; }
  const resumed = await account.resume().catch(() => false);
  renderButton();
  if (!resumed && shouldOffer()) showOffer();
  window.addEventListener('focus', () => void focusCheck());
  if (resumed) void focusCheck();
}
