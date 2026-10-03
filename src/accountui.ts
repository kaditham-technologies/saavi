// The account face of Saavi 0.6.0 (docs/ACCOUNT-SIGNIN.md): the header
// button, the first-run offer, the narrated sign-in, the account panel (the
// published-key match, where your keys live, app passwords) and the
// "changed on another device" prompt. Crypto and protocol live elsewhere —
// account.ts (session), mailkeychain.ts (core keychain), keymatch.ts.
import * as account from './account';
import { SignInError } from './account';
import * as mk from './mailkeychain';
import * as pgp from './pgp';
import { wkdProbe } from './wkd';
import { assess, privateFpr, publicFpr, showFpr, type Assessment, type LegState } from './keymatch';
import { confirmAdoption, planAdoption, type AdoptionInput, type AdoptionStep } from './adoption';
import { decideBanner, readBaseline, writeBaseline } from './changes';
import { vksLookup } from './vks';
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
/** The key check's last result, per address (the panel draws it). */
let checks: AddrCheck[] = [];
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
    // Signed out by any road — the button, or the server refusing the
    // grant — nothing of the last account may linger: no alert, no blob,
    // no key check drawn from it.
    remoteNewer = null; lastBlob = null; checks = [];
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
    form.append(addr.wrap, pass.wrap, code.wrap, steps.ol, err, acts);
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
        for (const i of [addr.input, pass.input, code.input]) i.disabled = true;
        steps.ol.hidden = false;
        try {
          await account.signIn(addr.input.value, pass.input.value, code.wrap.hidden ? undefined : code.input.value, {
            step: (s) => {
              if (s === 'deriving') steps.set('derive', 'active');
              else { steps.set('derive', 'done'); steps.set('auth', 'active', `Signing in to ${host()}`); }
            },
          });
          steps.set('auth', 'done', `Signed in to ${host()}`);
          try { await bringKeys(steps.set, pass.input.value); } finally { account.forgetSecrets(); }
          remoteNewer = null;   // a fresh sign-in has just brought the keys
          card.classList.remove('busy');
          closeCard();
          void showPanel();
        } catch (e) {
          card.classList.remove('busy');
          go.disabled = false; cancel.disabled = false;
          for (const i of [addr.input, pass.input, code.input]) i.disabled = false;
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
 * Fetch → unlock (proof) → seal → check, each step narrated, each failure
 * named. Throws only for failures the caller should show; a missing keychain
 * is not a failure — it says what to do and carries on. The caller forgets
 * the password afterwards.
 */
async function bringKeys(set: (id: string, s: StepState, label?: string, note?: string) => void, password: string,
  opts: { adoptFromKeychain?: boolean } = {}): Promise<void> {
  const user = account.address()!;
  await account.ready();
  const set0 = await account.addresses();
  let addrs = set0.list;
  if (!set0.complete) {
    // Never restore a subset silently (argus A4).
    const go = await confirmBox('Your other addresses could not be read',
      `The mail server did not return your account’s other addresses (aliases) just now, so only ${user} is known. Bring the keys for ${user} now and the rest later, or stop and try again in a moment?`,
      `Only ${user}`);
    if (!go) { set('fetch', 'skip', 'Stopped — your alias list was unavailable'); throw new Error('Nothing was changed. Try “Bring keys here” again in a moment.'); }
    addrs = [user];
  }
  set('fetch', 'active');
  let src: { blob: string; version: number };
  try {
    src = await mk.fetchOnce();
  } catch (e) {
    const m = errText(e);
    if (/no keychain yet/i.test(m)) {
      set('fetch', 'skip', 'No keychain on this account yet', 'keys made here can be backed up with Sync now');
      set('unlock', 'skip'); set('seal', 'skip');
      await checkStep(set, addrs);
      return;
    }
    set('fetch', 'fail', undefined, m);
    throw new Error(`${m} You are signed in; open the account panel and use “Bring keys here” to try again.`);
  }
  lastBlob = src.blob;
  set('fetch', 'done', `Fetched your keychain (version ${src.version})`);
  let n = 0;
  try {
    const parsed = mk.parseBlob(src.blob);
    for (const a of addrs) { const r = parsed.rings[a]; if (r) n += 1 + r.retired.length; }
  } catch { /* restore names a damaged blob itself */ }

  // Adoption: which addresses change key here, with a retired key never
  // brought back unasked (docs/ACCOUNT-SIGNIN.md, "Adoption").
  const adopt = await confirmAdoption(await adoptionPlan(addrs, src.blob, opts.adoptFromKeychain === true), confirmReactivation);

  set('unlock', 'active', `Unlocking ${n} key${n === 1 ? '' : 's'}`);
  await account.painted();
  let pending: string[] = [];
  try {
    const r = await mk.restore(user, password, addrs, src, { adopt });
    pending = r.pending;
    set('unlock', 'done', `Unlocked ${n} key${n === 1 ? '' : 's'}`, pending.length ? `${pending.length} wear an older passphrase` : '');
  } catch (e) {
    const m = errText(e);
    if (/already on this device/.test(m)) {
      // Nothing to bring — but this version has now been seen (argus A1).
      await mk.acceptVersion(user, addrs, src.version).catch(() => false);
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
  writeBaseline(user, src.version);
  for (const a of pending) {
    for (;;) {
      const got = await ask({
        title: `The key for ${a}`,
        message: 'This key is locked with a passphrase other than your sign-in password — the one you chose when it was made (before Kaditham Mail moved to one password). Enter it to bring this key here, or skip it for now.',
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
    throw new Error(`The keys came in, but the key store refused the write: ${errText(e)} Keep Saavi open and use “Bring keys here” again; closing will ask before discarding anything.`);
  }
  hooks.refreshKeys();
  await checkStep(set, addrs);
}

/** For each address that already has a ring here: the key a source names
 *  as current — the domain's published key by default, the keychain's on
 *  the customer's explicit choice. planAdoption drops agreements and flags
 *  any target this computer has retired. */
async function adoptionPlan(addrs: string[], blob: string, fromKeychain: boolean): Promise<AdoptionStep[]> {
  let parsed: ReturnType<typeof mk.parseBlob>;
  try { parsed = mk.parseBlob(blob); } catch { return []; }
  const inputs: AdoptionInput[] = [];
  for (const a of addrs) {
    const local = pgp.ringFor(a);
    const remote = parsed.rings[a];
    if (!local || !remote) continue;
    const current = await publicFpr(local.active.publicKey).catch(() => null);
    if (!current) continue;
    const retired = (await Promise.all(local.retired.map((r) => publicFpr(r.publicKey).catch(() => null)))).filter((f): f is string => Boolean(f));
    const target = fromKeychain ? await privateFpr(remote.active.privateKey).catch(() => null) : await wkdFpr(a);
    inputs.push({ address: a, current, retired, target, source: fromKeychain ? 'keychain' : 'published' });
  }
  return planAdoption(inputs);
}

/** The first-class confirm step: bringing back a key this computer retired. */
function confirmReactivation(step: AdoptionStep): Promise<boolean> {
  const by = step.source === 'published'
    ? `${step.address.split('@')[1]} is publishing it as the current key`
    : 'your account keychain names it as the current key';
  return confirmBox(`Bring back a key you retired?`,
    `For ${step.address}, ${by}:\n\n${showFpr(step.target)}\n\nThis computer retired that key — usually because a newer one replaced it, sometimes because it was exposed. A source naming a retired key as current is a device that missed the change, a directory that has not caught up, or someone trying to turn your account back to a key they hold. Saavi cannot tell which.\n\nKeep your current key unless you deliberately went back to this one.`,
    'Make it current again', true);
}

async function wkdFpr(address: string): Promise<string | null> {
  try {
    const r = await wkdProbe(address);
    return r.key ? await publicFpr(r.key) : null;
  } catch { return null; }
}

// --------------------------------------------------------- the key check

interface AddrCheck { address: string; a: Assessment }

async function computeChecks(addrs: string[]): Promise<AddrCheck[]> {
  let parsed: ReturnType<typeof mk.parseBlob> | null = null;
  if (lastBlob) { try { parsed = mk.parseBlob(lastBlob); } catch { parsed = null; } }
  return Promise.all(addrs.map(async (address) => {
    const ring = pgp.ringFor(address);
    const local = ring ? await publicFpr(ring.active.publicKey).catch(() => null) : null;
    const [w, v] = await Promise.all([
      wkdProbe(address).catch(() => ({ key: null, status: 'unreachable' as const })),
      vksLookup(address).then((k) => ({ k, ok: true }), () => ({ k: null, ok: false })),
    ]);
    const domain = { fpr: w.key ? await publicFpr(w.key).catch(() => null) : null, reached: w.status !== 'unreachable' };
    const remote = parsed?.rings[address];
    const keychain = parsed
      ? { fpr: remote ? await privateFpr(remote.active.privateKey).catch(() => null) : null, reached: true }
      : { fpr: null, reached: true, read: false };
    const vks = { fpr: v.k ? await publicFpr(v.k).catch(() => null) : null, reached: v.ok };
    return { address, a: assess({ local, domain, keychain, vks }) };
  }));
}

async function checkStep(set: (id: string, s: StepState, label?: string, note?: string) => void, addrs: string[]): Promise<void> {
  set('match', 'active');
  checks = await computeChecks(addrs);
  const s = checks.map((c) => c.a.summary);
  if (s.includes('differs')) set('match', 'fail', 'Your key does not match everywhere', 'see the account panel');
  else if (s.includes('consistent')) set('match', 'done', `Matches what ${addrs[0].split('@')[1]} published to this computer just now`);
  else if (s.includes('unchecked')) set('match', 'skip', 'Could not reach your domain’s key directory just now');
  else set('match', 'skip', 'Nothing published to compare yet');
}

const LEG_TEXT: Record<LegState, string> = {
  agrees: 'same key ✓', differs: 'a DIFFERENT key', absent: 'no key for this address',
  unreachable: 'could not be reached just now', 'not-read': 'not read this session',
};

function checkBlock(c: AddrCheck): HTMLElement {
  const { a } = c;
  const domain = c.address.split('@')[1];
  const box = el('div', 'acct-match');
  const head = el('div', 'acct-match-head');
  head.append(el('b', undefined, c.address));
  const g = el('dl', 'kv');
  const row = (label: string, state: LegState | 'self', fpr: string | null) => {
    g.append(el('dt', undefined, label));
    const dd = el('dd', state === 'differs' ? 'acct-odd' : state === 'agrees' ? 'acct-ok' : '');
    if (state === 'self' || state === 'differs') dd.append(el('span', 'mono', showFpr(fpr!)));
    if (state === 'differs') dd.append(el('span', 'acct-leg-word', LEG_TEXT.differs));
    else if (state !== 'self') dd.append(LEG_TEXT[state]);
    g.append(dd);
  };
  if (a.summary === 'no-local-key') {
    head.append(el('span', 'acct-badge', 'No key on this computer for this address'));
    box.append(head);
    return box;
  }
  row('This computer', 'self', a.local);
  row(`What ${domain} published`, a.legs.domain.state, a.legs.domain.fpr);
  row('Your account keychain', a.legs.keychain.state, a.legs.keychain.fpr);
  row('keys.openpgp.org (independent)', a.legs.vks.state, a.legs.vks.fpr);

  const notes: string[] = [];
  if (a.summary === 'consistent') {
    box.classList.add('ok');
    head.append(el('span', 'acct-badge ok', `Matches what ${domain} published to this computer just now ✓`));
    notes.push(`${domain} served this computer the same key it holds. That is what the domain answered here; Saavi cannot see what it answers anyone else.`);
  } else if (a.summary === 'differs') {
    box.classList.add('warn');
    head.append(el('span', 'acct-badge warn', 'Not the same key everywhere'));
    if (a.legs.domain.state === 'differs') notes.push(`${domain} is publishing a different key from the one this computer holds, so mail sealed by people who look you up there will not open here. The harmless reason: a key changed on another device a moment ago and this computer has not caught up — bring the change here from the keychain section. If you changed nothing, take it seriously: the published key decides who can read mail sent to you. Sealing is not blocked; you decide.`);
    if (a.legs.keychain.state === 'differs') notes.push('Your account keychain names a different current key — most likely another device made a new one. “Bring keys here” takes it (your password proves it first), or keep this computer’s key.');
  } else if (a.summary === 'unpublished') {
    head.append(el('span', 'acct-badge', `Not published by ${domain}`));
    notes.push(`${domain} answered and publishes no key for this address, so people cannot find one to seal mail to you. Publishing happens from Kaditham Mail, or from Details → Publish.`);
  } else {
    head.append(el('span', 'acct-badge', 'Not checked'));
    notes.push(`${domain}’s key directory could not be reached, so nothing was compared — not a mismatch. Check again when online.`);
  }
  if (a.independent === 'agrees') notes.push('keys.openpgp.org — run independently of Kaditham, and only after the owner confirmed the address by mail — holds the same key. Independent agreement is the strongest sign here that the domain is not showing you something different.');
  else if (a.independent === 'differs') notes.push('keys.openpgp.org holds a different key for this address. That is often an older key you published there yourself and never replaced; if you did not, someone else confirmed this address there. It does not change who can read Kaditham mail, but it is worth a look.');
  else if (a.independent === 'absent') notes.push('keys.openpgp.org holds no confirmed key for this address — no independent view, which is not a problem in itself.');
  box.append(head, g, ...notes.map((t) => el('p', 'hint', t)));
  return box;
}

// ---------------------------------------------------------------- panel

export async function showPanel(): Promise<void> {
  if (!account.signedIn()) { showSignIn(); return; }
  const card = openCard((c) => c.append(el('h2', undefined, 'Kaditham Mail'), el('p', 'hint', 'Loading your account…')), true);
  const user = account.address()!;
  const fresh = await account.ready().then(() => null, (e) => errText(e));
  const set0 = fresh ? { list: [user], complete: false, primary: null, push: null } : await account.addresses();
  const addrs = set0.list;
  const st = fresh ? null : await mk.status().catch(() => null);
  const [devs, aps] = fresh ? [{ ok: false as const, e: fresh }, { ok: false as const, e: fresh }] : await Promise.all([
    account.devices().then((d) => ({ ok: true as const, d }), (e) => ({ ok: false as const, e: errText(e) })),
    account.appPasswords().then((a) => ({ ok: true as const, a }), (e) => ({ ok: false as const, e: errText(e) })),
  ]);
  if (!checks.length || checks.some((c) => !addrs.includes(c.address)) || addrs.some((a) => !checks.some((c) => c.address === a))) checks = await computeChecks(addrs);
  if (!veil?.contains(card)) return;   // closed meanwhile
  if (!account.signedIn()) { closeCard(); return; }
  card.replaceChildren();

  const who = el('div', 'acct-who');
  who.append(el('span', 'acct-dot big', user[0].toUpperCase()));
  const lines = el('div');
  lines.append(el('b', undefined, user), el('span', 'hint', ` · ${host()}`));
  who.append(lines);
  card.append(who);
  if (fresh) card.append(el('p', 'error', fresh));
  else if (!set0.complete) card.append(el('p', 'hint', 'Your other addresses (aliases) could not be read just now — only this address is shown. Reopen the panel in a moment.'));

  if (remoteNewer !== null) card.append(changeBlock());

  // Keychain
  const kc = el('section', 'acct-sec');
  kc.append(el('h3', undefined, 'Your keychain'));
  kc.append(el('p', 'hint', st
    ? st.exists ? `Version ${st.version} · last changed ${when(st.updatedAt)}. Your keys are locked with your password inside it; the server cannot open them.`
      : 'No keychain yet. Sync now backs up the keys this computer holds for your addresses.'
    : 'Could not reach the keychain just now — your keys here keep working offline.'));
  const kcActs = el('div', 'acct-row');
  if (!st || st.exists) {
    // Retry for a first restore that failed or was skipped (argus A2).
    const bring = el('button', 'mini', 'Bring keys here');
    bring.type = 'button';
    bring.title = 'Fetch your keychain and add any keys this computer does not have yet — your password proves them first';
    bring.addEventListener('click', () => void adoptChange());
    kcActs.append(bring);
  }
  const sync = el('button', 'mini', 'Sync now');
  sync.type = 'button';
  sync.title = 'Back up the keys on this computer to your keychain';
  sync.addEventListener('click', () => void syncNow(sync));
  const syncNote = el('span', 'hint acct-sync-note');
  kcActs.append(sync, syncNote);
  kc.append(kcActs);
  card.append(kc);

  // The key check
  const ms = el('section', 'acct-sec');
  ms.append(el('h3', undefined, 'Your key, as others see it'));
  for (const c of checks) ms.append(checkBlock(c));
  const again = el('button', 'mini', 'Check again');
  again.type = 'button';
  again.addEventListener('click', async () => {
    again.disabled = true; again.textContent = 'Checking…';
    checks = await computeChecks(addrs);
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
    if (!(await confirmBox('Sign out on this computer?',
      'This ends the Kaditham Mail session on this computer only. Your keys stay here, sealed by its keychain, and keep working offline.\n\nIt does not sign out your other devices or apps — to end every session everywhere, change your Kaditham Mail password.',
      'Sign out'))) return;
    // Clear what the button shows BEFORE signOut re-renders it (argus A6).
    lastBlob = null; checks = []; remoteNewer = null;
    await account.signOut();
    renderButton();
    closeCard();
    hooks.status('Signed out on this computer. Your keys are still here.');
  });
  const close = el('button', 'primary', 'Close');
  close.type = 'button';
  close.addEventListener('click', closeCard);
  acts.append(out, close);
  card.append(acts);
}

/** Ask for the password: Saavi forgets it after every operation that needs
 *  it, so each restore, push or adoption asks once. */
async function needPassword(why: string): Promise<boolean> {
  if (account.hasSecrets()) return true;
  const got = await ask({
    title: 'Confirm your password',
    message: `${why} Saavi keeps your password in memory only for the moment it is needed, then forgets it.`,
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
  b.disabled = true;
  try {
    await account.ready();
    const set0 = await account.addresses();
    const push = set0.push;
    if (!push) {
      // A push from a partial address list would be deferred by the no-shrink
      // guard anyway; say why instead of pretending (argus A4).
      say('Your other addresses could not be read just now — nothing was synced. Try again in a moment.');
      return;
    }
    if (!(await needPassword('Syncing proves your password to the keychain.'))) return;
    const user = account.address()!;
    say('Checking for changes…');
    if (await localDiffersFromAccount(push)) {
      say('');
      await notice2('This computer and your account disagree',
        'For at least one address, this computer’s current key is not the one your account uses. Syncing now would make this computer’s key the current one on every device. Review “Your key, as others see it” first; to take the account’s key instead, use “Bring keys here”.');
      return;
    }
    const r = await mk.sync(user, push);
    say(r === 'unchanged' ? 'Already in step.' : r === 'nothing-local' ? 'Nothing here to back up yet.' : r === 'exists' ? 'Your account already has a keychain — use “Bring keys here” first.' : `Synced (${r}).`);
    const v = mk.knownVersion(user);
    if (v !== null) writeBaseline(user, v);
    remoteNewer = null;
    renderButton();
  } catch (e) {
    const m = errText(e);
    say(/proof|password confirmed/i.test(m) ? 'The server did not accept that password. Try again, or sign out and in again.' : m);
  } finally {
    account.forgetSecrets();
    b.disabled = false;
  }
}

async function notice2(title: string, message: string): Promise<void> {
  await confirmBox(title, message, 'OK');
}

/** Would a push replace the account's current key for some address? */
async function localDiffersFromAccount(addrs: string[]): Promise<boolean> {
  try { lastBlob = (await mk.fetchOnce()).blob; } catch { if (!lastBlob) return false; }
  let parsed: ReturnType<typeof mk.parseBlob>;
  try { parsed = mk.parseBlob(lastBlob!); } catch { return false; }
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

/** Bring the keychain's keys here — the banner's "Bring it here" and the
 *  panel's "Bring keys here" (argus A2). Proof-gated like every restore. */
async function adoptChange(): Promise<void> {
  try { await account.ready(); } catch (e) { hooks.status(errText(e)); return; }
  if (!(await needPassword('Bringing keys here proves them with your password.'))) return;
  const pass = account.ringSecret()!;
  openCard((card) => {
    card.classList.add('busy');
    card.append(el('h2', undefined, 'Bringing your keychain here'));
    const steps = stepList([
      ['fetch', 'Fetching your keychain'], ['unlock', 'Unlocking your keys'],
      ['seal', 'Sealing them to this computer'], ['match', 'Checking your key'],
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
        // When the published key has not caught up with the keychain, show
        // both and let the customer choose which one becomes current here.
        try {
          const src = await mk.fetchOnce();
          lastBlob = src.blob;
          const { list } = await account.addresses();
          const parsed = mk.parseBlob(src.blob);
          for (const a of list) {
            const remote = parsed.rings[a];
            if (!remote || !pgp.ringFor(a)) continue;
            const rf = await privateFpr(remote.active.privateKey).catch(() => null);
            const wf = await wkdFpr(a);
            if (rf && wf && rf !== wf) {
              fromKeychain = await confirmBox('Your published key has not caught up',
                `Your keychain names ${showFpr(rf)} as the current key for ${a}, but ${a.split('@')[1]} still publishes ${showFpr(wf)}. If you just changed it on another device, take the keychain’s. If you did not, keep what is published and check your account.`,
                'Take the keychain’s key');
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
        account.forgetSecrets();
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
      if (!account.signedIn() || account.address() !== user) return;
      // No answer (offline, a 5xx) says nothing about the keychain: keep
      // whatever the last real answer showed.
      if (v === null) return;
      const d = decideBanner(v, mk.knownVersion(user), readBaseline(user));
      if (d.baseline !== null) writeBaseline(user, d.baseline);
      remoteNewer = d.banner;
      renderButton();
    } catch { /* offline — next focus */ } finally { focusInFlight = null; }
  })();
  await focusInFlight;
}

/** Saavi made or imported a key for some address. If it is one of the
 *  account's, offer to back it up — explicit, since pushing makes it the
 *  current key on every device. */
export async function keysChanged(email: string, passUsed: string): Promise<void> {
  if (!account.signedIn()) return;
  const set0 = await account.addresses().catch(() => ({ list: [] as string[], complete: false, primary: null, push: null as string[] | null }));
  if (!set0.list.includes(email.toLowerCase())) return;
  // An alias the keychain does not accept yet (no send-as identity) is
  // left alone rather than offered and refused (argus, 0.6.2).
  if (set0.push && !set0.push.includes(email.toLowerCase())) return;
  if (!(await confirmBox('Use this key on all your devices?',
    `${email} belongs to your Kaditham Mail account. Back this key up to your keychain and make it the current key everywhere? Older keys stay, so old mail still opens.`,
    'Back it up'))) return;
  if (!set0.push) { hooks.status('Your other addresses could not be read just now — open the account panel and use Sync now in a moment.'); return; }
  try {
    await account.ready();
    if (!(await needPassword('Backing up proves your password to the keychain.'))) return;
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
    const user = account.address()!;
    const r = await mk.sync(user, set0.push);
    const v = mk.knownVersion(user);
    if (v !== null) writeBaseline(user, v);
    hooks.status(r === 'exists' ? 'Your account already has a keychain — open the account panel and use “Bring keys here” first.' : 'Backed up to your Kaditham Mail keychain.');
  } catch (e) {
    hooks.status(`Could not back it up: ${errText(e)}`);
  } finally {
    account.forgetSecrets();
  }
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
  // dev server may preview the flows against an in-page fake server;
  // production builds strip this branch.
  const preview = import.meta.env.DEV && localStorage.getItem('saavi-account-preview') === '1';
  if (!('__TAURI_INTERNALS__' in window) && !preview) { btn.hidden = true; return; }
  const resumed = await account.resume().catch(() => false);
  renderButton();
  if (!resumed && shouldOffer()) showOffer();
  window.addEventListener('focus', () => void focusCheck());
  if (resumed) void focusCheck();
}
