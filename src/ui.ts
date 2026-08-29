// In-app dialogs. window.confirm/prompt are unreliable inside webviews
// (WKWebView returns null for prompt, and confirm looks alien), so every
// question Saavi asks goes through here: one promise, keyboard-friendly,
// themed like the rest of the app.

export interface AskField {
  name: string;
  label: string;
  type?: 'text' | 'password' | 'select' | 'email';
  value?: string;
  options?: { value: string; label: string }[];
  placeholder?: string;
  hint?: string;
}

export interface AskOptions {
  title: string;
  message?: string;
  fields?: AskField[];
  ok?: string;
  cancel?: string;
  danger?: boolean;
  /** Long text shown in a mono box (fingerprints, key blocks). */
  code?: string;
}

let open: { el: HTMLElement; cancel: () => void } | null = null;

function el<K extends keyof HTMLElementTagNameMap>(tag: K, cls?: string, text?: string): HTMLElementTagNameMap[K] {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}

/** Ask a question. Resolves to the field values, or null when dismissed. */
export function ask(o: AskOptions): Promise<Record<string, string> | null> {
  return new Promise((resolve) => {
    // Only one question at a time; a superseded one answers "dismissed".
    open?.cancel();
    const veil = el('div', 'veil ask-veil');
    const card = el('form', 'card ask-card');
    veil.append(card);
    card.append(el('h2', undefined, o.title));
    if (o.message) card.append(el('p', 'hint', o.message));
    // Anything shown in the code box is there to be USED elsewhere — a
    // fingerprint to read down the phone, a public key to paste into a mail.
    // Drag-selecting an armored block inside a webview is miserable, so the
    // box carries its own copy button.
    if (o.code) {
      const wrap = el('div', 'ask-code-wrap');
      wrap.append(el('pre', 'fpr ask-code', o.code));
      const copy = el('button', 'mini ask-copy', 'Copy');
      copy.type = 'button';
      copy.addEventListener('click', async () => {
        try {
          await navigator.clipboard.writeText(o.code!);
          copy.textContent = 'Copied';
        } catch {
          // Clipboard denied: select it instead, so the keyboard still works.
          const pre = wrap.querySelector('pre');
          if (pre) {
            const r = document.createRange();
            r.selectNodeContents(pre);
            const sel = window.getSelection();
            sel?.removeAllRanges();
            sel?.addRange(r);
          }
          copy.textContent = 'Selected';
        }
        setTimeout(() => { copy.textContent = 'Copy'; }, 1600);
      });
      wrap.append(copy);
      card.append(wrap);
    }
    const inputs: { name: string; get: () => string }[] = [];
    for (const f of o.fields ?? []) {
      const lab = el('label', 'fld');
      lab.append(el('span', undefined, f.label));
      if (f.type === 'select') {
        const s = el('select');
        for (const opt of f.options ?? []) s.append(new Option(opt.label, opt.value, false, opt.value === f.value));
        lab.append(s);
        inputs.push({ name: f.name, get: () => s.value });
      } else {
        const i = el('input');
        i.type = f.type ?? 'text';
        i.value = f.value ?? '';
        if (f.placeholder) i.placeholder = f.placeholder;
        i.autocomplete = 'off';
        i.spellcheck = false;
        lab.append(i);
        inputs.push({ name: f.name, get: () => i.value });
      }
      if (f.hint) lab.append(el('span', 'hint', f.hint));
      card.append(lab);
    }
    const acts = el('div', 'card-acts');
    const cancel = el('button', undefined, o.cancel ?? 'Cancel');
    cancel.type = 'button';
    // notice() passes cancel:'' to mean "there is only one way out of this
    // dialog" — an empty button still rendered, a blank chip beside Close.
    cancel.hidden = o.cancel === '';
    const ok = el('button', 'primary' + (o.danger ? ' danger' : ''), o.ok ?? 'OK');
    ok.type = 'submit';
    acts.append(cancel, ok);
    card.append(acts);
    const done = (v: Record<string, string> | null): void => {
      veil.remove();
      if (open?.el === veil) open = null;
      document.removeEventListener('keydown', onKey);
      resolve(v);
    };
    const onKey = (e: KeyboardEvent): void => {
      if (e.key === 'Escape') { e.stopPropagation(); done(null); }
    };
    cancel.addEventListener('click', () => done(null));
    card.addEventListener('submit', (e) => {
      e.preventDefault();
      done(Object.fromEntries(inputs.map((i) => [i.name, i.get()])));
    });
    document.addEventListener('keydown', onKey, true);
    document.body.append(veil);
    open = { el: veil, cancel: () => done(null) };
    const first = card.querySelector<HTMLElement>('input, select') ?? ok;
    first.focus();
  });
}

export async function confirmBox(title: string, message: string, ok = 'Continue', danger = false, code?: string): Promise<boolean> {
  return (await ask({ title, message, ok, danger, code })) !== null;
}

export async function notice(title: string, message: string, code?: string): Promise<void> {
  await ask({ title, message, ok: 'Close', cancel: '', code }).then(() => undefined);
}
