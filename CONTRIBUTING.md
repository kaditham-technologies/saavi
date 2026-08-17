# Contributing

Thanks for taking the time to contribute! Saavi is small but it holds
people's keys, so we ask for rigour over speed.

## Repo layout

- `src/pgp.ts` — the keystore and every OpenPGP operation. **OpenPGP.js
  only** — PRs adding bespoke or additional crypto will be declined.
- `src/wkd.ts` — Web Key Directory lookup (hashing + fetch, no crypto).
- `src/main.ts` — the app: the −k key table and the −d sealer.
- `src/style.css` — the design system; tokens at the top, sections below.
- `src-tauri/` — the Rust shell. Kept deliberately thin: window, menu,
  (later) OS keychain and file dialogs. Logic stays in the frontend.

## Ground rules

- No new runtime dependencies without an issue discussing why. The
  frontend has exactly one (openpgp); keeping the audit surface small is
  a feature.
- Anything touching `pgp.ts` needs tests or a written argument for why a
  test cannot express the property.
- User-facing copy is part of the product: plain sentences, no jargon,
  honest about limits. Match the existing voice.
- Formatting/lint runs in CI; `npm run build` must pass with zero
  TypeScript errors.

## Developing

```sh
npm ci && npm run dev        # frontend only, in a browser
cargo tauri dev              # the real shell
```
