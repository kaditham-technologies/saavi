# Contributing

Thanks for taking the time to contribute! Saavi is small but it holds
people's keys, so we ask for rigour over speed.

## Repo layout

- `src/pgp.ts` — the keystore and every OpenPGP operation. **OpenPGP.js
  only** — PRs adding bespoke or additional crypto will be declined.
- `src/wkd.ts` — Web Key Directory lookup (hashing + fetch, no crypto).
- `src/main.ts` — the app: the −k key table and the −d sealer.
- `src/style.css` — the design system; tokens at the top, sections below.
- `src-tauri/` — the Rust shell. Kept deliberately thin: window, the
  dialog/fs/http plugins, (later) OS keychain. Logic stays in the frontend.
- `docs/` — [ROADMAP](docs/ROADMAP.md) and the [parity contract](docs/PARITY.md)
  with Kaditham Mail's KGPG window (`pgp.ts`/`wkd.ts` are upstream here).

## Ground rules

- No new runtime dependencies without an issue discussing why. The
  frontend has one library dependency (openpgp) plus the Tauri bridge
  packages; keeping the audit surface small is a feature.
- Anything touching `pgp.ts` or `wkd.ts` needs a written argument in the
  PR for why the change is correct (there is no test suite yet — adding
  one is welcome and would be the first thing we'd merge).
- User-facing copy is part of the product: plain sentences, no jargon,
  honest about limits. Match the existing voice.
- CI builds the frontend (`npm run build`, strict TypeScript, zero
  errors), builds the Linux shell, and runs `npm audit` / `cargo audit`.
  There is no formatter; follow `.editorconfig` and the surrounding style.
- Security issues go to the address in [SECURITY.md](SECURITY.md), not to
  the issue tracker.

## Developing

```sh
npm ci && npm run dev        # frontend only, in a browser
cargo tauri dev              # the real shell
```
