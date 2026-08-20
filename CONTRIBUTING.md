# Contributing

Thanks for taking the time to contribute! Saavi is small but it holds
people's keys, so we ask for rigour over speed.

## Repo layout

- `src/pgp.ts` — the keystore and every OpenPGP operation. **OpenPGP.js
  only** — PRs adding bespoke or additional crypto will be declined.
- `src/wkd.ts` — Web Key Directory lookup (hashing + fetch, no crypto).
- `src/gpg.ts` — typed wrappers for the system-GnuPG commands; no logic.
- `src/main.ts` — the app: the −k key table and the −d sealer, branching
  on the keyring source (Saavi store / System GnuPG).
- `src/style.css` — the design system; tokens at the top, sections below.
- `src-tauri/src/gpg.rs` — the system keyring: runs the user's `gpg` with
  fixed arguments, parses `--with-colons` and `--status-fd`. **Never a
  second OpenPGP implementation here** — if gpg can't do it, we don't.
  Every input that becomes an argument is validated; everything else is
  stdin. `cargo test` covers the parsers and a live round trip.
- `src-tauri/` otherwise stays thin: window, the dialog/fs/http plugins,
  (later) OS keychain. Logic stays in the frontend.
- `docs/` — [ROADMAP](docs/ROADMAP.md) and the [parity contract](docs/PARITY.md)
  with Kaditham Mail's KGPG window (`pgp.ts`/`wkd.ts` are upstream here).

## Ground rules

- No new runtime dependencies without an issue discussing why. The
  frontend has one library dependency (openpgp) plus the Tauri bridge
  packages; keeping the audit surface small is a feature.
- Anything touching `gpg.rs` needs a Rust test (`cd src-tauri && cargo test`;
  the live test needs `gpg` on PATH and skips otherwise).
- Anything touching `pgp.ts` or `wkd.ts` needs a test in `tests/`
  (`npm test`, vitest against real OpenPGP.js — no mocks of the crypto),
  or a written argument for why a test cannot express the property.
- User-facing copy is part of the product: plain sentences, no jargon,
  honest about limits. Match the existing voice.
- CI builds the frontend (`npm run build`, strict TypeScript, zero
  errors), runs `npm test`, builds the Linux shell, and runs `npm audit` / `cargo audit`.
  There is no formatter; follow `.editorconfig` and the surrounding style.
- Security issues go to the address in [SECURITY.md](SECURITY.md), not to
  the issue tracker.

## Developing

```sh
npm ci && npm run dev        # frontend only, in a browser
npm test                     # keystore / WKD suite
cargo tauri dev              # the real shell
```
