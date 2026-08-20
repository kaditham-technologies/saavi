# Third-party notices

Saavi is MIT-licensed (see [LICENSE](LICENSE)). It builds on the following
open-source components, which keep their own licenses.

## Frontend (bundled into the app)

| Component | License | Role |
|---|---|---|
| [OpenPGP.js](https://github.com/openpgpjs/openpgpjs) | LGPL-3.0-or-later | every OpenPGP operation |
| [@tauri-apps/api](https://github.com/tauri-apps/tauri) and plugins (dialog, fs, http) | MIT OR Apache-2.0 | bridge to the desktop shell |

OpenPGP.js is LGPL. To honour the LGPL's relinking requirement it is built
as its own chunk (`dist/assets/openpgp-*.js`, see `vite.config.ts`) rather
than being inlined into Saavi's code, so a user can replace it with their
own build of the library. Saavi does not modify OpenPGP.js.

## Desktop shell (Rust)

[Tauri](https://tauri.app) 2 and its plugins, MIT OR Apache-2.0, plus their
transitive crates — run `cargo license` or `cargo deny list` in `src-tauri/`
for the full tree. Linux builds link dynamically against the system
WebKitGTK (LGPL-2.1+) and GTK (LGPL-2.1+).

## Build-time only (not shipped)

Vite (MIT), TypeScript (Apache-2.0), tauri-cli (MIT OR Apache-2.0).

The full JavaScript tree with per-package license fields is in
`package-lock.json` (`npm ls --all` / `npx license-checker`).
