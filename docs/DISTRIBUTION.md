# Distribution: GitHub releases + direct download

Saavi is distributed the way Mullvad and Proton distribute their desktop
apps: the source and every release live on GitHub, **and** the same signed
binaries are offered for direct download from our own site, with the
release-signing fingerprint published there so the two channels vouch for
each other. This document is the contract between this repo and the
download page, written so Kaditham Mail, Calendar and later apps can reuse
it unchanged.

## What a release produces

Pushing a `v*` tag runs `.github/workflows/release.yml`, which publishes
to `https://github.com/kaditham-technologies/saavi/releases/tag/vX.Y.Z`:

| Asset | Purpose |
|---|---|
| `saavi_X.Y.Z_amd64.deb`, `saavi_X.Y.Z_amd64.AppImage`, `Saavi_X.Y.Z_universal.dmg`, `Saavi_X.Y.Z_x64_en-US.msi`, `Saavi_X.Y.Z_x64-setup.exe` | the installers (Tauri bundles) |
| `<asset>.sig` | detached GPG signature per binary |
| `SHA256SUMS`, `SHA256SUMS.asc` | checksums; clearsigned copy |
| `saavi_pubkey.gpg` | the release-signing public key |
| `Saavi_X.Y.Z_universal.app.tar.gz` | the macOS bundle the updater installs |
| `latest.json` | machine-readable index of all of the above, for the download page |
| `updater.json` | the Tauri updater's manifest: one entry per platform target, minisign-signed |
| release body | CHANGELOG section + a clearsigned "Verify this release" note |

`latest.json` and `updater.json` are different documents and are easy to
confuse. `latest.json` describes the release to the download page (name,
tag, signing key, checksums, assets) and has no `platforms` key; the
updater reads `updater.json` and nothing else.

The release-signing key is `DCF5 773B 84E9 AABA 785F D5A8 4D2A ECE6 8A95 3F46`.
Its fingerprint must be published on the website (not only on GitHub) so a
compromised repository cannot swap key and binaries together.

## `latest.json`

```json
{
  "name": "Saavi",
  "version": "0.1.1",
  "tag": "v0.1.1",
  "published": "2026-08-18T14:21:07Z",
  "release_url": "https://github.com/kaditham-technologies/saavi/releases/tag/v0.1.1",
  "signing_key": { "url": ".../saavi_pubkey.gpg", "fingerprint": "DCF5 773B ..." },
  "checksums": { "url": ".../SHA256SUMS", "signed": ".../SHA256SUMS.asc" },
  "assets": [
    { "name": "saavi_0.1.1_amd64.AppImage", "platform": "linux", "arch": "x86_64",
      "format": "appimage", "url": "...", "sig": "....sig", "sha256": "…" }
  ]
}
```

The newest release's manifest is always at the stable URL
`https://github.com/kaditham-technologies/saavi/releases/latest/download/latest.json`.
`platform` is `linux` / `macos` / `windows`; `format` is `deb` / `appimage` /
`dmg` / `msi`; new targets appear automatically when the bundle list grows.

## What the download page does

The page is **https://kaditham.ie/saavi/** — the URL the release note
points at — built by `~/kaditham/downloads` on the web host (see its
README; one `apps/<app>/` directory per product, so Kaditham Mail and
later apps reuse it unchanged). Every 15 minutes it:

1. Fetches the newest release from the GitHub API (server-side — the
   visitor's browser never talks to GitHub, so the page works where GitHub
   is blocked and we don't leak visitors to a third party).
2. **Mirrors, doesn't hotlink.** Downloads every asset to
   `kaditham.ie/saavi/dl/vX.Y.Z/…` and serves from there. Before anything
   is published, `SHA256SUMS.asc` and every installer's `.sig` are verified
   in a throwaway keyring holding only the pinned release key; a mismatch
   publishes nothing. A mirror that re-checks is what makes the two
   channels independent.
3. Renders one card per platform (the visitor's first), every format with
   size, SHA-256 and `.sig` link; re-publishes `latest.json` with mirror
   URLs at `kaditham.ie/saavi/latest.json`.
4. Shows the fingerprint and the `gpg --verify` steps on the page itself.
   That is the out-of-band publication step 3 of the release note relies on.

## Release checklist

Tick these in order. The ones that get forgotten are the last three: they
are the only steps whose failure looks exactly like success.

1. **Say what changed, everywhere a user reads.** CHANGELOG section for the
   new version — and if the release changes behaviour a user can see, the
   README (trust boundary, the two-faces table), `SECURITY.md` if it touches
   the trust model, and the tutorial pages on kaditham.ie. A feature that
   ships undocumented is a support question with a delay on it; a document
   that describes the old behaviour is worse than one that says nothing.
2. **Bump the version in five places:** `package.json`,
   `package-lock.json` (2 entries), `src-tauri/tauri.conf.json`,
   `src-tauri/Cargo.toml`, `src-tauri/Cargo.lock` (the `name = "saavi"`
   entry only — a dependency may share the old number).
3. **Green tests:** `npx tsc --noEmit`, `npm test`, `npx playwright test`.
   A new behaviour wants a spec that has been *seen to fail* without the
   change; one that only passes with it proves nothing.
4. **Tag and push:** `git tag -a vX.Y.Z && git push origin main --follow-tags`.
   One tag per push. The workflow builds, signs and auto-publishes.
5. **Verify the release by bytes, not by the green tick.**
   `gpg --verify SHA256SUMS.asc` — it is CLEARSIGNED, so one argument, not
   a detached pair — must print `VALIDSIG` for the pinned fingerprint, and
   at least one installer's `sha256sum` must match the signed manifest.
   Check `updater.json` carries every platform target, not `latest.json`,
   which has no `platforms` key by design.
6. **Publish the mirror:** `~/kaditham/downloads/sync-release.sh saavi`
   (the cron does it within 15 minutes; doing it by hand lets you read the
   verification output).
7. **Re-shoot the screenshots and walkthroughs.** `docs/screenshots/shots.js`
   and `docs/screenshots/walkthroughs.js` against the new build, then
   replace the images on the tutorial pages. Every screenshot carries the
   version in its status bar, so a stale one dates the whole page — and
   nobody notices, because the number sits in a corner. They had drifted
   three releases before anyone looked.
8. **Bust the CDN.** kaditham.ie is behind Cloudflare with a year-long
   `max-age` on `wp-content/uploads`, so replacing an image in place
   changes nothing for visitors. Stamp every reference `?v=X.Y.Z` and
   confirm with a byte count — a stale asset still returns 200.
9. **Check the webmail rail.** `scripts/auto-sync-core.sh` runs at `:17`
   and the status line should read `core vX.Y.Z`. Confirm from the
   deployed bundle (`grep -oh "core v0\.[0-9.]*" dist/assets/*.js`), not
   from the sync log, which reported success while shipping the wrong tag
   for weeks.

## Reusing this for other apps

Copy `release.yml`, `.github/release-verify.md` and `.github/release-install.md`, change the product
name, identifier and the fingerprint line, and provision the same two
secrets (`GPG_SIGNING_KEY`, and GitHub's own token). One signing key per
app is preferable to one key for everything: a compromise of one app's
pipeline then does not let an attacker sign another. The download page
needs only the per-app `latest.json` URL.

## Not yet

- Apple notarization / Windows Authenticode (see TODO.md) — until then
  `release-install.md` tells users how to get past the OS warnings.
- Reproducible builds so third parties can regenerate the checksums.
