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
| `latest.json` | machine-readable index of all of the above |
| release body | CHANGELOG section + a clearsigned "Verify this release" note |

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
- In-app update checks (would use `latest.json`; the Tauri updater plugin
  needs its own minisign key — a separate decision).
- Reproducible builds so third parties can regenerate the checksums.
