# <img src="src-tauri/icons/icon.png" width="64" align="center" alt=""> Saavi

**Saavi** (சாவி, Tamil for *key*) — the friendliest face of GPG.

A small, fast desktop app for OpenPGP keys and sealed text: generate,
import, back up and manage keys in a keyring you can actually read, and
encrypt/decrypt with them — to anyone whose key is discoverable over
[WKD](https://datatracker.ietf.org/doc/html/draft-koch-openpgp-webkey-service),
including Proton Mail users.

> The browser can't fully protect your keys; this is the app that can.
> Web-based E2EE lives inside a browser profile where any extension with
> site access can watch the page. Saavi is a native shell with no
> extension ecosystem: your keys live on your device, locked with your
> passphrase, and nothing else is in the room.

Saavi is a sibling of [Muthirai](https://github.com/kaditham-technologies/muthirai)
(the seal) and [Kaditham Mail](https://mail.kaditham.ie) (the letter). It
works fully standalone — no account, no server — and pairs with Kaditham
Mail if you have it.

## Trust boundary

- **Keys are generated on your device** (OpenPGP.js, OS-grade randomness)
  and never leave it, except as a passphrase-locked backup file you
  download yourself.
- **The keystore is encrypted at rest.** Private keys are stored armored
  and locked with your passphrase (OpenPGP S2K); unlocked keys exist only
  in process memory, per session.
- **Only public keys ever travel** — outbound WKD lookups fetch other
  people's public keys; optional publishing sends yours.
- **What Saavi cannot protect against:** a compromised operating system,
  or someone with your passphrase and your device. There is no key escrow
  and no recovery; the backup file and passphrase are the whole story.

## The two faces (KGpg heritage)

| Mode | What it is |
|---|---|
| **−k Keys** | The keyring: a table of every key — address, key ID, created, active/retired, session lock state — with New / Import / Backup / Delete on a toolbar. |
| **−d Encrypt/Decrypt** | The sealer: paste or type text, name recipients (WKD lookup or paste a key), seal or unseal. |

## Build

Frontend (any machine with Docker, no local Node needed):

```sh
docker run --rm -u $(id -u) -v "$PWD":/app -w /app node:20-alpine npm ci
docker run --rm -u $(id -u) -v "$PWD":/app -w /app node:20-alpine npm run build
```

Desktop shell (needs Rust + platform webview headers; on Debian/Ubuntu:
`libwebkit2gtk-4.1-dev build-essential libssl-dev`):

```sh
cargo install tauri-cli --version '^2'
cargo tauri build        # or: cargo tauri dev
```

## License

MIT — see [LICENSE](LICENSE). Crypto policy: OpenPGP operations go through
[OpenPGP.js](https://github.com/openpgpjs/openpgpjs) only; PRs adding
bespoke or additional crypto implementations will be declined
(see [CONTRIBUTING](CONTRIBUTING.md)).
