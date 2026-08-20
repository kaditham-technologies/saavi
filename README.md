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
- **Private keys are passphrase-locked at rest** (OpenPGP S2K, armored);
  addresses and public keys sit beside them in the clear. Unlocked keys
  exist only in process memory, per session.
- **Only public keys ever travel** — the app's sole network use is
  fetching other people's public keys over WKD (in system mode, gpg's own
  `--auto-key-locate wkd`). Nothing is uploaded.
- **System GnuPG mode adds no new key handling.** Saavi runs `gpg`; it
  does not read `~/.gnupg`, hold secret keys, or see passphrases.
- **What Saavi cannot protect against:** a compromised operating system,
  or someone with your passphrase and your device. There is no key escrow
  and no recovery; the backup file and passphrase are the whole story.

## Two keyrings

| Source | Where keys live | Needs |
|---|---|---|
| **Saavi store** (default) | Saavi's own passphrase-locked store, via OpenPGP.js | nothing — works on any machine |
| **System GnuPG** | your real `~/.gnupg`: the keys git, pass, mutt and Kleopatra use | GnuPG installed (Gpg4win, GPG Suite/Homebrew, or your distro's package) |

In system mode Saavi is a face for **your own `gpg`**: every operation is
the gpg binary with a fixed argument set; listing is `--with-colons`,
outcomes come from `--status-fd`. gpg-agent and your pinentry handle
passphrases (and smartcards), so Saavi never sees them. Trust is gpg's web
of trust: an untrusted recipient key is refused until you say "this once",
and every unsealed message shows gpg's signature verdict — who signed,
fingerprint, and how far you trust that key. Saavi will not delete secret
keys from the GnuPG keyring.

## The two faces (KGpg heritage)

| Mode | What it is |
|---|---|
| **−k Keys** | The keyring: a table of every key — address, key ID, created, status/trust, secret-key presence — with New / Import / Backup / Delete / Details on a toolbar. Details shows fingerprint, subkeys, user IDs, and (system keyring) lets you set expiry, change passphrase, add or revoke user IDs, set owner trust, certify keys, fetch from keys.openpgp.org. |
| **−d Encrypt/Decrypt** | The sealer: paste or type text, name recipients (WKD / keys.openpgp.org lookup, or paste a key), choose whether to sign, then Seal, Unseal, Sign (clearsign) or Verify. Drop a file on the window to seal it; drop a `.gpg` to unseal. Signature verdicts are shown on every unseal and verify. |

Tired of typing it? Tick **remember in the OS keychain** when unlocking
and Saavi opens the key through macOS Keychain / Windows Credential
Manager / your Linux keyring instead — per key, opt-in, reversible.

First key? The wizard can **suggest a passphrase** — six random words
from the EFF list, about 77 bits — and asks you to keep it in a password
manager (KeePassXC, Bitwarden). Saavi will not try to be one.

## Build

Frontend (any machine with Docker, no local Node needed):

```sh
docker run --rm -u $(id -u) -v "$PWD":/app -w /app node:22-alpine npm ci
docker run --rm -u $(id -u) -v "$PWD":/app -w /app node:22-alpine npm run build
```

Desktop shell (needs Rust + platform webview headers; on Debian/Ubuntu:
`libwebkit2gtk-4.1-dev build-essential libssl-dev libdbus-1-dev`):

```sh
cargo install tauri-cli --version '^2'
cargo tauri build        # or: cargo tauri dev
```

## License

MIT — see [LICENSE](LICENSE). Crypto policy: OpenPGP operations go through
[OpenPGP.js](https://github.com/openpgpjs/openpgpjs) only; PRs adding
bespoke or additional crypto implementations will be declined
(see [CONTRIBUTING](CONTRIBUTING.md)). Third-party licenses, including
OpenPGP.js (LGPL-3.0-or-later), are listed in
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

## More

- [CHANGELOG](CHANGELOG.md) · [Roadmap](docs/ROADMAP.md) · [Parity with Kaditham Mail](docs/PARITY.md) · [Distribution](docs/DISTRIBUTION.md)
- [Contributing](CONTRIBUTING.md) · [TODO / hardening backlog](TODO.md) · [Security policy](SECURITY.md) · [Code of conduct](CODE_OF_CONDUCT.md)
- Downloads: [GitHub releases](https://github.com/kaditham-technologies/saavi/releases)
  (Linux `.deb`/`.AppImage`, macOS `.dmg`, Windows `.msi`/`.exe` — all
  GPG-signed, with `SHA256SUMS.asc` and `latest.json`), mirrored
  on the Kaditham site. Every release carries a clearsigned verification
  note; the signing-key fingerprint is published on the website too.
