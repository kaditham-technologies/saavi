# Roadmap

Ordered by intent, not promise.

1. **OS keychain** — move keystore locking from passphrase-only to the
   platform keychain (GNOME Keyring / macOS Keychain / Windows
   Credential Manager) via the Tauri keyring plugin.
2. ~~**Files**~~ — shipped: seal/unseal via buttons or drag-and-drop, both
   keyrings, signature verdicts shown.
3. ~~**System GnuPG keyring**~~ — shipped: the real `~/.gnupg` as a second
   keyring source, by delegating to the user's `gpg` binary (not gpgme or
   Sequoia: no second OpenPGP implementation, no reading gpg's private
   store). Remaining: key editing (expiry, UIDs, trust signatures),
   smartcard status, and a "which key signs my git commits" view.
4. **Kaditham Mail pairing** — sign in to publish keys to the directory
   and WKD, and sync identities.
5. **Post-quantum hybrids** — ML-KEM/ML-DSA composite keys once
   OpenPGP.js ships draft-ietf-openpgp-pqc; in-app rotation as the
   migration path.
6. **Reproducible builds** — published hashes a third party can
   regenerate from source.
