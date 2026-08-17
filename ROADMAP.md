# Roadmap

Ordered by intent, not promise.

1. **OS keychain** — move keystore locking from passphrase-only to the
   platform keychain (GNOME Keyring / macOS Keychain / Windows
   Credential Manager) via the Tauri keyring plugin.
2. **Files** — drag-and-drop seal/unseal for files, not just text.
3. **System GnuPG keyring** — manage the real `~/.gnupg` (git signing,
   pass, mutt) rather than only Saavi's own store. The true KGpg
   succession. Likely via sequoia/gpgme in the Rust shell.
4. **Kaditham Mail pairing** — sign in to publish keys to the directory
   and WKD, and sync identities.
5. **Post-quantum hybrids** — ML-KEM/ML-DSA composite keys once
   OpenPGP.js ships draft-ietf-openpgp-pqc; in-app rotation as the
   migration path.
6. **Reproducible builds** — published hashes a third party can
   regenerate from source.
