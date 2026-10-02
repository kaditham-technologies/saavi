# Roadmap

Ordered by intent, not promise.

1. ~~**OS keychain**~~ — shipped: opt-in per key; the passphrase is kept
   in the platform store (`keyring` crate) and the key unlocks silently.
2. ~~**Files**~~ — shipped: seal/unseal via buttons or drag-and-drop, both
   keyrings, signature verdicts shown.
3. ~~**System GnuPG keyring**~~ — shipped: the real `~/.gnupg` as a second
   keyring source, by delegating to the user's `gpg` binary (not gpgme or
   Sequoia: no second OpenPGP implementation, no reading gpg's private
   store). Remaining: key editing (expiry, UIDs, trust signatures),
   smartcard status, and a "which key signs my git commits" view.
4. ~~**Kaditham Mail pairing**~~ — shipped in 0.6.0 as sign in with
   Kaditham Mail: keychain restore and sync, the published-key match check,
   the device list (docs/ACCOUNT-SIGNIN.md). Remaining: QR device pairing
   (KEY-SYNC S2, 0.7.0), device revocation and pin sync (S3).
5. **Post-quantum hybrids** — ML-KEM/ML-DSA composite keys once
   OpenPGP.js ships draft-ietf-openpgp-pqc; in-app rotation as the
   migration path.
6. **Reproducible builds** — published hashes a third party can
   regenerate from source.
