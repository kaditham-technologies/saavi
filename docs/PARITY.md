# Parity: Saavi ↔ Kaditham Mail's KGPG window

Saavi and the floating KGPG window inside the Kaditham Mail web client
are the same product in two bodies. This file is the contract that keeps
them from drifting.

## Shared core (Saavi is upstream)

`src/pgp.ts` (keystore + every OpenPGP operation) and `src/wkd.ts`
(WKD lookup) are owned HERE. The webmail vendors them via
`scripts/sync-saavi.sh` in its repo, which applies only declared,
mechanical brandings (storage prefix, backup-file wording) and records
the upstream commit in `.saavi-core-ref`. **Never edit those files in
the webmail** — change them here, then re-sync.

## Feature matrix

| Feature | Saavi | KGPG window | Notes |
|---|---|---|---|
| Key table (−k): generate/import/backup/delete, rings per address | ✓ | ✓ | shared core |
| Sealer (−d): encrypt/decrypt text | ✓ | ✓ | shared core |
| WKD recipient lookup | ✓ | ✓ | webmail: directory first, WKD fallback |
| Named themes (Paper…Phosphor) | ✓ | ✓ | shared palette family, not shared code |
| Paste-a-public-key recipient | ✓ | ✓ | armor normalized in core (single-line paste) |
| Kaditham directory publish | via pairing (planned) | ✓ | service feature, not core |
| Zero-access storage toggle | n/a | ✓ (Settings) | server feature |
| Account identities as addresses | planned pairing | ✓ | |
| OS keychain | planned | n/a (browser) | the reason Saavi exists |
| System GnuPG keyring (`gpg.rs`/`gpg.ts`) | ✓ | n/a (browser) | Saavi-only; delegates to the user's gpg |

## The rule

A new capability lands in the shared core when it is about keys or
sealing; platform-specific surfaces (service integration, OS
integration) stay in their own repo but get a row in this table —
in both copies of this file.
