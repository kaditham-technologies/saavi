// System GnuPG keyring — typed wrappers over the shell's gpg commands
// (src-tauri/src/gpg.rs). Nothing here touches key material: the Rust side
// runs the user's own `gpg`, and passphrases are handled by gpg-agent and
// pinentry. Available only inside the Tauri shell and only when gpg exists.

export interface GpgInfo {
  found: boolean;
  path: string | null;
  version: string | null;
  homedir: string | null;
}

export interface UserId {
  uid: string;
  name: string;
  email: string;
  validity: string;
}

export interface SystemKey {
  fingerprint: string;
  key_id: string;
  algo: string;
  created: string | null;
  expires: string | null;
  validity: string;
  owner_trust: string;
  has_secret: boolean;
  revoked: boolean;
  expired: boolean;
  disabled: boolean;
  can_encrypt: boolean;
  can_sign: boolean;
  uids: UserId[];
}

export interface SignatureInfo {
  status: 'good' | 'bad' | 'unknown-key' | 'expired' | 'revoked' | 'error';
  fingerprint: string;
  key_id: string;
  uid: string;
  trust: string;
}

export interface DecryptOutcome {
  text: string;
  signatures: SignatureInfo[];
  encrypted_to: string[];
}

export interface EncryptOutcome {
  armored: string;
  untrusted: string[];
  missing: string[];
}

export interface ImportOutcome {
  imported: number;
  unchanged: number;
  secret_imported: number;
  fingerprints: string[];
}

export function inShell(): boolean {
  return '__TAURI_INTERNALS__' in window;
}

async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  const { invoke } = await import('@tauri-apps/api/core');
  return invoke<T>(cmd, args);
}

export const info = (): Promise<GpgInfo> => call('gpg_info');
export const listKeys = (): Promise<SystemKey[]> => call('gpg_list_keys');
export const exportPublic = (fingerprint: string): Promise<string> => call('gpg_export_public', { fingerprint });
export const exportSecret = (fingerprint: string): Promise<string> => call('gpg_export_secret', { fingerprint });
export const importKey = (armored: string): Promise<ImportOutcome> => call('gpg_import', { armored });
export const deletePublic = (fingerprint: string): Promise<void> => call('gpg_delete_public', { fingerprint });
export const generate = (name: string, email: string, algo: string): Promise<string> =>
  call('gpg_generate', { name, email, algo });
export const encrypt = (
  text: string,
  recipients: string[],
  opts: { signWith?: string | null; trustAll?: boolean; locateWkd?: boolean } = {},
): Promise<EncryptOutcome> =>
  call('gpg_encrypt', {
    text,
    recipients,
    signWith: opts.signWith ?? null,
    trustAll: opts.trustAll ?? false,
    locateWkd: opts.locateWkd ?? true,
  });
export const decrypt = (armored: string): Promise<DecryptOutcome> => call('gpg_decrypt', { armored });

/** Fingerprint in 4-char groups for display. */
export function fmtFpr(raw: string): string {
  return raw.toUpperCase().replace(/(.{4})/g, '$1 ').trim();
}

/** One line a person can act on: who signed, and what gpg thinks of it. */
export function describeSignature(s: SignatureInfo): string {
  const who = s.uid || (s.key_id ? `key ${s.key_id}` : 'an unknown key');
  const fpr = s.fingerprint ? ` (${fmtFpr(s.fingerprint)})` : '';
  switch (s.status) {
    case 'good': {
      const t = s.trust || 'undefined';
      const verdict =
        t === 'ultimate' || t === 'full' ? 'trusted key'
        : t === 'marginal' ? 'marginally trusted key'
        : t === 'never' ? 'a key you marked as NOT trusted'
        : 'key not yet trusted — verify the fingerprint';
      return `Good signature from ${who}${fpr} — ${verdict}.`;
    }
    case 'bad':
      return `BAD signature from ${who}${fpr} — the message was altered after signing.`;
    case 'expired':
      return `Good signature from ${who}${fpr}, but the key or signature has expired.`;
    case 'revoked':
      return `Good signature from ${who}${fpr}, but the key is REVOKED.`;
    case 'unknown-key':
      return `Signed by a key not in your keyring (${s.key_id}); cannot verify.`;
    default:
      return `Signature could not be checked (${s.key_id}).`;
  }
}
