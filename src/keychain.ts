// OS keychain for Saavi-store passphrases — wrappers over the shell's
// keychain commands (src-tauri/src/keychain.rs). Shell only; absent in a
// plain browser and on Linux without a Secret Service daemon.

export function inShell(): boolean {
  return '__TAURI_INTERNALS__' in window;
}

async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  const { invoke } = await import('@tauri-apps/api/core');
  return invoke<T>(cmd, args);
}

let availability: Promise<boolean> | null = null;
export function available(): Promise<boolean> {
  if (!inShell()) return Promise.resolve(false);
  availability ??= call<boolean>('keychain_available').catch(() => false);
  return availability;
}
export const get = (fingerprint: string): Promise<string | null> => call('keychain_get', { fingerprint });
export const set = (fingerprint: string, passphrase: string): Promise<void> => call('keychain_set', { fingerprint, passphrase });
export const forget = (fingerprint: string): Promise<void> => call('keychain_delete', { fingerprint });
