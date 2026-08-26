// Generate ONE demo key for the whole run (a curve25519 keypair takes about
// a second; per-test generation would dominate the suite) and park it where
// the fixtures can seed it into localStorage.
import { mkdirSync, writeFileSync } from 'node:fs';
import { EMAIL, PASS, RING_FILE } from './fixtures';

export default async function globalSetup(): Promise<void> {
  const openpgp = await import('openpgp');
  const { privateKey, publicKey, revocationCertificate } = await openpgp.generateKey({
    userIDs: [{ name: 'Anjali', email: EMAIL }],
    passphrase: PASS,
    type: 'ecc',
    curve: 'curve25519Legacy',
    format: 'armored',
  });
  mkdirSync('e2e/.artifacts', { recursive: true });
  writeFileSync(RING_FILE, JSON.stringify({
    active: { publicKey, privateKey, created: new Date().toISOString(), revocationCertificate },
    retired: [],
  }));
}
