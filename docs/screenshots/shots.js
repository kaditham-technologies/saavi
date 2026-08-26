// Screenshot rig: serve the built frontend, seed a demo ring, photograph
// the flows the tutorial pages narrate. Output: /out/*.png at 2x.
const { chromium } = require('playwright');

const PASS = 'lantern-orbit-velvet-canyon-ember-tide';

async function demoRing() {
  const openpgp = await import('/app/node_modules/openpgp/dist/node/openpgp.mjs');
  const { privateKey, publicKey, revocationCertificate } = await openpgp.generateKey({
    userIDs: [{ name: 'Anjali', email: 'anjali@example.ie' }],
    passphrase: PASS,
    type: 'ecc', curve: 'curve25519Legacy', format: 'armored',
  });
  return { active: { publicKey, privateKey, created: new Date().toISOString(), revocationCertificate }, retired: [] };
}

(async () => {
  const ring = JSON.stringify(await demoRing());
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1060, height: 680 }, deviceScaleFactor: 2 });
  await ctx.addInitScript(([r]) => {
    localStorage.setItem('saavi-ring-anjali@example.ie', r);
    localStorage.setItem('saavi-update-check', 'off');
  }, [ring]);
  const page = await ctx.newPage();
  await page.goto('http://localhost:4173/');
  await page.waitForSelector('.row', { timeout: 15000 });
  await page.waitForTimeout(400);

  // 1. the keyring table
  await page.screenshot({ path: '/out/keyring.png' });

  // 2. click the key → details modal
  await page.click('.row');
  await page.waitForSelector('#details:not([hidden])');
  await page.waitForTimeout(500);
  await page.screenshot({ path: '/out/details.png' });
  await page.click('#details-close');

  // 3. New key → the generate modal with suggested words
  await page.click('#act-new');
  await page.waitForSelector('#modal:not([hidden])');
  await page.fill('#m-name', 'Anjali');
  await page.fill('#m-email', 'anjali@example.ie');
  await page.waitForTimeout(400);
  await page.screenshot({ path: '/out/generate.png' });

  // 4. actually generate → the "Your key is ready" screen
  await page.click('#m-go');
  await page.waitForSelector('#f-done:not([hidden])', { timeout: 60000 });
  await page.waitForTimeout(400);
  await page.screenshot({ path: '/out/done.png' });
  await page.click('#m-cancel').catch(() => {});
  await page.keyboard.press('Escape');
  await page.waitForTimeout(400);

  // 5. the sealer, filled, and sealed to self
  await page.click('#tab-seal');
  await page.fill('#seal-to', 'anjali@example.ie');
  await page.fill('#seal-in', 'Meet me at the harbour at six — bring the good coffee.\n\n— A');
  await page.waitForTimeout(200);
  await page.screenshot({ path: '/out/sealer.png' });
  await page.click('#seal-enc');
  await page.waitForTimeout(4000);
  await page.screenshot({ path: '/out/sealed.png' });

  await browser.close();
  console.log('done');
})().catch((e) => { console.error(e); process.exit(1); });
