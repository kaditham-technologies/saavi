import { test, expect } from '@playwright/test';
import { EMAIL, PASS, seed } from './fixtures';

const LETTER = 'Meet me at the harbour at six — bring the good coffee.';

test('seal to self, then unseal after unlocking — the letter survives', async ({ context, page }) => {
  await seed(context);
  await page.goto('/');
  await page.click('#tab-seal');
  await page.fill('#seal-to', EMAIL);
  await page.fill('#seal-in', LETTER);
  await page.click('#seal-enc');
  await expect(page.locator('#seal-out')).toHaveValue(/BEGIN PGP MESSAGE/, { timeout: 30_000 });

  // round-trip: paste the armor back and unseal — the locked key demands
  // its passphrase through the unlock dialog first
  const armor = await page.inputValue('#seal-out');
  await page.fill('#seal-in', armor);
  await page.click('#seal-dec');
  await expect(page.locator('#modal')).toBeVisible();
  await page.fill('#m-pass', PASS);
  await page.locator('#modal-form button[type=submit], #m-go').first().click();
  await expect(page.locator('#seal-out')).toHaveValue(new RegExp(LETTER.slice(0, 20)), { timeout: 30_000 });
});

test('a wrong passphrase does not unlock', async ({ context, page }) => {
  await seed(context);
  await page.goto('/');
  await page.click('#tab-seal');
  await page.fill('#seal-to', EMAIL);
  await page.fill('#seal-in', LETTER);
  await page.click('#seal-enc');
  await expect(page.locator('#seal-out')).toHaveValue(/BEGIN PGP MESSAGE/, { timeout: 30_000 });
  await page.fill('#seal-in', await page.inputValue('#seal-out'));
  await page.click('#seal-dec');
  await expect(page.locator('#modal')).toBeVisible();
  await page.fill('#m-pass', 'not the passphrase');
  await page.locator('#modal-form button[type=submit], #m-go').first().click();
  // the dialog stays, an error shows, and no plaintext appears
  await expect(page.locator('#modal')).toBeVisible();
  await expect(page.locator('#m-err')).toBeVisible();
});
