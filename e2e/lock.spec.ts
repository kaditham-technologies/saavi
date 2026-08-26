import { test, expect } from '@playwright/test';
import { EMAIL, PASS, seed } from './fixtures';

test('Lock forgets an unlocked key; using it again asks anew', async ({ context, page }) => {
  await seed(context);
  await page.goto('/');
  // unlock by unsealing something sealed to self
  await page.click('#tab-seal');
  await page.fill('#seal-to', EMAIL);
  await page.fill('#seal-in', 'lock test');
  await page.click('#seal-enc');
  await expect(page.locator('#seal-out')).toHaveValue(/BEGIN PGP MESSAGE/, { timeout: 30_000 });
  await page.fill('#seal-in', await page.inputValue('#seal-out'));
  await page.click('#seal-dec');
  await page.fill('#m-pass', PASS);
  await page.locator('#modal-form button[type=submit], #m-go').first().click();
  await expect(page.locator('#seal-out')).toHaveValue(/lock test/, { timeout: 30_000 });

  // the keyring shows it unlocked; Lock flips it back
  await page.click('#tab-keys');
  await expect(page.locator('.dot-open')).toHaveCount(1);
  await page.click('#act-lock');
  await expect(page.locator('.dot-open')).toHaveCount(0);

  // and unsealing again demands the passphrase again
  await page.click('#tab-seal');
  await page.click('#seal-dec');
  await expect(page.locator('#modal')).toBeVisible();
});
