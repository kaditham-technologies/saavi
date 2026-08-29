import { test, expect } from '@playwright/test';
import { EMAIL, OTHER_EMAIL, PASS, otherKey, seed } from './fixtures';

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

test('an unsigned seal to someone else stays readable to the sender', async ({ context, page }) => {
  // The bug this pins: the sender's own key was only added when a "Sign as"
  // identity was chosen, so an unsigned seal to somebody else produced
  // ciphertext the sender could never open again — while the tutorial
  // promised a copy always came back to them.
  await seed(context);
  await page.goto('/');
  await page.click('#tab-seal');
  await page.fill('#seal-to', otherKey());      // a pasted key: no network needed
  await page.fill('#seal-in', LETTER);
  await page.selectOption('#seal-sign', '');    // explicitly NOT signing
  await page.click('#seal-enc');
  await expect(page.locator('#seal-out')).toHaveValue(/BEGIN PGP MESSAGE/, { timeout: 30_000 });
  await expect(page.locator('#seal-out-label')).toHaveText(/also readable by you/);

  // Sealed to Dara, unsealed by us: only the self copy can make this work.
  await page.fill('#seal-in', await page.inputValue('#seal-out'));
  await page.click('#seal-dec');
  await expect(page.locator('#modal')).toBeVisible();
  await page.fill('#m-pass', PASS);
  await page.locator('#modal-form button[type=submit], #m-go').first().click();
  await expect(page.locator('#seal-out')).toHaveValue(new RegExp(LETTER.slice(0, 20)), { timeout: 30_000 });
  expect(OTHER_EMAIL).not.toBe(EMAIL);
});

test('a pasted key does not swallow the addresses beside it', async ({ context, page }) => {
  // Before: any pasted key short-circuited the whole To field, so typed
  // addresses were dropped without a word — the sender believed everyone
  // listed could open the letter. Now the address is a real recipient, so
  // its failed lookup stops the seal instead of vanishing.
  await seed(context);
  await page.goto('/');
  await page.click('#tab-seal');
  await page.fill('#seal-to', `${otherKey()}\nnobody@example.invalid`);
  await page.fill('#seal-in', LETTER);
  await page.click('#seal-enc');
  await expect(page.locator('#seal-err')).toBeVisible({ timeout: 60_000 });
  await expect(page.locator('#seal-err')).toContainText('nobody@example.invalid');
  await expect(page.locator('#seal-out-fld')).toBeHidden();
});
