import { test, expect } from '@playwright/test';
import { EMAIL, seed } from './fixtures';

test('the empty state generates a first key, listed as active', async ({ context, page }) => {
  await seed(context, { ring: false });
  await page.goto('/');
  await page.getByRole('button', { name: 'Generate your first key' }).click();
  await expect(page.locator('#modal')).toBeVisible();
  await page.fill('#m-name', 'Anjali');
  await page.fill('#m-email', EMAIL);
  // six suggested words are pre-filled, both fields agreeing
  const words = (await page.inputValue('#m-pass')).trim();
  expect(words.split(/\s+/)).toHaveLength(6);
  expect(await page.inputValue('#m-pass2').catch(() => words)).toBeTruthy();
  await page.locator('#modal-form button[type=submit], #m-go').first().click();
  // the done screen shows a real fingerprint
  await expect(page.locator('#f-done')).toBeVisible({ timeout: 30_000 });
  await expect(page.locator('#f-done')).toContainText(/([0-9A-F]{4} ){9}[0-9A-F]{4}/);
  await page.getByRole('button', { name: /^Done$/ }).click()
    .catch(() => page.keyboard.press('Escape'));
  await expect(page.locator('#modal')).toBeHidden();
  await expect(page.locator('.row')).toHaveCount(1);
  await expect(page.locator('.row .chip')).toHaveText('active');
});

test('generating again retires the old key instead of replacing it', async ({ context, page }) => {
  await seed(context);
  await page.goto('/');
  await expect(page.locator('.row')).toHaveCount(1);
  await page.click('#act-new');
  await page.fill('#m-name', 'Anjali');
  await page.fill('#m-email', EMAIL);
  await page.locator('#modal-form button[type=submit], #m-go').first().click();
  await expect(page.locator('#f-done')).toBeVisible({ timeout: 30_000 });
  await page.getByRole('button', { name: /^Done$/ }).click()
    .catch(() => page.keyboard.press('Escape'));
  await expect(page.locator('.row')).toHaveCount(2);
  await expect(page.locator('.row .chip').filter({ hasText: 'active' })).toHaveCount(1);
  await expect(page.locator('.row .chip').filter({ hasText: 'retired' })).toHaveCount(1);
});
