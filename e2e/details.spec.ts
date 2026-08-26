import { test, expect } from '@playwright/test';
import { EMAIL, seed } from './fixtures';

test('a single click on a key opens its details', async ({ context, page }) => {
  await seed(context);
  await page.goto('/');
  await page.locator('.row').click();
  await expect(page.locator('#details')).toBeVisible();
  await expect(page.locator('#details-title')).toHaveText(EMAIL);
  await expect(page.locator('#details-body')).toContainText('Fingerprint');
  await expect(page.locator('#details-body')).toContainText(/([0-9A-F]{4} ){9}[0-9A-F]{4}/);
  for (const label of ['Copy fingerprint', 'Export public key…', 'Show public key', 'Publish key…', 'Revocation certificate…']) {
    await expect(page.locator('#details-acts').getByRole('button', { name: label })).toBeVisible();
  }
  await page.click('#details-close');
  await expect(page.locator('#details')).toBeHidden();
});

test('the revocation certificate saves without an unlock (captured at generation)', async ({ context, page }) => {
  await seed(context);
  await page.goto('/');
  await page.locator('.row').click();
  await page.locator('#details-acts').getByRole('button', { name: 'Revocation certificate…' }).click();
  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Save…' }).click();
  const file = await download;
  expect(file.suggestedFilename()).toContain('revocation');
});
