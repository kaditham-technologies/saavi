// Network-facing flows against a MOCKED network: the update banner and the
// keyserver publish dialog, deterministic and fully offline.
import { test, expect } from '@playwright/test';
import { EMAIL, seed } from './fixtures';

const CORS = { 'access-control-allow-origin': '*', 'content-type': 'application/json' };

test('a newer manifest raises the banner; dismissal is per-version', async ({ context, page }) => {
  await seed(context, { updates: true });
  await context.route('https://kaditham.ie/wp-content/uploads/saavi/latest.json', (r) =>
    r.fulfill({ headers: CORS, json: { version: '9.9.9', published: '2027-01-01T00:00:00Z' } }));
  await page.goto('/');
  await expect(page.locator('#update-banner')).toBeVisible();
  await expect(page.locator('#update-banner-text')).toContainText('Saavi 9.9.9 is available');
  await page.click('#update-banner-x');
  await expect(page.locator('#update-banner')).toBeHidden();
  // the quiet pill stays as the reminder
  await expect(page.locator('#update-pill')).toBeVisible();
  await expect(page.locator('#update-pill')).toContainText('9.9.9');
});

test('being current raises nothing', async ({ context, page }) => {
  await seed(context, { updates: true });
  await context.route('https://kaditham.ie/wp-content/uploads/saavi/latest.json', (r) =>
    r.fulfill({ headers: CORS, json: { version: '0.0.1', published: '2020-01-01T00:00:00Z' } }));
  await page.goto('/');
  await expect(page.locator('.row')).toBeVisible(); // app settled
  await expect(page.locator('#update-banner')).toBeHidden();
  await expect(page.locator('#update-pill')).toBeHidden();
});

test('publishing a key uploads and asks for the verification mail', async ({ context, page }) => {
  await seed(context);
  await context.route('https://keys.openpgp.org/vks/v1/upload', (r) =>
    r.fulfill({ headers: CORS, json: { key_fpr: 'ABCD', token: 'tok-1', status: { [EMAIL]: 'unpublished' } } }));
  const verified: unknown[] = [];
  await context.route('https://keys.openpgp.org/vks/v1/request-verify', (r) => {
    verified.push(r.request().postDataJSON());
    return r.fulfill({ headers: CORS, json: { token: 'tok-1', status: { [EMAIL]: 'pending' } } });
  });
  await page.goto('/');
  await page.locator('.row').click();
  await page.locator('#details-acts').getByRole('button', { name: 'Publish key…' }).click();
  await page.getByRole('button', { name: /^Publish$/ }).click();
  await expect(page.getByText('One step left')).toBeVisible({ timeout: 15_000 });
  expect(verified).toHaveLength(1);
  expect(verified[0]).toMatchObject({ token: 'tok-1', addresses: [EMAIL] });
});
