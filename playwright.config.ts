// E2E of the browser build — the same code the webmail's KGPG window
// vendors, so these specs are also the parity floor for the shared core.
// The Tauri-only half (system GnuPG, native dialogs, installers) is out of
// scope here; it would need tauri-driver and real OS sessions.
import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  globalSetup: './e2e/global-setup',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'list' : [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: 'http://localhost:4173',
    viewport: { width: 1060, height: 680 },
  },
  webServer: {
    // dist/ is static; python needs no node-version dance in CI images.
    command: 'python3 -m http.server 4173 -d dist',
    url: 'http://localhost:4173/',
    reuseExistingServer: !process.env.CI,
  },
});
