import { defineConfig, devices } from '@playwright/test';

/**
 * E2E config for the accessibility (axe-core) regression gate.
 * Serves the built site via `vite preview` under the repo's base path
 * (/crypto-lab-mpcith-sign/) and scans it with a single Chromium project.
 */
const PORT = 4242;
const BASE = '/crypto-lab-mpcith-sign/';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: 'list',
  use: {
    baseURL: `http://localhost:${PORT}${BASE}`,
    colorScheme: 'dark',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: {
    command: `npm run preview -- --port ${PORT} --strictPort`,
    url: `http://localhost:${PORT}${BASE}`,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
