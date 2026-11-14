// SPDX-License-Identifier: MIT
import { defineConfig, devices } from '@playwright/test';

// Chromium always; Firefox and WebKit where installed (GZ_BROWSERS=chromium,firefox,webkit).
const wanted = (process.env.GZ_BROWSERS || 'chromium').split(',');
const all = {
  chromium: devices['Desktop Chrome'],
  firefox: devices['Desktop Firefox'],
  webkit: devices['Desktop Safari'],
};

export default defineConfig({
  testDir: '.',
  testMatch: /.*\.spec\.mjs/,
  timeout: 30000,
  workers: 1,
  reporter: [['list']],
  projects: wanted.map((name) => ({ name, use: { ...all[name], headless: true } })),
});
