// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  // CI's `ng serve` JIT-compiles lazy routes on first hit; give each test a
  // much larger envelope there so a cold deep-link compile doesn't time out.
  timeout: process.env['CI'] ? 120000 : 30000,
  retries: 1,
  use: {
    baseURL: 'http://localhost:4200',
    headless: true,
    screenshot: 'only-on-failure',
  },
  webServer: {
    // Dev server (both locally and in CI). It compiles lazy routes on first
    // hit, so deep-link tests get generous CI timeouts (see ROUTE_TIMEOUT in
    // the spec). We deliberately do NOT serve the production build here: that
    // build registers the ngsw service worker, which intercepts the ATT&CK
    // fetch below Playwright's page.route and breaks data interception under
    // test. E2E is non-blocking (its own workflow), so the slower dev serve is
    // an acceptable trade for reliable interception.
    command: 'npx ng serve --port 4200',
    port: 4200,
    // Locally a long-lived `ng serve` can go stale (dead HMR socket serving
    // an old bundle) — restart it when e2e results look impossible.
    reuseExistingServer: !process.env['CI'],
    timeout: 180000,
  },
});
