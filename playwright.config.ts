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
    // CI: statically serve a DEVELOPMENT build (the workflow runs
    // `ng build -c development` first). The dev config sets
    // `serviceWorker: false`, which is the key: the production ngsw worker
    // intercepts the ATT&CK fetch below Playwright's page.route and breaks
    // data interception, while `ng serve`'s per-route JIT compilation starved
    // deep-link tests on the constrained runner. A prebuilt SW-free bundle
    // avoids both failure modes.
    // Locally: plain dev server.
    command: process.env['CI']
      ? 'npx http-server dist/mitre-mitigation-navigator/browser -p 4200 -s'
      : 'npx ng serve --port 4200',
    port: 4200,
    // Locally a long-lived `ng serve` can go stale (dead HMR socket serving
    // an old bundle) — restart it when e2e results look impossible.
    reuseExistingServer: !process.env['CI'],
    timeout: 180000,
  },
});
