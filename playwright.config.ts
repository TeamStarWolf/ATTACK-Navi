// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { defineConfig } from '@playwright/test';

const CI = !!process.env['CI'];

export default defineConfig({
  testDir: './e2e',
  // CI serves a cold static build on a constrained runner; give each test a
  // much larger envelope there so a cold deep-link chunk load doesn't time out.
  timeout: CI ? 120000 : 30000,
  // One retry on CI absorbs a genuinely slow runner, but a test that only
  // passes on retry is reported as `flaky` in the JSON report and
  // e2e/check-flaky.mjs fails the workflow on it, so retries never hide a
  // real intermittent failure. Locally a failure is a failure.
  retries: CI ? 1 : 0,
  reporter: CI
    ? [['list'], ['json', { outputFile: 'playwright-report/results.json' }], ['html', { open: 'never' }]]
    : 'list',
  use: {
    baseURL: 'http://localhost:4200',
    headless: true,
    screenshot: 'only-on-failure',
    trace: CI ? 'retain-on-failure' : 'off',
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
    command: CI
      ? 'npx http-server dist/mitre-mitigation-navigator/browser -p 4200 -s'
      : 'npx ng serve --port 4200',
    port: 4200,
    // Locally a long-lived `ng serve` can go stale (dead HMR socket serving
    // an old bundle) — restart it when e2e results look impossible.
    reuseExistingServer: !CI,
    timeout: 180000,
  },
});
