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
    // CI serves the prebuilt production bundle statically: `ng serve` JIT-
    // compiles each lazy route on first hit, which starved deep-link tests
    // on the constrained runner (>60s per cold route). The workflow runs
    // `ng build` before `playwright test`. Locally we keep the dev server.
    command: process.env['CI']
      ? 'npx http-server dist/mitre-mitigation-navigator/browser -p 4200 -s'
      : 'npx ng serve --port 4200',
    port: 4200,
    // Locally a long-lived `ng serve` can go stale (dead HMR socket serving
    // an old bundle) — restart it when e2e results look impossible.
    reuseExistingServer: !process.env['CI'],
    timeout: 120000,
  },
});
