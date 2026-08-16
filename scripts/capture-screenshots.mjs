// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Captures the README screenshots from a running dev server (default
// http://localhost:4200). Overwrites the files referenced by README.md.
//
// Usage: npx ng serve  (in another terminal)  then:
//        node scripts/capture-screenshots.mjs

import { chromium } from '@playwright/test';

const BASE = process.env.BASE_URL ?? 'http://localhost:4200';
const VIEWPORT = { width: 1600, height: 900 };

const browser = await chromium.launch();
const context = await browser.newContext({ viewport: VIEWPORT, deviceScaleFactor: 2 });

// Skip onboarding; ensure dark theme for consistent shots.
await context.addInitScript(() => {
  localStorage.setItem('onboarding-completed', 'true');
  localStorage.setItem('mitre-nav-theme', 'dark');
});

const page = await context.newPage();

async function settle(ms = 1200) {
  await page.waitForLoadState('networkidle').catch(() => {});
  await page.waitForTimeout(ms);
}

// 1) Hero — the matrix.
await page.goto(`${BASE}/#/matrix`);
await page.waitForSelector('.cell', { timeout: 120000 });
await settle(2000);
await page.screenshot({ path: 'screenshots/attack-navi-live.png' });
console.log('captured: attack-navi-live.png (matrix hero)');

// 2) Technique detail sidebar.
await page.click('.cell >> nth=4');
await page.waitForSelector('.sidebar.open .sidebar-body', { timeout: 30000 });
await page.mouse.move(8, 860); // park the cursor so no hover tooltip lingers
await settle(2500);
await page.screenshot({ path: 'screenshots/live2.png' });
console.log('captured: live2.png (technique sidebar)');

// 3) Intel workspace (threat groups) — close the sidebar drawer first.
await page.keyboard.press('Escape');
await page.waitForTimeout(400);
await page.goto(`${BASE}/#/intel/groups`);
await page.waitForSelector('app-threat-panel', { timeout: 60000 });
await settle(2500);
await page.screenshot({ path: 'screenshots/attack-navi-intel.png' });
console.log('captured: attack-navi-intel.png (intel workspace)');

await browser.close();
console.log('done');
