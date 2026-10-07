// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Visual regression suite. Screenshot baselines are font-rendering-dependent
// and therefore per-platform. The committed baselines were captured on Windows
// (e2e/visual.spec.ts-snapshots/*-win32.png), so the suite runs LOCALLY as the
// pre-push safety net for theme/layout regressions — exactly the class of bug
// (invisible light-mode tab bar, drawer CSS leaking onto pages) that
// computed-style assertions miss.
//
// It is skipped in CI until Linux baselines exist. To add them, capture inside
// the Playwright container the workflow uses, commit the *-linux.png files and
// drop the skip:
//   docker run --rm -v "$PWD":/work -w /work mcr.microsoft.com/playwright:v1.63.0-noble \
//     npx playwright test e2e/visual.spec.ts --update-snapshots
//
// Update the local baselines intentionally with:  npm run test:visual:update
//
// No fixed sleeps: `toHaveScreenshot` already waits until two consecutive
// captures are identical, so late chips/badges are settled by construction.
// Each test waits for the specific element it is about to photograph instead.
import { test, expect, Page } from '@playwright/test';

const BASE = 'http://localhost:4200';

test.describe('visual regression', () => {
  test.skip(!!process.env['CI'], 'screenshot baselines are per-platform (win32 only); run locally');

  test.beforeEach(async ({ page }) => {
    await page.route('https://raw.githubusercontent.com/mitre-attack/attack-stix-data/**', route =>
      route.fulfill({ path: 'src/assets/data/enterprise-attack.json', contentType: 'application/json' }),
    );
    await page.addInitScript(() => {
      localStorage.setItem('onboarding-completed', 'true');
      localStorage.setItem('mitre-nav-theme', 'dark');
    });
  });

  /** Wait for the matrix grid and its fonts; toHaveScreenshot settles the rest. */
  async function matrixReady(page: Page): Promise<void> {
    await expect(page.locator('.cell').first()).toBeVisible({ timeout: 60000 });
    await expect(page.locator('.tactic-header').first()).toBeVisible();
    await page.evaluate(() => document.fonts.ready);
  }

  const shot = {
    animations: 'disabled' as const,
    // Live-ish chrome (data-health dots, KEV badge) may differ run to run.
    maxDiffPixelRatio: 0.02,
  };

  test('matrix — dark', async ({ page }) => {
    await page.goto(`${BASE}/#/matrix`);
    await matrixReady(page);
    await expect(page).toHaveScreenshot('matrix-dark.png', shot);
  });

  test('matrix — light', async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem('mitre-nav-theme', 'light'));
    await page.goto(`${BASE}/#/matrix`);
    await matrixReady(page);
    await expect(page).toHaveScreenshot('matrix-light.png', shot);
  });

  test('workspace shell — dark', async ({ page }) => {
    await page.goto(`${BASE}/#/coverage/timeline`);
    await expect(page.locator('app-timeline-panel > *').first()).toBeVisible({ timeout: 60000 });
    await page.evaluate(() => document.fonts.ready);
    await expect(page).toHaveScreenshot('workspace-dark.png', shot);
  });

  test('workspace shell — light', async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem('mitre-nav-theme', 'light'));
    await page.goto(`${BASE}/#/coverage/timeline`);
    await expect(page.locator('app-timeline-panel > *').first()).toBeVisible({ timeout: 60000 });
    await page.evaluate(() => document.fonts.ready);
    await expect(page).toHaveScreenshot('workspace-light.png', shot);
  });

  test('technique sidebar — dark', async ({ page }) => {
    await page.goto(`${BASE}/#/matrix`);
    await matrixReady(page);
    await page.click('.cell >> nth=4');
    await expect(page.locator('.sidebar.open .sidebar-body')).toBeVisible({ timeout: 30000 });
    await expect(page.locator('.sidebar-header .attack-id')).toContainText(/T\d/);
    // Park the pointer away from the cells so no hover state is captured.
    await page.mouse.move(8, 860);
    await expect(page).toHaveScreenshot('sidebar-dark.png', shot);
  });

  test('command palette — dark', async ({ page }) => {
    await page.goto(`${BASE}/#/matrix`);
    await matrixReady(page);
    await page.keyboard.press('Control+k');
    const input = page.locator('app-universal-search input');
    await expect(input).toBeVisible({ timeout: 10000 });
    await input.fill('gap');
    await expect(page.locator('app-universal-search .result-body').first()).toBeVisible();
    await expect(page).toHaveScreenshot('palette-dark.png', shot);
  });
});
