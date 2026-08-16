// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Visual regression suite. Screenshot baselines are font-rendering-dependent
// and therefore per-platform, so this suite runs LOCALLY only (skipped in CI)
// as the pre-push safety net for theme/layout regressions — exactly the class
// of bug (invisible light-mode tab bar, drawer CSS leaking onto pages) that
// computed-style assertions miss.
//
// Update baselines intentionally with:  npm run test:visual:update
import { test, expect, Page } from '@playwright/test';

const BASE = 'http://localhost:4200';

test.describe('visual regression', () => {
  test.skip(!!process.env['CI'], 'screenshot baselines are per-platform; run locally');

  test.beforeEach(async ({ page }) => {
    await page.route('https://raw.githubusercontent.com/mitre-attack/attack-stix-data/**', route =>
      route.fulfill({ path: 'src/assets/data/enterprise-attack.json', contentType: 'application/json' }),
    );
    await page.addInitScript(() => {
      localStorage.setItem('onboarding-completed', 'true');
      localStorage.setItem('mitre-nav-theme', 'dark');
    });
  });

  /** Wait for the matrix grid and let late chips/badges settle. */
  async function matrixReady(page: Page): Promise<void> {
    await page.waitForSelector('.cell', { timeout: 60000 });
    await page.waitForTimeout(1500);
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
    await page.waitForSelector('app-timeline-panel', { timeout: 60000 });
    await page.waitForTimeout(800);
    await expect(page).toHaveScreenshot('workspace-dark.png', shot);
  });

  test('workspace shell — light', async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem('mitre-nav-theme', 'light'));
    await page.goto(`${BASE}/#/coverage/timeline`);
    await page.waitForSelector('app-timeline-panel', { timeout: 60000 });
    await page.waitForTimeout(800);
    await expect(page).toHaveScreenshot('workspace-light.png', shot);
  });

  test('technique sidebar — dark', async ({ page }) => {
    await page.goto(`${BASE}/#/matrix`);
    await matrixReady(page);
    await page.click('.cell >> nth=4');
    await page.waitForSelector('.sidebar.open .sidebar-body', { timeout: 30000 });
    await page.mouse.move(8, 860);
    await page.waitForTimeout(1200);
    await expect(page).toHaveScreenshot('sidebar-dark.png', shot);
  });

  test('command palette — dark', async ({ page }) => {
    await page.goto(`${BASE}/#/matrix`);
    await matrixReady(page);
    await page.keyboard.press('Control+k');
    await page.waitForSelector('app-universal-search input', { timeout: 10000 });
    await page.fill('app-universal-search input', 'gap');
    await page.waitForTimeout(600);
    await expect(page).toHaveScreenshot('palette-dark.png', shot);
  });
});
