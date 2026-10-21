// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Bundle smoke: after the initial-bundle trims (the command palette and the
// shortcuts overlay load right after first paint), every route still renders
// on a FRESH load, not only after an in-session navigation. One test per row of
// the shared route table, each a new page, so each one boots the app cold.
// Run it alone with: npx playwright test e2e/bundle-smoke.spec.ts -g "bundle smoke"
import { test, expect, BASE, ROUTE_TIMEOUT } from './fixtures/workspace';
import { CURRENT_ROUTES, hashRoute } from './fixtures/workspace/routes';

/**
 * The first heading each page shows. Workspaces, the status page and the
 * technique page open with an h1; the matrix has no h1, its first heading is
 * the first tactic column header.
 */
const firstHeading = (path: string): string =>
  path === '/matrix' ? 'app-matrix-page th.tactic-header' : 'h1';

test.describe('bundle smoke: every route renders its first heading on a fresh load', () => {
  for (const { path, host } of CURRENT_ROUTES) {
    test(`#${path} boots cold and shows its first heading`, async ({ page }) => {
      await page.goto(`${BASE}/#${path}`);
      await expect(page.locator(`${host} > *`).first()).toBeVisible({ timeout: ROUTE_TIMEOUT });
      const heading = page.locator(firstHeading(path)).first();
      await expect(heading).toBeVisible({ timeout: ROUTE_TIMEOUT });
      await expect(heading).not.toHaveText(/^\s*$/);
      await expect(page).toHaveURL(hashRoute(path));
    });
  }

  test('the command palette and the shortcuts overlay still open on a fresh load', async ({ page }) => {
    await page.goto(`${BASE}/#/matrix`);
    await expect(page.locator('app-matrix-page > *').first()).toBeVisible({ timeout: ROUTE_TIMEOUT });
    const paletteInput = page.locator('app-universal-search input').first();
    // Ctrl+K and the toolbar trigger both open the palette; Escape closes it.
    await page.keyboard.press('Control+k');
    await expect(paletteInput).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(page.locator('app-universal-search input')).toHaveCount(0);
    await page.locator('.palette-trigger').click();
    await expect(paletteInput).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(page.locator('app-universal-search input')).toHaveCount(0);
    // '?' and the nav-rail Help button both open the shortcuts overlay.
    await page.keyboard.press('?');
    await expect(page.locator('app-keyboard-help .help-modal')).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(page.locator('app-keyboard-help .help-modal')).toHaveCount(0);
    await page.locator('.help-btn').click();
    await expect(page.locator('app-keyboard-help .help-modal')).toBeVisible();
  });
});
