// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { test, expect } from '@playwright/test';

// The universal platform bar renders immediately from the bundled menu, before any
// ATT&CK data loads, so these tests do not mock the data layer. They cover the desktop
// hover + fly-out paths and the mobile accordion.

test.describe('platform bar', () => {
  test.beforeEach(async ({ page }) => {
    // Skip the first-visit onboarding overlay so it cannot intercept hovers.
    await page.addInitScript(() => localStorage.setItem('onboarding-completed', '1'));
    await page.setViewportSize({ width: 1280, height: 720 });
    await page.goto('/#/matrix');
    await expect(page.locator('nav.tsw-bar')).toBeVisible();
  });

  test('a top-level menu opens on hover', async ({ page }) => {
    await page.getByRole('link', { name: 'Bookmarks', exact: true }).hover();
    await expect(page.locator('#tsw-panel-bookmarks')).toBeVisible();
  });

  test('an entry with sub-entries flies out to the side on hover', async ({ page }) => {
    await page.getByRole('link', { name: 'Bookmarks', exact: true }).hover();
    const panel = page.locator('#tsw-panel-bookmarks');
    await expect(panel).toBeVisible();

    await panel.locator('.tsw-bar__entry-row').filter({ hasText: 'Vulnerability management' }).hover();
    const flyout = page.locator('#tsw-flyout-bookmarks-1');
    await expect(flyout).toBeVisible();
    await expect(flyout.locator('[data-flyitem]').first()).toBeVisible();
  });

  // The chevron-button / touch-tap path is covered by the component unit spec: at desktop
  // width Playwright always reports a fine pointer with hover, so a mouse move to the
  // chevron opens the fly-out on hover before the click can be read as a tap.

  test('the caret opens the menu for keyboard and ArrowRight enters a fly-out', async ({ page }) => {
    await page.getByRole('button', { name: 'Bookmarks menu' }).focus();
    await page.keyboard.press('ArrowDown'); // opens the panel, focuses the first entry
    await expect(page.locator('#tsw-panel-bookmarks')).toBeVisible();

    // Wait for focus to reach the first entry before moving on (focus lands after render).
    const firstEntry = page.locator('#tsw-panel-bookmarks [data-menuitem]').first();
    await expect(firstEntry).toBeFocused();

    await page.keyboard.press('ArrowDown'); // move to "Vulnerability management" (first fly-out opener)
    const opener = page.locator('#tsw-panel-bookmarks .tsw-bar__entry-label').first();
    await expect(opener).toBeFocused();

    await page.keyboard.press('ArrowRight'); // open its fly-out and enter it
    await expect(page.locator('#tsw-flyout-bookmarks-1')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Vulnerability management submenu' })).toHaveAttribute('aria-expanded', 'true');

    // ArrowLeft returns and closes the fly-out.
    await page.keyboard.press('ArrowLeft');
    await expect(page.locator('#tsw-flyout-bookmarks-1')).toBeHidden();
  });

  test('a pending entry never renders', async ({ page }) => {
    await page.getByRole('link', { name: 'Home', exact: true }).hover();
    const panel = page.locator('#tsw-panel-home');
    await expect(panel).toBeVisible();
    await expect(panel).not.toContainText('Security policy');
    await expect(panel).not.toContainText('Search');
  });

  test('its own class names keep the app toolbar selectors unique', async ({ page }) => {
    // Exactly one theme button and one brand link, both in the app toolbar, not the bar.
    await expect(page.locator('.theme-btn')).toHaveCount(1);
    await expect(page.locator('nav.tsw-bar .theme-btn')).toHaveCount(0);
    await expect(page.locator('nav.tsw-bar .brand-link')).toHaveCount(0);
  });

  test('under 760px the menu button opens an inline accordion', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 800 });
    const burger = page.getByRole('button', { name: 'Open platform menu' });
    await expect(burger).toBeVisible();
    await burger.click();
    await page.getByRole('button', { name: 'Bookmarks' }).click();
    await expect(page.locator('.tsw-bar__m-sub').first()).toBeVisible();
  });
});
