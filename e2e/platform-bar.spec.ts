// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { test, expect } from '@playwright/test';

// The universal platform bar renders immediately from the bundled menu, before any
// ATT&CK data loads, so these tests do not mock the data layer. They cover the desktop
// hover + two levels of fly-out (bookmarks: category > subsection > leaf), the keyboard
// path, external-leaf attributes, and the mobile three-level accordion.

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

  test('a category flies out, and its subsection flies out again (three levels)', async ({ page }) => {
    await page.getByRole('link', { name: 'Bookmarks', exact: true }).hover();
    await expect(page.locator('#tsw-panel-bookmarks')).toBeVisible();

    // Category index 1 ("Vulnerability Management") nests subsections.
    await page.locator('#tsw-panel-bookmarks .tsw-bar__entry-row').filter({ hasText: 'Vulnerability Management' }).hover();
    const catFly = page.locator('#tsw-flyout-bookmarks-1');
    await expect(catFly).toBeVisible();

    // Its first subsection flies out a further level into the leaves.
    await catFly.locator('.tsw-bar__entry-row').filter({ hasText: 'CVE & Vuln Databases' }).hover();
    const subFly = page.locator('#tsw-flyout-bookmarks-1-0');
    await expect(subFly).toBeVisible();
    await expect(subFly.locator('.tsw-bar__menu-link--ext').first()).toBeVisible();
  });

  test('an external leaf carries target, rel and the new-tab note', async ({ page }) => {
    await page.getByRole('link', { name: 'Bookmarks', exact: true }).hover();
    // Daily Driver (category 0) is a leaves-only category of external links.
    await page.locator('#tsw-panel-bookmarks .tsw-bar__entry-row').filter({ hasText: 'Daily Driver' }).hover();
    const fly = page.locator('#tsw-flyout-bookmarks-0');
    await expect(fly).toBeVisible();
    const ext = fly.locator('.tsw-bar__menu-link--ext').first();
    await expect(ext).toHaveAttribute('target', '_blank');
    await expect(ext).toHaveAttribute('rel', 'noopener noreferrer');
    await expect(ext).toContainText('opens in a new tab on an external site');
    await expect(ext.locator('.tsw-bar__ext')).toHaveAttribute('aria-hidden', 'true');
  });

  test('the caret opens the menu for keyboard; ArrowRight enters a fly-out, Escape walks back', async ({ page }) => {
    await page.getByRole('button', { name: 'Bookmarks menu' }).focus();
    await page.keyboard.press('ArrowDown'); // opens the panel, focuses the first category
    await expect(page.locator('#tsw-panel-bookmarks')).toBeVisible();

    const firstEntry = page.locator('#tsw-panel-bookmarks .tsw-bar__entry-label').first();
    await expect(firstEntry).toBeFocused();

    await page.keyboard.press('ArrowDown'); // move to "Vulnerability Management"
    const opener = page.locator('#tsw-panel-bookmarks .tsw-bar__entry-label').nth(1);
    await expect(opener).toBeFocused();

    await page.keyboard.press('ArrowRight'); // open its fly-out and enter it
    await expect(page.locator('#tsw-flyout-bookmarks-1')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Vulnerability Management submenu' })).toHaveAttribute('aria-expanded', 'true');

    // Escape closes the deepest open level and returns here.
    await page.keyboard.press('Escape');
    await expect(page.locator('#tsw-flyout-bookmarks-1')).toBeHidden();
    await expect(page.locator('#tsw-panel-bookmarks')).toBeVisible();
  });

  test('a pending entry never renders; a de-pended entry does', async ({ page }) => {
    await page.getByRole('link', { name: 'Home', exact: true }).hover();
    const panel = page.locator('#tsw-panel-home');
    await expect(panel).toBeVisible();
    await expect(panel).toContainText('Front page');
    // "Search" carries no pending note, so it renders.
    await expect(panel).toContainText('Search');
    // "Security policy" is still pending, so it must not render.
    await expect(panel).not.toContainText('Security policy');
  });

  test('its own class names keep the app toolbar selectors unique', async ({ page }) => {
    await expect(page.locator('.theme-btn')).toHaveCount(1);
    await expect(page.locator('nav.tsw-bar .theme-btn')).toHaveCount(0);
    await expect(page.locator('nav.tsw-bar .brand-link')).toHaveCount(0);
  });

  test('under 760px the menu button opens a three-level inline accordion', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 800 });
    const burger = page.getByRole('button', { name: 'Open platform menu' });
    await expect(burger).toBeVisible();
    await burger.click();

    // Each level is a real link plus a separate caret button.
    await expect(page.getByRole('link', { name: 'Bookmarks', exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Bookmarks section' }).click();
    // Level 2: the categories drop inline.
    await expect(page.getByRole('link', { name: 'Vulnerability Management', exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Vulnerability Management section' }).click();
    // Level 3: the subsections drop inline.
    await expect(page.getByRole('link', { name: 'CVE & Vuln Databases', exact: true })).toBeVisible();
    // No "Open X" row anywhere.
    await expect(page.locator('#tsw-bar-mobile')).not.toContainText('Open Bookmarks');
  });
});

// A coarse-pointer context at desktop width: Chromium then reports `(hover: none)`, so the
// component's hover paths stay off and the menu is carried entirely by taps (Chromium only).
test.describe('platform bar — touch at desktop width', () => {
  test.use({ hasTouch: true, isMobile: true, viewport: { width: 1024, height: 768 } });

  test.beforeEach(async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem('onboarding-completed', '1'));
    await page.goto('/#/matrix');
    await expect(page.locator('nav.tsw-bar')).toBeVisible();
  });

  test('taps carry the menu: button opens it, chevron opens a fly-out, label navigates', async ({ page }) => {
    // Tap the top-level button → the menu opens.
    await page.getByRole('button', { name: 'Bookmarks menu' }).tap();
    await expect(page.locator('#tsw-panel-bookmarks')).toBeVisible();

    // Tap a category chevron → its fly-out opens (hover did not already open it).
    await page.getByRole('button', { name: 'Vulnerability Management submenu' }).tap();
    await expect(page.locator('#tsw-flyout-bookmarks-1')).toBeVisible();

    // Tap a category label → it follows its link (stub the destination so we stay local).
    await page.route('**/LINKS.md**', (r) =>
      r.fulfill({ contentType: 'text/html', body: '<!doctype html><title>links</title>' }),
    );
    await Promise.all([
      page.waitForURL('**/LINKS.md**'),
      page.locator('#tsw-panel-bookmarks .tsw-bar__entry-label').first().tap(),
    ]);
  });
});
