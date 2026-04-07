// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { test, expect } from '@playwright/test';

const BASE = 'http://localhost:4200';

test.describe('ATT&CK Navi', () => {
  test('loads the matrix', async ({ page }) => {
    await page.goto(BASE);
    await expect(page.locator('app-root')).toBeVisible();
    await expect(page.locator('.matrix-wrapper')).toBeVisible({ timeout: 15000 });
    // Matrix should have tactic header columns
    const tacticHeaders = page.locator('.tactic-header');
    await expect(tacticHeaders.first()).toBeVisible();
    const count = await tacticHeaders.count();
    expect(count).toBeGreaterThanOrEqual(10);
  });

  test('clicking a technique opens sidebar', async ({ page }) => {
    await page.goto(BASE);
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: 15000 });
    await page.locator('.cell').first().click();
    await expect(page.locator('.sidebar.open')).toBeVisible({ timeout: 5000 });
  });

  test('sidebar shows technique details', async ({ page }) => {
    await page.goto(BASE);
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: 15000 });
    await page.locator('.cell').first().click();
    await expect(page.locator('.sidebar.open .sidebar-body')).toBeVisible({ timeout: 5000 });
    // Should contain a technique ID (T followed by digits)
    await expect(page.locator('.sidebar-header .attack-id')).toContainText(/T\d/);
  });

  test('search filters techniques', async ({ page }) => {
    await page.goto(BASE);
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: 15000 });
    const searchInput = page.locator('input[placeholder*="Search techniques"]');
    await searchInput.fill('PowerShell');
    // Wait for search to apply -- highlighted or dimmed cells should appear
    await page.waitForTimeout(500);
    const highlighted = page.locator('.cell.search-highlighted');
    const dimmed = page.locator('.cell.search-dimmed');
    // At least some cells should be affected by search
    const highlightedCount = await highlighted.count();
    const dimmedCount = await dimmed.count();
    expect(highlightedCount + dimmedCount).toBeGreaterThan(0);
  });

  test('heatmap mode switches', async ({ page }) => {
    await page.goto(BASE);
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: 15000 });
    // Open heatmap/view dropdown
    await page.locator('.heatmap-btn').click();
    await expect(page.locator('.views-menu')).toBeVisible();
    // Click Risk mode
    const riskBtn = page.locator('.heatmap-mode-btn', { hasText: 'Risk' });
    await riskBtn.click();
    // The heatmap button label should now reflect Risk
    await expect(page.locator('.heatmap-btn')).toContainText('Risk');
  });

  test('nav rail opens panels', async ({ page }) => {
    await page.goto(BASE);
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: 15000 });
    // Click INTEL nav item
    await page.locator('.nav-item', { hasText: 'INTEL' }).click();
    await expect(page.locator('app-threat-intelligence-panel')).toBeVisible({ timeout: 5000 });
  });

  test('dashboard panel opens', async ({ page }) => {
    await page.goto(BASE);
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: 15000 });
    // Click Dashboard nav item
    await page.locator('.nav-item', { hasText: 'Dashboard' }).click();
    await expect(page.locator('app-dashboard-panel')).toBeVisible({ timeout: 5000 });
  });

  test('escape closes sidebar', async ({ page }) => {
    await page.goto(BASE);
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: 15000 });
    await page.locator('.cell').first().click();
    await expect(page.locator('.sidebar.open')).toBeVisible({ timeout: 5000 });
    await page.keyboard.press('Escape');
    // Sidebar should close (no longer have .open class)
    await expect(page.locator('.sidebar.open')).toBeHidden({ timeout: 3000 });
  });

  test('theme toggle works', async ({ page }) => {
    await page.goto(BASE);
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: 15000 });
    // Find and click theme toggle button
    const themeBtn = page.locator('.theme-btn');
    if (await themeBtn.count() > 0) {
      await themeBtn.click();
      await expect(page.locator('body')).toHaveClass(/light-mode/);
      // Toggle back
      await themeBtn.click();
      await expect(page.locator('body')).not.toHaveClass(/light-mode/);
    }
  });

  // ─── Additional E2E tests ─────────────────────────────────────────────────

  test('assessment wizard opens', async ({ page }) => {
    await page.goto(BASE);
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: 15000 });
    await page.locator('.nav-item', { hasText: 'ASSESS' }).click();
    await expect(page.locator('app-assessment-wizard')).toBeVisible({ timeout: 5000 });
  });

  test('collection panel opens', async ({ page }) => {
    await page.goto(BASE);
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: 15000 });
    await page.locator('.nav-item', { hasText: 'COLLECT' }).click();
    await expect(page.locator('app-collection-panel')).toBeVisible({ timeout: 5000 });
  });

  test('gap analysis panel opens', async ({ page }) => {
    await page.goto(BASE);
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: 15000 });
    await page.locator('.nav-item', { hasText: 'GAP RPT' }).click();
    await expect(page.locator('app-gap-analysis-panel')).toBeVisible({ timeout: 5000 });
  });

  test('asset panel opens', async ({ page }) => {
    await page.goto(BASE);
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: 15000 });
    await page.locator('.nav-item', { hasText: 'ASSETS' }).click();
    await expect(page.locator('app-asset-panel')).toBeVisible({ timeout: 5000 });
  });

  test('IR playbook panel opens', async ({ page }) => {
    await page.goto(BASE);
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: 15000 });
    await page.locator('.nav-item', { hasText: 'IR PLAY' }).click();
    await expect(page.locator('app-ir-playbook-panel')).toBeVisible({ timeout: 5000 });
  });

  test('CVE panel opens', async ({ page }) => {
    await page.goto(BASE);
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: 15000 });
    await page.locator('.nav-item', { hasText: 'CVE' }).click();
    await expect(page.locator('app-cve-panel')).toBeVisible({ timeout: 5000 });
  });

  test('sigma export panel opens', async ({ page }) => {
    await page.goto(BASE);
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: 15000 });
    await page.locator('.nav-item', { hasText: 'SIGMA' }).click();
    await expect(page.locator('app-sigma-export')).toBeVisible({ timeout: 5000 });
  });

  test('settings panel opens', async ({ page }) => {
    await page.goto(BASE);
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: 15000 });
    await page.locator('.nav-item', { hasText: 'Settings' }).click();
    await expect(page.locator('app-settings-panel')).toBeVisible({ timeout: 5000 });
  });

  test('sidebar shows signal pills', async ({ page }) => {
    await page.goto(BASE);
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: 15000 });
    await page.locator('.cell').first().click();
    await expect(page.locator('.sidebar.open')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('.signal-pill')).toHaveCount({ minimum: 1 }, { timeout: 10000 });
  });

  test('sidebar shows completeness score', async ({ page }) => {
    await page.goto(BASE);
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: 15000 });
    await page.locator('.cell').first().click();
    await expect(page.locator('.sidebar.open')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('.completeness-bar')).toBeVisible();
  });

  test('sidebar collapsible sections toggle', async ({ page }) => {
    await page.goto(BASE);
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: 15000 });
    await page.locator('.cell').first().click();
    await expect(page.locator('.sidebar.open')).toBeVisible({ timeout: 5000 });
    const section = page.locator('.collapsible-title').first();
    await expect(section).toBeVisible();
    await section.click();
    // After clicking, the section's aria-expanded should toggle
    await expect(section).toHaveAttribute('aria-expanded', 'false');
  });

  test('technique URL pre-selection works', async ({ page }) => {
    await page.goto(BASE + '/#tech=T1059');
    await expect(page.locator('.sidebar.open')).toBeVisible({ timeout: 15000 });
    await expect(page.locator('.sidebar-header .attack-id')).toContainText('T1059');
  });

  test('multiple heatmap modes render', async ({ page }) => {
    await page.goto(BASE);
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: 15000 });
    // Open heatmap dropdown
    await page.locator('.heatmap-btn').click();
    await expect(page.locator('.views-menu')).toBeVisible();
    // Switch to KEV mode
    const kevBtn = page.locator('.heatmap-mode-btn', { hasText: 'KEV' });
    if (await kevBtn.count() > 0) {
      await kevBtn.click();
      // Matrix should still render with tactic headers
      await expect(page.locator('.tactic-header')).toHaveCount({ minimum: 5 });
    }
  });

  test('dashboard shows widgets', async ({ page }) => {
    await page.goto(BASE);
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: 15000 });
    await page.locator('.nav-item', { hasText: 'Dashboard' }).click();
    await expect(page.locator('app-dashboard-panel')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('.widget-card')).toHaveCount({ minimum: 3 }, { timeout: 10000 });
  });

  test('detection panel opens', async ({ page }) => {
    await page.goto(BASE);
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: 15000 });
    await page.locator('.nav-item', { hasText: 'Detect' }).click();
    await expect(page.locator('app-detection-panel')).toBeVisible({ timeout: 5000 });
  });
});
