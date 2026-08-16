// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { test, expect } from '@playwright/test';

const BASE = 'http://localhost:4200';

// CI runs against `ng serve`, which JIT-compiles each lazy route the first
// time it is hit. On the constrained CI runner that cold compile can take
// tens of seconds, so deep-link assertions (which land directly on a cold
// route) get a much longer budget there than locally.
const ROUTE_TIMEOUT = process.env['CI'] ? 60000 : 15000;

test.describe('ATT&CK Navi', () => {
  // Serve the bundled STIX asset for MITRE ATT&CK data requests. Each test
  // runs in a fresh browser context (no IndexedDB cache), so fetching the
  // ~40MB live bundle per test made every run network-bound and flaky.
  test.beforeEach(async ({ page }) => {
    await page.route('https://raw.githubusercontent.com/mitre-attack/attack-stix-data/**', route =>
      route.fulfill({ path: 'src/assets/data/enterprise-attack.json', contentType: 'application/json' }),
    );
    // Fresh contexts have empty localStorage â€” the first-visit onboarding
    // overlay would otherwise intercept every click.
    await page.addInitScript(() => localStorage.setItem('onboarding-completed', 'true'));
  });

  test('loads the matrix', async ({ page }) => {
    await page.goto(BASE);
    await expect(page.locator('app-root > *').first()).toBeVisible();
    await expect(page.locator('.matrix-wrapper')).toBeVisible({ timeout: ROUTE_TIMEOUT });
    // Matrix should have tactic header columns
    const tacticHeaders = page.locator('.tactic-header');
    await expect(tacticHeaders.first()).toBeVisible();
    const count = await tacticHeaders.count();
    expect(count).toBeGreaterThanOrEqual(10);
  });

  test('clicking a technique opens sidebar', async ({ page }) => {
    await page.goto(BASE);
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: ROUTE_TIMEOUT });
    await page.locator('.cell').first().click();
    await expect(page.locator('.sidebar.open')).toBeVisible({ timeout: 5000 });
  });

  test('sidebar shows technique details', async ({ page }) => {
    await page.goto(BASE);
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: ROUTE_TIMEOUT });
    await page.locator('.cell').first().click();
    await expect(page.locator('.sidebar.open .sidebar-body')).toBeVisible({ timeout: 5000 });
    // Should contain a technique ID (T followed by digits)
    await expect(page.locator('.sidebar-header .attack-id')).toContainText(/T\d/);
  });

  test('search filters techniques', async ({ page }) => {
    await page.goto(BASE);
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: ROUTE_TIMEOUT });
    const searchInput = page.locator('input[placeholder*="Search techniques"]');
    await searchInput.fill('PowerShell');
    // Toolbar search (highlight mode) marks matches .highlighted and the rest .dimmed
    await expect(page.locator('.cell.highlighted').first()).toBeVisible({ timeout: 5000 });
    const highlightedCount = await page.locator('.cell.highlighted').count();
    const dimmedCount = await page.locator('.cell.dimmed').count();
    expect(highlightedCount).toBeGreaterThan(0);
    expect(dimmedCount).toBeGreaterThan(highlightedCount);
  });

  test('heatmap mode switches', async ({ page }) => {
    await page.goto(BASE);
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: ROUTE_TIMEOUT });
    // Open heatmap/view dropdown
    await page.locator('.heatmap-btn').click();
    await expect(page.locator('.views-menu')).toBeVisible();
    // Click Risk mode ("Risk" also substring-matches "Unified Risk")
    const riskBtn = page
      .locator('.heatmap-mode-btn', { hasText: 'Risk' })
      .filter({ hasNotText: 'Unified' });
    await riskBtn.click();
    // The heatmap button label should now reflect Risk
    await expect(page.locator('.heatmap-btn')).toContainText('Risk');
  });

  test('nav rail routes to every workspace', async ({ page }) => {
    await page.goto(BASE);
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: ROUTE_TIMEOUT });
    const workspaces: Array<[label: string, urlPart: string]> = [
      ['Dashboard', '/dashboard'],
      ['Intel', '/intel'],
      ['Detect', '/detect'],
      ['Exposure', '/exposure'],
      ['Coverage', '/coverage'],
      ['Library', '/library'],
      ['Reports', '/reports'],
    ];
    for (const [label, urlPart] of workspaces) {
      await page.locator('.nav-item', { hasText: label }).click();
      await expect(page).toHaveURL(new RegExp(`#${urlPart}`));
      await expect(page.locator('app-workspace-shell').first()).toBeVisible({ timeout: 5000 });
    }
    // Matrix returns home
    await page.locator('.nav-item', { hasText: 'Matrix' }).click();
    await expect(page.locator('.matrix-wrapper')).toBeVisible({ timeout: 5000 });
  });

  test('dashboard panel opens', async ({ page }) => {
    await page.goto(BASE);
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: ROUTE_TIMEOUT });
    // Click Dashboard nav item
    await page.locator('.nav-item', { hasText: 'Dashboard' }).click();
    await expect(page.locator('app-dashboard-panel > *').first()).toBeVisible({ timeout: 5000 });
  });

  test('workspace tab bar switches tabs', async ({ page }) => {
    await page.goto(BASE + '/#/intel/groups');
    await expect(page.locator('app-threat-panel > *').first()).toBeVisible({ timeout: ROUTE_TIMEOUT });
    await page.locator('app-workspace-shell a', { hasText: 'Software' }).click();
    await expect(page).toHaveURL(/#\/intel\/software/);
    await expect(page.locator('app-software-panel > *').first()).toBeVisible({ timeout: 5000 });
  });

  test('browser back returns to the previous workspace', async ({ page }) => {
    await page.goto(BASE);
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: ROUTE_TIMEOUT });
    await page.locator('.nav-item', { hasText: 'Coverage' }).click();
    await expect(page).toHaveURL(/#\/coverage/);
    await page.goBack();
    await expect(page).toHaveURL(/#\/matrix/);
    await expect(page.locator('.matrix-wrapper')).toBeVisible({ timeout: 5000 });
  });

  test('escape closes sidebar', async ({ page }) => {
    await page.goto(BASE);
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: ROUTE_TIMEOUT });
    await page.locator('.cell').first().click();
    await expect(page.locator('.sidebar.open')).toBeVisible({ timeout: 5000 });
    await page.keyboard.press('Escape');
    // Sidebar should close (no longer have .open class)
    await expect(page.locator('.sidebar.open')).toBeHidden({ timeout: 3000 });
  });

  test('theme toggle works', async ({ page }) => {
    await page.goto(BASE);
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: ROUTE_TIMEOUT });
    // Default-agnostic (light became the default in the v0.10 makeover):
    // toggling flips the body class, toggling again restores it.
    const themeBtn = page.locator('.theme-btn');
    if (await themeBtn.count() > 0) {
      const startedLight = await page.locator('body').evaluate(b => b.classList.contains('light-mode'));
      await themeBtn.click();
      if (startedLight) {
        await expect(page.locator('body')).not.toHaveClass(/light-mode/);
      } else {
        await expect(page.locator('body')).toHaveClass(/light-mode/);
      }
      await themeBtn.click();
      if (startedLight) {
        await expect(page.locator('body')).toHaveClass(/light-mode/);
      } else {
        await expect(page.locator('body')).not.toHaveClass(/light-mode/);
      }
    }
  });

  // â”€â”€â”€ Additional E2E tests â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

  // Direct-URL deep links: one per formerly-overlay destination that had a
  // dedicated nav item. Tab-level destinations are reachable by URL alone.
  const DEEP_LINKS: Array<[name: string, url: string, host: string]> = [
    ['assessment wizard', '/#/coverage/assessment', 'app-assessment-wizard'],
    ['collections', '/#/library/collections', 'app-collection-panel'],
    ['gap analysis', '/#/exposure/gap-analysis', 'app-gap-analysis-panel'],
    ['assets', '/#/coverage/assets', 'app-asset-panel'],
    ['IR playbooks', '/#/reports/playbooks', 'app-ir-playbook-panel'],
    ['CVE', '/#/exposure/cve', 'app-cve-panel'],
    ['sigma', '/#/detect/sigma', 'app-sigma-export'],
  ];
  for (const [name, url, host] of DEEP_LINKS) {
    test(`deep link renders ${name}`, async ({ page }) => {
      await page.goto(BASE + url);
      await expect(page.locator(`${host} > *`).first()).toBeVisible({ timeout: ROUTE_TIMEOUT });
    });
  }

  test('settings opens from the rail', async ({ page }) => {
    await page.goto(BASE);
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: ROUTE_TIMEOUT });
    await page.locator('.nav-item', { hasText: 'Settings' }).click();
    await expect(page.locator('app-settings-panel > *').first()).toBeVisible({ timeout: 5000 });
  });

  test('help button opens keyboard shortcuts overlay', async ({ page }) => {
    await page.goto(BASE);
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: ROUTE_TIMEOUT });
    await page.locator('.help-btn').click();
    await expect(page.locator('app-keyboard-help .help-overlay, app-keyboard-help .keyboard-help, app-keyboard-help > *').first()).toBeVisible({ timeout: 5000 });
  });

  test('sidebar shows signal pills', async ({ page }) => {
    await page.goto(BASE);
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: ROUTE_TIMEOUT });
    await page.locator('.cell').first().click();
    await expect(page.locator('.sidebar.open')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('.signal-pill').first()).toBeVisible({ timeout: 10000 });
  });

  test('sidebar shows completeness score', async ({ page }) => {
    await page.goto(BASE);
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: ROUTE_TIMEOUT });
    await page.locator('.cell').first().click();
    await expect(page.locator('.sidebar.open')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('.completeness-bar')).toBeVisible();
  });

  test('sidebar collapsible sections toggle', async ({ page }) => {
    await page.goto(BASE);
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: ROUTE_TIMEOUT });
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
    await expect(page.locator('.sidebar.open')).toBeVisible({ timeout: ROUTE_TIMEOUT });
    await expect(page.locator('.sidebar-header .attack-id')).toContainText('T1059');
  });

  test('multiple heatmap modes render', async ({ page }) => {
    await page.goto(BASE);
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: ROUTE_TIMEOUT });
    // Open heatmap dropdown
    await page.locator('.heatmap-btn').click();
    await expect(page.locator('.views-menu')).toBeVisible();
    // Switch to KEV mode
    const kevBtn = page.locator('.heatmap-mode-btn', { hasText: 'KEV' });
    if (await kevBtn.count() > 0) {
      await kevBtn.click();
      // Matrix should still render with tactic headers
      await expect(page.locator('.tactic-header').nth(4)).toBeVisible();
    }
  });

  test('dashboard shows widgets', async ({ page }) => {
    await page.goto(BASE);
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: ROUTE_TIMEOUT });
    await page.locator('.nav-item', { hasText: 'Dashboard' }).click();
    await expect(page.locator('app-dashboard-panel > *').first()).toBeVisible({ timeout: 5000 });
    await expect(page.locator('.widget-card').nth(2)).toBeVisible({ timeout: 10000 });
  });

  test('detection panel opens', async ({ page }) => {
    await page.goto(BASE);
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: ROUTE_TIMEOUT });
    await page.locator('.nav-item', { hasText: 'Detect' }).click();
    await expect(page.locator('app-detection-panel > *').first()).toBeVisible({ timeout: 5000 });
  });

  test('deep link survives a reload', async ({ page }) => {
    await page.goto(BASE + '/#/coverage/controls');
    await expect(page.locator('app-controls-panel > *').first()).toBeVisible({ timeout: ROUTE_TIMEOUT });
    await page.reload();
    await expect(page.locator('app-controls-panel > *').first()).toBeVisible({ timeout: ROUTE_TIMEOUT });
    await expect(page).toHaveURL(/#\/coverage\/controls/);
  });

  test('legacy filter-key share link lands on the matrix with filters applied', async ({ page }) => {
    await page.goto(BASE + '/#heat=kev');
    await expect(page).toHaveURL(/#\/matrix\?.*heat=kev/);
    await expect(page.locator('.matrix-wrapper')).toBeVisible({ timeout: ROUTE_TIMEOUT });
  });
});
