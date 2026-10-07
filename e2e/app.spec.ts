// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { test, expect, Page } from '@playwright/test';

const BASE = 'http://localhost:4200';

// CI serves a static DEVELOPMENT build through http-server (see
// playwright.config.ts), so a deep link's first hit still has to download that
// lazy route's chunk and boot the app on a constrained runner. Deep-link
// assertions (which land directly on a cold route) get a much longer budget
// there than locally, where `ng serve` is warm.
const ROUTE_TIMEOUT = process.env['CI'] ? 60000 : 15000;

// The four ATT&CK bundles the app revalidates from MITRE's STIX repo, each
// routed to the matching bundled snapshot. They MUST be routed per domain: the
// old single `attack-stix-data/**` route answered the ICS and Mobile fetches
// with the Enterprise bundle, so a domain-switch test would have passed against
// relabelled Enterprise data.
const STIX = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master';
const ATTACK_FIXTURES: Array<[url: string, file: string]> = [
  [`${STIX}/enterprise-attack/enterprise-attack.json`, 'src/assets/data/enterprise-attack.json'],
  [`${STIX}/ics-attack/ics-attack.json`, 'src/assets/data/ics-attack.json'],
  [`${STIX}/mobile-attack/mobile-attack.json`, 'src/assets/data/mobile-attack.json'],
  [
    'https://raw.githubusercontent.com/center-for-threat-informed-defense/fight-fraud-framework/main/public/f3-stix.json',
    'src/assets/data/f3-attack.json',
  ],
];

const isAppOrigin = (url: URL) =>
  (url.hostname === 'localhost' || url.hostname === '127.0.0.1') && url.port === '4200';

/**
 * Make the page hermetic. Everything that is not the app itself is blocked
 * (every enrichment loader already treats a failed fetch as "no data"), and
 * the ATT&CK bundles are served from the repo's own snapshots, so a run never
 * depends on GitHub, CISA, NVD, FIRST or MITRE being reachable.
 *
 * Playwright evaluates routes in reverse registration order, so the catch-all
 * goes first and the fixture routes registered after it win.
 */
async function hermetic(page: Page): Promise<void> {
  await page.route(url => !isAppOrigin(url), route => route.abort('blockedbyclient'));
  for (const [url, file] of ATTACK_FIXTURES) {
    await page.route(url, route => route.fulfill({ path: file, contentType: 'application/json' }));
  }
}

test.describe('ATT&CK Navi', () => {
  test.beforeEach(async ({ page }) => {
    await hermetic(page);
    // Fresh contexts have empty localStorage — the first-visit onboarding
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
    // The toolbar MUST have exactly one theme button; a renamed or dropped
    // button is a failure, not a reason to skip the assertions below.
    const themeBtn = page.locator('.theme-btn');
    await expect(themeBtn).toHaveCount(1);
    // Default-agnostic (light became the default in the v0.10 makeover):
    // toggling flips the body class, toggling again restores it.
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
  });

  // ─── Additional E2E tests ───────────────────────────────────────────────────

  // Direct-URL deep links: one per lazy-loaded destination. Tab-level
  // destinations are reachable by URL alone, and a provider that is only
  // resolved when the standalone component is instantiated in a real browser
  // surfaces here and nowhere else in CI.
  const DEEP_LINKS: Array<[name: string, url: string, host: string]> = [
    ['assessment wizard', '/#/coverage/assessment', 'app-assessment-wizard'],
    ['collections', '/#/library/collections', 'app-collection-panel'],
    ['gap analysis', '/#/exposure/gap-analysis', 'app-gap-analysis-panel'],
    ['assets', '/#/coverage/assets', 'app-asset-panel'],
    ['IR playbooks', '/#/reports/playbooks', 'app-ir-playbook-panel'],
    ['CVE', '/#/exposure/cve', 'app-cve-panel'],
    ['sigma', '/#/detect/sigma', 'app-sigma-export'],
    ['CVE dossier', '/#/exposure/dossier', 'app-dossier-panel'],
    ['SSVC', '/#/exposure/ssvc', 'app-ssvc-panel'],
    ['kill chain', '/#/exposure/kill-chain', 'app-killchain-panel'],
    ['technique graph', '/#/exposure/graph', 'app-technique-graph-panel'],
    ['CTEM', '/#/exposure/ctem', 'app-ctem-page'],
    ['saved layers', '/#/library/layers', 'app-layers-panel'],
    ['export hub', '/#/reports/exports', 'app-export-hub'],
  ];
  for (const [name, url, host] of DEEP_LINKS) {
    test(`deep link renders ${name}`, async ({ page }) => {
      await page.goto(BASE + url);
      await expect(page.locator(`${host} > *`).first()).toBeVisible({ timeout: ROUTE_TIMEOUT });
    });
  }

  test('dossier deep link opens the CVE named in the query', async ({ page }) => {
    await page.goto(BASE + '/#/exposure/dossier?cve=cve-2021-44228');
    await expect(page.locator('app-dossier-panel > *').first()).toBeVisible({ timeout: ROUTE_TIMEOUT });
    // The lookup box is normalised to upper case and a dossier (asset or
    // composed live) is on screen; the blocked NVD fetch must not break it.
    await expect(page.locator('app-dossier-panel .lookup input').first()).toHaveValue('CVE-2021-44228');
    await expect(page.locator('app-dossier-panel .dossier .identity h3')).toContainText('CVE-2021-44228', { timeout: ROUTE_TIMEOUT });
  });

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
    // The KEV mode MUST be offered; losing it from the menu is a failure.
    const kevBtn = page.locator('.heatmap-mode-btn', { hasText: 'KEV' });
    await expect(kevBtn).toHaveCount(1);
    await kevBtn.click();
    await expect(page.locator('.heatmap-btn')).toContainText('KEV');
    // Matrix should still render with tactic headers
    await expect(page.locator('.tactic-header').nth(4)).toBeVisible();
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

  test('switching to ICS renders the ICS matrix, not Enterprise relabelled', async ({ page }) => {
    await page.goto(BASE);
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: ROUTE_TIMEOUT });
    const icsOnly = page.locator('.tactic-header', { hasText: 'Inhibit Response Function' });
    const enterpriseOnly = page.locator('.tactic-header', { hasText: 'Exfiltration' });
    await expect(enterpriseOnly).toHaveCount(1);
    await expect(icsOnly).toHaveCount(0);

    await page.locator('.domain-btn[title="ICS ATT&CK"]').click();

    // Both the bundled snapshot and the (routed) live revalidation are ICS now.
    await expect(icsOnly).toHaveCount(1, { timeout: ROUTE_TIMEOUT });
    await expect(enterpriseOnly).toHaveCount(0);
    await expect(page.locator('.domain-btn[title="ICS ATT&CK"]')).toHaveClass(/active/);
    await expect(page.locator('.cell').first()).toBeVisible();
    // Impair Process Control is the other ICS-only column; a tactic column
    // never comes from Enterprise.
    await expect(page.locator('.tactic-header', { hasText: 'Impair Process Control' })).toHaveCount(1);
    await expect(page.locator('.tactic-header', { hasText: 'Credential Access' })).toHaveCount(0);
  });

  test('uploading a Navigator layer saves it and colors the matrix by it', async ({ page }) => {
    // importNavigatorLayer() reports through window.alert (and window.confirm
    // on a domain mismatch); an unanswered dialog would hang the flow.
    const dialogs: string[] = [];
    page.on('dialog', dialog => {
      dialogs.push(dialog.message());
      void dialog.accept();
    });

    await page.goto(BASE + '/#/reports/exports');
    const card = page.locator('.export-card', { hasText: 'Import Navigator Layer' });
    await expect(card).toBeVisible({ timeout: ROUTE_TIMEOUT });

    // BrowserFileService.pickTextFile creates its <input type=file> on the fly,
    // so the chooser is intercepted rather than filled through a selector.
    const chooser = page.waitForEvent('filechooser');
    await card.click();
    // Relative to the repo root, like the fixture paths in hermetic() above.
    await (await chooser).setFiles('e2e/fixtures/navigator-layer.json');

    // Saved to IndexedDB and listed by the hub.
    const saved = page.locator('.saved-layer-list .sl-name', { hasText: 'E2E Coverage' });
    await expect(saved).toHaveCount(1, { timeout: 15000 });
    await expect(page.locator('.saved-layer-row.active .sl-name')).toHaveText('E2E Coverage');
    expect(dialogs.some(m => m.includes('"E2E Coverage" imported and saved (3 techniques)'))).toBeTruthy();

    // The matrix is now in the library heatmap mode, driven by the upload.
    await page.locator('.nav-item', { hasText: 'Matrix' }).click();
    await expect(page.locator('.matrix-wrapper')).toBeVisible({ timeout: ROUTE_TIMEOUT });
    await expect(page.locator('.heatmap-btn')).toContainText('Library');

    // ...and the sidebar surfaces the layer's own entry for a scored technique.
    await page.locator('.cell', { hasText: 'T1059' }).first().click();
    await expect(page.locator('.sidebar.open')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('#sb-sec-imported-layer')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('.imported-layer-section')).toContainText('Score: 90');
  });
});
