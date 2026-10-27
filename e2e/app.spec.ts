// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { readFileSync } from 'node:fs';
import { test, expect, Browser, BrowserContext, Page, Route } from '@playwright/test';
import { openWorkspace } from './fixtures/workspace';

const BASE = 'http://localhost:4200';

// Locally the suite runs against `ng serve`, which JIT-compiles each lazy
// route the first time it is hit. In CI (.github/workflows/e2e.yml) it runs
// against a static DEVELOPMENT build served by http-server, so there is no
// per-route compile; the larger CI budget below covers the slower runner and
// the first load of the ~54 MB bundled STIX asset on a cold route.
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

// The enrichment source behind the sidebar's signal pills. Every other
// enrichment host is blocked, so the pills come from this bundled fixture
// (a Navigator layer of Sigma rule counts in SigmaHQ's own format) instead of
// the live SigmaHQ coverage layer.
const SIGMA_COVERAGE_URL =
  'https://raw.githubusercontent.com/SigmaHQ/sigma/master/other/sigma_attack_nav_coverage.json';
const ENRICHMENT_FIXTURES: Array<[url: string, file: string]> = [
  [SIGMA_COVERAGE_URL, 'e2e/fixtures/sigma-coverage.json'],
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
  for (const [url, file] of [...ATTACK_FIXTURES, ...ENRICHMENT_FIXTURES]) {
    await page.route(url, route => route.fulfill({ path: file, contentType: 'application/json' }));
  }
}

test.describe('ATT&CK-Navi', () => {
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
    // Click the heat=risk lens, relabelled 'Threat-weighted mapping gap' in E1.1
    const riskBtn = page.locator('.heatmap-mode-btn', { hasText: 'Threat-weighted mapping gap' });
    await riskBtn.click();
    // The heatmap button shows the lens's short label
    await expect(page.locator('.heatmap-btn')).toContainText('Threat-weighted gap');
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
    // Signals are computed when a technique is selected, so the (routed) Sigma
    // coverage layer must have been served before the click. The listener is
    // registered before navigation because the fetch starts at app boot.
    const sigmaServed = page.waitForResponse(SIGMA_COVERAGE_URL);
    await page.goto(BASE);
    await sigmaServed;
    // T1059 carries a rule count in e2e/fixtures/sigma-coverage.json (12 on
    // the parent + 7 on T1059.001, rolled up to 19 by SigmaService).
    const cell = page.locator('.cell', { hasText: 'T1059' }).first();
    await cell.waitFor({ state: 'visible', timeout: ROUTE_TIMEOUT });
    await cell.click();
    await expect(page.locator('.sidebar.open')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('.signal-pill').first()).toBeVisible({ timeout: 10000 });
    await expect(page.locator('.signal-pill', { hasText: 'Sigma' })).toContainText('19');
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

    // The pinned ICS bundle is on screen (E1.4: no live revalidation replaces it).
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
    // on a domain mismatch, plus the opt-in confirm before comment-derived
    // statuses are written); an unanswered dialog would hang the flow. The
    // handler accepts every dialog type, so alert and both confirms say yes.
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
    expect(dialogs.some(m => m.includes('"E2E Coverage" imported and saved (3 technique entries)'))).toBeTruthy();

    // The matrix is now in the library heatmap mode, driven by the upload.
    await page.locator('.nav-item', { hasText: 'Matrix' }).click();
    await expect(page.locator('.matrix-wrapper')).toBeVisible({ timeout: ROUTE_TIMEOUT });
    await expect(page.locator('.heatmap-btn')).toContainText('Library');

    // ...and the sidebar surfaces the layer's own entry for a scored technique.
    await page.locator('.cell', { hasText: 'T1059' }).first().click();
    await expect(page.locator('.sidebar.open')).toBeVisible({ timeout: 5000 });
    await expect(page.locator('#sb-sec-imported-layer')).toBeVisible({ timeout: 5000 });
    // SidebarComponent.ngOnInit collapses this section by default; expand it
    // so the layer's own entry (score badge) is rendered.
    await page.locator('#sb-sec-imported-layer').click();
    await expect(page.locator('.imported-layer-section')).toContainText('Score: 90');
  });
});

// E2.3 (P2-04): the drawer writes tech= (with heat=) and dom= into the URL, so a
// pasted link reopens the same technique, lens and domain. Each test opens the
// link in a NEW browser context: nothing carries over from a previous visit.
test.describe('E2.3: tech= and dom= share links', () => {
  async function newVisitor(browser: Browser): Promise<{ context: BrowserContext; page: Page }> {
    const context = await browser.newContext();
    const page = await context.newPage();
    await hermetic(page);
    await page.addInitScript(() => localStorage.setItem('onboarding-completed', 'true'));
    return { context, page };
  }

  test('[AC] (query form) a pasted link reopens the same technique and lens in a new context', async ({ browser }) => {
    const { context, page } = await newVisitor(browser);
    try {
      await page.goto(BASE + '/#/matrix?heat=kev&tech=T1059.001');
      await expect(page.locator('.sidebar.open .sidebar-header .attack-id')).toHaveText('T1059.001', { timeout: ROUTE_TIMEOUT });
      await expect(page.locator('.heatmap-btn')).toContainText('KEV');
      // The URL writer's first pass (300 ms debounce) used to drop tech=.
      await page.waitForTimeout(1000);
      expect(new URL(page.url()).hash).toContain('tech=T1059.001');
    } finally {
      await context.close();
    }
  });

  // P2-18 (E2.3-b): the page form of the same link. The technique page owns the
  // evidence card, so the drawer is not rendered there; "Open in matrix" carries
  // the selection and the lens to the matrix, whose drawer then opens on it, and
  // the drawer's "Full page" link carries the lens back (round 1: it used to drop
  // the query, so a copied page link reopened the default lens).
  test('[AC] (page form) a pasted link reopens the same technique and lens in a new context', async ({ browser }) => {
    const { context, page } = await newVisitor(browser);
    let pageLink = '';
    try {
      await page.goto(BASE + '/#/technique/enterprise/T1059.001?heat=coverage');
      const card = page.locator('app-technique-page [data-testid="evidence-card"]');
      await expect(card).toBeVisible({ timeout: ROUTE_TIMEOUT });
      await expect(page.locator('app-technique-page .tp-id')).toHaveText('T1059.001');
      const why = card.getByTestId('ev-why');
      await expect(why).toContainText('Lens: Mitigations mapped');
      await expect(why).toContainText(/Why this colour: score \d+ of max \d+: /);
      await expect(card.getByTestId('ev-known')).toBeVisible();
      await expect(card.getByTestId('ev-threat')).toBeVisible();
      // A fresh profile: Known and Threat only, and no drawer on this route.
      await expect(card.getByTestId('ev-proven')).toHaveCount(0);
      await expect(card.getByTestId('ev-covered')).toHaveCount(0);
      await expect(page.locator('app-sidebar')).toHaveCount(0);

      await page.getByTestId('open-in-matrix').click();
      await expect(page).toHaveURL(/#\/matrix\?(.*&)?tech=T1059\.001(&|$)/, { timeout: ROUTE_TIMEOUT });
      await expect(page).toHaveURL(/#\/matrix\?(.*&)?heat=coverage(&|$)/);
      await expect(page.locator('.heatmap-btn')).toContainText('Mitigations mapped');
      await expect(page.locator('.sidebar.open .sidebar-header .attack-id')).toHaveText('T1059.001', { timeout: ROUTE_TIMEOUT });
      await expect(page.locator('.sidebar.open [data-testid="evidence-card"]')).toBeVisible();

      // The drawer's "Full page" link is the page link a user copies: it keeps the lens.
      const fullPage = page.getByTestId('drawer-full-page');
      await expect(fullPage).toHaveAttribute('href', /^#\/technique\/enterprise\/T1059\.001\?(.*&)?heat=coverage(&|$)/);
      pageLink = (await fullPage.getAttribute('href'))!;
      await fullPage.click();
      await expect(page).toHaveURL(/#\/technique\/enterprise\/T1059\.001\?(.*&)?heat=coverage(&|$)/, { timeout: ROUTE_TIMEOUT });
      await expect(page.locator('app-technique-page [data-testid="ev-why"]')).toContainText('Lens: Mitigations mapped', { timeout: ROUTE_TIMEOUT });
    } finally {
      await context.close();
    }

    // That copied link, pasted into a new context, reopens the same technique and lens.
    const second = await newVisitor(browser);
    try {
      await second.page.goto(BASE + '/' + pageLink);
      const card = second.page.locator('app-technique-page [data-testid="evidence-card"]');
      await expect(card).toBeVisible({ timeout: ROUTE_TIMEOUT });
      await expect(second.page.locator('app-technique-page .tp-id')).toHaveText('T1059.001');
      await expect(card.getByTestId('ev-why')).toContainText('Lens: Mitigations mapped');
    } finally {
      await second.context.close();
    }
  });

  // RP-F item 4: the page's domain switch clears the filters, which reset the lens
  // after the URL reader applied heat=. The page now re-applies the pasted lens, so a
  // non-Enterprise technique link keeps it and "Open in matrix" carries it. The writer
  // adds tech= once the technique is selected, so its arrival marks the rewritten URL.
  for (const [dom, id, heat, label] of [
    ['ics', 'T0883', 'coverage', 'Mitigations mapped'],
    ['ics', 'T0883', 'kev', 'KEV'],
    ['mobile', 'T1404', 'coverage', 'Mitigations mapped'],
  ] as const) {
    test(`[RP-F 4] a pasted #/technique/${dom}/${id}?heat=${heat} keeps its lens, and Open in matrix carries it`, async ({ browser }) => {
      const { context, page } = await newVisitor(browser);
      try {
        await page.goto('about:blank');
        await page.goto(`${BASE}/#/technique/${dom}/${id}?heat=${heat}`);
        const card = page.locator('app-technique-page [data-testid="evidence-card"]');
        await expect(card).toBeVisible({ timeout: ROUTE_TIMEOUT });
        await expect(page.locator('app-technique-page .tp-id')).toHaveText(id);
        await expect(card.getByTestId('ev-why')).toContainText(`Lens: ${label}`);
        await expect(page).toHaveURL(new RegExp(`[?&]tech=${id}(&|$)`), { timeout: ROUTE_TIMEOUT });
        await expect(page).toHaveURL(new RegExp(`#/technique/${dom}/${id}\\?(.*&)?heat=${heat}(&|$)`));
        expect(new URL(page.url()).hash).not.toContain('heat=frequency');

        await page.getByTestId('open-in-matrix').click();
        await expect(page).toHaveURL(new RegExp(`#/matrix\\?(.*&)?heat=${heat}(&|$)`), { timeout: ROUTE_TIMEOUT });
        await expect(page).toHaveURL(new RegExp(`[?&]dom=${dom}(&|$)`));
        await expect(page.locator('.heatmap-btn')).toContainText(label);
        await expect(page.locator('.sidebar.open .sidebar-header .attack-id')).toHaveText(id, { timeout: ROUTE_TIMEOUT });
      } finally {
        await context.close();
      }
    });
  }

  test('an ICS technique link loads ICS and opens its drawer (dom=ics&tech=T0807)', async ({ browser }) => {
    const { context, page } = await newVisitor(browser);
    try {
      await page.goto(BASE + '/#/matrix?dom=ics&tech=T0807');
      await expect(page.locator('.domain-btn[title="ICS ATT&CK"]')).toHaveClass(/active/, { timeout: ROUTE_TIMEOUT });
      await expect(page.locator('.sidebar.open .sidebar-header .attack-id')).toHaveText('T0807', { timeout: ROUTE_TIMEOUT });
    } finally {
      await context.close();
    }
  });
});

// E1.4 (decision D2): ATT&CK is pinned to the bundled release. MITRE's live Enterprise STIX
// is served here as a newer release (the bundled file with its x-mitre-collection version
// set to 20.0, as v20.0 shipped on 2026-10-13). Before E1.4 the default live mode fetched
// it on load and swapped the matrix to it; now it is fetched only by "Check for ATT&CK
// update", only offered, and applied for this session only.
test.describe('E1.4: pinned ATT&CK, "Check for ATT&CK update"', () => {
  let live20 = '';

  test.beforeAll(() => {
    const bundle = JSON.parse(readFileSync('src/assets/data/enterprise-attack.json', 'utf8')) as { objects: Array<Record<string, unknown>> };
    const collection = bundle.objects.find(o => o['type'] === 'x-mitre-collection');
    expect(collection?.['x_mitre_version']).toBe('19.2');
    collection!['x_mitre_version'] = '20.0';
    live20 = JSON.stringify(bundle);
  });

  test('the version never changes by itself; a newer release is offered and applies to this session only', async ({ page }) => {
    test.slow(); // the 20.0 copy is a full Enterprise bundle
    await hermetic(page);
    await page.addInitScript(() => localStorage.setItem('onboarding-completed', 'true'));
    let liveRequests = 0;
    await page.route(ATTACK_FIXTURES[0][0], route => {
      liveRequests++;
      return route.fulfill({ status: 200, contentType: 'application/json', body: live20 });
    });

    const version = page.locator('.attack-version');
    const status = page.locator('[data-testid="attack-update"]');
    await page.goto(BASE);
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: ROUTE_TIMEOUT });
    await expect(version).toHaveText('v19.2');
    await expect(status).toHaveAttribute('role', 'status');
    await page.waitForLoadState('networkidle');
    expect(liveRequests, 'a fresh profile loads the pinned bundle and never asks MITRE').toBe(0);
    await expect(page.locator('.source-mode-btn')).toHaveCount(0);

    // The check offers 20.0 and changes nothing.
    const check = page.getByRole('button', { name: 'Check for ATT&CK update' });
    await check.click();
    await expect(status).toContainText('ATT&CK 20.0 is available', { timeout: ROUTE_TIMEOUT });
    await expect(status).toContainText('pinned to 19.2');
    expect(liveRequests).toBe(1);
    await expect(version).toHaveText('v19.2');

    // Declining keeps 19.2.
    await status.getByRole('button', { name: 'Keep 19.2' }).click();
    await expect(status).toHaveAttribute('data-status', 'idle');
    await expect(version).toHaveText('v19.2');

    // Only the explicit choice applies it.
    await check.click();
    await status.getByRole('button', { name: 'Use 20.0 for this session' }).click();
    await expect(version).toHaveText('v20.0');
    await expect(status).toContainText('Using ATT&CK 20.0 for this session only');
    expect(liveRequests).toBe(2);

    // Session only: a reload starts on the pinned bundle again, without asking MITRE.
    await page.reload();
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: ROUTE_TIMEOUT });
    await expect(version).toHaveText('v19.2');
    await page.waitForLoadState('networkidle');
    expect(liveRequests).toBe(2);
  });
});

// The owner's shell request: the technique drawer resizes from its inner (left)
// edge and the left rail collapses to icons only; both persist per browser and
// neither control exists in the <= 768 px bottom-bar layout.
test.describe('shell: resizable drawer and collapsible rail', () => {
  // Optional local screenshots for the PR (unset in CI).
  const SHOTS = process.env['SHELL_SHOTS'];

  test.beforeEach(async ({ page }) => {
    await hermetic(page);
    await page.addInitScript(() => localStorage.setItem('onboarding-completed', 'true'));
  });

  const boxWidth = async (page: Page, selector: string): Promise<number> =>
    (await page.locator(selector).boundingBox())?.width ?? 0;

  const noHorizontalPageScroll = (page: Page): Promise<boolean> =>
    page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth);

  async function openDrawer(page: Page): Promise<void> {
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: ROUTE_TIMEOUT });
    if (!(await page.locator('.sidebar.open').isVisible())) await page.locator('.cell').first().click();
    await expect(page.locator('.sidebar.open .sidebar-header .attack-id')).toContainText(/T\d/, { timeout: 5000 });
    // The drawer slides in (a 0.25 s transform transition). Wait until it has
    // stopped, flush with the right edge, before anyone reads the handle's box:
    // a mouse-down at a mid-slide position misses the handle.
    await expect
      .poll(
        () =>
          page.locator('.sidebar.open').evaluate((el) => {
            const running = el.getAnimations().filter((a) => a.playState === 'running').length;
            const right = Math.round(el.getBoundingClientRect().right);
            return running === 0 && right === window.innerWidth;
          }),
        { timeout: 5000 },
      )
      .toBe(true);
  }

  /** Text of the matrix's keyboard-focused cell(s); the matrix moves this on bare arrow keys. */
  const focusedCells = (page: Page): Promise<string[]> =>
    page.locator('.cell.focused').evaluateAll((els) => els.map((e) => (e.textContent ?? '').trim()));

  test('shell: drag, keyboard and double-click resize the technique drawer; the width persists', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto(BASE + '/#/matrix');
    await openDrawer(page);

    const handle = page.getByRole('separator', { name: 'Resize technique panel' });
    await expect(handle).toBeVisible();
    await expect(handle).toHaveAttribute('aria-orientation', 'vertical');
    await expect(handle).toHaveAttribute('aria-valuemin', '320');
    await expect(handle).toHaveAttribute('aria-valuemax', '864');
    await expect(handle).toHaveAttribute('aria-valuenow', '460');
    await expect.poll(() => boxWidth(page, '.sidebar.open')).toBeCloseTo(460, 0);
    // The open drawer takes its width from the workspace (it no longer covers the matrix).
    const workspaceBefore = await boxWidth(page, '.workspace-area');
    const matrixBefore = await boxWidth(page, 'app-matrix');
    const workspaceRight = async (): Promise<number> => {
      const b = (await page.locator('.workspace-area').boundingBox())!;
      return b.x + b.width;
    };
    expect(await workspaceRight()).toBeCloseTo(1440 - 460, 0);
    if (SHOTS) await page.screenshot({ path: `${SHOTS}/drawer-default.png` });

    // Drag the handle 160 px to the left: the drawer widens by about 160 px.
    const box = (await handle.boundingBox())!;
    const x = box.x + box.width / 2;
    const y = box.y + box.height / 2;
    await page.mouse.move(x, y);
    await page.mouse.down();
    await page.mouse.move(x - 80, y, { steps: 4 });
    await page.mouse.move(x - 160, y, { steps: 4 });
    await page.mouse.up();
    await expect.poll(() => boxWidth(page, '.sidebar.open')).toBeGreaterThan(460 + 155);
    expect(await boxWidth(page, '.sidebar.open')).toBeLessThan(460 + 165);
    await expect(handle).toHaveAttribute('aria-valuenow', '620');
    // The drag selected no text and the page gained no horizontal scroll.
    expect(await page.evaluate(() => String(window.getSelection() ?? ''))).toBe('');
    expect(await noHorizontalPageScroll(page)).toBe(true);
    const drawerBox = (await page.locator('.sidebar.open').boundingBox())!;
    expect(drawerBox.x + drawerBox.width).toBeCloseTo(1440, 0);
    // The matrix area changes the opposite way: 160 px narrower, ending where the drawer starts.
    await expect.poll(() => boxWidth(page, '.workspace-area')).toBeCloseTo(workspaceBefore - 160, 0);
    await expect.poll(() => boxWidth(page, 'app-matrix')).toBeCloseTo(matrixBefore - 160, 0);
    expect(await workspaceRight()).toBeCloseTo(drawerBox.x, 0);
    if (SHOTS) await page.screenshot({ path: `${SHOTS}/drawer-dragged.png` });

    // Reload: the width persists (applied on the first render).
    await page.reload();
    await openDrawer(page);
    await expect(handle).toHaveAttribute('aria-valuenow', '620');
    await expect.poll(() => boxWidth(page, '.sidebar.open')).toBeCloseTo(620, 0);

    // Keyboard, like a left-edge splitter: ArrowRight moves the separator right
    // (three presses narrow the drawer by 48 px), ArrowLeft moves it left (wider).
    await handle.focus();
    if (SHOTS) await page.screenshot({ path: `${SHOTS}/drawer-handle-focus.png` });
    const focusedBefore = await focusedCells(page);
    for (let i = 0; i < 3; i++) await page.keyboard.press('ArrowRight');
    await expect(handle).toHaveAttribute('aria-valuenow', '572');
    await expect.poll(() => boxWidth(page, '.sidebar.open')).toBeCloseTo(572, 0);
    await page.keyboard.press('ArrowLeft');
    await expect(handle).toHaveAttribute('aria-valuenow', '588');
    await expect.poll(() => boxWidth(page, '.sidebar.open')).toBeCloseTo(588, 0);
    // The arrows stayed in the handle: the matrix's keyboard focus did not move.
    expect(await focusedCells(page)).toEqual(focusedBefore);
    await expect(handle).toBeFocused();

    // Double-click resets to the default.
    await handle.dblclick();
    await expect(handle).toHaveAttribute('aria-valuenow', '460');
    await expect.poll(() => boxWidth(page, '.sidebar.open')).toBeCloseTo(460, 0);

    // Pin and Escape still work.
    const pin = page.locator('.sidebar.open .pin-btn');
    await pin.click();
    await expect(pin).toHaveAttribute('aria-pressed', 'true');
    await pin.click();
    await expect(pin).toHaveAttribute('aria-pressed', 'false');
    await page.locator('.sidebar-header .technique-name').click();
    await page.keyboard.press('Escape');
    await expect(page.locator('.sidebar.open')).toBeHidden({ timeout: 3000 });
  });

  test('shell: the rail collapses to icons with titles, persists, and expands', async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto(BASE + '/#/matrix');
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: ROUTE_TIMEOUT });

    const rail = page.locator('app-nav-rail');
    const items = page.locator('#app-nav-rail .nav-list a.nav-item');
    const railWide = await boxWidth(page, 'app-nav-rail');
    const workspaceWide = await boxWidth(page, '.workspace-area');
    expect(railWide).toBeCloseTo(260, 0);

    const collapse = page.getByRole('button', { name: 'Collapse navigation' });
    await expect(collapse).toHaveAttribute('aria-expanded', 'true');
    await expect(collapse).toHaveAttribute('aria-controls', 'app-nav-rail');
    await collapse.click();

    const expand = page.getByRole('button', { name: 'Expand navigation' });
    await expect(expand).toHaveAttribute('aria-expanded', 'false');
    await expect(rail).toHaveClass(/collapsed/);
    await expect.poll(() => boxWidth(page, 'app-nav-rail')).toBeLessThan(railWide - 150);
    const railNarrow = await boxWidth(page, 'app-nav-rail');
    // The main area gains the freed width.
    await expect.poll(() => boxWidth(page, '.workspace-area')).toBeCloseTo(workspaceWide + railWide - railNarrow, 0);
    expect(await noHorizontalPageScroll(page)).toBe(true);

    // Icons stay, each with the workspace name as title and aria-label; labels are hidden.
    await expect(items).toHaveCount(9);
    for (let i = 0; i < 9; i++) {
      const item = items.nth(i);
      await expect(item.locator('.nav-icon svg')).toBeVisible();
      await expect(item.locator('.nav-label')).toBeHidden();
      const label = await item.getAttribute('aria-label');
      expect(label).toBeTruthy();
      await expect(item).toHaveAttribute('title', label!);
    }
    // Section groupings and the bottom Help / Settings remain; the viewpoint shows its icon.
    await expect(page.locator('#app-nav-rail .rail-section-label')).toHaveCount(3);
    await expect(page.getByRole('link', { name: 'Settings' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Keyboard shortcuts and help' })).toBeVisible();
    await expect(page.locator('app-viewpoint-selector .vp-trigger .vp-icon')).toBeVisible();
    await expect(page.locator('app-viewpoint-selector .vp-text')).toBeHidden();
    if (SHOTS) await page.screenshot({ path: `${SHOTS}/rail-collapsed.png` });

    // Reload: still collapsed.
    await page.reload();
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: ROUTE_TIMEOUT });
    await expect(page.getByRole('button', { name: 'Expand navigation' })).toHaveAttribute('aria-expanded', 'false');
    expect(await boxWidth(page, 'app-nav-rail')).toBeCloseTo(railNarrow, 0);

    // Expand: restored.
    await page.getByRole('button', { name: 'Expand navigation' }).click();
    await expect(page.getByRole('button', { name: 'Collapse navigation' })).toHaveAttribute('aria-expanded', 'true');
    await expect.poll(() => boxWidth(page, 'app-nav-rail')).toBeCloseTo(railWide, 0);
    await expect(items.first().locator('.nav-label')).toBeVisible();
    await expect.poll(() => boxWidth(page, '.workspace-area')).toBeCloseTo(workspaceWide, 0);
  });

  test('shell: at the mobile width neither control is present and the bottom bar is unchanged', async ({ page }) => {
    // Even with both preferences stored, the <= 768 px layout ignores them.
    await page.addInitScript(() => {
      localStorage.setItem('navrail-collapsed-v1', '1');
      localStorage.setItem('technique-drawer-width-v1', '700');
    });
    await page.setViewportSize({ width: 375, height: 812 });
    await page.goto(BASE + '/#/matrix?tech=T1059.001');
    await expect(page.locator('.sidebar.open .sidebar-header .attack-id')).toHaveText('T1059.001', { timeout: ROUTE_TIMEOUT });

    await expect(page.getByRole('separator', { name: 'Resize technique panel' })).toBeHidden();
    expect(await boxWidth(page, '.sidebar.open')).toBeCloseTo(375, 0);

    const rail = (await page.locator('app-nav-rail').boundingBox())!;
    expect(rail.width).toBeCloseTo(375, 0);
    expect(rail.height).toBeCloseTo(56, 0);
    await expect(page.locator('app-nav-rail')).not.toHaveClass(/collapsed/);
    await expect(page.locator('.rail-collapse-btn')).toBeHidden();
    await expect(page.locator('#app-nav-rail .nav-list .nav-label').first()).toBeVisible();
    if (SHOTS) await page.screenshot({ path: `${SHOTS}/mobile.png` });
  });
});

// P2-19 (E2.4): the default-lens rule. A profile with one recorded validation
// run (D4) opens #/matrix on Posture, and the link names it. The fresh-profile
// half (Prevalence, no heat=) is journey 4 in journeys.spec.ts, unchanged.
test.describe('E2.4: default-lens rule', () => {
  const oneRun = JSON.stringify({
    schema: 2, tombstones: [],
    records: [{
      id: 'e2e-p2-19-run', techniqueId: 'T1059.001', runDate: '2026-10-01T00:00:00.000Z', status: 'passed', attackResult: 'executed',
      source: 'manual', domain: null, attackVersion: 'unknown', createdAt: '2026-10-01T00:00:00.000Z', updatedAt: '2026-10-01T00:00:00.000Z',
      techniqueRef: null, outcomes: [], proofScope: 'own-run', statusFromSource: false,
    }],
  });

  test('[AC] one recorded run switches the default to Posture: the View button shows Posture and the URL has heat=posture', async ({ page }) => {
    await openWorkspace(page, { seed: { 'navi.v2.validation-runs': oneRun } });
    await page.goto(BASE + '/#/matrix');
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: ROUTE_TIMEOUT });
    await expect(page.locator('.heatmap-btn')).toContainText('Posture');
    await expect(page).toHaveURL(/#\/matrix\?(.*&)?heat=posture(&|$)/, { timeout: 5000 });
    await expect(page.locator('.first-glance-banner')).toHaveCount(0);
  });

  // RP-F item 1: an invalid or empty heat= is not a lens choice, so D4 still
  // runs. Each link is a fresh navigation (about:blank first): the app does not
  // re-read heat= on an in-session hash-only change.
  for (const link of ['#/matrix?heat=bogus', '#/matrix?heat=']) {
    test(`[RP-F 1] one recorded run and a pasted ${link}: Posture, heat=posture, no banner`, async ({ page }) => {
      await openWorkspace(page, { seed: { 'navi.v2.validation-runs': oneRun } });
      await page.goto('about:blank');
      await page.goto(BASE + '/' + link);
      await page.locator('.cell').first().waitFor({ state: 'visible', timeout: ROUTE_TIMEOUT });
      await expect(page.locator('.heatmap-btn')).toContainText('Posture');
      await expect(page).toHaveURL(/#\/matrix\?(.*&)?heat=posture(&|$)/, { timeout: 5000 });
      expect(new URL(page.url()).hash).not.toContain('heat=frequency');
      await expect(page.locator('.first-glance-banner')).toHaveCount(0);
    });
  }

  // RP-F decision 10: owner data that first appears in the session (a bulk set of 3
  // techniques) while Frequency is on screen only as the D4 default must not write
  // heat=frequency: a reload then runs D4 and boots Posture (P2-19 walk step 5). A
  // Frequency chosen through the View menu is a choice and survives the reload.
  // The reload is a fresh navigation; the in-session lens change goes through the View menu.
  async function bulkSetThreeImplemented(page: Page): Promise<void> {
    await page.locator('.heatmap-btn').click();
    await page.locator('.views-menu .menu-action', { hasText: 'Multi-select' }).click();
    const boxes = page.locator('.cell-checkbox');
    await expect(boxes.first()).toBeVisible({ timeout: ROUTE_TIMEOUT });
    for (let i = 0; i < 3; i++) await boxes.nth(i).click();
    await expect(page.locator('.bulk-bar .bulk-count')).toHaveText('3 selected');
    await page.locator('.bulk-bar .bulk-btn.impl').click();
    // Owner data now exists (D4): the Prevalence banner hides in the same session.
    await expect(page.locator('.first-glance-banner')).toHaveCount(0, { timeout: ROUTE_TIMEOUT });
  }

  test('[RP-F 10] a fresh profile bulk-sets 3 techniques on #/matrix: heat stays absent, and a reload boots Posture with heat=posture', async ({ page }) => {
    await openWorkspace(page);
    await page.goto(BASE + '/#/matrix');
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: ROUTE_TIMEOUT });
    await expect(page.locator('.heatmap-btn')).toContainText('Frequency');
    await expect(page.locator('.first-glance-banner')).toBeVisible();
    await bulkSetThreeImplemented(page);
    await expect(page.locator('.heatmap-btn')).toContainText('Frequency');
    // The URL writer is debounced (300 ms); give it well over that before reading the hash.
    await page.waitForTimeout(1500);
    expect(new URL(page.url()).hash).not.toContain('heat=');
    await page.reload();
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: ROUTE_TIMEOUT });
    await expect(page.locator('.heatmap-btn')).toContainText('Posture');
    await expect(page).toHaveURL(/#\/matrix\?(.*&)?heat=posture(&|$)/, { timeout: 5000 });
    await expect(page.locator('.first-glance-banner')).toHaveCount(0);
  });

  test('[RP-F 10] Frequency chosen in the View menu before the bulk set is written as heat=frequency and kept on reload', async ({ page }) => {
    await openWorkspace(page);
    await page.goto(BASE + '/#/matrix');
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: ROUTE_TIMEOUT });
    await page.locator('.heatmap-btn').click();
    await page.locator('.views-menu .lens-item[data-lens="frequency"] .heatmap-mode-btn').click();
    await expect(page.locator('.views-menu')).toBeHidden();
    await bulkSetThreeImplemented(page);
    await expect(page).toHaveURL(/#\/matrix\?(.*&)?heat=frequency(&|$)/, { timeout: 5000 });
    await page.reload();
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: ROUTE_TIMEOUT });
    await expect(page.locator('.heatmap-btn')).toContainText('Frequency');
    await expect(page).toHaveURL(/#\/matrix\?(.*&)?heat=frequency(&|$)/, { timeout: 5000 });
  });

  // RP-F decision 19: the toolbar brand link (routerLink /matrix) dropped the query, and
  // with no state change the writer left #/matrix bare, so F5 lost a chosen lens (3 of 3
  // in round 3). The lens is now written back; the D4 default path stays bare (decision 10).
  test('[RP-F 19] KEV chosen in the View menu survives the brand link and F5', async ({ page }) => {
    await openWorkspace(page);
    await page.goto(BASE + '/#/matrix');
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: ROUTE_TIMEOUT });
    await page.locator('.heatmap-btn').click();
    await page.locator('.views-menu .lens-item[data-lens="kev"] .heatmap-mode-btn').click();
    await expect(page.locator('.views-menu')).toBeHidden();
    await expect(page).toHaveURL(/#\/matrix\?(.*&)?heat=kev(&|$)/, { timeout: LENS_STEP_TIMEOUT });
    await page.locator('.brand-link').click();
    await expect(page).toHaveURL(/#\/matrix\?(.*&)?heat=kev(&|$)/, { timeout: 5000 });
    await page.reload();
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: ROUTE_TIMEOUT });
    await expect(page.locator('.heatmap-btn')).toContainText('KEV');
    await expect(page).toHaveURL(/#\/matrix\?(.*&)?heat=kev(&|$)/, { timeout: 5000 });
  });

  test('[RP-F 19] the D4 default path is unchanged: the brand link leaves #/matrix bare and F5 opens Frequency with the banner', async ({ page }) => {
    await openWorkspace(page);
    await page.goto(BASE + '/#/matrix');
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: ROUTE_TIMEOUT });
    await expect(page.locator('.heatmap-btn')).toContainText('Frequency');
    await page.locator('.brand-link').click();
    // The URL writer is debounced (300 ms); give it well over that before reading the hash.
    await page.waitForTimeout(1500);
    expect(new URL(page.url()).hash).not.toContain('heat=');
    await page.reload();
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: ROUTE_TIMEOUT });
    await expect(page.locator('.heatmap-btn')).toContainText('Frequency');
    await expect(page.locator('.first-glance-banner')).toBeVisible();
    expect(new URL(page.url()).hash).not.toContain('heat=');
  });

  test('[RP-F 4] one recorded run and a pasted #/technique/ics/T0883?heat=status: Status survives the domain switch, not Posture', async ({ page }) => {
    await openWorkspace(page, { seed: { 'navi.v2.validation-runs': oneRun } });
    await page.goto('about:blank');
    await page.goto(BASE + '/#/technique/ics/T0883?heat=status');
    const card = page.locator('app-technique-page [data-testid="evidence-card"]');
    await expect(card).toBeVisible({ timeout: ROUTE_TIMEOUT });
    await expect(card.getByTestId('ev-why')).toContainText('Lens: Status');
    await expect(page).toHaveURL(/[?&]tech=T0883(&|$)/, { timeout: ROUTE_TIMEOUT });
    await expect(page).toHaveURL(/#\/technique\/ics\/T0883\?(.*&)?heat=status(&|$)/);
    await page.getByTestId('open-in-matrix').click();
    await expect(page).toHaveURL(/#\/matrix\?(.*&)?heat=status(&|$)/, { timeout: ROUTE_TIMEOUT });
    await expect(page.locator('.heatmap-btn')).toContainText('Status');
  });

  test('[RP-F 1] one recorded run and a pasted #/technique/enterprise/T1059.001?heat=bogus: the page explains Posture and the link says heat=posture', async ({ page }) => {
    await openWorkspace(page, { seed: { 'navi.v2.validation-runs': oneRun } });
    await page.goto('about:blank');
    await page.goto(BASE + '/#/technique/enterprise/T1059.001?heat=bogus');
    const card = page.locator('app-technique-page [data-testid="evidence-card"]');
    await expect(card).toBeVisible({ timeout: ROUTE_TIMEOUT });
    await expect(card.getByTestId('ev-why')).toContainText('Lens: Posture');
    await expect(page).toHaveURL(/#\/technique\/enterprise\/T1059\.001\?(.*&)?heat=posture(&|$)/, { timeout: 5000 });
    expect(new URL(page.url()).hash).not.toContain('heat=frequency');
    await page.getByTestId('open-in-matrix').click();
    await expect(page).toHaveURL(/#\/matrix\?(.*&)?heat=posture(&|$)/, { timeout: ROUTE_TIMEOUT });
    await expect(page.locator('.heatmap-btn')).toContainText('Posture');
  });

  // RP-F decision 17: paints implies speaks. T1078 carries M1015 implemented (an undated
  // full mark) and a later failed run, so the mark is contradicted. In round 3 the Proven
  // lens drew the hatch while its aria-label and tooltip said only "no recorded detection".
  // Each lens is a pasted link (a fresh navigation); the drawer's why line is read too.
  const T1078 = 'attack-pattern--b17a1a56-e99c-403c-8948-561df0cffe81';
  const M1015 = 'course-of-action--e3388c78-2a8d-47c2-8422-c1398b324462';
  const contradictedSeed = {
    'mitre-nav-impl-v1': JSON.stringify([[M1015, 'implemented']]),
    'navi.v2.validation-runs': JSON.stringify({
      schema: 2, tombstones: [],
      records: [{
        id: 'e2e-rpf17-failed', techniqueId: 'T1078', runDate: '2026-10-20T15:00:00.000Z', status: 'failed', attackResult: 'executed',
        source: 'manual', domain: null, attackVersion: 'unknown', createdAt: '2026-10-20T15:00:00.000Z', updatedAt: '2026-10-20T15:00:00.000Z',
        techniqueRef: null, outcomes: [], proofScope: 'own-run', statusFromSource: false,
      }],
    }),
  };
  for (const [lens, label, hatch] of [
    ['posture', 'Posture', true], ['covered', 'Covered', true], ['proven', 'Proven', true], ['status', 'Status', false],
  ] as const) {
    test(`[RP-F 17] T1078 (M1015 and a later failed run) on heat=${lens}: aria-label, tooltip and why line say contradicted${hatch ? ', with the hatch' : ', no hatch'}`, async ({ page }) => {
      await openWorkspace(page, { seed: contradictedSeed });
      await page.goto('about:blank');
      await page.goto(`${BASE}/#/matrix?heat=${lens}`);
      await expect(page.locator('.heatmap-btn')).toContainText(label, { timeout: ROUTE_TIMEOUT });
      const cell = page.locator(`[data-tech-id="${T1078}"] .cell`).first();
      await expect(cell).toBeVisible({ timeout: ROUTE_TIMEOUT });
      await expect(cell).toHaveAttribute('aria-label', /contradicted by a later failed run/);
      if (hatch) await expect(cell).toHaveClass(/posture-contradicted/);
      else await expect(cell).not.toHaveClass(/posture-contradicted/);
      await cell.hover();
      await expect(page.locator('.tooltip-card .tt-posture')).toContainText('contradicted by a later failed run');
      await cell.click();
      const why = page.locator('.sidebar.open [data-testid="ev-why"]');
      await expect(why).toContainText(/contradict/, { timeout: ROUTE_TIMEOUT });
      await expect(why).toContainText(`Lens: ${label}`);
    });
  }
});

// RP-F item 5: with the technique drawer open at 1440x900 the View button wraps to
// the controls row's left end, and the right-aligned absolute menu opened at
// x = -277: clipped by the workspace and under the 260 px rail, whose labels took
// the clicks. The menu is now fixed above the rail and clamped to the row and the
// viewport. Every click below is a real pointer click: Playwright refuses it when
// another element would receive it.
//
// RP-F round 1 (check-flaky): on the production build 2 of 6 runs timed out after
// 5 s waiting for heat= to follow a pick. Timed in the page, the URL writer's
// replaceUrl navigation took about 2 ms and no write was skipped; the 300 ms
// debounce itself fired up to 6.3 s late, because the main thread is saturated for
// several seconds after a data-loading lens (Campaigns, Intelligence, My Exposure)
// is first picked shortly after boot. The URL is right, only late, so every step
// waits LENS_STEP_TIMEOUT rather than 5 s: the check is still that heat= follows
// each pick, without timing the lens's first data load.
//
// RP-F round 2: a write whose debounce fired during an in-flight navigation was
// dropped until the next state change, so a pick with no later change could leave
// heat= stale whatever the timeout. UrlStateService now holds that write and runs
// it when the navigation settles (unit-tested in url-state.service.spec.ts), so the
// timeout above only absorbs the late debounce.
const LENS_STEP_TIMEOUT = process.env['CI'] ? 60000 : 30000;

test.describe('View menu above the rail (RP-F item 5)', () => {
  test('[RP-F 5] at 1440x900 with the drawer open, every lens in the View menu takes a real click and the menu never lies over the rail', async ({ page }) => {
    test.setTimeout(process.env['CI'] ? 600000 : 300000);
    await page.setViewportSize({ width: 1440, height: 900 });
    await openWorkspace(page);
    await page.goto(BASE + '/#/matrix?tech=T1059.001');
    await expect(page.locator('.sidebar.open .sidebar-header .attack-id')).toHaveText('T1059.001', { timeout: ROUTE_TIMEOUT });
    const rail = (await page.locator('app-nav-rail').boundingBox())!;
    expect(rail.width).toBeGreaterThan(200);
    const menu = page.locator('.views-menu');
    const openMenu = async () => {
      await page.locator('.heatmap-btn').click({ timeout: LENS_STEP_TIMEOUT });
      await expect(menu).toBeVisible({ timeout: LENS_STEP_TIMEOUT });
    };
    await openMenu();
    const lenses = await menu.locator('.lens-item').evaluateAll(els => els.map(e => e.getAttribute('data-lens')!));
    expect(lenses.length).toBeGreaterThan(30);
    for (const lens of lenses) {
      if (!(await menu.isVisible())) await openMenu();
      const box = (await menu.boundingBox())!;
      expect(box.x, `${lens}: the menu's left edge clears the rail`).toBeGreaterThanOrEqual(rail.x + rail.width);
      expect(box.x + box.width, `${lens}: inside the viewport`).toBeLessThanOrEqual(1440);
      expect(box.y + box.height, `${lens}: inside the viewport`).toBeLessThanOrEqual(900);
      const button = menu.locator(`.lens-item[data-lens="${lens}"] .heatmap-mode-btn`);
      const disabled = (await button.getAttribute('aria-disabled')) === 'true';
      if (disabled) {
        // aria-disabled: Playwright's click() waits for an enabled element, so the real
        // click is the mouse at the button's centre after hover() has checked that this
        // button, not the rail or the drawer, receives pointer events there.
        await button.hover({ timeout: LENS_STEP_TIMEOUT });
        const b = (await button.boundingBox())!;
        await page.mouse.click(b.x + b.width / 2, b.y + b.height / 2);
        await expect(menu, `${lens}: a disabled lens keeps the menu open`).toBeVisible({ timeout: LENS_STEP_TIMEOUT });
      } else {
        await button.click({ timeout: LENS_STEP_TIMEOUT });
        await expect(menu, `${lens}: picking a lens closes the menu`).toBeHidden({ timeout: LENS_STEP_TIMEOUT });
        await expect(page).toHaveURL(new RegExp(`[?&]heat=${lens}(&|$)`), { timeout: LENS_STEP_TIMEOUT });
      }
    }
    await expect(page.locator('.sidebar.open .sidebar-header .attack-id')).toHaveText('T1059.001');
  });
});

// Technique page design PR 1 (fix-first). The page and the drawer start the same
// per-technique live fetches through one coordinator, so a cold paste and the
// drawer's Full page agree (the owner's screenshot: D3FEND 20 through Full page,
// 0 on a pasted link); the card asks for the KEV catalogue on idle and says
// loading, the count, or failed with Retry; and the page takes the workspace's
// width. Pasted-link tests are fresh navigations (about:blank first).
test.describe('technique page PR 1: D3FEND parity, KEV states, the page width', () => {
  const D3FEND_T1037 = 'https://d3fend.mitre.org/api/offensive-technique/attack/T1037.json';
  /** Four live countermeasures for T1037; the bundled D3FEND seed maps none to it. */
  const D3FEND_LIVE = ['Process Spawn Analysis', 'Script Execution Analysis', 'File Analysis', 'Executable Allowlisting'];
  const d3fendAnswer = {
    off_to_def: {
      results: {
        bindings: D3FEND_LIVE.map((label, i) => ({
          def_tech_id: { value: `D3-PR1-${i}` },
          def_tech_label: { value: label },
          def_tactic_label: { value: i < 3 ? 'Detect' : 'Harden' },
          def_tech: { value: `http://d3fend.mitre.org/ontologies/d3fend.owl#${label.replace(/\s+/g, '')}` },
        })),
      },
    },
  };
  // The CTID KEV-to-ATT&CK mapping at its pinned path (the directory listing on
  // api.github.com stays blocked, so the service falls back to the pinned file).
  const CTID_KEV = 'https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/main/mappings/kev/attack-16.1/kev-07.28.2025/enterprise/kev-07.28.2025_attack-16.1-enterprise.json';
  const ctidKev = {
    mapping_objects: [{
      capability_id: 'CVE-2024-3400', attack_object_id: 'T1059.001', mapping_type: 'exploitation_technique',
      capability_description: 'PAN-OS GlobalProtect command injection', capability_group: 'command_injection',
    }],
  };

  async function newVisitor(browser: Browser, viewport = { width: 1440, height: 900 }): Promise<{ context: BrowserContext; page: Page }> {
    const context = await browser.newContext({ viewport });
    const page = await context.newPage();
    await hermetic(page);
    await page.route(D3FEND_T1037, route => route.fulfill({ json: d3fendAnswer }));
    await page.addInitScript(() => localStorage.setItem('onboarding-completed', 'true'));
    return { context, page };
  }

  /** The Known rows of the evidence card in `scope`, as text. */
  async function knownRows(scope: ReturnType<Page['locator']>): Promise<string[]> {
    const rows = scope.locator('[data-testid="ev-known"] .ev-known-row');
    await expect(rows).toHaveCount(5, { timeout: ROUTE_TIMEOUT });
    return (await rows.allInnerTexts()).map(t => t.replace(/\s+/g, ' ').trim());
  }

  const d3fendRow = (rows: string[]) => rows.find(r => r.startsWith('D3FEND countermeasures'));

  test('a cold paste of #/technique/enterprise/T1037 counts the live D3FEND answer, the same as the drawer and its Full page', async ({ browser }) => {
    const pageCard = (p: Page) => p.locator('app-technique-page [data-testid="evidence-card"]');
    const drawerCard = (p: Page) => p.locator('.sidebar.open [data-testid="evidence-card"]');

    // 1. A pasted link in a new context: the page primes the coordinator itself.
    const cold = await newVisitor(browser);
    let pasted: string[] = [];
    try {
      await cold.page.goto('about:blank');
      await cold.page.goto(`${BASE}/#/technique/enterprise/T1037`);
      await expect(pageCard(cold.page)).toBeVisible({ timeout: ROUTE_TIMEOUT });
      await expect(pageCard(cold.page).locator('[data-testid="ev-known"]'))
        .toContainText(`D3FEND countermeasures ${D3FEND_LIVE.length}`, { timeout: ROUTE_TIMEOUT });
      pasted = await knownRows(pageCard(cold.page));
      expect(d3fendRow(pasted)).toBe(`D3FEND countermeasures ${D3FEND_LIVE.length} MITRE D3FEND`);
      // Open in matrix: the drawer's card reads the same rows.
      await cold.page.getByTestId('open-in-matrix').click();
      await expect(drawerCard(cold.page)).toBeVisible({ timeout: ROUTE_TIMEOUT });
      expect(await knownRows(drawerCard(cold.page))).toEqual(pasted);
    } finally {
      await cold.context.close();
    }

    // 2. The drawer first, then its Full page, in another new context: the same rows on both.
    const warm = await newVisitor(browser);
    try {
      await warm.page.goto('about:blank');
      await warm.page.goto(`${BASE}/#/matrix?tech=T1037`);
      await expect(drawerCard(warm.page)).toBeVisible({ timeout: ROUTE_TIMEOUT });
      await expect(drawerCard(warm.page).locator('[data-testid="ev-known"]'))
        .toContainText(`D3FEND countermeasures ${D3FEND_LIVE.length}`, { timeout: ROUTE_TIMEOUT });
      const drawer = await knownRows(drawerCard(warm.page));
      expect(drawer).toEqual(pasted);
      await warm.page.getByTestId('drawer-full-page').click();
      await expect(pageCard(warm.page)).toBeVisible({ timeout: ROUTE_TIMEOUT });
      expect(await knownRows(pageCard(warm.page))).toEqual(drawer);
    } finally {
      await warm.context.close();
    }
  });

  test('a failed D3FEND live call reads "D3FEND did not load · Retry" on the page and in the drawer, never 0; Retry counts the live answer', async ({ browser }) => {
    const pageCard = (p: Page) => p.locator('app-technique-page [data-testid="evidence-card"]');
    const drawerCard = (p: Page) => p.locator('.sidebar.open [data-testid="evidence-card"]');
    const { context, page } = await newVisitor(browser);
    // d3fend.mitre.org rate-limits this technique (registered last, so it answers before the live answer).
    const rateLimited = (route: Route) => route.fulfill({ status: 429, body: 'Too Many Requests' });
    await page.route(D3FEND_T1037, rateLimited);
    try {
      await page.goto('about:blank');
      await page.goto(`${BASE}/#/technique/enterprise/T1037`);
      await expect(pageCard(page)).toBeVisible({ timeout: ROUTE_TIMEOUT });
      const failed = pageCard(page).getByTestId('ev-known-failed');
      await expect(failed).toHaveText(/D3FEND countermeasures\s+n\/a\s+D3FEND did not load\s+·\s+Retry/, { timeout: ROUTE_TIMEOUT });
      await expect(pageCard(page).getByTestId('ev-known-summary')).toContainText('D3FEND did not load');
      const pasted = await knownRows(pageCard(page));
      expect(d3fendRow(pasted)).not.toMatch(/\b0\b/);
      // The drawer reads the same failed row: one coordinator, one D3FEND state.
      await page.getByTestId('open-in-matrix').click();
      await expect(drawerCard(page)).toBeVisible({ timeout: ROUTE_TIMEOUT });
      expect(await knownRows(drawerCard(page))).toEqual(pasted);
      // d3fend.mitre.org answers again: Retry counts the live answer.
      await page.unroute(D3FEND_T1037, rateLimited);
      await drawerCard(page).getByTestId('ev-d3fend-retry').click();
      await expect(drawerCard(page).locator('[data-testid="ev-known"]'))
        .toContainText(`D3FEND countermeasures ${D3FEND_LIVE.length}`, { timeout: ROUTE_TIMEOUT });
      await expect(drawerCard(page).getByTestId('ev-known-failed')).toHaveCount(0);
    } finally {
      await context.close();
    }
  });

  for (const host of ['page', 'drawer'] as const) {
    test(`a sub-technique whose own D3FEND call failed after its parent answered: Retry in the ${host} sends the call again`, async ({ browser }) => {
      // The shared 'd3fend-technique-api' record reads loaded once the parent answered;
      // Retry must still ask for the failed sub-technique (round 3).
      const D3FEND_SUB = 'https://d3fend.mitre.org/api/offensive-technique/attack/T1037.001.json';
      const card = (p: Page) => host === 'page'
        ? p.locator('app-technique-page [data-testid="evidence-card"]')
        : p.locator('.sidebar.open [data-testid="evidence-card"]');
      const { context, page } = await newVisitor(browser);
      const subDown = (route: Route) => route.abort('failed');
      await page.route(D3FEND_SUB, subDown);
      // The parent answers 2 s later, after the sub-technique's call failed.
      await page.route(D3FEND_T1037, async route => {
        await new Promise(resolve => setTimeout(resolve, 2_000));
        await route.fulfill({ json: d3fendAnswer }).catch(() => undefined);
      });
      let subCalls = 0;
      page.on('request', req => { if (req.url() === D3FEND_SUB) subCalls++; });
      try {
        await page.goto('about:blank');
        const parentAnswered = page.waitForResponse(D3FEND_T1037, { timeout: ROUTE_TIMEOUT });
        await page.goto(host === 'page' ? `${BASE}/#/technique/enterprise/T1037.001` : `${BASE}/#/matrix?tech=T1037.001`);
        await expect(card(page)).toBeVisible({ timeout: ROUTE_TIMEOUT });
        const failed = card(page).getByTestId('ev-known-failed');
        await expect(failed).toHaveText(/D3FEND countermeasures\s+n\/a\s+D3FEND did not load\s+·\s+Retry/, { timeout: ROUTE_TIMEOUT });
        // The parent's answer lands: the shared record now reads loaded, the row still failed.
        await parentAnswered;
        await expect(failed).toBeVisible();
        const before = subCalls;
        await page.unroute(D3FEND_SUB, subDown);
        await page.route(D3FEND_SUB, route => route.fulfill({ json: { off_to_def: { results: { bindings: [] } } } }));
        await failed.getByTestId('ev-d3fend-retry').click();
        await expect.poll(() => subCalls, { timeout: ROUTE_TIMEOUT }).toBeGreaterThan(before);
        await expect(card(page).getByTestId('ev-known-failed')).toHaveCount(0, { timeout: ROUTE_TIMEOUT });
        expect(d3fendRow(await knownRows(card(page)))).toBe(`D3FEND countermeasures ${D3FEND_LIVE.length} MITRE D3FEND`);
      } finally {
        await context.close();
      }
    });
  }

  test('KEV on demand: the line reads loading, then the count, with no lens that loads KEV', async ({ browser }) => {
    const { context, page } = await newVisitor(browser);
    let release: () => void = () => undefined;
    const held = new Promise<void>(resolve => (release = resolve));
    await page.route(CTID_KEV, async route => {
      await held;
      await route.fulfill({ json: ctidKev });
    });
    try {
      await page.goto('about:blank');
      await page.goto(`${BASE}/#/technique/enterprise/T1059.001`);
      const kev = page.locator('app-technique-page [data-testid="ev-kev"]');
      await expect(kev).toHaveAttribute('data-kev-state', 'loading', { timeout: ROUTE_TIMEOUT });
      await expect(kev).toContainText('KEV-linked CVEs: loading');
      await expect(kev).not.toContainText('not loaded in this session');
      await expect(page.locator('app-technique-page .ev-kev-region')).toHaveAttribute('aria-live', 'polite');
      release();
      await expect(kev).toHaveAttribute('data-kev-state', 'loaded', { timeout: ROUTE_TIMEOUT });
      await expect(kev).toContainText(/KEV-linked CVEs: [1-9]\d*/);
      await expect(kev.getByTestId('ev-kev-count')).toHaveAttribute('href', '#/exposure/cve');
      // Every listed CVE is its id and KEV name, the id linked to its dossier (design 4.3).
      const cve = kev.getByTestId('ev-kev-cve').filter({ hasText: 'CVE-2024-3400' });
      await expect(cve).toHaveCount(1);
      await expect(cve.locator('.ev-cve-name')).toHaveText(/\S/);
      await expect(cve.getByRole('link', { name: 'CVE-2024-3400' })).toHaveAttribute('href', '#/exposure/dossier?cve=CVE-2024-3400');
      const unlinked = await kev.evaluate(el => {
        const all = el.textContent?.match(/CVE-\d{4}-\d+/g) ?? [];
        const linked = [...el.querySelectorAll('a')].map(a => a.textContent?.trim() ?? '').filter(t => t.startsWith('CVE-'));
        return all.filter(id => !linked.includes(id));
      });
      expect(unlinked, 'no CVE id without its dossier link').toEqual([]);
      // The default lens is on screen throughout: the card asked for KEV, not a lens.
      expect(new URL(page.url()).hash).not.toContain('heat=kev');
    } finally {
      release();
      await context.close();
    }
  });

  test('KEV on demand: the live feed and the bundled snapshot both failing reads failed with Retry, and Retry loads it', async ({ browser }) => {
    const { context, page } = await newVisitor(browser);
    const snapshotDown = (route: Route) => route.abort('failed');
    await page.route('**/assets/data/kev-snapshot.json', snapshotDown);
    await page.route(CTID_KEV, route => route.fulfill({ json: ctidKev }));
    try {
      await page.goto('about:blank');
      await page.goto(`${BASE}/#/technique/enterprise/T1059.001`);
      const kev = page.locator('app-technique-page [data-testid="ev-kev"]');
      await expect(kev).toHaveAttribute('data-kev-state', 'failed', { timeout: ROUTE_TIMEOUT });
      await expect(kev).toContainText('KEV catalogue unavailable: the live feed and the bundled snapshot both failed');
      await expect(kev).not.toContainText(/KEV-linked CVEs: 0\b/);
      await page.unroute('**/assets/data/kev-snapshot.json', snapshotDown);
      await kev.getByRole('button', { name: 'Retry' }).click();
      await expect(kev).toHaveAttribute('data-kev-state', 'loaded', { timeout: ROUTE_TIMEOUT });
      await expect(kev).toContainText('CVE-2024-3400');
    } finally {
      await context.close();
    }
  });

  test('ICS: the Enterprise-only Known families and the KEV line read not applicable in ICS, never 0', async ({ browser }) => {
    const { context, page } = await newVisitor(browser);
    try {
      await page.goto('about:blank');
      await page.goto(`${BASE}/#/technique/ics/T0883`);
      const card = page.locator('app-technique-page [data-testid="evidence-card"]');
      await expect(card).toBeVisible({ timeout: ROUTE_TIMEOUT });
      await expect(card.getByTestId('ev-known-na')).toHaveCount(4);
      await expect(card.getByTestId('ev-known-summary')).toContainText('(4 not applicable in ICS ATT&CK)');
      for (const row of await card.getByTestId('ev-known-na').allInnerTexts()) {
        expect(row).toContain('not applicable in ICS ATT&CK');
        expect(row).not.toMatch(/\b0\b/);
      }
      await expect(card.getByTestId('ev-kev')).toHaveAttribute('data-kev-state', 'not-applicable');
      await expect(card.getByTestId('ev-kev')).toContainText('not applicable in ICS ATT&CK');
    } finally {
      await context.close();
    }
  });

  test('CTID F3: a technique with an Enterprise id reads the Enterprise counts and KEV line, never "not applicable"', async ({ browser }) => {
    const { context, page } = await newVisitor(browser);
    try {
      await page.goto('about:blank');
      await page.goto(`${BASE}/#/technique/f3/T1110`);
      const card = page.locator('app-technique-page [data-testid="evidence-card"]');
      await expect(card).toBeVisible({ timeout: ROUTE_TIMEOUT });
      await expect(card.getByTestId('ev-known-summary')).toContainText('reference families', { timeout: ROUTE_TIMEOUT });
      await expect(card.getByTestId('ev-known-na')).toHaveCount(0);
      await expect(card.getByTestId('ev-known-summary')).not.toContainText('not applicable');
      await expect(card.getByTestId('ev-kev')).not.toHaveAttribute('data-kev-state', 'not-applicable');
    } finally {
      await context.close();
    }
  });

  for (const viewport of [{ width: 2000, height: 1100 }, { width: 1440, height: 900 }]) {
    test(`the page takes the workspace width at ${viewport.width}x${viewport.height}, scrolls itself, and the h1 is plain text`, async ({ browser }) => {
      const { context, page } = await newVisitor(browser, viewport);
      try {
        await page.goto('about:blank');
        await page.goto(`${BASE}/#/technique/enterprise/T1037`);
        await expect(page.locator('app-technique-page [data-testid="evidence-card"]')).toBeVisible({ timeout: ROUTE_TIMEOUT });
        const m = await page.evaluate(() => {
          const ws = document.querySelector('.workspace-area') as HTMLElement;
          const host = document.querySelector('app-technique-page') as HTMLElement;
          const cs = getComputedStyle(ws);
          const inner = ws.clientWidth - parseFloat(cs.paddingLeft) - parseFloat(cs.paddingRight);
          const doc = document.documentElement;
          const card = document.querySelector('app-technique-page [data-testid="evidence-card"]') as HTMLElement;
          const rect = card.getBoundingClientRect();
          const content = rect.right - parseFloat(getComputedStyle(card).paddingRight) - parseFloat(getComputedStyle(card).borderRightWidth);
          // The blocks of the card's first row of blocks: the last one ends at the card's content edge.
          const blocks = [...card.querySelectorAll<HTMLElement>(':scope > .ev-block')].map(b => b.getBoundingClientRect());
          const firstRow = blocks.filter(b => Math.abs(b.top - blocks[0].top) < 2);
          return {
            inner, host: host.getBoundingClientRect().width, overflowY: getComputedStyle(host).overflowY,
            sideScroll: doc.scrollWidth > doc.clientWidth, card: rect.width,
            blocksRight: Math.max(...firstRow.map(b => b.right)), content,
          };
        });
        expect(m.host / m.inner, `page ${m.host} px of a ${m.inner} px workspace`).toBeGreaterThanOrEqual(0.9);
        expect(m.card, 'the card is no longer capped at 760 px').toBeGreaterThan(760);
        expect(m.content - m.blocksRight, `the blocks end at ${m.blocksRight} px, the card's content at ${m.content} px: no empty column inside the card`)
          .toBeLessThan(2);
        expect(m.overflowY).toBe('auto');
        expect(m.sideScroll).toBe(false);
        const h1 = page.locator('app-technique-page h1#tp-h1');
        await expect(h1).toHaveText(/T1037\s+Boot or Logon Initialization Scripts/);
        await expect(h1.locator('a')).toHaveCount(0);
        await expect(h1).toBeFocused();
        await expect(page).toHaveTitle('T1037 Boot or Logon Initialization Scripts · ATT&CK-Navi');
        await expect(page.getByTestId('tp-tactic')).toHaveText(['TA0003 Persistence', 'TA0004 Privilege Escalation']);
        const ext = page.getByTestId('tp-attack-link');
        await expect(ext).toHaveAttribute('rel', 'noopener noreferrer');
        await expect(ext).toHaveAttribute('target', '_blank');
        // Design 4.9: one main landmark, holding the article the h1 labels.
        await expect(page.locator('main, [role="main"]')).toHaveCount(1);
        await expect(page.locator('main > article.technique-page')).toHaveAttribute('aria-labelledby', 'tp-h1');
      } finally {
        await context.close();
      }
    });
  }
});
