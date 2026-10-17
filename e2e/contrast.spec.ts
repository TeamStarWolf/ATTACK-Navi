// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Plan P1 row E1.5 ("Honest first glance"), PR 2 of 2. Acceptance criteria:
//
//   text >= 4.5:1 in both themes on 10 routes
//   no D3FEND 404s in the console
//
// The theme follows the OS (D13), so each colour scheme is emulated and the
// app renders that theme. Each route is checked twice: axe's color-contrast
// rule must report 0 violations, and a strict scan (fixtures/contrast.ts) must
// find no text node under 4.5:1, which also covers the large text axe holds
// only to 3:1. The four light-mode leaks the plan names in section 4.9
// (onboarding titles, palette match highlight, KEV numbers, score chips) only
// render after an interaction, so each gets its own check in both themes.
import type { Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { test, expect, BASE, ROUTE_TIMEOUT } from './fixtures/workspace';
import { lowContrastText, settleAnimations } from './fixtures/contrast';

/** One landing route per workspace, plus Status and the matrix. */
const CONTRAST_ROUTES: ReadonlyArray<{ path: string; host: string }> = [
  { path: '/matrix', host: 'app-matrix-page' },
  { path: '/dashboard/overview', host: 'app-dashboard-panel' },
  { path: '/intel/groups', host: 'app-threat-panel' },
  { path: '/detect/detections', host: 'app-detection-panel' },
  { path: '/exposure/cve', host: 'app-cve-panel' },
  { path: '/coverage/assessment', host: 'app-assessment-wizard' },
  { path: '/library/workbench', host: 'app-library-workbench' },
  { path: '/reports/builder', host: 'app-report-panel' },
  { path: '/status', host: 'app-status-page' },
  { path: '/settings/preferences', host: 'app-settings-panel' },
];

const SCHEMES = ['light', 'dark'] as const;

/** axe color-contrast violations under `root` (the whole page when omitted), one line per node. */
async function axeContrast(page: Page, root?: string): Promise<string[]> {
  let builder = new AxeBuilder({ page }).withRules(['color-contrast']);
  if (root) builder = builder.include(root);
  const results = await builder.analyze();
  return results.violations.flatMap(v =>
    v.nodes.map(n => `${n.target.join(' ')}: ${(n.failureSummary ?? '').split('\n').slice(1).join(' ').trim()}`),
  );
}

/** Both checks, as readable lines, so a failure names the node and its ratio. */
async function contrastFailures(page: Page, root?: string): Promise<string[]> {
  const scan = await lowContrastText(page, { root });
  return [
    ...(await axeContrast(page, root)).map(line => `axe ${line}`),
    ...scan.map(n => `scan ${n.path} "${n.text}": ${n.color} on ${n.background} = ${n.ratio}:1`),
  ];
}

/**
 * Opens a drawer section. A section whose data arrives after the drawer opened
 * starts collapsed, so it is expanded by its heading once it is listed.
 */
async function expandDrawerSection(page: Page, headingId: string): Promise<void> {
  const heading = page.locator(`.sidebar #${headingId}`);
  await expect(heading).toBeVisible({ timeout: ROUTE_TIMEOUT });
  if ((await heading.getAttribute('aria-expanded')) === 'false') await heading.click();
  await expect(heading).toHaveAttribute('aria-expanded', 'true');
}

async function expectTheme(page: Page, scheme: (typeof SCHEMES)[number]): Promise<void> {
  // D13: no stored choice, so the theme is the emulated OS scheme.
  await expect
    .poll(() => page.evaluate(() => document.body.classList.contains('light-mode')))
    .toBe(scheme === 'light');
}

// Synthetic CTID control mappings, so the drawer's score chips render in a
// hermetic run. One row per score value and category the chips style.
const M365_URL = '**/mappings-explorer/main/mappings/m365/**';
const CSA_CCM_URL = '**/mappings-explorer/main/mappings/csa_ccm/**';
const controlRows = (prefix: string) =>
  [
    ['significant', 'protect'],
    ['partial', 'detect'],
    ['minimal', 'respond'],
  ].map(([value, category], i) => ({
    attack_object_id: 'T1059.001',
    capability_id: `${prefix}-${i + 1}`,
    capability_group: 'Fixture',
    capability_description: `Synthetic ${value} ${category} control`,
    score_category: category,
    score_value: value,
  }));

for (const scheme of SCHEMES) {
  test.describe(`text contrast >= 4.5:1, ${scheme} theme (plan E1.5)`, () => {
    test.use({ colorScheme: scheme });
    test.describe.configure({ mode: 'parallel', timeout: process.env['CI'] ? 120000 : 60000 });

    for (const { path, host } of CONTRAST_ROUTES) {
      test(`#${path}`, async ({ page }) => {
        await page.goto(`${BASE}/#${path}`);
        await expect(page.locator(`${host} > *`).first()).toBeVisible({ timeout: ROUTE_TIMEOUT });
        // Late chips and badges settle; every off-origin request is aborted.
        await page.waitForLoadState('networkidle', { timeout: 10000 }).catch(() => undefined);
        await expectTheme(page, scheme);
        await settleAnimations(page);
        expect(await contrastFailures(page)).toEqual([]);
      });
    }

    test.describe('leak 1: onboarding titles', () => {
      test.use({ workspace: { skipOnboarding: false } });

      test('every onboarding step', async ({ page }) => {
        await page.goto(`${BASE}/#/matrix`);
        const card = page.locator('.onboarding-card');
        await expect(card).toBeVisible({ timeout: ROUTE_TIMEOUT });
        await expectTheme(page, scheme);
        const failures: string[] = [];
        for (let step = 1; ; step++) {
          await expect(card.locator('.step-title')).toBeVisible();
          await settleAnimations(page);
          failures.push(...(await contrastFailures(page, '.onboarding-card')).map(f => `step ${step}: ${f}`));
          const next = card.locator('.btn-primary', { hasText: 'Next' });
          if (!(await next.count())) break;
          await next.click();
        }
        expect(failures).toEqual([]);
      });
    });

    test('leak 2: palette match highlight', async ({ page }) => {
      await page.goto(`${BASE}/#/matrix`);
      await page.locator('.cell').first().waitFor({ state: 'visible', timeout: ROUTE_TIMEOUT });
      await expectTheme(page, scheme);
      await page.locator('.palette-trigger').click();
      await page.locator('.us-input').fill('power');
      await expect(page.locator('.us-panel .match-hl').first()).toBeVisible();
      await settleAnimations(page);
      expect(await contrastFailures(page, '.us-panel')).toEqual([]);
    });

    test('leak 3: KEV numbers', async ({ page }) => {
      await page.goto(`${BASE}/#/exposure/cve`);
      await expect(page.locator('app-cve-panel > *').first()).toBeVisible({ timeout: ROUTE_TIMEOUT });
      await expectTheme(page, scheme);
      await page.getByRole('button', { name: 'KEV Dashboard' }).click();
      // The live KEV feed is blocked here, so the dated bundled snapshot (E1.3) fills the tab.
      await expect(page.locator('.kev-stats .dashboard-value').first()).toBeVisible({ timeout: ROUTE_TIMEOUT });
      await settleAnimations(page);
      expect(await contrastFailures(page, '.kev-tab')).toEqual([]);
    });

    test('leak 4: score chips in the technique drawer', async ({ page }) => {
      for (const [url, prefix] of [
        [M365_URL, 'M365'],
        [CSA_CCM_URL, 'CCM'],
      ] as const) {
        await page.route(url, route => route.fulfill({ json: { mapping_objects: controlRows(prefix) } }));
      }
      await page.goto(`${BASE}/#/matrix?tech=T1059.001`);
      await expect(page.locator('.sidebar.open')).toBeVisible({ timeout: ROUTE_TIMEOUT });
      await expectTheme(page, scheme);
      await expect(page.locator('.sidebar .coverage-score-card .score-item').first()).toBeVisible();
      await expandDrawerSection(page, 'sb-sec-csa-ccm');
      await expandDrawerSection(page, 'sb-sec-m365-controls');
      // 3 CSA CCM score chips, and 3 score plus 3 category chips for M365.
      await expect(page.locator('.sidebar .ctrl-pill-badge')).toHaveCount(9, { timeout: ROUTE_TIMEOUT });
      await settleAnimations(page);
      expect(await contrastFailures(page, '.sidebar .coverage-score-card, .sidebar .ctrl-pill-badge')).toEqual([]);
    });
  });
}

// "No D3FEND 404s in the console". d3fend.mitre.org keys a sub-technique by its
// dotted id: .../attack/T1059.001.json is 200 and .../attack/T1059/001.json is
// 404 (both checked against d3fend.mitre.org on 2026-10-17). The route below
// answers the same way, so the old slash URL would 404 here as it did live.
test.describe('D3FEND links on a sub-technique drawer (plan E1.5)', () => {
  const API = 'https://d3fend.mitre.org/api/offensive-technique/attack/';

  test('the drawer requests the dotted id and its parent, and no D3FEND request 404s', async ({ page }) => {
    const requested: string[] = [];
    const notFound: string[] = [];
    const console404: string[] = [];
    page.on('response', res => {
      if (res.url().includes('d3fend.mitre.org') && res.status() >= 400) notFound.push(`${res.status()} ${res.url()}`);
    });
    page.on('console', msg => {
      if (msg.type() === 'error' && /404/.test(msg.text())) console404.push(`${msg.text()} @ ${msg.location().url}`);
    });
    await page.route(`${API}**`, route => {
      const url = route.request().url();
      requested.push(url);
      const id = url.slice(API.length).match(/^(T\d{4}(?:\.\d{3})?)\.json$/)?.[1];
      if (!id) return route.fulfill({ status: 404, contentType: 'text/html', body: '<h1>Not Found</h1>' });
      return route.fulfill({
        json: {
          off_to_def: {
            results: {
              bindings: [
                {
                  def_tech_id: { value: 'D3-FIM' },
                  def_tech_label: { value: 'File Integrity Monitoring' },
                  def_tactic_label: { value: 'Detect' },
                  def_tech: { value: 'http://d3fend.mitre.org/ontologies/d3fend.owl#FileIntegrityMonitoring' },
                },
              ],
            },
          },
        },
      });
    });

    await page.goto(`${BASE}/#/matrix?tech=T1059.001`);
    await expect(page.locator('.sidebar.open')).toBeVisible({ timeout: ROUTE_TIMEOUT });
    await expandDrawerSection(page, 'sb-sec-d3fend');
    const link = page.locator('.sidebar .d3fend-section a.d3fend-id', { hasText: 'D3-FIM' });
    await expect(link).toHaveAttribute('href', 'https://d3fend.mitre.org/technique/d3f:FileIntegrityMonitoring', {
      timeout: ROUTE_TIMEOUT,
    });
    await page.waitForLoadState('networkidle', { timeout: 10000 }).catch(() => undefined);

    expect([...new Set(requested)].sort()).toEqual([`${API}T1059.001.json`, `${API}T1059.json`]);
    expect(notFound).toEqual([]);
    expect(console404).toEqual([]);
  });
});
