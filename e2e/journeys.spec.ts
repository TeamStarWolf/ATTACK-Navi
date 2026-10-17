// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The eight acceptance journeys of the redesign plan (Appendix C), as pending
// tests (plan epic E0.3).
//
// Each journey is a test.fixme: it is listed (and counted as skipped) in every
// run so the CI report always shows the eight journeys and the phase each one
// is due to turn green in. The body is the journey script, step by step, as
// comments. The phase that builds a journey's last piece replaces its comments
// with assertions and changes test.fixme to test; nothing else in this file
// needs to move.
//
// The journeys load their data from the shared fixture workspace
// (e2e/fixtures/workspace). The "shared fixture workspace" block at the end is
// live today: it guards that fixture so a journey never turns on against data
// that has drifted from what its script promises.
import { readFileSync } from 'node:fs';
import { Page } from '@playwright/test';
import { test, expect, loadSampleOrg, BASE, ROUTE_TIMEOUT } from './fixtures/workspace';
import { CURRENT_ROUTES } from './fixtures/workspace/routes';

/** Annotation shown next to each pending journey in the report. */
const greenBy = (phase: string) => ({ tag: '@journey', annotation: { type: 'green by', description: phase } });

test.describe('acceptance journeys (plan Appendix C)', () => {
  test.fixme('journey 1, VM: KEV to packet', greenBy('P5'), async () => {
    // 1. Load the fixture workspace (sample-org.json: fw-edge-01 runs PAN-OS 11.1.0).
    // 2. On Home, paste CVE-2024-3400 and open the CVE page (#/cve/CVE-2024-3400).
    // 3. Assert a dated KEV badge (date from the catalog's dateAdded).
    // 4. Assert an SSVC decision with every input shown.
    // 5. Assert the affected assets (fw-edge-01).
    // 6. Assert the techniques from the bundled chain, each edge with its confidence.
    // 7. Assert at least one Blunt control.
    // 8. Assert a packet with every field.
    // 9. Force the KEV fetch to fail; assert the decision reads 'provisional: exploitation unknown'.
    //    Live since P1 (E1.3) in the 'journey 1 ... KEV-down branch' block below.
    // 10. Record a close date; assert MTTM appears in the VM brief.
  });

  test.fixme('journey 2, Detection: gap to rule', greenBy('P7'), async () => {
    // 1. Select two actors.
    // 2. Open Detect > Gaps and take the first row.
    // 3. Open its SigmaHQ rules; assert the links resolve.
    // 4. Export SPL; assert the output contains no TODO.
  });

  test.fixme('journey 3, Purple: range import', greenBy('P2 (fixture), P6 (vendored)'), async () => {
    // 1. Import the synthetic 8-row fixture contract (sample-org.json rangeContract,
    //    6 distinct techniques).
    // 2. Assert 6 Proven-in-range cells, each with the lab badge.
    // 3. Open #/mission/CORNERIA-ROOT-01; assert it renders.
    // 4. Open the T1558.003 drawer; assert it lists 'validated, wazuh:100821'.
  });

  // Journey 4 is live in the 'journey 4, Honesty: empty user' block below:
  // step 2 (the default lens, E1.5 / D4) and step 3 (the DOM scan, one test per route).

  test.fixme('journey 5, Share', greenBy('P2 (tech, dom: E2.3) / P4 (lens, v, redirects)'), async () => {
    // 1. In a new browser context, open #/matrix?lens=posture&tech=T1059.001&dom=enterprise&v=20.0
    //    (sample-org.json share.hash).
    // 2. Assert the same lens, the T1059.001 drawer open and data version 20.0.
    // 3. Assert every old route redirects (redirects.spec.ts PLANNED_REDIRECTS all on)
    //    and that ?view= survives each redirect.
  });

  test.fixme('journey 6, Accessibility', greenBy('P8'), async () => {
    // 1. Run axe on every route (a11y.spec.ts); assert 0 serious and 0 critical
    //    (today the spec is report-only against docs/A11Y_BASELINE.json).
    // 2. Assert the matrix has exactly one tab stop.
    // 3. Assert the arrow keys move between cells.
    // 4. Press Enter; assert the drawer opens with focus inside it.
  });

  test.fixme('journey 7, Learner: study and progress', greenBy('P6'), async () => {
    // 1. Choose the Learner role.
    // 2. Open T1059.001; assert the drawer opens on the Learn tab.
    // 3. Print-preview the full page.
    // 4. Mark it studied in one click.
    // 5. Export the progress layer; assert it contains T1059.001.
  });

  test.fixme('journey 8, CTI: report to layer', greenBy('P7'), async () => {
    // 1. Start a timer; record every request that leaves the browser.
    // 2. Paste the fixture report text (sample-org.json ctiReport.text).
    // 3. Assert the expected technique ids are proposed, each with its sentence
    //    (ctiReport.expected).
    // 4. Accept them and save a layer with citations.
    // 5. Assert no network request left the browser.
    // 6. Assert elapsed time <= 2 minutes.
  });
});

/**
 * Every banned string visible on the page: the rendered text, plus the
 * title, aria-label, placeholder and alt attributes a reader hovers over or a
 * screen reader announces. Words match whole and case-insensitively, so
 * 'covered' also catches 'Covered' and 'COVERED' but not 'uncovered' or
 * 'discovered'. A grade string is the word 'grade' (not 'government-grade') or a lone letter grade
 * (A to F, optionally + or -) shown in an element whose class names a grade.
 */
async function bannedStringsOnPage(page: Page, forbidden: readonly string[]): Promise<string[]> {
  return page.evaluate((words) => {
    const escape = (w: string) => w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const patterns = [...words.map(w => new RegExp(`\\b${escape(w)}\\b`, 'i')), /(?<![\w-])grades?\b(?!-)/i];
    const texts: Array<[where: string, text: string]> = [['text', document.body.innerText]];
    for (const el of Array.from(document.body.querySelectorAll('[title], [aria-label], [placeholder], [alt]'))) {
      for (const attr of ['title', 'aria-label', 'placeholder', 'alt']) {
        const v = el.getAttribute(attr);
        if (v) texts.push([`${el.tagName.toLowerCase()}[${attr}]`, v]);
      }
    }
    const hits: string[] = [];
    for (const [where, text] of texts) {
      for (const line of text.split('\n')) {
        for (const re of patterns) {
          if (re.test(line)) hits.push(`${where}: ${line.trim().slice(0, 160)}`);
        }
      }
    }
    for (const el of Array.from(document.body.querySelectorAll('[class*="grade"]'))) {
      const t = (el as HTMLElement).innerText?.trim() ?? '';
      if (/^[A-F][+-]?$/.test(t)) hits.push(`letter grade '${t}' in .${String(el.className).trim().replace(/\s+/g, '.')}`);
    }
    return [...new Set(hits)];
  }, forbidden);
}

// Journey 4, step 3 (plan Appendix C, green by P1 through E1.1): on a fresh
// profile no route may say 'covered', 'defended', 'LOW RISK', 'protected',
// 'Coverage Score' or show a grade. A fresh profile has no owner data, so
// nothing on screen can be Covered or Proven. The words come from
// sample-org.json honesty.forbiddenStrings; scripts/lint-truth-vocab.mjs is
// the source-level half of the same rule.
test.describe('journey 4, Honesty: empty user', () => {
  test.use({ workspace: { skipOnboarding: false } });
  // Each route is its own test so a failure names the route; they share no state.
  test.describe.configure({ mode: 'parallel', timeout: process.env['CI'] ? 120000 : 60000 });
  const { forbiddenStrings } = loadSampleOrg().honesty;

  // Step 2 (plan E1.5, decision D4): a fresh profile opens on Prevalence, a
  // Threat lens, never on Posture or Reference depth, and a one-line banner
  // says what the lens is and that it is reference data.
  test('default lens is neither Posture nor Reference depth', greenBy('P1 (E1.5, D4)'), async ({ page }) => {
    await page.goto(`${BASE}/#/matrix`);
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: ROUTE_TIMEOUT });
    // No heat= in the URL: the default lens is in force. The onboarding
    // dialog is open on a fresh profile, so the lens is read from the View
    // button's label rather than from the menu behind the dialog.
    expect(new URL(page.url()).hash).not.toContain('heat=');
    const lens = page.locator('.heatmap-btn');
    await expect(lens).toContainText('Frequency');
    expect(await lens.innerText()).not.toMatch(/reference depth|posture/i);
    const banner = page.locator('.first-glance-banner');
    await expect(banner).toBeVisible();
    await expect(banner).toContainText('Showing adversary prevalence');
    await expect(banner).toContainText('reference data');
  });

  for (const { path, host } of CURRENT_ROUTES) {
    test(`DOM scan #${path}`, greenBy('P1'), async ({ page }) => {
      await page.goto(`${BASE}/#${path}`);
      await expect(page.locator(`${host} > *`).first()).toBeVisible({ timeout: ROUTE_TIMEOUT });
      // Let late chips, badges and lazy sections settle. All off-origin
      // requests are aborted, so the network goes idle quickly.
      await page.waitForLoadState('networkidle', { timeout: 10000 }).catch(() => undefined);
      expect(await bannedStringsOnPage(page, forbiddenStrings)).toEqual([]);
    });
  }

  // The routes above never open a drawer, so the technique drawer gets its own
  // scan. T1059.001 has bundled CAR and D3FEND data, so its signal pills and
  // sections render with no network. A one-word lowercase literal is skipped by
  // the source lint as identifier-like; when the drawer renders one, this scan
  // is where it is checked.
  test('DOM scan #/matrix with the T1059.001 drawer open', greenBy('P1'), async ({ page }) => {
    await page.goto(`${BASE}/#/matrix?tech=T1059.001`);
    await expect(page.locator('.sidebar.open')).toBeVisible({ timeout: ROUTE_TIMEOUT });
    await expect(page.locator('.sidebar-header .attack-id')).toContainText('T1059.001');
    await expect(page.locator('.sidebar .signal-pill').first()).toBeVisible({ timeout: ROUTE_TIMEOUT });
    await page.waitForLoadState('networkidle', { timeout: 10000 }).catch(() => undefined);
    expect(await bannedStringsOnPage(page, forbiddenStrings)).toEqual([]);
  });
});

// Journey 1, the KEV-down branch (plan P1 row E1.3: "the KEV-down branch of journey 1
// passes"). The rest of journey 1 (Home, the CVE page, affected assets, the technique
// chain, the packet, MTTM) is due in P5 and stays pending above. Until the CVE page
// exists (P4/P5), the SSVC decision for the journey's CVE is read where the app shows it
// today: Exposure > SSVC. NVD is served from a trimmed fixture; every other off-origin
// request stays blocked by the hermetic workspace, so the live KEV feed always fails here.
test.describe('journey 1, VM: KEV to packet: KEV-down branch (plan E1.3)', () => {
  const { vmJourney } = loadSampleOrg();
  const snapshotDate: string = JSON.parse(readFileSync('src/assets/data/kev-snapshot.json', 'utf8')).__meta.snapshotDate;
  const nvdBody = readFileSync('e2e/fixtures/nvd-cve-2024-3400.json', 'utf8');

  /** Serve NVD, force the live KEV feed offline, and assess the journey's CVE. Returns the blocked-request count. */
  async function assessWithKevDown(page: Page): Promise<() => number> {
    let liveKevRequests = 0;
    await page.route(
      url => url.href.startsWith('https://services.nvd.nist.gov/rest/json/cves/2.0'),
      route => route.fulfill({ status: 200, contentType: 'application/json', body: nvdBody }),
    );
    await page.route(
      url => url.href.includes('known_exploited_vulnerabilities.json'),
      route => { liveKevRequests++; return route.abort('internetdisconnected'); },
    );
    await page.goto(`${BASE}/#/exposure/ssvc`);
    const input = page.getByRole('searchbox', { name: 'CVE identifier or keyword search' });
    await expect(input).toBeVisible({ timeout: ROUTE_TIMEOUT });
    await input.fill(vmJourney.cve);
    await page.getByRole('button', { name: 'Assess' }).click();
    return () => liveKevRequests;
  }

  test('live KEV down: the decision is made from the bundled snapshot, dated, with every input shown', greenBy('P1 (E1.3)'), async ({ page }) => {
    const liveKevRequests = await assessWithKevDown(page);

    await expect(page.getByTestId('kev-snapshot-notice')).toContainText(`Using the bundled CISA KEV snapshot of ${snapshotDate}`, { timeout: ROUTE_TIMEOUT });
    // A dated KEV badge: the date added, and which catalogue it was read from.
    await expect(page.getByTestId('kev-fact')).toHaveText(`KEV yes, added 2024-04-12 (KEV snapshot of ${snapshotDate})`);
    // An SSVC decision with every input shown, each with its basis.
    const decision = page.getByTestId('ssvc-decision');
    await expect(decision.locator('strong')).toHaveText('act');
    const inputs = page.locator('table.points tbody tr');
    await expect(inputs).toHaveCount(6);
    await expect(inputs.filter({ hasText: 'Exploitation' })).toContainText(`bundled CISA KEV snapshot of ${snapshotDate}`);
    // The view banner names the failed live feed and the snapshot standing in for it.
    const banner = page.locator('app-source-banner [data-testid="source-banner"]');
    await expect(banner.locator('[data-source-id="cisa-kev"]')).toContainText('CISA Known Exploited Vulnerabilities (failed)');
    await expect(banner.locator('[data-source-id="cisa-kev"]')).toContainText(`snapshot of ${snapshotDate}`);
    expect(liveKevRequests(), 'the live KEV feed was requested and failed').toBeGreaterThan(0);
  });

  test('KEV and its snapshot both down: decision blocked, exploitation unknown, never track', greenBy('P1 (E1.3)'), async ({ page }) => {
    let snapshotRequests = 0;
    await page.route(
      url => url.pathname.endsWith('/assets/data/kev-snapshot.json'),
      route => { snapshotRequests++; return route.abort('internetdisconnected'); },
    );
    await assessWithKevDown(page);

    const decision = page.getByTestId('ssvc-decision');
    await expect(decision.locator('strong')).toHaveText('decision blocked: exploitation unknown', { timeout: ROUTE_TIMEOUT });
    // Appendix C's wording for this branch.
    await expect(decision).toContainText('Provisional: exploitation unknown');
    await expect(decision).not.toContainText(/track/i);
    await expect(page.getByTestId('ssvc-timeline').locator('strong')).toHaveText('blocked: KEV membership unknown');
    await expect(page.getByTestId('kev-fact')).toHaveText('KEV unknown');
    await expect(page.getByTestId('kev-unavailable-notice')).toContainText('exploitation is unknown');
    const inputs = page.locator('table.points tbody tr');
    await expect(inputs).toHaveCount(6);
    await expect(inputs.filter({ hasText: 'Exploitation' }).locator('select')).toHaveValue('unknown');
    // Nothing in the worklist reads track either.
    await expect(page.locator('table.rows .pill', { hasText: /^\s*track\*?\s*$/i })).toHaveCount(0);
    const banner = page.locator('app-source-banner [data-testid="source-banner"]');
    await expect(banner).toContainText('CISA KEV snapshot (bundled) (failed)');
    expect(snapshotRequests, 'the snapshot was requested and failed').toBeGreaterThan(0);
  });

  // E1.4: the Briefing strip on every route announces the same failure, and the
  // snapshot standing in for it, in its polite live region.
  test('live KEV down: the Briefing strip announces the failure and "using snapshot of <date>"', greenBy('P1 (E1.4)'), async ({ page }) => {
    await assessWithKevDown(page);
    const live = page.getByTestId('briefing-live');
    await expect(live).toHaveAttribute('role', 'status');
    await expect(live).toHaveAttribute('aria-live', 'polite');
    await expect(live).toContainText('CISA Known Exploited Vulnerabilities', { timeout: ROUTE_TIMEOUT });
    await expect(live).toContainText(/\d+ sources? failed/);
    await expect(live).toContainText(`CISA Known Exploited Vulnerabilities: using snapshot of ${snapshotDate}.`);
  });
});

// Plan P1 row E1.4 (PR 2 of 2): the toolbar vintage chip and the Briefing
// strip. The chip renders DataService.freshness$ (the pinned release, its
// bundle date and an aggregate source dot) and opens the data-health view; the
// strip is a polite live region on every route. Ten routes: Matrix, Status and
// one view in each of the eight other workspaces.
test.describe('vintage chip and Briefing strip on every route (plan E1.4)', () => {
  test.describe.configure({ mode: 'parallel', timeout: process.env['CI'] ? 120000 : 60000 });
  const collection = (JSON.parse(readFileSync('src/assets/data/enterprise-attack.json', 'utf8')) as {
    objects: Array<{ type: string; x_mitre_version?: string; modified?: string }>;
  }).objects.find(o => o.type === 'x-mitre-collection')!;
  const pinned = collection.x_mitre_version!;
  const bundleDate = collection.modified!.slice(0, 10);
  const CHIP_ROUTES = [
    '/matrix',
    '/status',
    '/dashboard/overview',
    '/intel/groups',
    '/detect/detections',
    '/exposure/cve',
    '/coverage/assessment',
    '/library/layers',
    '/reports/builder',
    '/settings/preferences',
  ];

  test('the ten routes are current routes', () => {
    expect(CHIP_ROUTES).toHaveLength(10);
    const current = new Set(CURRENT_ROUTES.map(r => r.path));
    expect(CHIP_ROUTES.filter(p => !current.has(p))).toEqual([]);
  });

  for (const path of CHIP_ROUTES) {
    test(`#${path}: the chip shows the pinned version and bundle date; the strip is a live region`, greenBy('P1 (E1.4)'), async ({ page }) => {
      const host = CURRENT_ROUTES.find(r => r.path === path)!.host;
      await page.goto(`${BASE}/#${path}`);
      await expect(page.locator(`${host} > *`).first()).toBeVisible({ timeout: ROUTE_TIMEOUT });

      const chip = page.getByTestId('vintage-chip');
      await expect(chip).toHaveCount(1);
      await expect(chip).toBeVisible();
      await expect(chip).toHaveAttribute('data-state', 'pinned', { timeout: ROUTE_TIMEOUT });
      await expect(chip.locator('.attack-version')).toHaveText(`v${pinned}`);
      await expect(chip).toContainText('pinned');
      await expect(chip).toContainText(bundleDate);
      expect(await chip.getAttribute('aria-label')).toContain(`ATT&CK ${pinned} (pinned); bundle dated ${bundleDate}`);

      const strip = page.getByTestId('briefing-strip');
      await expect(strip).toHaveCount(1);
      await expect(strip).toBeVisible();
      const live = page.getByTestId('briefing-live');
      await expect(live).toHaveAttribute('role', 'status');
      await expect(live).toHaveAttribute('aria-live', 'polite');
      await expect(live).not.toBeEmpty();
    });
  }

  test('the chip opens the data-health view', greenBy('P1 (E1.4)'), async ({ page }) => {
    await page.goto(`${BASE}/#/dashboard/overview`);
    await expect(page.locator('app-dashboard-panel > *').first()).toBeVisible({ timeout: ROUTE_TIMEOUT });
    await page.getByTestId('vintage-chip').click();
    await expect(page).toHaveURL(/#\/status$/);
    await expect(page.locator('app-status-page app-data-health')).toBeVisible({ timeout: ROUTE_TIMEOUT });
    await expect(page.locator('app-status-page app-source-health')).toBeVisible();
  });
});

test.describe('shared fixture workspace', () => {
  const org = loadSampleOrg();

  // Every technique the journeys rely on must exist, unrevoked and not
  // deprecated, in the bundled Enterprise snapshot the e2e run serves.
  test('every sample-org technique id is live in the bundled Enterprise ATT&CK', () => {
    const bundle = JSON.parse(readFileSync('src/assets/data/enterprise-attack.json', 'utf8')) as {
      objects: Array<{
        type: string;
        revoked?: boolean;
        x_mitre_deprecated?: boolean;
        external_references?: Array<{ source_name: string; external_id?: string }>;
      }>;
    };
    const live = new Set<string>();
    for (const o of bundle.objects) {
      if (o.type !== 'attack-pattern' || o.revoked || o.x_mitre_deprecated) continue;
      const id = o.external_references?.find(r => r.source_name === 'mitre-attack')?.external_id;
      if (id) live.add(id);
    }
    const used = new Set([
      ...org.rangeContract.rows.map(r => r.technique_id),
      ...org.ctiReport.expected.map(e => e.technique_id),
      'T1059.001', // journeys 5 and 7
    ]);
    expect([...used].filter(id => !live.has(id))).toEqual([]);
  });

  test('the range contract is the 8-row, 6-technique contract journey 3 promises', () => {
    const rows = org.rangeContract.rows;
    expect(rows).toHaveLength(8);
    expect(new Set(rows.map(r => r.technique_id)).size).toBe(6);
    expect(rows.every(r => r.mission_id === 'CORNERIA-ROOT-01')).toBe(true);
    expect(rows).toContainEqual(
      expect.objectContaining({ technique_id: 'T1558.003', result: 'validated', detection: 'wazuh:100821' }),
    );
  });

  test('the CTI report holds every expected sentence verbatim', () => {
    for (const { sentence } of org.ctiReport.expected) {
      expect(org.ctiReport.text).toContain(sentence);
    }
  });

  test('journey 1 and journey 5 inputs are present', () => {
    expect(org.synthetic).toBe(true);
    const asset = org.assets.find(a => a.id === org.vmJourney.affectedAssetIds[0]);
    expect(asset?.cves).toContain(org.vmJourney.cve);
    expect(org.vmJourney.cve).toBe('CVE-2024-3400');
    expect(org.share.hash).toBe('/matrix?lens=posture&tech=T1059.001&dom=enterprise&v=20.0');
  });
});

// Plan P1 row E1.2 has no Appendix C journey of its own; this is the minimal
// journey-level check the row asks for: switching to ICS disables the lenses
// that have no ICS data, each with its stated reason, and the matrix shows the
// active one as n/a instead of an all-zero map.
test.describe('lens availability (plan E1.2)', () => {
  test('switching to ICS shows why each lens without ICS data is disabled', async ({ page }) => {
    await page.goto(BASE);
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: ROUTE_TIMEOUT });
    await expect(page.locator('.lens-na-banner.shown')).toHaveCount(0);

    await page.locator('.domain-btn[title="ICS ATT&CK"]').click();
    await expect(page.locator('.tactic-header', { hasText: 'Inhibit Response Function' })).toHaveCount(1, { timeout: ROUTE_TIMEOUT });

    // A domain switch resets the lens to the default, Prevalence (E1.5, D4),
    // which has ICS data: nothing is n/a.
    await expect(page.locator('.heatmap-btn')).toContainText('Frequency');
    await expect(page.locator('.lens-na-banner.shown')).toHaveCount(0);

    // A viewpoint can still put an Enterprise-only lens on screen: Red Team
    // leads with Atomic, which has no ICS data. A stated reason, and every
    // cell hatched as n/a rather than painted as zero.
    await page.locator('.vp-trigger').click();
    await page.getByRole('menuitemradio', { name: /Red Team/ }).click();
    const banner = page.locator('.lens-na-banner.shown');
    await expect(banner).toContainText('Atomic is n/a for ICS ATT&CK');
    await expect(banner).toHaveAttribute('role', 'status');
    const cells = await page.locator('.cell').count();
    expect(cells).toBeGreaterThan(0);
    await expect(page.locator('.cell.lens-na')).toHaveCount(cells);

    // The lens menu disables the 23 lenses without ICS data, each with its reason.
    await page.locator('.heatmap-btn').click();
    await expect(page.locator('.lens-na-summary')).toContainText('23 of 33 lenses have no ICS ATT&CK data');
    const disabled = page.locator('.heatmap-groups .heatmap-mode-btn[aria-disabled="true"]');
    await expect(disabled).toHaveCount(23);
    for (const btn of await disabled.all()) {
      const reasonId = await btn.getAttribute('aria-describedby');
      expect(reasonId).toBeTruthy();
      await expect(page.locator(`#${reasonId}`)).toContainText('is n/a for ICS ATT&CK: ');
    }
    await expect(page.locator('.lens-item[data-lens="frequency"] .heatmap-mode-btn')).not.toHaveAttribute('aria-disabled', 'true');

    // The '?' card opens as a dialog that states the reason, and Escape returns focus.
    const help = page.locator('.lens-item[data-lens="sigma"] .lens-help-btn');
    await help.click();
    const dialog = page.getByRole('dialog', { name: 'Sigma Rules' });
    await expect(dialog).toBeVisible();
    await expect(dialog).toContainText('Sigma Rules is n/a for ICS ATT&CK');
    await expect(dialog.locator('.lens-card-close')).toBeFocused();
    await page.keyboard.press('Escape');
    await expect(dialog).toHaveCount(0);
    await expect(help).toBeFocused();
  });
});

// Plan P1 row E1.6 has no Appendix C journey of its own; these are the minimal
// journey-level checks for the three acceptance criteria this PR addresses
// (the unit specs carry the same criteria: opencti.service.spec.ts,
// threat-intelligence-panel.component.spec.ts, matrix-controls.component.spec.ts,
// data-source-names.spec.ts and the compliance-panel specs).
test.describe('stop shipping broken or misleading output (plan E1.6)', () => {
  test('OpenCTI makes 0 requests on a fresh profile', async ({ page }) => {
    const openCti: string[] = [];
    page.on('request', req => {
      if (/opencti|\/graphql\b/i.test(req.url())) openCti.push(req.url());
    });
    await page.goto(`${BASE}/#/intel/feeds`);
    const panel = page.locator('app-threat-intelligence-panel');
    await expect(panel.locator('.stat-card', { hasText: 'OpenCTI' })).toContainText('Not configured', { timeout: ROUTE_TIMEOUT });
    for (const tab of ['Indicators', 'Actors', 'MISP', 'Overview']) {
      await panel.locator('.tab-btn', { hasText: tab }).first().click();
    }
    await panel.locator('.tab-btn', { hasText: 'Indicators' }).first().click();
    await expect(page.getByTestId('opencti-not-configured')).toBeVisible();
    await page.goto(`${BASE}/#/settings/preferences`);
    await expect(page.locator('app-settings-panel > *').first()).toBeVisible({ timeout: ROUTE_TIMEOUT });
    await page.waitForLoadState('networkidle', { timeout: 10000 }).catch(() => undefined);
    expect(openCti, 'requests to an OpenCTI instance or a /graphql endpoint').toEqual([]);
  });

  test('the data-source filter lists each component once', async ({ page }) => {
    await page.goto(BASE);
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: ROUTE_TIMEOUT });
    const options = (await page.locator('.ds-select option').allTextContents())
      .map(t => t.trim())
      .filter(t => t !== 'All data sources');
    expect(options.length).toBeGreaterThan(10);
    const keys = options.map(o => o.toLowerCase());
    expect(keys.filter((k, i) => keys.indexOf(k) !== i), 'sources listed twice in different spellings').toEqual([]);
    expect(options).toContain('macos:unifiedlog');
    expect(options).not.toContain('macOS:unifiedlog');
  });

  test('a cold share link with the other spelling selects the listed one', async ({ page }) => {
    // The URL state is applied before the domain loads; the picker must still show the source.
    await page.goto(`${BASE}/#/matrix?ds=macOS%3Aunifiedlog`);
    await page.reload();
    await page.locator('.cell').first().waitFor({ state: 'visible', timeout: ROUTE_TIMEOUT });
    await expect(page.locator('.ds-select')).toHaveValue('macos:unifiedlog');
    expect(await page.locator('.ds-select').evaluate((el: HTMLSelectElement) => el.selectedIndex)).toBeGreaterThan(0);
  });

  test('every compliance tab shows its mapping version, and CIS shows source withdrawn upstream', async ({ page }) => {
    await page.goto(`${BASE}/#/coverage/compliance`);
    const panel = page.locator('app-compliance-panel');
    const tabs = panel.locator('.tab-bar .tab-btn');
    await expect(tabs.first()).toBeVisible({ timeout: ROUTE_TIMEOUT });
    // The tab bar order (compliance-mapping-meta.ts COMPLIANCE_TABS).
    const keys = ['cis', 'aws', 'azure', 'gcp', 'nist', 'cri', 'csa-ccm', 'm365-ctrl', 'soc2', 'iso27001', 'pci'];
    const count = await tabs.count();
    expect(count).toBe(keys.length);
    const stamps: string[] = [];
    for (let i = 0; i < count; i++) {
      await tabs.nth(i).click();
      const stamp = page.getByTestId('mapping-stamp');
      // Wait for this tab's stamp, not the previous tab's still on screen.
      await expect(stamp).toHaveAttribute('data-tab', keys[i]);
      stamps.push((await stamp.textContent())!.trim());
    }
    expect(stamps[0]).toMatch(/^Source withdrawn upstream: /);
    expect(stamps.filter(s => /mapped vs ATT&CK 16\.1/.test(s)).length).toBe(6);
    expect(stamps.filter(s => /mapped vs ATT&CK 17\.1/.test(s)).length).toBe(1);
    expect(stamps.filter(s => s.startsWith('Project-authored mapping')).length).toBe(3);
    await tabs.first().click();
    await expect(page.getByTestId('mapping-withdrawn')).toContainText('Source withdrawn upstream.');
    await expect(panel.locator('.score-card .score-label', { hasText: 'CIS' })).toHaveCount(0);
  });
});
