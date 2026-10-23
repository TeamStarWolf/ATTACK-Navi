// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// RP-F round 6 (decisions 31 to 33): the shapes the round-6 walk broke. Every
// drawer is opened by a pasted link (a fresh navigation: the app does not re-read
// heat=, tech= or dom= on an in-session hash-only change); data-tech-id holds the
// technique's STIX id.
import { readFileSync } from 'node:fs';
import { test, expect, type Page } from '@playwright/test';
import { BASE, ROUTE_TIMEOUT, openWorkspace } from './fixtures/workspace';

const T1200 = 'attack-pattern--d40239b3-05ff-46d8-9bdd-b46d13463ef9';
const T1003_001 = 'attack-pattern--65f2d882-3f41-4d48-8a06-29af77ec9f90';

/** The words a range telemetry partial reads on every lens and page (decision 31). */
const TELEMETRY_WORDS = 'range telemetry observed via wazuh:5: partial, no detection alerted';

/** A contract-valid export with one telemetry-observed row on T1200, as the breaker imported it. */
const T1200_TELEMETRY_EXPORT = JSON.stringify({
  schema: 'lylat-validated-detections/1', range_build_ref: 'a1b2c3d', generated_at: '2026-10-21T00:00:00Z',
  rows: [{
    mission_id: 'SYNTH-MISSION-T', technique_ref: { domain: 'enterprise', id: 'T1200', attack_version: '19.2' },
    detection_ref: 'wazuh:5', coverage_state: 'telemetry-observed', outcome: 'logged',
    negative_control: 'detection-only', validated_at: '2026-10-21', evidence_ref: 'SYNTH-MISSION-T-step1',
  }],
});

/** The Sigma coverage layer the workbench's detection rules come from, served from the e2e fixture (see app.spec.ts). */
const SIGMA_COVERAGE_URL = 'https://raw.githubusercontent.com/SigmaHQ/sigma/master/other/sigma_attack_nav_coverage.json';

/** Import a range export through Detect > Validation's "Import range results" (a local file read). */
async function importRange(page: Page, name: string, body: string | Buffer, mission: string): Promise<void> {
  await page.goto(`${BASE}/#/detect/validation`);
  await expect(page.locator('#vp-import-range')).toBeEnabled({ timeout: ROUTE_TIMEOUT });
  await page.locator('#vp-import-range').setInputFiles({ name, mimeType: 'application/json', buffer: Buffer.from(body) });
  await expect(page.locator('.vp-import-msg').first()).toContainText(`lylat-range:${mission}`, { timeout: ROUTE_TIMEOUT });
}

/** Open a pasted link in a fresh navigation. */
async function paste(page: Page, hash: string): Promise<void> {
  await page.goto('about:blank');
  await page.goto(`${BASE}/${hash}`);
}

test.describe('RP-F round 6', () => {
  // Decision 31: a range row whose coverage_state is telemetry-observed is a partial by
  // telemetry. Round 6 read the breadth-threshold sentence here and offered Confirm,
  // which minted a self-attested mark 'via wazuh:5' (full Covered in one click).
  test('[RP-F 31] a telemetry-only range row on T1200: telemetry words on Posture, Covered and the page; no Confirm; Record a run', async ({ page }) => {
    await openWorkspace(page);
    await importRange(page, 't1200-telemetry.json', T1200_TELEMETRY_EXPORT, 'SYNTH-MISSION-T');

    // Posture, in the drawer.
    await paste(page, '#/matrix?heat=posture&tech=T1200');
    const drawer = page.locator('.sidebar.open');
    await expect(drawer.locator('.sidebar-header .attack-id')).toHaveText('T1200', { timeout: ROUTE_TIMEOUT });
    const card = drawer.locator('[data-testid="evidence-card"]');
    const why = card.getByTestId('ev-why');
    await expect(why).toContainText(`Covered (range, partial via wazuh:5) from ${TELEMETRY_WORDS}`, { timeout: ROUTE_TIMEOUT });
    await expect(why).toContainText('Lens: Posture');
    await expect(why).not.toContainText('breadth threshold');
    // The cell speaks the same cause in its aria-label.
    const cell = page.locator(`[data-tech-id="${T1200}"] .cell`).first();
    await expect(cell).toHaveAttribute('aria-label', new RegExp(`T1200: .*${TELEMETRY_WORDS.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`));
    // The Covered block names the row; no Confirm anywhere on the card; "Record a run" instead.
    const mark = card.getByTestId('ev-covered').getByTestId('ev-mark');
    await expect(mark).toHaveCount(1);
    await expect(mark).toContainText('telemetry observed in the range via wazuh:5');
    await expect(mark).toContainText('partial');
    await expect(card.getByTestId('ev-confirm')).toHaveCount(0);
    await mark.getByTestId('ev-record-run').click();
    await expect(page).toHaveURL(/#\/detect\/validation/, { timeout: ROUTE_TIMEOUT });
    await expect(page.locator('.vp-modal-head h3')).toContainText('T1200', { timeout: ROUTE_TIMEOUT });

    // Covered, in the drawer.
    await paste(page, '#/matrix?heat=covered&tech=T1200');
    const coveredWhy = page.locator('.sidebar.open [data-testid="evidence-card"] [data-testid="ev-why"]');
    await expect(coveredWhy).toContainText(`Covered (self-attested or range), partial via wazuh:5 from ${TELEMETRY_WORDS}`, { timeout: ROUTE_TIMEOUT });
    await expect(coveredWhy).not.toContainText('breadth threshold');

    // The technique page.
    await paste(page, '#/technique/enterprise/T1200?heat=posture');
    const pageWhy = page.locator('app-technique-page [data-testid="evidence-card"] [data-testid="ev-why"]');
    await expect(pageWhy).toContainText(`Covered (range, partial via wazuh:5) from ${TELEMETRY_WORDS}`, { timeout: ROUTE_TIMEOUT });
    await expect(page.locator('app-technique-page [data-testid="ev-confirm"]')).toHaveCount(0);
  });

  test("[RP-F 31] the P2-20 fixture's T1003.001 (alerted plus telemetry rows) stays Proven and names the telemetry row", async ({ page }) => {
    await openWorkspace(page);
    await importRange(page, 'fixture.json', readFileSync('src/testing/fixtures/lylat/validated-detections.fixture.json'), 'SYNTH-MISSION-A');
    await paste(page, '#/matrix?heat=posture&tech=T1003.001');
    const drawer = page.locator('.sidebar.open');
    await expect(drawer.locator('.sidebar-header .attack-id')).toHaveText('T1003.001', { timeout: ROUTE_TIMEOUT });
    const card = drawer.locator('[data-testid="evidence-card"]');
    await expect(card.getByTestId('ev-why')).toContainText(
      'Proven in range on 10/19/26 by lylat-range:SYNTH-MISSION-A; 1 rule fired; a later run on 10/20/26 observed telemetry only',
      { timeout: ROUTE_TIMEOUT });
    await expect(card.getByTestId('ev-confirm')).toHaveCount(0);
    await expect(card.getByTestId('ev-record-run')).toHaveCount(1);
    await expect(page.locator(`[data-tech-id="${T1003_001}"] .cell`).first()).toBeAttached();
  });

  // Decision 32: a run whose attack did not execute stores untested, whatever rules are
  // ticked. Round 6 recorded "Failed prerequisite" with its rule ticked and stored passed.
  test('[RP-F 32] Record Run with "Failed prerequisite" and every rule ticked stores untested; the tile, the history and the pill read untested', async ({ page }) => {
    await openWorkspace(page);
    await page.route(SIGMA_COVERAGE_URL, route => route.fulfill({ path: 'e2e/fixtures/sigma-coverage.json', contentType: 'application/json' }));
    const sigmaServed = page.waitForResponse(SIGMA_COVERAGE_URL);
    await page.goto(`${BASE}/#/matrix`);
    await sigmaServed;
    await expect(page.locator('.cell').first()).toBeVisible({ timeout: ROUTE_TIMEOUT });
    // In-app navigation keeps the loaded Sigma counts (T1059 carries 12 in the fixture).
    await page.evaluate(() => { window.location.hash = '#/detect/validation'; });
    await expect(page.locator('app-validation-panel')).toBeVisible({ timeout: ROUTE_TIMEOUT });
    await page.getByRole('button', { name: /Techniques/ }).click();
    await page.locator('.vp-search').fill('T1059');
    const tile = page.locator('.vp-tcard', { has: page.locator('.vp-tid', { hasText: /^T1059$/ }) });
    await expect(tile).toHaveCount(1, { timeout: ROUTE_TIMEOUT });
    await tile.getByRole('button', { name: /Record Run/ }).click();
    const modal = page.locator('.vp-modal');
    await expect(modal).toBeVisible();
    await modal.locator('select').selectOption('failed-prereq');
    const boxes = modal.locator('fieldset', { hasText: 'Detections fired' }).locator('input[type="checkbox"]');
    expect(await boxes.count()).toBeGreaterThan(0);
    for (const box of await boxes.all()) await box.check();
    await modal.getByRole('button', { name: 'Save Run' }).click();
    await expect(modal).toHaveCount(0);

    await expect(tile.locator('.vp-status-badge')).toHaveText(/UNTESTED/);
    await page.getByRole('button', { name: /Run History/ }).click();
    await expect(page.locator('.vp-runs-table tbody tr').first().locator('.vp-status-badge')).toHaveText(/UNTESTED/);

    await paste(page, '#/matrix?tech=T1059');
    const pill = page.locator('.sidebar.open app-validation-status-pill');
    await expect(pill.locator('.vsp-status').first()).toHaveText('UNTESTED', { timeout: ROUTE_TIMEOUT });
  });

  // Decision 33: with more rules fired than expected the pill reads "N fired, M expected",
  // never "N of M" (round 6: a tile "fired 2/1" beside a pill "UNTESTED 2 of 1").
  test('[RP-F 33] a run that fired more rules than it expected: the pill and the Run History read "2 fired, 1 expected"', async ({ page }) => {
    await openWorkspace(page, {
      seed: {
        'navi.v2.validation-runs': JSON.stringify({
          schema: 2, tombstones: [],
          records: [{
            id: 'e2e-rpf33', techniqueId: 'T1059', techniqueName: 'Command and Scripting Interpreter', runDate: '2026-10-20T15:00:00.000Z',
            operator: '', telemetryRequired: [], telemetryAvailable: [], atomicTestId: '', atomicCommand: '', attackResult: 'executed',
            detectionsExpected: ['siem:a'], detectionsFired: ['siem:a', 'siem:b'], responsePlaybook: '', responseActions: [],
            evidenceLinks: [], notes: '', status: 'untested', source: 'manual', domain: null, attackVersion: 'unknown', techniqueRef: null,
            outcomes: [], proofScope: 'own-run', statusFromSource: false,
            createdAt: '2026-10-20T15:00:00.000Z', updatedAt: '2026-10-20T15:00:00.000Z',
          }],
        }),
      },
    });
    await paste(page, '#/matrix?tech=T1059');
    const pill = page.locator('.sidebar.open app-validation-status-pill');
    await expect(pill.locator('.vsp-meta').first()).toHaveText(/^\s*detection rules: 2 fired, 1 expected\s*$/, { timeout: ROUTE_TIMEOUT });
    await expect(pill).not.toContainText('2 of 1');

    await page.evaluate(() => { window.location.hash = '#/detect/validation'; });
    await expect(page.locator('app-validation-panel')).toBeVisible({ timeout: ROUTE_TIMEOUT });
    await page.getByRole('button', { name: /Run History/ }).click();
    const row = page.locator('.vp-runs-table tbody tr').first();
    await expect(row).toContainText('2 fired, 1 expected');
    await expect(row).not.toContainText('2/1');
  });
});
