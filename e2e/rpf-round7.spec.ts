// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// RP-F round 7 (decisions 35 to 39): the shapes the round-7 walk broke. Every
// drawer is opened by a pasted link (a fresh navigation: the app does not re-read
// heat=, tech= or dom= on an in-session hash-only change); data-tech-id holds the
// technique's STIX id.
import { readFileSync } from 'node:fs';
import { test, expect, type Page } from '@playwright/test';
import { BASE, ROUTE_TIMEOUT, openWorkspace } from './fixtures/workspace';

const T1082 = 'attack-pattern--354a7f88-63fb-41b5-a801-ce3b377b36f1';
const T1083 = 'attack-pattern--7bc57495-ea59-4380-be31-a64af124ef18';
const M1038 = 'course-of-action--47e0e9fe-96ce-4f65-8bb1-8be1feacb5db';
const T1003_001 = 'attack-pattern--65f2d882-3f41-4d48-8a06-29af77ec9f90';

const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** The words of a telemetry-observed row whose rule fired (decision 35). */
const firedWords = (rule: string, verb: 'alerted' | 'blocked') =>
  `range telemetry observed via ${rule}: partial; the rule ${verb} in this run, but the range reports telemetry-only coverage, so it is not proof (range run on 10/20/26)`;

/** A contract-valid export: telemetry-observed rows whose rule alerted, blocked or only logged (round 7, letters A and G). */
const ROUND7_EXPORT = JSON.stringify({
  schema: 'lylat-validated-detections/1', range_build_ref: 'a1b2c3d', generated_at: '2026-10-21T00:00:00Z',
  rows: ([['T1082', 'wazuh:12', 'alerted'], ['T1083', 'wazuh:13', 'blocked'], ['T1106', 'wazuh:14', 'alerted'], ['T1200', 'wazuh:5', 'logged']] as const)
    .map(([id, rule, outcome], i) => ({
      mission_id: 'SYNTH-MISSION-R7', technique_ref: { domain: 'enterprise', id, attack_version: '19.2' },
      detection_ref: rule, coverage_state: 'telemetry-observed', outcome,
      negative_control: 'detection-only', validated_at: '2026-10-20', evidence_ref: `SYNTH-MISSION-R7-step${i + 1}`,
    })),
});

/** Import a range export through Detect > Validation's "Import range results" (a local file read). */
async function importRange(page: Page, name: string, body: string, mission: string): Promise<void> {
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

test.describe('RP-F round 7', () => {
  // Decision 35: the telemetry cause carries the row's outcome. Round 7 read "partial, no
  // detection alerted" on T1082 (alerted via wazuh:12) and T1083 (blocked via wazuh:13)
  // beside the pill "PARTIAL LAB 1 of 1 detection rules fired" and the card's own Proven
  // block "No proof: 1 rule fired ... (status partial)".
  test('[RP-F 35] telemetry rows whose rule alerted or blocked: the why line, aria-label, Covered block, page and Record-a-run tooltip agree with the pill and the Proven block', async ({ page }) => {
    await openWorkspace(page, { seed: { 'mitre-nav-impl-v1': JSON.stringify([[M1038, 'implemented']]) } });
    await importRange(page, 'round7.json', ROUND7_EXPORT, 'SYNTH-MISSION-R7');

    for (const [id, stix, rule, verb] of [['T1082', T1082, 'wazuh:12', 'alerted'], ['T1083', T1083, 'wazuh:13', 'blocked']] as const) {
      const words = firedWords(rule, verb);
      await paste(page, `#/matrix?heat=posture&tech=${id}`);
      const drawer = page.locator('.sidebar.open');
      await expect(drawer.locator('.sidebar-header .attack-id')).toHaveText(id, { timeout: ROUTE_TIMEOUT });
      const card = drawer.locator('[data-testid="evidence-card"]');
      const why = card.getByTestId('ev-why');
      await expect(why).toContainText(`Covered (range, partial via ${rule}) from ${words}`, { timeout: ROUTE_TIMEOUT });
      await expect(why).not.toContainText('no detection alerted');
      await expect(page.locator(`[data-tech-id="${stix}"] .cell`).first()).toHaveAttribute('aria-label', new RegExp(`${id}: .*${escape(words)}`));
      const mark = card.getByTestId('ev-covered').getByTestId('ev-mark');
      await expect(mark.getByTestId('ev-mark-cause')).toHaveText(words);
      await expect(mark.getByTestId('ev-record-run')).toHaveAttribute('title', `${words}; record a validation run of this technique in Detect > Validation`);
      await expect(card.getByTestId('ev-confirm')).toHaveCount(0);
      // The Proven block keeps the fired count and names the range run; the pill counts the same rule.
      await expect(card.getByTestId('ev-proven-empty')).toHaveText(/No proof: 1 rule fired in the range run on 10\/20\/26 \(status partial\)/);
      const pill = drawer.locator('app-validation-status-pill');
      await expect(pill.locator('.vsp-status').first()).toHaveText('PARTIAL');
      await expect(pill.locator('.vsp-meta').first()).toContainText('1 of 1');

      await paste(page, `#/matrix?heat=covered&tech=${id}`);
      await expect(page.locator('.sidebar.open [data-testid="evidence-card"] [data-testid="ev-why"]'))
        .toContainText(`Covered (self-attested or range), partial via ${rule} from ${words}`, { timeout: ROUTE_TIMEOUT });

      await paste(page, `#/technique/enterprise/${id}?heat=posture`);
      const pageCard = page.locator('app-technique-page [data-testid="evidence-card"]');
      await expect(pageCard.getByTestId('ev-why')).toContainText(words, { timeout: ROUTE_TIMEOUT });
      await expect(pageCard.getByTestId('ev-mark-cause')).toHaveText(words);
    }

    // T1106 under M1038 implemented (mixed): both causes, Confirm for M1038, Record a run for the row.
    await paste(page, '#/matrix?heat=posture&tech=T1106');
    const mixed = page.locator('.sidebar.open [data-testid="evidence-card"]');
    await expect(mixed.getByTestId('ev-why')).toContainText(
      `the breadth threshold; ${firedWords('wazuh:14', 'alerted')}`, { timeout: ROUTE_TIMEOUT });
    await expect(mixed.getByTestId('ev-confirm')).toHaveCount(1);
    await expect(mixed.getByTestId('ev-record-run')).toHaveCount(1);

    // T1200 (logged) keeps the no-alert words.
    await paste(page, '#/matrix?heat=posture&tech=T1200');
    await expect(page.locator('.sidebar.open [data-testid="evidence-card"] [data-testid="ev-why"]'))
      .toContainText('Covered (range, partial via wazuh:5) from range telemetry observed via wazuh:5: partial, no detection alerted', { timeout: ROUTE_TIMEOUT });
  });

  // Decision 35, last sentence (PR #240 round 1): the Proven wording names the run's
  // source. The P2-20 fixture's T1003.001 is proven by a contract-imported run, and its
  // cell tooltip and aria-label read "Proven in range", naming neither the range run nor
  // (rightly) "your run".
  test("[RP-F 35] the P2-20 fixture's T1003.001: the tooltip, aria-label and why line name the range run, never 'your run'", async ({ page }) => {
    await openWorkspace(page);
    await importRange(page, 'fixture.json', readFileSync('src/testing/fixtures/lylat/validated-detections.fixture.json', 'utf8'), 'SYNTH-MISSION-A');
    await paste(page, '#/matrix?heat=posture');
    const cell = page.locator(`[data-tech-id="${T1003_001}"] .cell`).first();
    await expect(cell).toBeVisible({ timeout: ROUTE_TIMEOUT });
    await expect(cell).toHaveAttribute('aria-label', /^T1003\.001: LSASS Memory, Proven in a range run/);
    await expect(cell).not.toHaveAttribute('aria-label', /your run/);
    await cell.hover();
    const tip = page.locator('.tooltip-card .tt-posture');
    await expect(tip).toContainText('Proven in a range run');
    await expect(tip).not.toContainText('your run');
    await cell.click();
    const why = page.locator('.sidebar.open [data-testid="evidence-card"] [data-testid="ev-why"]');
    await expect(why).toContainText(
      'Proven in a range run on 10/19/26 by lylat-range:SYNTH-MISSION-A; 1 rule fired; a later run on 10/20/26 observed telemetry only',
      { timeout: ROUTE_TIMEOUT });
    await expect(page.locator('.sidebar.open [data-testid="evidence-card"]')).not.toContainText('your run');
  });

  // Decision 36: the scenario table and the Report Builder read the typed cause. Round 7
  // read a breadth cause ("a broad mitigation marked implemented") for telemetry-only
  // range partials there.
  test('[RP-F 36] telemetry-only range partials: the scenario note and the Report Builder count them under the telemetry cause', async ({ page }) => {
    await openWorkspace(page);
    await importRange(page, 'round7.json', ROUND7_EXPORT, 'SYNTH-MISSION-R7');

    // Lazarus Group uses T1082, T1083 and T1106: three telemetry-only partials.
    await page.goto(`${BASE}/#/intel/scenarios`);
    const picker = page.locator('app-scenario-panel app-threat-profile-picker').first();
    await picker.locator('.tpp-search input').fill('Lazarus');
    await picker.locator('.tpp-item', { hasText: 'Lazarus Group' }).first().click();
    const causeLines = page.locator('[data-testid="scenario-partial-cause"]');
    await expect(causeLines).toHaveText(['partial (range telemetry, no alert credited): 3'], { timeout: ROUTE_TIMEOUT });
    await expect(page.locator('app-scenario-panel')).not.toContainText('broad mitigation');

    await page.goto(`${BASE}/#/reports/builder`);
    const card = page.locator('[data-testid="report-partial"]');
    await expect(card.locator('[data-testid="report-partial-cause"]')).toHaveText(['partial (range telemetry, no alert credited): 4'], { timeout: ROUTE_TIMEOUT });
    await expect(card).not.toContainText('broad mitigation');
    await expect(page.locator('[data-testid="report-split-note"]'))
      .toContainText('a broad mitigation not confirmed per technique, or range telemetry with no alert credited, counts as partial');
  });

  // Decision 37: decision 32 on every write path. Import JSON kept an explicit 'passed'
  // with attackResult errored or failed-prereq, so T1027 and T1486 read Proven (2/2).
  test('[RP-F 37] Import JSON: T1027 (errored) and T1486 (failed-prereq) with status passed store untested; the summary counts them; pill, card and tile never read Proven', async ({ page }) => {
    await openWorkspace(page);
    const run = (id: string, techniqueId: string, attackResult: string) => ({
      id, techniqueId, techniqueName: techniqueId, runDate: '2026-10-20T15:00:00.000Z', operator: '', telemetryRequired: [], telemetryAvailable: [],
      atomicTestId: '', atomicCommand: '', attackResult, detectionsExpected: ['sigma:r7'], detectionsFired: ['sigma:r7'],
      responsePlaybook: '', responseActions: [], evidenceLinks: [], notes: '', status: 'passed', source: 'manual',
    });
    const body = JSON.stringify({ schemaVersion: '2.0', runs: [run('r7-t1027', 'T1027', 'errored'), run('r7-t1486', 'T1486', 'failed-prereq')] });
    await page.goto(`${BASE}/#/detect/validation`);
    await expect(page.locator('app-validation-panel')).toBeVisible({ timeout: ROUTE_TIMEOUT });
    await page.locator('#vp-import-runs').setInputFiles({ name: 'runs.json', mimeType: 'application/json', buffer: Buffer.from(body) });
    await expect(page.locator('.vp-import-msg').first()).toContainText('2 runs stored untested: the attack did not execute', { timeout: ROUTE_TIMEOUT });

    await page.getByRole('button', { name: /Techniques/ }).click();
    for (const id of ['T1027', 'T1486']) {
      await page.locator('.vp-search').fill(id);
      const tile = page.locator('.vp-tcard', { has: page.locator('.vp-tid', { hasText: new RegExp(`^${id}$`) }) });
      await expect(tile.locator('.vp-status-badge')).toHaveText(/UNTESTED/, { timeout: ROUTE_TIMEOUT });
    }

    for (const id of ['T1027', 'T1486']) {
      await paste(page, `#/matrix?heat=posture&tech=${id}`);
      const drawer = page.locator('.sidebar.open');
      await expect(drawer.locator('.sidebar-header .attack-id')).toHaveText(id, { timeout: ROUTE_TIMEOUT });
      await expect(drawer.locator('app-validation-status-pill .vsp-status').first()).toHaveText('UNTESTED');
      const card = drawer.locator('[data-testid="evidence-card"]');
      await expect(card.getByTestId('ev-why')).not.toContainText('Proven');
      await expect(card.getByTestId('ev-proof')).toHaveCount(0);
      // The card names the run by its status and date, never a rung (decision 9).
      await expect(card.getByTestId('ev-runs-without-proof')).toContainText('untested on 10/20/26 (source manual, 1 rule fired)');
    }
  });

  // Decision 38: the fired fraction counts expected rules that fired. Expected [a, b]
  // with a and c fired read "2 of 2" before (every fired rule counted against the
  // expected ones).
  test('[RP-F 38] expected [a, b], fired [a, c]: the pill and Run History read "1 of 2 expected rules fired, plus 1 unexpected"', async ({ page }) => {
    await openWorkspace(page, {
      seed: {
        'navi.v2.validation-runs': JSON.stringify({
          schema: 2, tombstones: [],
          records: [{
            id: 'e2e-rpf38', techniqueId: 'T1059', techniqueName: 'Command and Scripting Interpreter', runDate: '2026-10-20T15:00:00.000Z',
            operator: '', telemetryRequired: [], telemetryAvailable: [], atomicTestId: '', atomicCommand: '', attackResult: 'executed',
            detectionsExpected: ['siem:a', 'siem:b'], detectionsFired: ['siem:a', 'siem:c'], responsePlaybook: '', responseActions: [],
            evidenceLinks: [], notes: '', status: 'partial', source: 'manual', domain: null, attackVersion: 'unknown', techniqueRef: null,
            outcomes: [], proofScope: 'own-run', statusFromSource: false,
            createdAt: '2026-10-20T15:00:00.000Z', updatedAt: '2026-10-20T15:00:00.000Z',
          }],
        }),
      },
    });
    const words = '1 of 2 expected rules fired, plus 1 unexpected';
    await paste(page, '#/matrix?tech=T1059');
    const pill = page.locator('.sidebar.open app-validation-status-pill');
    await expect(pill.locator('.vsp-meta').first()).toHaveText(new RegExp(`^\\s*${escape(words)}\\s*$`), { timeout: ROUTE_TIMEOUT });
    await expect(pill).not.toContainText('2 of 2');

    await page.evaluate(() => { window.location.hash = '#/detect/validation'; });
    await expect(page.locator('app-validation-panel')).toBeVisible({ timeout: ROUTE_TIMEOUT });
    await page.getByRole('button', { name: /Run History/ }).click();
    const row = page.locator('.vp-runs-table tbody tr').first();
    await expect(row).toContainText(words);
    await expect(row).not.toContainText('2/2');
  });

  // Decision 39: a manual failed run with no rule id is matched on source plus technique
  // (decision 29), so it is never called a run "of the rule".
  test('[RP-F 39] a manual failed run with no rule id after a pass: the why line reads "latest run failed, no rule named"', async ({ page }) => {
    const record = (id: string, runDate: string, status: string, rules: string[]) => ({
      id, techniqueId: 'T1078', techniqueName: 'Valid Accounts', runDate, operator: '', telemetryRequired: [], telemetryAvailable: [],
      atomicTestId: '', atomicCommand: '', attackResult: 'executed', detectionsExpected: rules, detectionsFired: rules,
      responsePlaybook: '', responseActions: [], evidenceLinks: [], notes: '', status, source: 'manual', domain: null,
      attackVersion: 'unknown', techniqueRef: null, outcomes: [], proofScope: 'own-run', statusFromSource: false,
      createdAt: runDate, updatedAt: runDate,
    });
    await openWorkspace(page, {
      seed: {
        'navi.v2.validation-runs': JSON.stringify({
          schema: 2, tombstones: [],
          records: [record('e2e-rpf39-pass', '2026-10-20T15:00:00.000Z', 'passed', ['sigma:r39']), record('e2e-rpf39-fail', '2026-10-21T15:00:00.000Z', 'failed', [])],
        }),
      },
    });
    await paste(page, '#/matrix?heat=posture&tech=T1078');
    const why = page.locator('.sidebar.open [data-testid="evidence-card"] [data-testid="ev-why"]');
    await expect(why).toContainText('contradicted: latest run failed, no rule named, on 10/21/26; an earlier run passed on 10/20/26', { timeout: ROUTE_TIMEOUT });
    await expect(why).not.toContainText('of the rule');
  });
});
