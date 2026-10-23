// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// RP-F round 8 (decisions 40 to 45): the breaker's multi-row and same-run shapes (g35)
// that the round-8 walk broke, imported the way the walk imported them: the contract
// rows through Detect > Validation's "Import range results" and the same-run shapes
// through "Import JSON". Every drawer is opened by a pasted link (a fresh navigation: the
// app does not re-read heat=, tech= or dom= on an in-session hash-only change);
// data-tech-id holds the technique's STIX id.
import { test, expect, type Page } from '@playwright/test';
import { BASE, ROUTE_TIMEOUT, openWorkspace } from './fixtures/workspace';

const STIX: Readonly<Record<string, string>> = {
  T1105: 'attack-pattern--e6919abc-99f9-4c6c-95a5-14761e7b2add',
  T1113: 'attack-pattern--0259baeb-9f63-4c69-bf10-eb038c390688',
  T1057: 'attack-pattern--8f4a33ec-8b1f-4b80-a2f6-642b2e479580',
  T1560: 'attack-pattern--53ac20cd-aca3-406e-9aa0-9fc7fdc60a5a',
  T1213: 'attack-pattern--d28ef391-8ed4-45dc-bc4a-2f43abf54416',
  T1221: 'attack-pattern--dc31fe1e-d722-49da-8f5f-92c7b5aff534',
  T1030: 'attack-pattern--c3888c54-775d-4b2f-b759-75a2ececcbfd',
  T1106: 'attack-pattern--391d824f-0ef1-47a0-b0ee-c59a75e27670',
};
const T1003_001 = 'attack-pattern--65f2d882-3f41-4d48-8a06-29af77ec9f90';
const T1037_001 = 'attack-pattern--eb125d40-0b2d-41ac-a71a-3229241c2cd3';
const M1038 = 'course-of-action--47e0e9fe-96ce-4f65-8bb1-8be1feacb5db';
const MISSION = 'R8-BREAK';

const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const NOT_PROOF = 'but the range reports telemetry-only coverage, so it is not proof';
/** A rule whose row is telemetry-observed and that fired in its own run (decisions 35 and 40). */
const alerted = (rule: string, day = '10/21/26') =>
  `range telemetry observed via ${rule}: partial; the rule alerted in this run, ${NOT_PROOF} (range run on ${day})`;
/** A quiet rule beside a rule of the technique that fired (decision 40). */
const quiet = (rule: string, day = '10/21/26') => `range telemetry observed via ${rule}: partial, this rule did not alert (range run on ${day})`;

/** [technique, coverage_state, outcome, rule, negative_control, validated_at] (g35.cjs). */
type Row = readonly [string, string, string, string, string, string];
const ROWS: readonly Row[] = [
  ['T1105', 'telemetry-observed', 'logged', 'wazuh:206', 'detection-only', '2026-10-20'],
  ['T1105', 'telemetry-observed', 'alerted', 'wazuh:206', 'detection-only', '2026-10-21'],
  ['T1113', 'telemetry-observed', 'alerted', 'wazuh:201', 'detection-only', '2026-10-21'],
  ['T1113', 'telemetry-observed', 'logged', 'wazuh:202', 'detection-only', '2026-10-21'],
  ['T1057', 'telemetry-observed', 'logged', 'wazuh:203', 'detection-only', '2026-10-21'],
  ['T1057', 'validated', 'alerted', 'wazuh:204', 'detection-only', '2026-10-21'],
  ['T1005', 'telemetry-observed', 'alerted', 'wazuh:207', 'detection-only', '2026-10-21'],
  ['T1005', 'deployed', 'none', 'wazuh:207', 'detection-only', '2026-10-21'],
  ['T1037.001', 'detection-authored', 'logged', 'wazuh:111', 'detection-only', '2026-10-21'],
  ['T1550.002', 'detection-authored', 'blocked', 'wazuh:110', 'blocked-on-hardened', '2026-10-21'],
  ['T1090.002', 'validated', 'logged', 'wazuh:103', 'detection-only', '2026-10-21'],
  ['T1018', 'validated', 'logged', 'wazuh:120', 'detection-only', '2026-10-21'],
  ['T1106', 'telemetry-observed', 'alerted', 'wazuh:14', 'detection-only', '2026-10-21'],
];

function contract(rows: readonly Row[] = ROWS): string {
  return JSON.stringify({
    schema: 'lylat-validated-detections/1', range_build_ref: 'abcdef1', generated_at: '2026-10-21T15:00:00Z',
    rows: rows.map(([id, cs, oc, rule, nc, d], i) => ({
      mission_id: MISSION, technique_ref: { domain: 'enterprise', id, attack_version: '19.2' }, detection_ref: rule,
      coverage_state: cs, outcome: oc, negative_control: nc, validated_at: d, evidence_ref: `${MISSION}-step${i + 1}`,
    })),
  });
}

/** An Import JSON run (g35.cjs J). */
function run(id: string, techniqueId: string, over: Record<string, unknown>): Record<string, unknown> {
  return {
    id, techniqueId, techniqueName: '', runDate: '2026-10-21', operator: '', telemetryRequired: [], telemetryAvailable: [],
    atomicTestId: '', atomicCommand: '', attackResult: 'executed', detectionsExpected: [], detectionsFired: [], responsePlaybook: '',
    responseActions: [], evidenceLinks: [], notes: '', status: 'partial', source: 'lylat-range:J35', missionId: 'J35', ...over,
  };
}
const tel = (ref: string | null, oc: string) => ({
  detectionRef: ref, outcome: oc, coverageState: 'telemetry-observed', negativeControl: 'detection-only', evidenceRef: 'J35-x', sourceAttackVersion: '19.2',
});
const MANUAL = { source: 'manual', missionId: undefined, status: 'untested', runDate: '2026-10-20T15:00:00.000Z', detectionsExpected: [], outcomes: [] };
const RUNS = JSON.stringify({
  exportedAt: '2026-10-22T00:00:00Z', schemaVersion: '2.0', runs: [
    run('j35-t1221', 'T1221', { detectionsExpected: ['wazuh:301'], detectionsFired: ['wazuh:301'], outcomes: [tel(null, 'alerted')] }),
    run('j35-t1560', 'T1560', { detectionsExpected: ['wazuh:303', 'wazuh:304'], outcomes: [tel('wazuh:303', 'logged'), { detectionRef: 'wazuh:304', outcome: 'alerted' }] }),
    run('j35-t1092', 'T1092', { detectionsExpected: ['wazuh:305'], outcomes: [tel('  ', 'alerted')] }),
    run('j35-t1030', 'T1030', { detectionsExpected: ['wazuh:306'], detectionsFired: ['wazuh:306'], outcomes: [tel('WAZUH:306', 'logged')] }),
    run('j35-t1027013', 'T1027.013', { status: 'passed', attackResult: 'errored', detectionsExpected: ['wazuh:307'], detectionsFired: ['wazuh:307'], outcomes: [tel('wazuh:307', 'alerted')] }),
    run('j35-t1213', 'T1213', { status: 'passed', detectionsExpected: ['wazuh:308', 'wazuh:309'], detectionsFired: ['wazuh:308'], outcomes: [tel('wazuh:309', 'logged'), { detectionRef: 'wazuh:308', outcome: 'alerted', coverageState: 'validated' }] }),
    run('r8-manual-t1069', 'T1069', MANUAL),
    run('r8-manual-t1018', 'T1018', MANUAL),
  ],
});

/** Import the contract through "Import range results", then the runs through "Import JSON" (local file reads). */
async function importAll(page: Page, body = contract()): Promise<void> {
  await page.goto(`${BASE}/#/detect/validation`);
  await expect(page.locator('#vp-import-range')).toBeEnabled({ timeout: ROUTE_TIMEOUT });
  await page.locator('#vp-import-range').setInputFiles({ name: 'range.json', mimeType: 'application/json', buffer: Buffer.from(body) });
  await expect(page.locator('.vp-import-msg').first()).toContainText(`lylat-range:${MISSION}`, { timeout: ROUTE_TIMEOUT });
  await page.locator('#vp-import-runs').setInputFiles({ name: 'runs.json', mimeType: 'application/json', buffer: Buffer.from(RUNS) });
  await expect(page.locator('.vp-import-msg').first()).toContainText('lylat-range:J35', { timeout: ROUTE_TIMEOUT });
}

/** Open a pasted link in a fresh navigation. */
async function paste(page: Page, hash: string): Promise<void> {
  await page.goto('about:blank');
  await page.goto(`${BASE}/${hash}`);
}

/** Open the drawer of `id` on `lens` by a pasted link; the drawer's evidence card. */
async function drawer(page: Page, id: string, lens: string) {
  await paste(page, `#/matrix?heat=${lens}&tech=${id}`);
  const open = page.locator('.sidebar.open');
  await expect(open.locator('.sidebar-header .attack-id')).toHaveText(id, { timeout: ROUTE_TIMEOUT });
  return { drawer: open, card: open.locator('[data-testid="evidence-card"]') };
}

test.describe('RP-F round 8', () => {
  // Decision 40: the telemetry cause per technique and per rule. Round 8 read "no detection
  // alerted" beside a pill or a Proven block that counted a fired rule on seven shapes.
  test('[RP-F 40] the seven multi-row and same-run shapes: one clause per rule on Posture, Covered and the technique page, never "no detection alerted" beside a fired rule', async ({ page }) => {
    test.setTimeout(240_000);
    await openWorkspace(page);
    await importAll(page);

    // [technique, the clauses in the why line's order, the Covered block's rows in mark order]
    const SHAPES: readonly (readonly [string, readonly string[], readonly string[]])[] = [
      ['T1105', [alerted('wazuh:206')], [alerted('wazuh:206')]],
      ['T1113', [quiet('wazuh:202'), alerted('wazuh:201')], [alerted('wazuh:201'), quiet('wazuh:202')]],
      ['T1057', [quiet('wazuh:203')], [quiet('wazuh:203')]],
      ['T1560', [quiet('wazuh:303')], [quiet('wazuh:303')]],
      ['T1213', [quiet('wazuh:309')], [quiet('wazuh:309')]],
      ['T1221', [alerted('wazuh:301')], [alerted('wazuh:301')]],
      ['T1030', [alerted('WAZUH:306')], [alerted('WAZUH:306')]],
    ];
    for (const [id, clauses, rows] of SHAPES) {
      // Covered: the why line, the cell's aria-label and the Covered block name each rule once.
      const { drawer: d, card } = await drawer(page, id, 'covered');
      const why = card.getByTestId('ev-why');
      for (const clause of clauses) await expect(why, id).toContainText(clause, { timeout: ROUTE_TIMEOUT });
      await expect(card, id).not.toContainText('no detection alerted');
      const cell = page.locator(`[data-tech-id="${STIX[id]}"] .cell`).first();
      for (const clause of clauses) await expect(cell, id).toHaveAttribute('aria-label', new RegExp(escape(clause)));
      await expect(cell, id).not.toHaveAttribute('aria-label', /no detection alerted/);
      const causes = card.getByTestId('ev-covered').getByTestId('ev-mark-cause');
      await expect(causes, id).toHaveText([...rows]);
      await expect(d.locator('app-validation-status-pill'), id).toBeVisible();

      // Posture: the same clauses (a Proven technique names its proof instead).
      const posture = await drawer(page, id, 'posture');
      await expect(posture.card, id).not.toContainText('no detection alerted');
      if (id !== 'T1057' && id !== 'T1213') {
        for (const clause of clauses) await expect(posture.card.getByTestId('ev-why'), id).toContainText(clause);
      }

      // The technique page.
      await paste(page, `#/technique/enterprise/${id}?heat=covered`);
      const pageCard = page.locator('app-technique-page [data-testid="evidence-card"]');
      for (const clause of clauses) await expect(pageCard.getByTestId('ev-why'), id).toContainText(clause, { timeout: ROUTE_TIMEOUT });
      await expect(pageCard, id).not.toContainText('no detection alerted');
    }

    // T1057: the Proven block names wazuh:204 while the Covered row for wazuh:203 reads quiet.
    const t1057 = await drawer(page, 'T1057', 'proven');
    await expect(t1057.card.getByTestId('ev-proof')).toContainText('wazuh:204');
    // T1560: the pill counts the one rule that fired.
    const t1560 = await drawer(page, 'T1560', 'covered');
    await expect(t1560.drawer.locator('app-validation-status-pill .vsp-meta').first()).toHaveText(/^\s*1 of 2 expected rules fired\s*$/);
  });

  // Decision 40, last sentence: the Status lens why line carries the telemetry clause its
  // aria-label and tooltip carry (T1106: M1038 implemented plus a telemetry row).
  test('[RP-F 40] T1106 on the Status lens: the why line carries the telemetry clause the aria-label carries', async ({ page }) => {
    await openWorkspace(page, { seed: { 'mitre-nav-impl-v1': JSON.stringify([[M1038, 'implemented']]) } });
    await importAll(page);
    const words = `Status: implemented, partial via M1038, ${alerted('wazuh:14')}`;
    const { card } = await drawer(page, 'T1106', 'status');
    await expect(card.getByTestId('ev-why')).toContainText(words, { timeout: ROUTE_TIMEOUT });
    await expect(page.locator(`[data-tech-id="${STIX['T1106']}"] .cell`).first()).toHaveAttribute('aria-label', new RegExp(escape(words)));
  });

  // Decision 41: the pill, the Proven block and the Covered block describe one run. Round 8
  // (T1005) showed the untested deployed run on the pill and the partial run in the
  // Proven block ("1 rule fired ... (status partial)").
  test('[RP-F 41] T1005: the pill, the Proven block and the Covered block name the same run; the other run of the day is counted', async ({ page }) => {
    await openWorkspace(page);
    await importAll(page);
    const { drawer: d, card } = await drawer(page, 'T1005', 'posture');
    const pill = d.locator('app-validation-status-pill');
    await expect(pill.locator('.vsp-status').first()).toHaveText('UNTESTED', { timeout: ROUTE_TIMEOUT });
    await expect(pill.locator('.vsp-meta').first()).toHaveText(/^\s*0 of 1 expected rules fired\s*$/);
    await expect(card.getByTestId('ev-proven-empty')).toHaveText(
      'No proof: no rule fired in the range run on 10/21/26 (status untested); and 1 more run the same day: partial (1 rule fired); '
      + 'a run is proof only when its status is passed.');
    const marks = card.getByTestId('ev-covered').getByTestId('ev-mark');
    await expect(marks).toHaveCount(1);
    await expect(marks.first()).toContainText('deployed in the range via wazuh:207');
    await expect(card).not.toContainText('telemetry observed in the range via wazuh:207');
  });

  // Decision 42: the runs line names its source. Round 8 read "1 run of yours recorded" on
  // T1090.002, whose only run was a range row.
  test('[RP-F 42] the runs line: "1 range run" (T1090.002), "1 run of yours" (T1069), "2 runs (1 yours, 1 range)" (T1018)', async ({ page }) => {
    await openWorkspace(page);
    await importAll(page);
    for (const [id, words] of [
      ['T1090.002', '1 range run recorded, latest untested on 10/21/26; see Detection Validation'],
      ['T1069', '1 run of yours recorded, latest untested on 10/20/26; see Detection Validation'],
      ['T1018', '2 runs (1 yours, 1 range) recorded, latest untested on 10/21/26; see Detection Validation'],
    ] as const) {
      const { card } = await drawer(page, id, 'posture');
      await expect(card.getByTestId('ev-why'), id).toContainText(words, { timeout: ROUTE_TIMEOUT });
    }
    const { card } = await drawer(page, 'T1090.002', 'posture');
    await expect(card.getByTestId('ev-why')).not.toContainText('of yours');
  });

  // Decision 43: Covered splits by source on the scenario table. Round 8 read the
  // self-attested reason on range-only full marks (T1005, T1037.001, T1550.002).
  test('[RP-F 43] APT28: range-only, self-attested and mixed Covered techniques name their own source in the scenario table, counted per source', async ({ page }) => {
    await openWorkspace(page, {
      seed: { 'mitre-nav-impl-v1': JSON.stringify([[T1003_001, 'implemented'], [T1037_001, 'implemented']]) },
    });
    await importAll(page);
    await page.goto(`${BASE}/#/intel/scenarios`);
    const picker = page.locator('app-scenario-panel app-threat-profile-picker').first();
    await picker.locator('.tpp-search input').fill('APT28');
    await picker.locator('.tpp-item', { has: page.locator('.tpp-item-name', { hasText: /^APT28$/ }) }).first().click();
    await expect(page.locator('[data-testid="scenario-covered-source"]')).toHaveText([
      'Covered (self-attested: mitigation, control, confirmation or your run): 2',
      'Covered (range: lab-validated detection): 3',
    ], { timeout: ROUTE_TIMEOUT });

    await page.locator('app-scenario-panel .tab-btn', { hasText: 'Techniques' }).click();
    const reason = (id: string) => page.locator('.tech-row', { has: page.locator('a', { hasText: new RegExp(`^${escape(id)}$`) }) }).locator('.tech-reasoning');
    for (const id of ['T1005', 'T1550.002']) await expect(reason(id), id).toHaveText('Covered (range: lab-validated detection)');
    await expect(reason('T1003.001')).toHaveText('Covered (self-attested: mitigation, control, confirmation or your run)');
    await expect(reason('T1037.001')).toHaveText(
      'Covered (self-attested: mitigation, control, confirmation or your run); Covered (range: lab-validated detection)');
    await expect(page.locator('app-scenario-panel')).not.toContainText('You recorded a mitigation, control, confirmation or run');
  });
});
