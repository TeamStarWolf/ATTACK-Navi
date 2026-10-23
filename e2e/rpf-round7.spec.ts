// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// RP-F round 7 (decisions 35 to 39): the shapes the round-7 walk broke. Every
// drawer is opened by a pasted link (a fresh navigation: the app does not re-read
// heat=, tech= or dom= on an in-session hash-only change); data-tech-id holds the
// technique's STIX id.
import { test, expect, type Page } from '@playwright/test';
import { BASE, ROUTE_TIMEOUT, openWorkspace } from './fixtures/workspace';

const T1082 = 'attack-pattern--354a7f88-63fb-41b5-a801-ce3b377b36f1';
const T1083 = 'attack-pattern--7bc57495-ea59-4380-be31-a64af124ef18';
const M1038 = 'course-of-action--47e0e9fe-96ce-4f65-8bb1-8be1feacb5db';

const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** The words of a telemetry-observed row whose rule fired (decision 35). */
const firedWords = (rule: string, verb: 'alerted' | 'blocked') =>
  `range telemetry observed via ${rule}: partial; the rule ${verb} in this run, but the range reports telemetry-only coverage, so it is not proof`;

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
});
