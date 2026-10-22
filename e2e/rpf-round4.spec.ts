// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// RP-F round 4 (decisions 23, 26, 27 and 28): the cases the round-4 walk broke,
// each as a pasted link (a fresh navigation: the app does not re-read heat=, tech=
// or dom= on an in-session hash-only change). The decision-25 fresh-boot profile
// cases are in profile-domain-notice.spec.ts.
import { test, expect } from '@playwright/test';
import { BASE, ROUTE_TIMEOUT, openWorkspace } from './fixtures/workspace';

/** heat= follows a pick after the debounced URL writer; the late debounce is absorbed here (see app.spec.ts). */
const LENS_STEP_TIMEOUT = process.env['CI'] ? 60000 : 30000;

const M1015 = 'course-of-action--e3388c78-2a8d-47c2-8422-c1398b324462';
const T1018 = 'attack-pattern--e358d692-23c0-4a31-9eb6-ecc13a8d7735';
const T1082 = 'attack-pattern--354a7f88-63fb-41b5-a801-ce3b377b36f1';

/** One validation run as the v2 store holds it. */
function runsStore(run: Record<string, unknown>): string {
  return JSON.stringify({
    schema: 2, tombstones: [],
    records: [{
      attackResult: 'executed', source: 'manual', domain: null, attackVersion: 'unknown', techniqueRef: null,
      outcomes: [], proofScope: 'own-run', statusFromSource: false, ...run,
    }],
  });
}

const oneRun = runsStore({
  id: 'e2e-rpf26-run', techniqueId: 'T1059.001', runDate: '2026-10-01T00:00:00.000Z', status: 'passed',
  createdAt: '2026-10-01T00:00:00.000Z', updatedAt: '2026-10-01T00:00:00.000Z',
});

test.describe('RP-F round 4', () => {
  // Decision 26: a repeated heat key takes its first VALID value; with none valid the key
  // is absent and D4 runs (Posture with owner data). Round 4: heat=frequency&heat=bogus
  // opened Frequency and rewrote to bare #/matrix, so F5 gave Posture.
  for (const [query, lens, label] of [
    ['heat=frequency&heat=bogus', 'frequency', 'Frequency'],
    ['heat=bogus&heat=kev', 'kev', 'KEV'],
    ['heat=bogus&heat=also-bogus', 'posture', 'Posture'],
  ] as const) {
    test(`[RP-F 26] one recorded run and a pasted #/matrix?${query}: ${label}, heat=${lens} once, kept on F5`, async ({ page }) => {
      await openWorkspace(page, { seed: { 'navi.v2.validation-runs': oneRun } });
      await page.goto('about:blank');
      await page.goto(`${BASE}/#/matrix?${query}`);
      await page.locator('.cell').first().waitFor({ state: 'visible', timeout: ROUTE_TIMEOUT });
      await expect(page.locator('.heatmap-btn')).toContainText(label);
      await expect(page).toHaveURL(new RegExp(`#/matrix\\?(.*&)?heat=${lens}(&|$)`), { timeout: LENS_STEP_TIMEOUT });
      const hash = new URL(page.url()).hash;
      expect(hash.match(/heat=/g)?.length).toBe(1);
      expect(hash).not.toContain('bogus');
      await page.reload();
      await page.locator('.cell').first().waitFor({ state: 'visible', timeout: ROUTE_TIMEOUT });
      await expect(page.locator('.heatmap-btn')).toContainText(label);
      await expect(page).toHaveURL(new RegExp(`#/matrix\\?(.*&)?heat=${lens}(&|$)`), { timeout: LENS_STEP_TIMEOUT });
    });
  }

  // Decisions 23 and 28: S12 T1018. An untested run that lists one fired rule read
  // "Proven (your run) ... 1 rule fired" beside the pill "UNTESTED 1 of 0 detection rules
  // fired". The card now follows the pill: no Proven line, and the Proven block names the
  // run and its status instead of "No recorded detection". M1015 elsewhere gives owner words.
  test('[RP-F 23/28] T1018 (an untested run with one fired rule) on heat=proven: the card names the run and its status, never Proven', async ({ page }) => {
    await openWorkspace(page, {
      seed: {
        'mitre-nav-impl-v1': JSON.stringify([[M1015, 'implemented']]),
        'navi.v2.validation-runs': runsStore({
          id: 'e2e-rpf23-s12', techniqueId: 'T1018', runDate: '2026-10-15T15:00:00.000Z', status: 'untested',
          detectionsExpected: [], detectionsFired: ['siem:curated'], outcomes: [{ detectionRef: 'siem:curated', outcome: 'alerted' }],
          createdAt: '2026-10-15T15:00:00.000Z', updatedAt: '2026-10-15T15:00:00.000Z',
        }),
      },
    });
    await page.goto('about:blank');
    await page.goto(`${BASE}/#/matrix?heat=proven`);
    await expect(page.locator('.heatmap-btn')).toContainText('Proven', { timeout: ROUTE_TIMEOUT });
    const cell = page.locator(`[data-tech-id="${T1018}"] .cell`).first();
    await expect(cell).toBeVisible({ timeout: ROUTE_TIMEOUT });
    await cell.click();
    const drawer = page.locator('.sidebar.open');
    await expect(drawer.locator('app-validation-status-pill .vsp-status').first()).toHaveText('UNTESTED', { timeout: ROUTE_TIMEOUT });
    const card = drawer.locator('[data-testid="evidence-card"]');
    await expect(card.getByTestId('ev-proven-empty')).toContainText('1 rule fired in your run on', { timeout: ROUTE_TIMEOUT });
    await expect(card.getByTestId('ev-proven-empty')).toContainText('(status untested)');
    await expect(card.getByTestId('ev-why')).toContainText('No proof: 1 rule fired');
    await expect(card).not.toContainText('No recorded detection');
    await expect(card).not.toContainText('Proven (your run)');
  });

  // Decision 27: paints implies speaks for every hatch. T1082 carries one not-reproducible
  // run. In round 4 its cross-hatch painted on Posture, Covered and Proven while the
  // aria-label read only "None" or "no recorded detection".
  const notReproducibleSeed = {
    'mitre-nav-impl-v1': JSON.stringify([[M1015, 'implemented']]),
    'navi.v2.validation-runs': runsStore({
      id: 'e2e-rpf27-nr', techniqueId: 'T1082', runDate: '2026-10-20T15:00:00.000Z', status: 'not-reproducible',
      createdAt: '2026-10-20T15:00:00.000Z', updatedAt: '2026-10-20T15:00:00.000Z',
    }),
  };
  for (const [lens, label] of [['posture', 'Posture'], ['covered', 'Covered'], ['proven', 'Proven']] as const) {
    test(`[RP-F 27] T1082 (a not-reproducible run) on heat=${lens}: the cross-hatch, and "not reproducible" in the aria-label, tooltip and why line`, async ({ page }) => {
      await openWorkspace(page, { seed: notReproducibleSeed });
      await page.goto('about:blank');
      await page.goto(`${BASE}/#/matrix?heat=${lens}`);
      await expect(page.locator('.heatmap-btn')).toContainText(label, { timeout: ROUTE_TIMEOUT });
      const cell = page.locator(`[data-tech-id="${T1082}"] .cell`).first();
      await expect(cell).toBeVisible({ timeout: ROUTE_TIMEOUT });
      await expect(cell).toHaveClass(/posture-not-reproducible/);
      await expect(cell).toHaveAttribute('aria-label', /not reproducible/);
      await cell.hover();
      await expect(page.locator('.tooltip-card .tt-posture')).toContainText('not reproducible');
      await cell.click();
      const why = page.locator('.sidebar.open [data-testid="ev-why"]');
      await expect(why).toContainText('not reproducible', { timeout: ROUTE_TIMEOUT });
      await expect(why).toContainText(`Lens: ${label}`);
    });
  }
});
