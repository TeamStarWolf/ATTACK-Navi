// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// RP-F round 5 (decision 30): the shapes the round-5 breaker walk broke, each as a
// pasted link (a fresh navigation: the app does not re-read heat=, tech= or dom= on
// an in-session hash-only change).
import { test, expect, type Page } from '@playwright/test';
import { BASE, ROUTE_TIMEOUT, openWorkspace } from './fixtures/workspace';

/** heat= follows a pick after the debounced URL writer; the late debounce is absorbed here (see app.spec.ts). */
const LENS_STEP_TIMEOUT = process.env['CI'] ? 60000 : 30000;

/** One validation run as the v2 store holds it. */
function runsStore(run: Record<string, unknown>): string {
  return JSON.stringify({
    schema: 2, tombstones: [],
    records: [{
      attackResult: 'executed', source: 'manual', domain: null, attackVersion: 'unknown', techniqueRef: null,
      detectionsExpected: [], detectionsFired: [], outcomes: [], proofScope: 'own-run', statusFromSource: false, ...run,
    }],
  });
}

/** Owner data: one passed run on an Enterprise technique, so the default lens is Posture (D4). */
const ownerSeed = {
  'navi.v2.validation-runs': runsStore({
    id: 'e2e-rpf30a-run', techniqueId: 'T1059.001', runDate: '2026-10-01T00:00:00.000Z', status: 'passed',
    createdAt: '2026-10-01T00:00:00.000Z', updatedAt: '2026-10-01T00:00:00.000Z',
  }),
};

/** The settled hash: one heat key, the lens, no bogus value. */
function settledHash(page: Page, route: string, lens: string) {
  return () => {
    const hash = new URL(page.url()).hash;
    return {
      route: hash.startsWith(route),
      heatKeys: hash.match(/heat=/g)?.length ?? 0,
      lens: new RegExp(`[?&]heat=${lens}(&|$)`).test(hash),
      bogus: hash.includes('bogus'),
    };
  };
}

test.describe('RP-F round 5', () => {
  // Decision 30a: the technique page reads a repeated heat key as the matrix does
  // (firstValidHeat) after its domain switch. Round 5: ICS and Mobile links with a
  // repeated key lost the lens to the default (Frequency, or Posture with owner data), 6/6.
  for (const [dom, id, query] of [
    ['ics', 'T0883', 'heat=bogus&heat=coverage'],
    ['ics', 'T0883', 'heat=coverage&heat=bogus'],
    ['mobile', 'T1404', 'heat=bogus&heat=coverage'],
  ] as const) {
    for (const owner of [false, true]) {
      test(`[RP-F 30a] ${owner ? 'with' : 'without'} owner data, a pasted #/technique/${dom}/${id}?${query} reads Mitigations mapped, keeps heat=coverage and Open in matrix carries it`, async ({ page }) => {
        await openWorkspace(page, owner ? { seed: ownerSeed } : {});
        await page.goto('about:blank');
        await page.goto(`${BASE}/#/technique/${dom}/${id}?${query}`);
        const card = page.locator('app-technique-page [data-testid="evidence-card"]');
        await expect(card).toBeVisible({ timeout: ROUTE_TIMEOUT });
        await expect(page.locator('app-technique-page .tp-id')).toHaveText(id);
        await expect(card.getByTestId('ev-why')).toContainText('Lens: Mitigations mapped');
        await expect(page).toHaveURL(new RegExp(`[?&]tech=${id}(&|$)`), { timeout: ROUTE_TIMEOUT });
        await expect.poll(settledHash(page, `#/technique/${dom}/${id}?`, 'coverage'), { timeout: LENS_STEP_TIMEOUT })
          .toEqual({ route: true, heatKeys: 1, lens: true, bogus: false });

        await page.getByTestId('open-in-matrix').click();
        await expect(page).toHaveURL(/#\/matrix\?(.*&)?heat=coverage(&|$)/, { timeout: ROUTE_TIMEOUT });
        await expect(page).toHaveURL(new RegExp(`[?&]dom=${dom}(&|$)`));
        await expect(page.locator('.heatmap-btn')).toContainText('Mitigations mapped');
        await expect(page.locator('.sidebar.open .sidebar-header .attack-id')).toHaveText(id, { timeout: ROUTE_TIMEOUT });
        await expect.poll(settledHash(page, '#/matrix?', 'coverage'), { timeout: LENS_STEP_TIMEOUT })
          .toEqual({ route: true, heatKeys: 1, lens: true, bogus: false });
      });
    }
  }
});
