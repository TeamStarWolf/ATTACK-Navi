// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// How the three rule-coverage sources are reported (feat/rule-coverage-snapshot).
//
// Elastic detection-rules, Splunk security_content and mdecrevoisier
// SIGMA-detection-rules are read from one bundled file,
// src/assets/data/rule-coverage-snapshot.json, built from the rule bodies at pinned
// commits by scripts/build-rule-coverage-snapshot.mjs. No request goes to GitHub for
// them. This spec checks what the app says about them:
//   1. the normal path: the file loads from the app's own origin, each source is
//      'loaded' with rows above 0 and its pinned commit in the version, and the matrix
//      lists none of them under 'Incomplete data' or as failed, and the Briefing line
//      does not name them;
//   2. the file missing (404, served through page.route): the banner says they did
//      not load, with 'bundled snapshot missing', and never lists them as
//      'Incomplete data'.
// Every other source stays offline (the hermetic workspace), so the banner also has a
// failed group for those; the checks below look at these three only.
import { Page } from '@playwright/test';
import { test, expect, BASE, ROUTE_TIMEOUT } from './fixtures/workspace';
import { SOURCE_DEFINITIONS } from '../src/app/services/source-inventory';

const SNAPSHOT = 'assets/data/rule-coverage-snapshot.json';
const IDS = ['elastic-tree', 'splunk-tree', 'mdecrevoisier-sigma-tree'] as const;
const nameOf = (id: string): string => SOURCE_DEFINITIONS.find(d => d.id === id)!.name;

/** Count the snapshot requests; optionally answer them with a 404. */
async function watchSnapshot(page: Page, missing: boolean): Promise<{ requests: () => number; github: () => number }> {
  let requests = 0;
  let github = 0;
  page.on('request', req => {
    const url = req.url();
    if (url.includes('api.github.com/repos/elastic/') || url.includes('api.github.com/repos/splunk/')
      || url.includes('api.github.com/repos/mdecrevoisier/SIGMA-detection-rules') || url.includes('sentinel-attack')) {
      github++;
    }
  });
  await page.route(url => url.href.includes(SNAPSHOT), route => {
    requests++;
    return missing
      ? route.fulfill({ status: 404, contentType: 'text/plain', body: 'Not Found' })
      : route.continue();
  });
  return { requests: () => requests, github: () => github };
}

/** Wait on the data-health view until each of the three settles in `status`, then open the matrix in-app. */
async function settleThenOpenMatrix(page: Page, status: 'loaded' | 'failed'): Promise<void> {
  await page.goto(`${BASE}/#/status`);
  for (const id of IDS) {
    const row = page.locator(`app-source-health tr[data-source-id="${id}"]`);
    await expect(row).toBeAttached({ timeout: ROUTE_TIMEOUT });
    await expect(row).toHaveAttribute('data-status', status, { timeout: ROUTE_TIMEOUT });
  }
  // In-app navigation keeps this session's source registry.
  await page.evaluate(() => { window.location.hash = '#/matrix'; });
}

const banner = (page: Page) => page.locator('app-source-banner [data-testid="source-banner"]');

test.describe('rule coverage comes from a bundled, pinned snapshot', () => {
  test('normal path: loaded with rows and the pinned commit; never Incomplete data or failed on the matrix', async ({ page }) => {
    const seen = await watchSnapshot(page, false);
    await settleThenOpenMatrix(page, 'loaded');

    await page.evaluate(() => { window.location.hash = '#/status'; });
    for (const id of IDS) {
      const row = page.locator(`app-source-health tr[data-source-id="${id}"]`);
      await expect(row).toHaveAttribute('data-status', 'loaded', { timeout: ROUTE_TIMEOUT });
      expect(Number(await row.locator('.sh-rows').textContent()), `${id} rows`).toBeGreaterThan(0);
      await expect(row).toContainText(/snapshot of \d{4}-\d{2}-\d{2}, [\w-]+\/[\w-]+@[0-9a-f]{7} \(commit \d{4}-\d{2}-\d{2}, \w+\)/);
      await expect(row).toContainText('Reference data about a public rule repository at the pinned commit');
      // Bundled with the app: no Retry button.
      await expect(row.getByRole('button')).toHaveCount(0);
    }
    await page.evaluate(() => { window.location.hash = '#/matrix'; });
    await expect(page.locator('app-matrix')).toBeVisible({ timeout: ROUTE_TIMEOUT });
    for (const id of IDS) {
      await expect(banner(page).locator(`[data-source-id="${id}"]`)).toHaveCount(0);
    }
    const live = page.getByTestId('briefing-live');
    await expect(live).toBeAttached({ timeout: ROUTE_TIMEOUT });
    for (const id of IDS) await expect(live).not.toContainText(nameOf(id));
    expect(seen.requests(), 'the snapshot was read from the app').toBeGreaterThan(0);
    expect(seen.github(), 'no tree listing is requested from GitHub').toBe(0);
  });

  test("the file missing (404): 'did not load' with 'bundled snapshot missing', never Incomplete data", async ({ page }) => {
    const seen = await watchSnapshot(page, true);
    await settleThenOpenMatrix(page, 'failed');

    const failed = banner(page).locator('[data-testid="source-banner-failed"]');
    await expect(failed).toBeVisible({ timeout: ROUTE_TIMEOUT });
    await expect(failed).toContainText('did not load');
    for (const id of IDS) {
      const item = failed.locator(`[data-source-id="${id}"]`);
      await expect(item).toContainText(`${nameOf(id)} (failed)`);
      await expect(item).toContainText('bundled snapshot missing');
      await expect(banner(page).locator(`[data-testid="source-banner-empty"] [data-source-id="${id}"]`)).toHaveCount(0);
    }
    expect(seen.requests()).toBeGreaterThan(0);
  });
});
