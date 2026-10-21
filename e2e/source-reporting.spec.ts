// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// How the four GitHub tree-listing sources are reported (fix/tree-listing-sources).
//
// Elastic detection-rules, Splunk security_content, edoardogerosa/sentinel-attack and
// mdecrevoisier SIGMA-detection-rules are read from unauthenticated GitHub git/trees
// listings. The listings answer, but no technique id can be read from the file names,
// so each source is 'empty'. This spec serves small real-shaped listings
// (src/testing/fixtures/github-tree-listings.json, abridged from the real ones) through
// page.route and checks what the matrix view says about them:
//   1. a complete 200 with no ids: the banner lists them under 'Incomplete data' with
//      the 'no technique ids' wording (kept to these four; any other empty source
//      gets the generic 'nothing usable' wording) and no Retry, and the Briefing line
//      says they answered with no technique ids;
//   2. a GitHub rate limit (403, X-RateLimit-Remaining: 0, X-RateLimit-Reset): the
//      banner says they did not load, with 'GitHub rate limit reached' and the time;
//   3. a truncated listing: they did not load, 'listing truncated'.
// Every other source stays offline (the hermetic workspace), so the banner also has a
// failed group; the checks below look inside the right group.
import { readFileSync } from 'node:fs';
import { Page, Route } from '@playwright/test';
import { test, expect, BASE, ROUTE_TIMEOUT } from './fixtures/workspace';
import { SOURCE_DEFINITIONS } from '../src/app/services/source-inventory';
import { TREE_LISTING_EMPTY_DETAIL, TREE_LISTING_SOURCE_IDS } from '../src/app/models/briefing';

interface Listing { sha: string; url: string; tree: Array<{ path: string; type: string }>; truncated: boolean }
type Key = 'elastic' | 'splunk' | 'sentinel' | 'mdecrevoisier';
const TREES = JSON.parse(readFileSync('src/testing/fixtures/github-tree-listings.json', 'utf8')) as Record<Key, { listing: Listing }>;

/** The four tree-listing sources: registry id, the request it makes, its fixture. */
const TREE_SOURCES: ReadonlyArray<{ id: string; key: Key; match: string }> = [
  { id: 'elastic-tree', key: 'elastic', match: 'api.github.com/repos/elastic/detection-rules/git/trees/' },
  { id: 'splunk-tree', key: 'splunk', match: 'api.github.com/repos/splunk/security_content/git/trees/' },
  { id: 'sentinel-attack-tree', key: 'sentinel', match: 'api.github.com/repos/edoardogerosa/sentinel-attack/git/trees/' },
  { id: 'mdecrevoisier-sigma-tree', key: 'mdecrevoisier', match: 'api.github.com/repos/mdecrevoisier/SIGMA-detection-rules/git/trees/' },
];
const nameOf = (id: string): string => SOURCE_DEFINITIONS.find(d => d.id === id)!.name;

/** GitHub's CORS headers on api.github.com: the rate-limit headers are exposed to the page. */
const GITHUB_CORS = {
  'access-control-allow-origin': '*',
  'access-control-expose-headers': 'ETag, Link, Retry-After, X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Used, X-RateLimit-Resource, X-RateLimit-Reset',
};

/** Answer each tree request (registered after the hermetic routes, so it wins) and count them. */
async function serveTrees(page: Page, answer: (key: Key, route: Route) => Promise<void>): Promise<() => number> {
  let served = 0;
  for (const s of TREE_SOURCES) {
    await page.route(url => url.href.includes(s.match), route => { served++; return answer(s.key, route); });
  }
  return () => served;
}

/** Load all four on the data-health view (two load on demand), wait for `status`, then open the matrix in-app. */
async function loadThenOpenMatrix(page: Page, status: 'empty' | 'failed'): Promise<void> {
  await page.goto(`${BASE}/#/status`);
  for (const s of TREE_SOURCES) {
    const row = page.locator(`app-source-health tr[data-source-id="${s.id}"]`);
    await expect(row).toBeAttached({ timeout: ROUTE_TIMEOUT });
    await expect(row).not.toHaveAttribute('data-status', 'loading', { timeout: ROUTE_TIMEOUT });
    if ((await row.getAttribute('data-status')) === 'pending') {
      await row.getByRole('button', { name: `Load now: ${nameOf(s.id)}` }).click();
    }
    await expect(row).toHaveAttribute('data-status', status, { timeout: ROUTE_TIMEOUT });
  }
  // In-app navigation keeps this session's source registry.
  await page.evaluate(() => { window.location.hash = '#/matrix'; });
}

const banner = (page: Page) => page.locator('app-source-banner [data-testid="source-banner"]');

test.describe('tree-listing sources say why they are empty or failed', () => {
  test("a complete listing with no ids: 'Incomplete data', 'no technique ids', no Retry; the Briefing agrees", async ({ page }) => {
    const served = await serveTrees(page, (key, route) =>
      route.fulfill({ status: 200, contentType: 'application/json', headers: GITHUB_CORS, body: JSON.stringify(TREES[key].listing) }));
    await loadThenOpenMatrix(page, 'empty');

    const empty = banner(page).locator('[data-testid="source-banner-empty"]');
    await expect(empty).toBeVisible({ timeout: ROUTE_TIMEOUT });
    await expect(empty).toContainText('Incomplete data');
    // The 'no technique ids' wording: the lead when only tree listings are empty, else a mark on each.
    await expect(empty).toContainText('no technique ids');
    expect([...TREE_LISTING_SOURCE_IDS], 'the app and this spec name the same four tree listings')
      .toEqual(TREE_SOURCES.map(s => s.id));
    for (const s of TREE_SOURCES) {
      const item = empty.locator(`[data-source-id="${s.id}"]`);
      await expect(item).toContainText(nameOf(s.id));
      await expect(item).toHaveAttribute('data-status', 'empty');
      await expect(item).toHaveAttribute('title', TREE_LISTING_EMPTY_DETAIL);
      // Not listed as a source that did not load.
      await expect(banner(page).locator(`[data-testid="source-banner-failed"] [data-source-id="${s.id}"]`)).toHaveCount(0);
    }
    await expect(empty).not.toContainText(/did not load|retry/i);
    await expect(empty.getByRole('link')).toHaveCount(0);
    await expect(empty.getByRole('button')).toHaveCount(0);

    const live = page.getByTestId('briefing-live');
    await expect(live).toContainText(/\d+ sources? answered with (no technique ids|nothing usable)/);
    await expect(live).toContainText('no technique ids');
    await expect(live).toContainText(nameOf('elastic-tree'));
    expect(served(), 'each tree listing was requested from the fixture').toBeGreaterThanOrEqual(TREE_SOURCES.length);
  });

  test("a GitHub rate limit: the banner says 'did not load' with 'GitHub rate limit reached' and the reset time", async ({ page }) => {
    const reset = Math.floor(Date.now() / 1000) + 37 * 60;
    await serveTrees(page, (_key, route) => route.fulfill({
      status: 403,
      contentType: 'application/json',
      headers: {
        ...GITHUB_CORS,
        'x-ratelimit-limit': '60',
        'x-ratelimit-remaining': '0',
        'x-ratelimit-used': '60',
        'x-ratelimit-resource': 'core',
        'x-ratelimit-reset': String(reset),
      },
      body: JSON.stringify({
        message: "API rate limit exceeded for 203.0.113.7. (But here's the good news: Authenticated requests get a higher rate limit.)",
        documentation_url: 'https://docs.github.com/rest/overview/resources-in-the-rest-api#rate-limiting',
      }),
    }));
    await loadThenOpenMatrix(page, 'failed');
    // The reset time in the browser's own time zone, as the app formats it.
    const hhmm = await page.evaluate(r => {
      const d = new Date(r * 1000);
      return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
    }, reset);

    const failed = banner(page).locator('[data-testid="source-banner-failed"]');
    await expect(failed).toBeVisible({ timeout: ROUTE_TIMEOUT });
    await expect(failed).toContainText('did not load');
    for (const s of TREE_SOURCES) {
      const item = failed.locator(`[data-source-id="${s.id}"]`);
      await expect(item).toContainText(`${nameOf(s.id)} (failed)`);
      await expect(item).toContainText(`GitHub rate limit reached (60 requests per hour per address); resets at ${hhmm}`);
    }
    await expect(banner(page).locator('[data-testid="source-banner-empty"] [data-source-id="elastic-tree"]')).toHaveCount(0);
  });

  test("a truncated listing is not parsed: the banner says 'did not load', 'listing truncated'", async ({ page }) => {
    await serveTrees(page, (key, route) => route.fulfill({
      status: 200,
      contentType: 'application/json',
      headers: GITHUB_CORS,
      body: JSON.stringify({ ...TREES[key].listing, truncated: true }),
    }));
    await loadThenOpenMatrix(page, 'failed');

    const failed = banner(page).locator('[data-testid="source-banner-failed"]');
    await expect(failed).toBeVisible({ timeout: ROUTE_TIMEOUT });
    for (const s of TREE_SOURCES) {
      await expect(failed.locator(`[data-source-id="${s.id}"]`))
        .toContainText(`${nameOf(s.id)} (failed): listing truncated by GitHub; counts would be incomplete`);
    }
  });
});
