// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The technique drawer's Rule sources section in the running app: Elastic
// detection-rules, Splunk security_content and mdecrevoisier SIGMA rule names with
// permalinks at the commits the bundled rule-coverage snapshot pins
// (src/assets/data/rule-coverage-snapshot.json). The snapshot is same-origin, so the
// hermetic workspace serves it; every off-origin request stays blocked. The drawer is
// opened by clicking the T1059 cell (a hash-only navigation does not apply tech=), and
// the dead Sentinel section is gone.
import { readFileSync } from 'node:fs';
import { test, expect, loadSampleOrg, BASE, ROUTE_TIMEOUT } from './fixtures/workspace';

interface SnapshotSource { owner: string; repo: string; sha: string; techniques: Record<string, { count: number }> }
const SNAPSHOT = JSON.parse(readFileSync('src/assets/data/rule-coverage-snapshot.json', 'utf8')) as {
  generated: string; sources: Record<'elastic' | 'splunk' | 'mdecrevoisier', SnapshotSource>;
};
const KEYS = ['elastic', 'splunk', 'mdecrevoisier'] as const;

test.describe('technique drawer: Rule sources at pinned commits', () => {
  test('T1059: three sources, each with rule names linking to the pinned commit; no Sentinel; no request of its own', async ({ page }) => {
    const snapshotRequests: string[] = [];
    page.on('request', req => {
      if (new URL(req.url()).pathname.endsWith('/assets/data/rule-coverage-snapshot.json')) snapshotRequests.push(req.url());
    });

    await page.goto(`${BASE}/#/matrix`);
    const cell = page.locator('.cell[aria-label^="T1059:"]').first();
    await cell.waitFor({ state: 'visible', timeout: ROUTE_TIMEOUT });
    // The app reads the snapshot at start (the Elastic, Splunk and Sigma services).
    await expect.poll(() => snapshotRequests.length, { timeout: ROUTE_TIMEOUT }).toBe(1);

    await cell.click();
    await expect(page.locator('.sidebar.open')).toBeVisible({ timeout: ROUTE_TIMEOUT });
    await expect(page.locator('.sidebar-header .attack-id')).toHaveText('T1059');

    const header = page.locator('#sb-sec-rule-sources');
    await expect(header).toHaveAttribute('aria-expanded', 'false');
    await header.click();
    await expect(header).toHaveAttribute('aria-expanded', 'true');

    const sources = page.locator('app-rule-source-list [data-testid="rule-source"]');
    await expect(sources).toHaveCount(3);
    expect(await sources.evaluateAll(els => els.map(e => e.getAttribute('data-source')))).toEqual([...KEYS]);

    for (const key of KEYS) {
      const pin = SNAPSHOT.sources[key];
      const count = pin.techniques['T1059']?.count ?? 0;
      expect(count, `${key} names T1059 at its pin`).toBeGreaterThan(0);
      const block = page.locator(`[data-testid="rule-source"][data-source="${key}"]`);
      await expect(block.locator('[data-testid="rule-source-count"]')).toHaveText(`${count} ${count === 1 ? 'rule' : 'rules'}`);
      const links = block.locator('a.rs-rule');
      expect(await links.count(), `${key} rules listed`).toBeGreaterThanOrEqual(1);
      const prefix = `https://github.com/${pin.owner}/${pin.repo}/blob/${pin.sha}/`;
      for (const href of await links.evaluateAll(els => els.map(e => e.getAttribute('href') ?? ''))) {
        expect(href.startsWith(prefix), `${key}: ${href} starts with ${prefix}`).toBe(true);
        expect(href.slice(prefix.length), `${key}: ${href} names a file`).not.toBe('');
        expect(href, `${key}: ${href} has no raw space`).not.toContain(' ');
      }
      expect((await links.first().innerText()).trim(), `${key} first rule name`).not.toBe('');
      await expect(block.locator('[data-testid="rule-source-provenance"]'))
        .toContainText(`${pin.owner}/${pin.repo}@${pin.sha.slice(0, 7)}`);
      await expect(block.locator('[data-testid="rule-source-provenance"]')).toContainText(`snapshot ${SNAPSHOT.generated}`);
    }

    // The section's own words stay on the reference rung (journey 4's list, open section included).
    const sectionText = await page.locator('[data-testid="rule-sources"]').innerText();
    expect(sectionText).toContain('reference data');
    for (const word of loadSampleOrg().honesty.forbiddenStrings) {
      const re = new RegExp(`\\b${word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i');
      expect(sectionText, `'${word}' in the Rule sources section`).not.toMatch(re);
    }

    // Opening the drawer and the section asked for nothing: the one start-up read is shared.
    expect(snapshotRequests).toHaveLength(1);

    // No Sentinel anywhere in the DOM, the jump index open included.
    await page.locator('.jump-index-toggle').click();
    await expect(page.locator('.jump-chip', { hasText: 'Rule sources' })).toBeVisible();
    await expect(page.locator('#sb-sec-sentinel-rules')).toHaveCount(0);
    const html = await page.evaluate(() => document.documentElement.outerHTML);
    expect(html).not.toMatch(/sentinel/i);
  });
});
