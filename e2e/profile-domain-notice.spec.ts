// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// RP-F decision 6: a cross-domain threat profile says which of its groups the
// loaded domain lacks instead of silently narrowing. A {APT29, FIN7} profile
// chosen on gap analysis, then the toolbar switch to ICS (the app does not
// re-apply dom= on an in-session hash navigation, so the switch is the toolbar
// button): the drawer line and the picker header carry the same sentence, the
// stored profile still holds both groups, and Enterprise restores the plain line.
import { Page } from '@playwright/test';
import { test, expect, BASE, ROUTE_TIMEOUT } from './fixtures/workspace';

const KEY = 'navi.v2.threat-profile';
const NOTICE = '1 of 2 groups present in ICS: FIN7; APT29 has no ICS use';

/** The stored source's group ids (the domain switch must never change them). */
async function storedIds(page: Page): Promise<string[]> {
  return page.evaluate((key) => {
    const raw = localStorage.getItem(key);
    const rec = raw ? JSON.parse(raw).records?.[0] : null;
    return rec && rec.kind === 'groups' ? [...rec.ids].sort() : [];
  }, KEY);
}

/** Open the drawer on the first cell and return its threat-profile line. */
async function drawerProfileLine(page: Page) {
  await page.locator('.cell').first().click();
  await expect(page.locator('.sidebar.open')).toBeVisible({ timeout: ROUTE_TIMEOUT });
  return page.locator('.sidebar.open [data-testid="ev-threat-profile"]');
}

test.describe('cross-domain threat profile (RP-F decision 6)', () => {
  test('{APT29, FIN7} on ICS names APT29 as absent; storage keeps both; Enterprise restores the plain line', async ({ page }) => {
    await page.goto(`${BASE}/#/exposure/gap-analysis`);
    const picker = page.locator('app-gap-analysis-panel app-threat-profile-picker');
    await expect(picker).toBeVisible({ timeout: ROUTE_TIMEOUT });
    await picker.getByRole('tab', { name: 'Groups' }).click();
    for (const name of ['APT29', 'FIN7']) {
      await picker.getByLabel('Search groups').fill(name);
      await picker.locator('ul[aria-label="Groups"] .tpp-item')
        .filter({ has: page.locator('.tpp-item-name', { hasText: new RegExp(`^${name}$`) }) })
        .click();
    }
    await expect(picker.locator('ul[aria-label="Groups"] .tpp-item[aria-pressed="true"]')).toHaveCount(1);   // FIN7 (search still on it)
    const ids = await storedIds(page);
    expect(ids.length).toBe(2);
    await expect(picker.locator('[data-testid="profile-domain-notice"]')).toHaveCount(0);   // all present on Enterprise

    // The toolbar domain switch to ICS: the picker header names the absent group.
    await page.locator('.domain-btn[title="ICS ATT&CK"]').click();
    await expect(picker.locator('[data-testid="profile-domain-notice"]')).toHaveText(NOTICE, { timeout: ROUTE_TIMEOUT });
    const absent = picker.locator('[data-testid="profile-absent-groups"] .tpp-item');
    await expect(absent).toHaveCount(1);
    await expect(absent).toContainText('APT29');
    await expect(absent).toContainText('has no ICS use');
    await expect(absent).toHaveAttribute('aria-pressed', 'true');   // kept in the selection
    await expect(absent).toHaveCSS('opacity', '1');                  // marked by a dashed rail, never faded below AA contrast
    await expect(absent).toHaveCSS('border-left-style', 'dashed');
    expect(await storedIds(page)).toEqual(ids);

    // The drawer line carries the same sentence (in-session navigation keeps ICS loaded).
    await page.goto(`${BASE}/#/matrix`);
    await expect(page.locator('.tactic-header', { hasText: 'Inhibit Response Function' })).toHaveCount(1, { timeout: ROUTE_TIMEOUT });
    const icsLine = await drawerProfileLine(page);
    await expect(icsLine).toContainText(`Threat profile (${NOTICE})`);
    expect(await storedIds(page)).toEqual(ids);

    // Back to Enterprise: the plain 2-group line, no notice anywhere.
    await page.locator('.domain-btn[title="Enterprise ATT&CK"]').click();
    await expect(page.locator('.tactic-header', { hasText: 'Inhibit Response Function' })).toHaveCount(0, { timeout: ROUTE_TIMEOUT });
    await expect(page.locator('.cell').first()).toBeVisible({ timeout: ROUTE_TIMEOUT });
    const entLine = await drawerProfileLine(page);
    await expect(entLine).toContainText('Threat profile (2 groups)');
    await expect(entLine).not.toContainText('present in');
    expect(await storedIds(page)).toEqual(ids);

    await page.goto(`${BASE}/#/exposure/gap-analysis`);
    await expect(picker).toBeVisible({ timeout: ROUTE_TIMEOUT });
    await expect(picker.locator('[data-testid="profile-domain-notice"]')).toHaveCount(0);
    await expect(picker.locator('[data-testid="profile-absent-groups"]')).toHaveCount(0);
  });

  // RP-F decision 25: a FRESH BOOT into ICS or Mobile resolves stored ids against the
  // all-domain group index. Round 4 read "G0016: unknown or withdrawn group id" for APT29
  // on a pasted ICS link, and a different sentence after F5. Pasted links, then F5.
  for (const [dom, notice] of [
    ['ics', NOTICE],
    ['mobile', '0 of 2 groups present in Mobile; APT29, FIN7 have no Mobile use'],
  ] as const) {
    test(`a profile stored as ['G0016','G0046'] on a fresh boot into ${dom} names the absent groups, and reads the same after F5`, async ({ page }) => {
      await page.addInitScript((key) => {
        if (localStorage.getItem(key) !== null) return;
        localStorage.setItem(key, JSON.stringify({ schema: 2, tombstones: [], records: [{
          kind: 'groups', ids: ['G0016', ' G0046 ', ''], domain: 'enterprise', attackVersion: '19.2', source: 'manual',
          createdAt: '2026-10-21T00:00:00.000Z', updatedAt: '2026-10-21T00:00:00.000Z',
        }] }));
      }, KEY);
      await page.goto('about:blank');
      await page.goto(`${BASE}/#/matrix?dom=${dom}`);
      await expect(page.locator('.cell').first()).toBeVisible({ timeout: ROUTE_TIMEOUT });
      const line = await drawerProfileLine(page);
      await expect(line).toContainText(`Threat profile (${notice})`, { timeout: ROUTE_TIMEOUT });
      await expect(line).not.toContainText('unknown or withdrawn');
      expect((await storedIds(page)).every((id) => id.startsWith('intrusion-set--'))).toBe(true);
      await page.reload();
      await expect(page.locator('.cell').first()).toBeVisible({ timeout: ROUTE_TIMEOUT });
      const again = await drawerProfileLine(page);
      await expect(again).toContainText(`Threat profile (${notice})`, { timeout: ROUTE_TIMEOUT });
    });
  }
});
