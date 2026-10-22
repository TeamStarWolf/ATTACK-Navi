// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The technique drawer looks the same in every section (owner request: "can all of
// the sidebar look uniform?"). The T1589 drawer (the owner's screenshot: Procedure
// Examples, CVE Exposure, Cloud & CIS Controls, VERIS, CAPEC ...) and the T1059.001
// drawer (Rule sources with rules, CVE capability groups) are opened from a fresh
// link at 1440x900, every section is expanded, and the computed styles are compared:
// every section header (its height too), every section card, every count pill, every
// row of each kind (its corners too), every row description, name, badge and plain
// text line, the Rule sources rules and the Detection Validation pill's parts must
// match the others. Run in both themes.
import type { Page } from '@playwright/test';
import { test, expect, BASE, ROUTE_TIMEOUT } from './fixtures/workspace';

const SCHEMES = ['dark', 'light'] as const;
const TECHNIQUES = ['T1589', 'T1059.001'] as const;

interface Audit {
  sections: string[];
  headers: Record<string, string[]>;
  cards: Record<string, string[]>;
  pills: Record<string, string[]>;
  rows: Record<string, Record<string, string[]>>;
  ids: Record<string, string[]>;
  more: Record<string, string[]>;
  descs: Record<string, string[]>;
  names: Record<string, string[]>;
  texts: Record<string, string[]>;
  badges: Record<string, string[]>;
  inlineBadges: string[];
  ruleRows: number;
  ruleRowsOnRoles: number;
}

/** Expand every collapsed section header (data that arrives late renders more of them). */
async function expandAll(page: Page): Promise<void> {
  for (let pass = 0; pass < 3; pass++) {
    const collapsed = page.locator('.sidebar [id^="sb-sec-"][aria-expanded="false"]');
    const n = await collapsed.count();
    if (n === 0 && pass > 0) break;
    for (let i = 0; i < n; i++) {
      const h = page.locator('.sidebar [id^="sb-sec-"][aria-expanded="false"]').first();
      if (!(await h.count())) break;
      await h.scrollIntoViewIfNeeded();
      await h.click();
    }
    await page.waitForTimeout(400);
  }
  await expect(page.locator('.sidebar [id^="sb-sec-"][aria-expanded="false"]')).toHaveCount(0);
  // Measure at rest: the pointer leaves the last header it clicked (no hover tint).
  await page.mouse.move(1, 1);
}

/** Group every element of a set by its computed-style key: one key means uniform. */
async function audit(page: Page): Promise<Audit> {
  return page.evaluate(() => {
    const css = (e: Element, props: string[]) => {
      const s = getComputedStyle(e);
      return props.map(p => `${p}=${s.getPropertyValue(p)}`).join('; ');
    };
    const group = (els: Element[], props: string[], name: (e: Element) => string) => {
      const out: Record<string, string[]> = {};
      for (const e of els) (out[css(e, props)] ??= []).push(name(e));
      return out;
    };
    const sidebar = document.querySelector('.sidebar')!;
    const sectionName = (e: Element) => {
      const card = e.closest('app-drawer-section');
      const h = card?.querySelector(':scope > .sb-head');
      return (h?.id || h?.querySelector('.sb-title')?.textContent || e.className || e.tagName).toString().trim();
    };
    const heads = [...sidebar.querySelectorAll('app-drawer-section > .sb-head')];
    const cards = [...sidebar.querySelectorAll('app-drawer-section, .evidence-card, .coverage-score-card')];
    const pills = [...sidebar.querySelectorAll('app-drawer-section > .sb-head .sb-count')];
    const rows: Record<string, Record<string, string[]>> = {};
    for (const kind of ['entity', 'detail', 'plain']) {
      rows[kind] = group([...sidebar.querySelectorAll(`app-drawer-row[data-row-kind="${kind}"]`)],
        ['padding-top', 'padding-right', 'padding-bottom', 'padding-left', 'min-height', 'font-family', 'font-size',
          'border-top-left-radius', 'border-bottom-left-radius'], sectionName);
    }
    // The Detection Validation pill is its own component inside a section card: its status line is an entity row.
    for (const r of sidebar.querySelectorAll('app-validation-status-pill .vsp > .vsp-row:not(.vsp-rules, .vsp-when)')) {
      const key = css(r, ['padding-top', 'padding-right', 'padding-bottom', 'padding-left', 'min-height', 'font-family', 'font-size',
        'border-top-left-radius', 'border-bottom-left-radius']);
      (rows['entity'][key] ??= []).push('Detection Validation');
    }
    const ruleRows = [...sidebar.querySelectorAll('[data-testid="rule-source"] a.rs-rule')];
    const badges = [...sidebar.querySelectorAll('app-drawer-section .sb-badge, app-validation-status-pill .vsp-status, app-validation-status-pill .vsp-lab')];
    return {
      sections: heads.map(h => h.id || (h.querySelector('.sb-title')?.textContent ?? '').trim()),
      headers: group(heads, ['font-family', 'font-size', 'font-weight', 'letter-spacing', 'text-transform', 'padding-top', 'padding-right',
        'padding-bottom', 'padding-left', 'border-bottom-width', 'border-bottom-style', 'background-color', 'color', 'min-height', 'height'], sectionName),
      cards: group(cards, ['border-top-width', 'border-right-width', 'border-bottom-width', 'border-left-width', 'border-top-style',
        'border-bottom-style', 'border-top-color', 'border-bottom-color', 'border-left-color', 'border-top-left-radius',
        'border-bottom-right-radius', 'padding-top', 'padding-right', 'padding-bottom', 'padding-left', 'background-color'],
        e => e.matches('app-drawer-section') ? sectionName(e) : e.className.toString()),
      pills: group(pills, ['font-size', 'font-weight', 'padding-top', 'padding-left', 'border-top-left-radius', 'border-top-width',
        'background-color', 'color', 'border-top-color'], sectionName),
      rows,
      ids: group([...sidebar.querySelectorAll('app-drawer-row .sb-id')], ['font-family', 'font-size', 'font-weight', 'padding-left',
        'border-top-left-radius', 'color', 'background-color'], sectionName),
      more: group([...sidebar.querySelectorAll('.show-more-btn')], ['font-family', 'font-size', 'padding-top', 'background-color',
        'border-top-width', 'color'], sectionName),
      descs: group([...sidebar.querySelectorAll('app-drawer-row .sb-desc, app-validation-status-pill .vsp-notes')], ['font-size', 'font-style',
        'font-weight', 'color', 'margin-top', 'padding-left', 'border-left-width', 'background-color'], sectionName),
      names: group([...sidebar.querySelectorAll('app-drawer-row .sb-name')], ['font-size', 'font-weight', 'color'], sectionName),
      texts: group([...sidebar.querySelectorAll('app-drawer-section .sb-text, app-validation-status-pill .vsp-empty, app-validation-status-pill .vsp-when')],
        ['font-size', 'font-style', 'color', 'margin-bottom', 'padding-left', 'background-color'], sectionName),
      badges: group(badges, ['font-size', 'font-weight', 'padding-top', 'padding-left', 'border-top-width', 'border-top-left-radius',
        'text-transform', 'letter-spacing'], sectionName),
      inlineBadges: badges.filter(b => b.hasAttribute('style')).map(b => `${sectionName(b)}: ${b.className}`),
      ruleRows: ruleRows.length,
      ruleRowsOnRoles: ruleRows.filter(a => a.matches('app-drawer-row[data-row-kind="entity"] .sb-name')).length,
    };
  });
}

/** One style key for the whole set; the message lists the odd ones out. */
function expectUniform(what: string, groups: Record<string, string[]>): void {
  const keys = Object.keys(groups);
  const detail = keys.map(k => `${groups[k].length} x {${k}}: ${groups[k].join(', ')}`).join('\n');
  expect(keys.length, `${what} are not uniform:\n${detail}`).toBeLessThanOrEqual(1);
}

test.describe('technique drawer: one section pattern and one row pattern', () => {
  for (const tech of TECHNIQUES) for (const scheme of SCHEMES) {
    test(`drawer uniformity audit (${scheme}): ${tech} at 1440x900, every section expanded`, async ({ page }) => {
      await page.setViewportSize({ width: 1440, height: 900 });
      await page.emulateMedia({ colorScheme: scheme });
      // A fresh navigation with tech= opens the drawer (an in-session hash change would not).
      await page.goto(`${BASE}/#/matrix?tech=${tech}`);
      await expect(page.locator('.sidebar.open')).toBeVisible({ timeout: ROUTE_TIMEOUT });
      await expect(page.locator('.sidebar-header .attack-id')).toHaveText(tech);
      await expect
        .poll(() => page.evaluate(() => document.body.classList.contains('light-mode')))
        .toBe(scheme === 'light');
      await page.waitForLoadState('networkidle', { timeout: 10000 }).catch(() => undefined);
      await expandAll(page);

      const a = await audit(page);
      // The owner's screenshot: these sections render, each as a card with the one header.
      for (const id of ['sb-sec-annotation', 'sb-sec-procedures', 'sb-sec-mitigations', 'sb-sec-rule-sources']) {
        expect(a.sections, `${id} renders`).toContain(id);
      }
      expect(a.sections, 'Detection Validation renders as a section card').toContain('Detection Validation');
      expect(a.sections.length).toBeGreaterThanOrEqual(10);
      expectUniform('section headers', a.headers);
      expectUniform('section cards', a.cards);
      expectUniform('count pills', a.pills);
      expectUniform('entity id chips', a.ids);
      expectUniform('show-more controls', a.more);
      for (const kind of Object.keys(a.rows)) expectUniform(`${kind} rows`, a.rows[kind]);
      expectUniform('row descriptions', a.descs);
      expectUniform('row names', a.names);
      expectUniform('plain text lines', a.texts);
      expectUniform('row badges', a.badges);
      expect(a.inlineBadges, 'badges with inline colours').toEqual([]);
      // Rule sources: every listed rule is an entity row's name.
      expect(a.ruleRowsOnRoles, 'Rule sources rules on the entity row').toBe(a.ruleRows);
      if (tech === 'T1059.001') expect(a.ruleRows, 'T1059.001 lists rules').toBeGreaterThan(0);
      expect(Object.values(a.rows['detail']).flat().length, 'detail rows (Procedure Examples)').toBeGreaterThan(0);
      // Every header and card style key is the canonical one.
      const head = Object.keys(a.headers)[0];
      expect(head).toContain('font-size=10px');
      expect(head).toContain('font-weight=700');
      expect(head).toContain('text-transform=uppercase');
      expect(head).toContain('height=24px');
      for (const kind of Object.keys(a.rows)) {
        for (const key of Object.keys(a.rows[kind])) expect(key, `${kind} row corners`).toContain('border-top-left-radius=0px');
      }
      expect(Object.keys(a.descs)[0]).toContain('font-style=normal');
      expect(Object.keys(a.texts)[0]).toContain('margin-bottom=8px');
      const card = Object.keys(a.cards)[0];
      expect(card).toContain('border-bottom-width=1px');
      expect(card).toContain('border-top-left-radius=12px');
      expect(card).toContain('padding-top=16px');
    });
  }
});
