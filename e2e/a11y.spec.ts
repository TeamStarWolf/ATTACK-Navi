// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Accessibility baseline (plan epic E0.3): axe-core on every current route, in
// REPORT-ONLY mode.
//
// Each route is loaded in the shared fixture workspace and scanned with the
// WCAG 2.x A/AA rule sets. A violation never fails the run; each test records
// its counts as an annotation (with the delta against the committed baseline)
// and attaches the full axe result. The baseline lives in
// docs/A11Y_BASELINE.json and is rewritten only on request:
//
//   A11Y_UPDATE_BASELINE=1 npx playwright test e2e/a11y.spec.ts
//
// Journey 6 (P8) turns this into a gate: 0 serious and 0 critical on every
// route. Until then the baseline is the yardstick a change is measured by.
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import AxeBuilder from '@axe-core/playwright';
import { test, expect, BASE, ROUTE_TIMEOUT } from './fixtures/workspace';
import { CURRENT_ROUTES } from './fixtures/workspace/routes';

const BASELINE_FILE = 'docs/A11Y_BASELINE.json';
const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'];
const IMPACTS = ['critical', 'serious', 'moderate', 'minor'] as const;
type Impact = (typeof IMPACTS)[number];

interface RouteCounts {
  /** Failing DOM nodes per impact level. */
  nodes: Record<Impact, number>;
  /** Failing rules, with their impact and node count. */
  rules: Record<string, { impact: Impact; nodes: number }>;
}

interface Baseline {
  description: string;
  mode: 'report-only';
  axeVersion: string;
  tags: string[];
  workspace: string;
  totals: { routes: number; rules: number; nodes: Record<Impact, number> };
  routes: Record<string, RouteCounts>;
}

function readBaseline(): Baseline | null {
  if (!existsSync(BASELINE_FILE)) return null;
  return JSON.parse(readFileSync(BASELINE_FILE, 'utf8')) as Baseline;
}

const zero = (): Record<Impact, number> => ({ critical: 0, serious: 0, moderate: 0, minor: 0 });

const UPDATE = process.env['A11Y_UPDATE_BASELINE'] === '1';

// Results gathered by this worker, written out by afterAll when updating the
// baseline. An update runs the routes in order in one worker so afterAll sees
// them all (if a failure restarts the worker, the new worker's afterAll merges
// the rest). A normal run only reports, so its routes spread across workers.
const measured = new Map<string, RouteCounts>();
let axeVersion = '';

test.describe('accessibility baseline (axe, report-only)', () => {
  // axe over a large DOM is CPU-bound; with many local workers it needs more than
  // the default 30 s (CI already allows 120 s per test).
  test.describe.configure({ mode: UPDATE ? 'default' : 'parallel', timeout: process.env['CI'] ? 120000 : 60000 });

  for (const { path, host } of CURRENT_ROUTES) {
    test(`axe #${path}`, async ({ page }, testInfo) => {
      await page.goto(`${BASE}/#${path}`);
      await expect(page.locator(`${host} > *`).first()).toBeVisible({ timeout: ROUTE_TIMEOUT });
      // Let late chips, badges and lazy sections settle before scanning. All
      // off-origin requests are aborted, so the network goes idle quickly.
      await page.waitForLoadState('networkidle', { timeout: 10000 }).catch(() => undefined);

      const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
      axeVersion = results.testEngine.version;

      const counts: RouteCounts = { nodes: zero(), rules: {} };
      for (const v of results.violations) {
        const impact = (v.impact ?? 'minor') as Impact;
        counts.nodes[impact] += v.nodes.length;
        counts.rules[v.id] = { impact, nodes: v.nodes.length };
      }
      measured.set(path, counts);

      const before = readBaseline()?.routes[path];
      const summary = IMPACTS.map(i => {
        const delta = before ? counts.nodes[i] - before.nodes[i] : 0;
        return `${i} ${counts.nodes[i]}${before && delta !== 0 ? ` (${delta > 0 ? '+' : ''}${delta})` : ''}`;
      }).join(', ');
      testInfo.annotations.push({ type: 'axe', description: before ? summary : `${summary} (no baseline)` });
      await testInfo.attach('axe-violations.json', {
        body: JSON.stringify(results.violations, null, 2),
        contentType: 'application/json',
      });
    });
  }

  test.afterAll(() => {
    if (!UPDATE || measured.size === 0) return;
    const previous = readBaseline();
    const merged: Record<string, RouteCounts> = { ...(previous?.routes ?? {}) };
    for (const [path, counts] of measured) merged[path] = counts;

    // Keep only current routes, in route-table order, so the file diffs cleanly.
    const routes: Record<string, RouteCounts> = {};
    const totals = { routes: 0, rules: 0, nodes: zero() };
    const ruleIds = new Set<string>();
    for (const { path } of CURRENT_ROUTES) {
      const c = merged[path];
      if (!c) continue;
      const sortedRules: RouteCounts['rules'] = {};
      for (const id of Object.keys(c.rules).sort()) {
        sortedRules[id] = c.rules[id];
        ruleIds.add(id);
      }
      routes[path] = { nodes: c.nodes, rules: sortedRules };
      totals.routes += 1;
      for (const i of IMPACTS) totals.nodes[i] += c.nodes[i];
    }
    totals.rules = ruleIds.size;

    const baseline: Baseline = {
      description:
        'axe-core violation counts per route, report-only (plan epic E0.3). Regenerate with ' +
        'A11Y_UPDATE_BASELINE=1 npx playwright test e2e/a11y.spec.ts. Journey 6 (P8) requires ' +
        '0 serious and 0 critical on every route.',
      mode: 'report-only',
      axeVersion: axeVersion || previous?.axeVersion || '',
      tags: TAGS,
      workspace: 'e2e/fixtures/workspace (hermetic, onboarding skipped, empty user state)',
      totals,
      routes,
    };
    writeFileSync(BASELINE_FILE, JSON.stringify(baseline, null, 2) + '\n');
  });
});
