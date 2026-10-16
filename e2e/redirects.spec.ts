// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Table-driven route and redirect spec (plan epic E0.3).
//
// Three tables from e2e/fixtures/workspace/routes.ts drive it:
//   - CURRENT_ROUTES: every routable page today must deep-link, keep its hash
//     and render its component. Passing baseline.
//   - CURRENT_REDIRECTS: the router's own redirects (empty path, workspace
//     default tabs, wildcard). Passing baseline.
//   - PLANNED_REDIRECTS: the redesign's old-to-new route map (plan Appendix A).
//     Pending until the IA move (E4.1) builds the targets; its acceptance is
//     "redirects.spec green for 47 tabs + 57 PANEL_ROUTE_MAP ids + every heat=".
//
// Adding a route or redirect is a one-line change to the table, not a new test.
import { readFileSync } from 'node:fs';
import { test, expect, BASE, ROUTE_TIMEOUT } from './fixtures/workspace';
import { CURRENT_ROUTES, CURRENT_REDIRECTS, PLANNED_REDIRECTS, hashRoute } from './fixtures/workspace/routes';

const hostFor = (path: string): string => {
  const row = CURRENT_ROUTES.find(r => r.path === path);
  if (!row) throw new Error(`redirect target ${path} is not in CURRENT_ROUTES`);
  return row.host;
};

/**
 * The routable pages declared in src/app: top-level `loadComponent` routes plus
 * every `loadComponent` child of each lazily loaded workspace route file.
 */
function declaredRoutes(): string[] {
  const top = readFileSync('src/app/app.routes.ts', 'utf8');
  const paths: string[] = [];
  for (const m of top.matchAll(/path:\s*'([\w-]+)',\s*loadComponent:/g)) paths.push(`/${m[1]}`);
  for (const m of top.matchAll(/path:\s*'([\w-]+)',\s*loadChildren:\s*\(\)\s*=>\s*import\('\.\/([^']+)'\)/g)) {
    const child = readFileSync(`src/app/${m[2]}.ts`, 'utf8');
    for (const c of child.matchAll(/path:\s*'([\w-]+)',\s*loadComponent:/g)) paths.push(`/${m[1]}/${c[1]}`);
  }
  return paths;
}

test.describe('routes: every current route deep-links and renders', () => {
  // The table must stay in step with the app: a route added, renamed or
  // removed in src/app without a matching table change fails here.
  test('the route table matches the routes declared in src/app', () => {
    const declared = declaredRoutes();
    expect(declared.length).toBeGreaterThan(0);
    expect([...declared].sort()).toEqual(CURRENT_ROUTES.map(r => r.path).sort());
  });

  for (const { path, host } of CURRENT_ROUTES) {
    test(`#${path} renders ${host}`, async ({ page }) => {
      await page.goto(`${BASE}/#${path}`);
      await expect(page.locator(`${host} > *`).first()).toBeVisible({ timeout: ROUTE_TIMEOUT });
      await expect(page).toHaveURL(hashRoute(path));
    });
  }
});

test.describe('redirects: current router redirects', () => {
  for (const { from, to } of CURRENT_REDIRECTS) {
    test(`#${from} redirects to #${to}`, async ({ page }) => {
      await page.goto(`${BASE}/#${from}`);
      await expect(page).toHaveURL(hashRoute(to), { timeout: ROUTE_TIMEOUT });
      await expect(page.locator(`${hostFor(to)} > *`).first()).toBeVisible({ timeout: ROUTE_TIMEOUT });
    });
  }

  test('a query on a current route survives the deep link', async ({ page }) => {
    await page.goto(`${BASE}/#/matrix?heat=kev`);
    await expect(page.locator('app-matrix-page > *').first()).toBeVisible({ timeout: ROUTE_TIMEOUT });
    await expect(page).toHaveURL(/#\/matrix\?(.*&)?heat=kev(&|$)/);
  });
});

test.describe('redirects: planned old-to-new map (plan Appendix A)', () => {
  for (const { old, planned, greenBy } of PLANNED_REDIRECTS) {
    test.fixme(
      `#${old} -> ${planned}`,
      { tag: '@redirect-planned', annotation: { type: 'green by', description: greenBy } },
      async () => {
        // When the target exists: goto `#${old}` (and `#${old}?view=x`), assert the
        // URL settles on the planned route, the target renders, and ?view= survives.
      },
    );
  }

  // The planned map must account for every route that exists today, so no
  // tab is orphaned by the IA move. Live now: it fails if a route is added to
  // the app without a decision about where it goes.
  test('every current route has a row in the planned map', () => {
    const mapped = new Set(PLANNED_REDIRECTS.map(r => r.old));
    expect(CURRENT_ROUTES.map(r => r.path).filter(p => !mapped.has(p))).toEqual([]);
  });
});
