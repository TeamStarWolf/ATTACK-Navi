// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Routes } from '@angular/router';
import { routes } from './app.routes';
import ROUTE_TABLE from './testing/route-table.json';

/** One route as the router sees it, with every workspace route file's children resolved. */
export interface RouteTableRow {
  path: string;
  kind: 'loadComponent' | 'loadChildren' | 'component' | 'redirect' | 'children';
  pathMatch: string | null;
  redirectTo: string | null;
  guards: string[];
  data: Record<string, unknown> | null;
  title: string | null;
}

const GUARD_KEYS = ['canActivate', 'canActivateChild', 'canDeactivate', 'canMatch', 'resolve'] as const;

/**
 * Flatten the route tree in declaration order. A loadChildren route is followed
 * by loading its route file, so the workspace tabs and their default-tab
 * redirects are part of the table, not only the top level.
 */
export async function flattenRoutes(list: Routes, prefix = ''): Promise<RouteTableRow[]> {
  const out: RouteTableRow[] = [];
  for (const r of list) {
    const path = [prefix, r.path ?? ''].filter(Boolean).join('/');
    const kind: RouteTableRow['kind'] = r.loadComponent ? 'loadComponent'
      : r.loadChildren ? 'loadChildren'
      : r.component ? 'component'
      : r.redirectTo !== undefined ? 'redirect'
      : 'children';
    out.push({
      path: `/${path}`,
      kind,
      pathMatch: r.pathMatch ?? null,
      redirectTo: typeof r.redirectTo === 'string' ? r.redirectTo : r.redirectTo === undefined ? null : 'function',
      guards: GUARD_KEYS.filter(k => r[k] !== undefined),
      data: r.data ? { ...r.data } : null,
      title: typeof r.title === 'string' ? r.title : null,
    });
    if (r.children) out.push(...await flattenRoutes(r.children, path));
    if (r.loadChildren) {
      const loaded = await r.loadChildren();
      if (!Array.isArray(loaded)) throw new Error(`loadChildren of /${path} did not resolve to a Routes array`);
      out.push(...await flattenRoutes(loaded as Routes, path));
    }
  }
  return out;
}

describe('app routes: unchanged by the bundle-budget work', () => {
  // route-table.json was generated from origin/main before the bundle trims
  // (it records its commit). Every path, redirect, pathMatch, loader kind,
  // guard and data entry must match it row for row, in order.
  it('every route path, redirect and loader equals the table committed from main', async () => {
    const rows = await flattenRoutes(routes);
    expect(rows.length).toBe(ROUTE_TABLE.routes.length);
    expect(rows).toEqual(ROUTE_TABLE.routes as RouteTableRow[]);
  });

  it('has no route guards (the table would record them if one were added)', async () => {
    const rows = await flattenRoutes(routes);
    expect(rows.filter(r => r.guards.length)).toEqual([]);
  });

  it('keeps the empty-path, default-tab and wildcard redirects', async () => {
    const redirects = (await flattenRoutes(routes)).filter(r => r.kind === 'redirect').map(r => `${r.path} -> ${r.redirectTo}`);
    expect(redirects).toEqual([
      '/ -> matrix',
      '/detect -> detections',
      '/exposure -> cve',
      '/dashboard -> overview',
      '/intel -> groups',
      '/coverage -> assessment',
      '/library -> workbench',
      '/reports -> builder',
      '/settings -> preferences',
      '/** -> matrix',
    ]);
  });
});
