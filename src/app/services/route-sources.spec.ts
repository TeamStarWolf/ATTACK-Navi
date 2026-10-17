// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Routes } from '@angular/router';
import { routes } from '../app.routes';
import { COVERAGE_ROUTES } from '../pages/coverage/coverage.routes';
import { DASHBOARD_ROUTES } from '../pages/dashboard/dashboard.routes';
import { DETECT_ROUTES } from '../pages/detect/detect.routes';
import { EXPOSURE_ROUTES } from '../pages/exposure/exposure.routes';
import { INTEL_ROUTES } from '../pages/intel/intel.routes';
import { LIBRARY_ROUTES } from '../pages/library/library.routes';
import { REPORTS_ROUTES } from '../pages/reports/reports.routes';
import { SETTINGS_ROUTES } from '../pages/settings/settings.routes';
import { SOURCE_DEFINITIONS } from './source-inventory';
import { ACTIVE_ATTACK, ATTACK_SOURCES, ROUTE_SOURCES, routePath, sourcesForRoute } from './route-sources';
import { AttackDomain } from './data.service';

const WORKSPACES: Record<string, Routes> = {
  coverage: COVERAGE_ROUTES,
  dashboard: DASHBOARD_ROUTES,
  detect: DETECT_ROUTES,
  exposure: EXPOSURE_ROUTES,
  intel: INTEL_ROUTES,
  library: LIBRARY_ROUTES,
  reports: REPORTS_ROUTES,
  settings: SETTINGS_ROUTES,
};

/** Every routable page path in the app (top-level pages and each workspace tab). */
function appPaths(): string[] {
  const paths: string[] = [];
  for (const r of routes) {
    if (!r.path || r.path === '**' || r.redirectTo) continue;
    if (r.loadComponent) paths.push(`/${r.path}`);
    const children = WORKSPACES[r.path]?.[0]?.children ?? [];
    for (const c of children) if (c.path && !c.redirectTo) paths.push(`/${r.path}/${c.path}`);
  }
  return paths;
}

const DOMAINS: AttackDomain[] = ['enterprise', 'ics', 'mobile', 'f3'];

describe('route-sources: which sources each view banner watches (E1.3)', () => {
  it('lists only routes that exist (no route was renamed or added for this)', () => {
    const real = new Set(appPaths());
    expect(real.size).toBeGreaterThan(40);
    expect(Object.keys(ROUTE_SOURCES).filter(p => !real.has(p))).toEqual([]);
  });

  it('names only sources in the inventory', () => {
    const ids = new Set(SOURCE_DEFINITIONS.map(d => d.id));
    const listed = Object.values(ROUTE_SOURCES).flat().filter(id => id !== ACTIVE_ATTACK);
    const attack = Object.values(ATTACK_SOURCES).flat();
    expect([...listed, ...attack].filter(id => !ids.has(id))).toEqual([]);
  });

  it('gives every live source at least one dependent route, so its failure shows up on a view', () => {
    const watched = new Set<string>();
    for (const path of Object.keys(ROUTE_SOURCES)) {
      for (const domain of DOMAINS) for (const id of sourcesForRoute(path, domain)) watched.add(id);
    }
    const live = SOURCE_DEFINITIONS.filter(d => d.kind === 'live').map(d => d.id);
    expect(live.filter(id => !watched.has(id))).toEqual([]);
  });

  it('resolves the matrix\'s ATT&CK sources to the active domain only', () => {
    const ics = sourcesForRoute('/matrix', 'ics');
    expect(ics).toContain('attack-ics');
    expect(ics).toContain('attack-live-ics');
    expect(ics).not.toContain('attack-enterprise');
    expect(ics).not.toContain(ACTIVE_ATTACK);
  });

  it('reads the route from a URL with a query string, and treats the empty path as the matrix', () => {
    expect(routePath('/exposure/cve?heat=risk&tech=T1059')).toBe('/exposure/cve');
    expect(routePath('/')).toBe('/matrix');
    expect(routePath('')).toBe('/matrix');
    expect(sourcesForRoute('/settings/changelog?x=1', 'enterprise')).toEqual(['attack-releases']);
    expect(sourcesForRoute('/status', 'enterprise')).toEqual([]);
  });
});
