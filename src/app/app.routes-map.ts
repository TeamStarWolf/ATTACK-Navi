// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License

/**
 * Maps legacy ActivePanel ids to router commands. Grows batch-by-batch as
 * panels convert from overlays to routed pages (P1b–P1d); ids absent here
 * still open as legacy overlays via FilterService. When all batches land,
 * every id maps and the ActivePanel machinery is deleted.
 */
export const PANEL_ROUTE_MAP: Readonly<Partial<Record<string, string[]>>> = {
  // P1a: the matrix is the home page (a nav "toggle" of any panel lands here).
  matrix: ['/matrix'],
  // P1b: Detection workspace
  detection: ['/detect', 'detections'],
  sigma: ['/detect', 'sigma'],
  siem: ['/detect', 'siem'],
  yara: ['/detect', 'yara'],
  validation: ['/detect', 'validation'],
  datasources: ['/detect', 'data-sources'],
  purple: ['/detect', 'purple-team'],
  // P1b: Exposure workspace
  cve: ['/exposure', 'cve'],
  'risk-matrix': ['/exposure', 'risk'],
  killchain: ['/exposure', 'kill-chain'],
  'technique-graph': ['/exposure', 'graph'],
  'gap-analysis': ['/exposure', 'gap-analysis'],
  priority: ['/exposure', 'priority'],
  whatif: ['/exposure', 'what-if'],
  // P1b: Dashboard workspace
  dashboard: ['/dashboard', 'overview'],
  analytics: ['/dashboard', 'analytics'],
};

export function routeForPanel(id: string): string[] | undefined {
  return PANEL_ROUTE_MAP[id];
}
