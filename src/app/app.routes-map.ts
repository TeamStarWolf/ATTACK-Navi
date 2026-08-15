// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License

/**
 * Maps legacy panel ids to router commands. Every destination the old
 * ActivePanel overlay system knew is a routed page now; PanelNavService
 * resolves ids through this map (unknown ids are ignored).
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
  // P1c: Threat Intel workspace
  threats: ['/intel', 'groups'],
  actor: ['/intel', 'actors'],
  'actor-compare': ['/intel', 'compare'],
  scenario: ['/intel', 'scenarios'],
  emulation: ['/intel', 'emulation'],
  'campaign-timeline': ['/intel', 'campaigns'],
  software: ['/intel', 'software'],
  intelligence: ['/intel', 'feeds'],
  // P1c: Coverage workspace
  assessment: ['/coverage', 'assessment'],
  controls: ['/coverage', 'controls'],
  'custom-mit': ['/coverage', 'custom-mitigations'],
  compliance: ['/coverage', 'compliance'],
  'coverage-diff': ['/coverage', 'diff'],
  timeline: ['/coverage', 'timeline'],
  target: ['/coverage', 'target'],
  assets: ['/coverage', 'assets'],
  // P1d: Library workspace
  library: ['/library', 'workbench'],
  layers: ['/library', 'layers'],
  collection: ['/library', 'collections'],
  comparison: ['/library', 'comparison'],
  roadmap: ['/library', 'roadmap'],
  watchlist: ['/library', 'watchlist'],
  tags: ['/library', 'tags'],
  // P1d: Reports workspace
  report: ['/reports', 'builder'],
  'ir-playbook': ['/reports', 'playbooks'],
  // P1d: Settings workspace
  settings: ['/settings', 'preferences'],
  changelog: ['/settings', 'changelog'],
};

export function routeForPanel(id: string): string[] | undefined {
  return PANEL_ROUTE_MAP[id];
}
