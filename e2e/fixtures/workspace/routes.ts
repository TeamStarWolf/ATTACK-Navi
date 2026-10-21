// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The route table the redirect and accessibility specs iterate.
//
// CURRENT_ROUTES mirrors src/app/app.routes.ts and the per-workspace
// *.routes.ts files as they are today: one row per routable page, with the
// component host element that proves the page rendered. redirects.spec.ts
// checks every row (a passing baseline), and a11y.spec.ts runs axe on every
// row. When a route is added, renamed or removed in the app, this table is
// the one place to change.
//
// PLANNED_REDIRECTS is the old-to-new route map from the redesign plan
// (Appendix A). Its rows run as pending (fixme) tests until the phase that
// introduces the new routes turns them on.

export interface RouteRow {
  /** Hash path, without the leading `#`. */
  path: string;
  /** Selector of the routed component; its first child must render. */
  host: string;
}

export const CURRENT_ROUTES: readonly RouteRow[] = [
  { path: '/matrix', host: 'app-matrix-page' },
  { path: '/status', host: 'app-status-page' },

  { path: '/dashboard/overview', host: 'app-dashboard-panel' },
  { path: '/dashboard/analytics', host: 'app-analytics-panel' },

  { path: '/intel/groups', host: 'app-threat-panel' },
  { path: '/intel/actors', host: 'app-actor-profile-panel' },
  { path: '/intel/compare', host: 'app-actor-compare-panel' },
  { path: '/intel/scenarios', host: 'app-scenario-panel' },
  { path: '/intel/emulation', host: 'app-emulation-plan-panel' },
  { path: '/intel/campaigns', host: 'app-campaign-timeline-panel' },
  { path: '/intel/software', host: 'app-software-panel' },
  { path: '/intel/feeds', host: 'app-threat-intelligence-panel' },

  { path: '/detect/detections', host: 'app-detection-panel' },
  { path: '/detect/sigma', host: 'app-sigma-export' },
  { path: '/detect/siem', host: 'app-siem-export' },
  { path: '/detect/yara', host: 'app-yara-export' },
  { path: '/detect/validation', host: 'app-validation-panel' },
  { path: '/detect/data-sources', host: 'app-datasource-panel' },
  { path: '/detect/purple-team', host: 'app-purple-team-panel' },

  { path: '/exposure/cve', host: 'app-cve-panel' },
  { path: '/exposure/risk', host: 'app-risk-matrix-panel' },
  { path: '/exposure/kill-chain', host: 'app-killchain-panel' },
  { path: '/exposure/graph', host: 'app-technique-graph-panel' },
  { path: '/exposure/gap-analysis', host: 'app-gap-analysis-panel' },
  { path: '/exposure/priority', host: 'app-priority-panel' },
  { path: '/exposure/ssvc', host: 'app-ssvc-panel' },
  { path: '/exposure/dossier', host: 'app-dossier-panel' },
  { path: '/exposure/what-if', host: 'app-whatif-panel' },
  { path: '/exposure/ctem', host: 'app-ctem-page' },

  { path: '/coverage/assessment', host: 'app-assessment-wizard' },
  { path: '/coverage/controls', host: 'app-controls-panel' },
  { path: '/coverage/custom-mitigations', host: 'app-custom-mit-panel' },
  { path: '/coverage/compliance', host: 'app-compliance-panel' },
  { path: '/coverage/diff', host: 'app-coverage-diff-panel' },
  { path: '/coverage/timeline', host: 'app-timeline-panel' },
  { path: '/coverage/target', host: 'app-target-panel' },
  { path: '/coverage/assets', host: 'app-asset-panel' },

  { path: '/library/workbench', host: 'app-library-workbench' },
  { path: '/library/layers', host: 'app-layers-panel' },
  { path: '/library/collections', host: 'app-collection-panel' },
  { path: '/library/comparison', host: 'app-comparison-panel' },
  { path: '/library/roadmap', host: 'app-roadmap-panel' },
  { path: '/library/watchlist', host: 'app-watchlist-panel' },
  { path: '/library/tags', host: 'app-tags-panel' },

  { path: '/reports/builder', host: 'app-report-panel' },
  { path: '/reports/playbooks', host: 'app-ir-playbook-panel' },
  { path: '/reports/exports', host: 'app-export-hub' },

  { path: '/settings/preferences', host: 'app-settings-panel' },
  { path: '/settings/changelog', host: 'app-changelog-panel' },

  // A detail page (P2-18): the route is technique/:domain/:id; this row is its
  // example (redirects.spec.ts PARAM_EXAMPLES maps the parameterised path to it).
  { path: '/technique/enterprise/T1059.001', host: 'app-technique-page' },
];

export interface RedirectRow {
  /** Hash path entered, without the leading `#` (may carry a query). */
  from: string;
  /** Hash path the router must settle on, without the leading `#`. */
  to: string;
}

/**
 * Redirects the router performs today: the empty path, each workspace's
 * default tab and the wildcard. Part of the passing baseline.
 */
export const CURRENT_REDIRECTS: readonly RedirectRow[] = [
  { from: '/', to: '/matrix' },
  { from: '/dashboard', to: '/dashboard/overview' },
  { from: '/intel', to: '/intel/groups' },
  { from: '/detect', to: '/detect/detections' },
  { from: '/exposure', to: '/exposure/cve' },
  { from: '/coverage', to: '/coverage/assessment' },
  { from: '/library', to: '/library/workbench' },
  { from: '/reports', to: '/reports/builder' },
  { from: '/settings', to: '/settings/preferences' },
  { from: '/no-such-route', to: '/matrix' },
];

/** A row of the plan's old-to-new route map, transcribed as written. */
export interface PlannedRedirect {
  old: string;
  /** The plan's target, verbatim (some name a query view or a section). */
  planned: string;
  greenBy: string;
}

/**
 * The redesign's old-to-new route map (plan Appendix A). When the phase that
 * builds a target lands, its row moves into a concrete RedirectRow (or a
 * row-specific assertion) and its pending test turns on. Every current route
 * must end up covered here or in CURRENT_ROUTES, and every `?view=` must
 * survive the redirect (journey 5).
 */
export const PLANNED_REDIRECTS: readonly PlannedRedirect[] = [
  { old: '/matrix', planned: '/matrix (unchanged)', greenBy: 'P4' },
  { old: '/exposure/cve', planned: '/exposure/inbox (results open /cve/:id)', greenBy: 'P4' },
  { old: '/exposure/ssvc', planned: '/cve/:id (Decide, What sections)', greenBy: 'P5' },
  { old: '/exposure/dossier', planned: '/cve/:id (Decide, What sections)', greenBy: 'P5' },
  { old: '/exposure/priority', planned: '/exposure/plan?view=rank', greenBy: 'P4' },
  { old: '/coverage/target', planned: '/exposure/plan?view=target', greenBy: 'P4' },
  { old: '/library/roadmap', planned: '/exposure/plan?view=roadmap', greenBy: 'P4' },
  { old: '/exposure/what-if', planned: '/exposure/plan?view=simulate', greenBy: 'P4' },
  { old: '/exposure/risk', planned: '/exposure/plan?view=quadrant', greenBy: 'P4' },
  { old: '/exposure/ctem', planned: '/exposure/program (summary on /home)', greenBy: 'P4' },
  { old: '/coverage/assets', planned: '/exposure/assets', greenBy: 'P4' },
  { old: '/exposure/gap-analysis', planned: '/detect/gaps (and /matrix?overlay=gap)', greenBy: 'P4' },
  { old: '/exposure/kill-chain', planned: '/posture/trend (tactic rollup)', greenBy: 'P4' },
  { old: '/exposure/graph', planned: '/threats/graph', greenBy: 'P4' },
  { old: '/detect/detections', planned: '/detect/coverage', greenBy: 'P4' },
  { old: '/detect/purple-team', planned: '/detect/coverage', greenBy: 'P4' },
  { old: '/detect/sigma', planned: '/detect/content?format=sigma', greenBy: 'P4' },
  { old: '/detect/siem', planned: '/detect/content?format=siem', greenBy: 'P4' },
  { old: '/detect/yara', planned: '/detect/content?format=yara', greenBy: 'P4' },
  { old: '/detect/validation', planned: '/detect/validation', greenBy: 'P4' },
  { old: '/detect/data-sources', planned: '/detect/telemetry', greenBy: 'P4' },
  { old: '/intel/groups', planned: '/threats/actors (/actor/:id, ?compare=)', greenBy: 'P4' },
  { old: '/intel/actors', planned: '/threats/actors (/actor/:id, ?compare=)', greenBy: 'P4' },
  { old: '/intel/compare', planned: '/threats/actors (/actor/:id, ?compare=)', greenBy: 'P4' },
  { old: '/library/comparison', planned: '/threats/actors (/actor/:id, ?compare=)', greenBy: 'P4' },
  { old: '/intel/scenarios', planned: '/threats/emulate', greenBy: 'P4' },
  { old: '/intel/emulation', planned: '/threats/emulate', greenBy: 'P4' },
  { old: '/intel/campaigns', planned: '/threats/campaigns-software', greenBy: 'P4' },
  { old: '/intel/software', planned: '/threats/campaigns-software', greenBy: 'P4' },
  { old: '/intel/feeds', planned: '/threats/feeds', greenBy: 'P4' },
  { old: '/dashboard/overview', planned: '/home', greenBy: 'P4' },
  { old: '/dashboard/analytics', planned: '/posture/trend?view=analytics until P9, then /home', greenBy: 'P4' },
  { old: '/coverage/timeline', planned: '/posture/trend', greenBy: 'P4' },
  { old: '/coverage/diff', planned: '/posture/trend (?view=diff)', greenBy: 'P4' },
  { old: '/coverage/controls', planned: '/posture/stack', greenBy: 'P4' },
  { old: '/coverage/custom-mitigations', planned: '/posture/stack', greenBy: 'P4' },
  { old: '/coverage/assessment', planned: '/posture/compliance', greenBy: 'P4' },
  { old: '/coverage/compliance', planned: '/posture/compliance', greenBy: 'P4' },
  { old: '/library/workbench', planned: '/library/reference', greenBy: 'P4' },
  { old: '/library/layers', planned: '/library/layers', greenBy: 'P4' },
  { old: '/library/collections', planned: '/library/layers', greenBy: 'P4' },
  { old: '/library/watchlist', planned: '/library/mine', greenBy: 'P4' },
  { old: '/library/tags', planned: '/library/mine', greenBy: 'P4' },
  { old: '/reports/builder', planned: '/reports/builder', greenBy: 'P4' },
  { old: '/reports/playbooks', planned: '/reports/builder?template=ir (IR playbook template, and drawer Defend)', greenBy: 'P4' },
  { old: '/reports/exports', planned: '/reports/export', greenBy: 'P4' },
  { old: '/status', planned: '/settings/data', greenBy: 'P4' },
  { old: '/settings/preferences', planned: '/settings/preferences', greenBy: 'P4' },
  { old: '/settings/changelog', planned: '/settings/whats-new', greenBy: 'P4' },
  { old: '/technique/enterprise/T1059.001', planned: '/technique/enterprise/T1059.001 (unchanged: the detail page, P2-18)', greenBy: 'P4' },
];

/** Escape a hash path for use inside a RegExp. */
export const escapeRegExp = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Matches a page URL whose hash route is exactly `path` (query allowed). */
export const hashRoute = (path: string): RegExp => new RegExp(`#${escapeRegExp(path)}(\\?.*)?$`);
