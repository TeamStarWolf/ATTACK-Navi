// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License

export interface NavCommand {
  /** Legacy panel id — resolved to a route via PANEL_ROUTE_MAP / PanelNavService. */
  panelId: string;
  label: string;
  /** Workspace shown as the result description. */
  workspace: string;
  /** Extra search terms (old names, synonyms). */
  keywords?: string;
}

/**
 * "Go to …" commands for the palette — one per destination, searchable by
 * current label, workspace, and the pre-overhaul names users may remember.
 */
export const NAV_COMMANDS: readonly NavCommand[] = [
  { panelId: 'matrix', label: 'Matrix', workspace: 'Home', keywords: 'grid techniques home' },

  { panelId: 'dashboard', label: 'Dashboard', workspace: 'Dashboard', keywords: 'overview stats' },
  { panelId: 'analytics', label: 'Analytics', workspace: 'Dashboard', keywords: 'charts trends' },

  { panelId: 'threats', label: 'Threat Groups', workspace: 'Intel', keywords: 'apt actors adversaries' },
  { panelId: 'actor', label: 'Actor Profiles', workspace: 'Intel', keywords: 'apt group profile' },
  { panelId: 'actor-compare', label: 'Actor Comparison', workspace: 'Intel', keywords: 'actor vs versus' },
  { panelId: 'scenario', label: 'Scenarios', workspace: 'Intel', keywords: 'attack scenario builder' },
  { panelId: 'emulation', label: 'Emulation Plans', workspace: 'Intel', keywords: 'adversary emulation red team' },
  { panelId: 'campaign-timeline', label: 'Campaigns', workspace: 'Intel', keywords: 'campaign timeline' },
  { panelId: 'software', label: 'Software & Malware', workspace: 'Intel', keywords: 'tools malware' },
  { panelId: 'intelligence', label: 'Intel Feeds', workspace: 'Intel', keywords: 'misp opencti tip threat intelligence' },

  { panelId: 'detection', label: 'Detections', workspace: 'Detect', keywords: 'detection coverage rules' },
  { panelId: 'sigma', label: 'Sigma Rules', workspace: 'Detect', keywords: 'sigma export' },
  { panelId: 'siem', label: 'SIEM Export', workspace: 'Detect', keywords: 'splunk elastic sentinel queries' },
  { panelId: 'yara', label: 'YARA Rules', workspace: 'Detect', keywords: 'yara export' },
  { panelId: 'validation', label: 'Detection Validation', workspace: 'Detect', keywords: 'validate purple team workbench' },
  { panelId: 'datasources', label: 'Data Sources', workspace: 'Detect', keywords: 'telemetry logs sources' },
  { panelId: 'purple', label: 'Purple Team', workspace: 'Detect', keywords: 'atomic red purple' },

  { panelId: 'cve', label: 'CVE Explorer', workspace: 'Exposure', keywords: 'vulnerabilities kev nvd' },
  { panelId: 'risk-matrix', label: 'Risk Matrix', workspace: 'Exposure', keywords: 'risk quadrant' },
  { panelId: 'killchain', label: 'Kill Chain', workspace: 'Exposure', keywords: 'kill chain phases' },
  { panelId: 'technique-graph', label: 'Technique Graph', workspace: 'Exposure', keywords: 'graph relationships network' },
  { panelId: 'gap-analysis', label: 'Gap Analysis', workspace: 'Exposure', keywords: 'gap report gaps uncovered' },
  { panelId: 'priority', label: 'Priority Mitigations', workspace: 'Exposure', keywords: 'ranked priorities' },
  { panelId: 'whatif', label: 'What-If Simulator', workspace: 'Exposure', keywords: 'simulate coverage' },
  { panelId: 'ctem', label: 'CTEM Program Board', workspace: 'Exposure', keywords: 'continuous threat exposure management gartner stages' },

  { panelId: 'assessment', label: 'Assessment Wizard', workspace: 'Coverage', keywords: 'assess maturity wizard' },
  { panelId: 'controls', label: 'Security Controls', workspace: 'Coverage', keywords: 'nist cis controls' },
  { panelId: 'custom-mit', label: 'Custom Mitigations', workspace: 'Coverage', keywords: 'custom mitigation' },
  { panelId: 'compliance', label: 'Compliance Frameworks', workspace: 'Coverage', keywords: 'soc2 iso pci comply' },
  { panelId: 'coverage-diff', label: 'Coverage Diff', workspace: 'Coverage', keywords: 'diff compare snapshots' },
  { panelId: 'timeline', label: 'Coverage Timeline', workspace: 'Coverage', keywords: 'snapshots history' },
  { panelId: 'target', label: 'Coverage Target', workspace: 'Coverage', keywords: 'target calculator goal' },
  { panelId: 'assets', label: 'Asset Inventory', workspace: 'Coverage', keywords: 'assets exposure hosts' },

  { panelId: 'library', label: 'Library Workbench', workspace: 'Library', keywords: 'tools channels index vendors' },
  { panelId: 'layers', label: 'Saved Layers', workspace: 'Library', keywords: 'layers snapshots' },
  { panelId: 'collection', label: 'Collections', workspace: 'Library', keywords: 'stix collection import export' },
  { panelId: 'comparison', label: 'Group Comparison', workspace: 'Library', keywords: 'compare groups overlap' },
  { panelId: 'roadmap', label: 'Remediation Roadmap', workspace: 'Library', keywords: 'roadmap plan phases' },
  { panelId: 'watchlist', label: 'Watchlist', workspace: 'Library', keywords: 'watch bookmarks starred' },
  { panelId: 'tags', label: 'Tag Manager', workspace: 'Library', keywords: 'tags labels' },

  { panelId: 'report', label: 'Report Builder', workspace: 'Reports', keywords: 'coverage report print' },
  { panelId: 'ir-playbook', label: 'IR Playbooks', workspace: 'Reports', keywords: 'incident response playbook' },
  { panelId: 'exports', label: 'Export Hub', workspace: 'Reports', keywords: 'export import csv xlsx navigator layer png pdf' },

  { panelId: 'settings', label: 'Settings', workspace: 'Settings', keywords: 'preferences options weights integrations' },
  { panelId: 'changelog', label: 'ATT&CK Changelog', workspace: 'Settings', keywords: 'versions releases history' },
] as const;

export interface ActionCommand {
  id: string;
  label: string;
  description: string;
  keywords?: string;
}

/** "Do …" commands for the palette. Dispatched by UniversalSearchComponent. */
export const ACTION_COMMANDS: readonly ActionCommand[] = [
  { id: 'toggle-theme', label: 'Toggle light / dark theme', description: 'Switch the color scheme', keywords: 'dark light mode theme' },
  { id: 'clear-filters', label: 'Clear all filters', description: 'Reset every active matrix filter', keywords: 'reset clear' },
  { id: 'copy-share-link', label: 'Copy share link', description: 'Copy a link to the current view', keywords: 'share url clipboard' },
  { id: 'keyboard-help', label: 'Keyboard shortcuts', description: 'Show the shortcuts overlay', keywords: 'help hotkeys keys' },
  { id: 'export-csv', label: 'Export coverage CSV', description: 'Download the coverage table', keywords: 'export download csv' },
  { id: 'export-xlsx', label: 'Export Excel workbook', description: 'Download the multi-sheet XLSX', keywords: 'export excel xlsx' },
  { id: 'export-navigator', label: 'Export Navigator layer', description: 'Download an ATT&CK Navigator layer', keywords: 'navigator layer json' },
  { id: 'open-navigator', label: 'Open in ATT&CK Navigator', description: 'Launch the official Navigator with this layer', keywords: 'navigator mitre' },
] as const;
