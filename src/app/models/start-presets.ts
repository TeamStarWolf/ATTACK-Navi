// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import type { HeatmapMode } from '../services/filter.service';

/**
 * A role-based start preset: an opinionated on-ramp that answers the critique's
 * "no opinionated path" by taking a first-time user straight to the workspace
 * their role lives in, with the matrix lens their role reads most pre-selected.
 * It changes nothing about the data — it only picks an existing lens
 * (FilterService.setHeatmapMode) and opens an existing workspace
 * (PanelNavService / PANEL_ROUTE_MAP), both of which the user can change at any
 * time. See StartPresetService.apply.
 */
export interface StartPreset {
  /** Stable id; the palette action is `start:<id>`. */
  id: string;
  /** Role name shown on the card / palette action. */
  label: string;
  /** Emoji shown on the card (no icon-registry entry needed). */
  icon: string;
  /** One line: the lens it picks and where it lands. */
  blurb: string;
  /** The matrix lens to select — a registered HeatmapMode. */
  heat: HeatmapMode;
  /** The workspace to open — a key of PANEL_ROUTE_MAP. */
  panel: string;
}

/**
 * The role presets. Each pairs a DISTINCT lens with the workspace that role
 * works in, so the starting view is genuinely different per role rather than
 * cosmetic. Keep this list short and differentiated; it is not a catalog of
 * every lens. The spec checks every `heat` is a real lens and every `panel` a
 * real route, so a typo fails the build rather than silently no-op'ing.
 */
export const START_PRESETS: readonly StartPreset[] = [
  {
    id: 'detection-engineer',
    label: 'Detection Engineer',
    icon: '\u{1F50D}',
    blurb: 'Detection-content lens, opened to the Detect workspace.',
    heat: 'detection',
    panel: 'detection',
  },
  {
    id: 'threat-intel-analyst',
    label: 'Threat Intel Analyst',
    icon: '\u{1F6F0}',
    blurb: 'Threat-intelligence lens, opened to Threat Groups.',
    heat: 'intelligence',
    panel: 'threats',
  },
  {
    id: 'vulnerability-manager',
    label: 'Vulnerability Manager',
    icon: '\u{1F534}',
    blurb: 'Known-Exploited-Vulnerabilities lens, opened to the CVE Explorer.',
    heat: 'kev',
    panel: 'cve',
  },
  {
    id: 'red-teamer',
    label: 'Red Teamer',
    icon: '\u{2694}',
    blurb: 'Technique-frequency lens, opened to Emulation Plans.',
    heat: 'frequency',
    panel: 'emulation',
  },
] as const;

/** The preset with this id, or undefined. */
export function startPresetById(id: string): StartPreset | undefined {
  return START_PRESETS.find((p) => p.id === id);
}
