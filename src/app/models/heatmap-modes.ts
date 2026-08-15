// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { HeatmapMode } from '../services/filter.service';

export interface HeatmapModeDef {
  value: HeatmapMode;
  /** Menu label. */
  label: string;
  /** Short name for the trigger button (replaces the old 27-branch ternary). */
  short: string;
  group: 'Coverage & Posture' | 'Threat Landscape' | 'Vulnerabilities' | 'Detections' | 'Frameworks';
}

/**
 * Single source of truth for every heatmap mode. The heatmap dropdown, the
 * trigger-button label, and mode cycling all read from this list — adding a
 * mode here is the only edit needed.
 */
export const HEATMAP_MODES: readonly HeatmapModeDef[] = [
  // Coverage & Posture
  { value: 'coverage',  label: '🛡 Coverage',       short: 'Coverage',    group: 'Coverage & Posture' },
  { value: 'status',    label: '✅ Status',          short: 'Status',      group: 'Coverage & Posture' },
  { value: 'controls',  label: '🔒 Controls',        short: 'Controls',    group: 'Coverage & Posture' },
  { value: 'unified',   label: '🎯 Unified Risk',    short: 'Unified',     group: 'Coverage & Posture' },
  { value: 'frequency', label: '📊 Frequency',       short: 'Frequency',   group: 'Coverage & Posture' },

  // Threat Landscape
  { value: 'risk',         label: '🔥 Risk',          short: 'Risk',         group: 'Threat Landscape' },
  { value: 'exposure',     label: '☢ Exposure',      short: 'Exposure',     group: 'Threat Landscape' },
  { value: 'software',     label: '💾 Software',      short: 'Software',     group: 'Threat Landscape' },
  { value: 'campaign',     label: '🎯 Campaign',      short: 'Campaign',     group: 'Threat Landscape' },
  { value: 'intelligence', label: '🧠 Intelligence',  short: 'Intelligence', group: 'Threat Landscape' },
  { value: 'my-exposure',  label: '🎯 My Exposure',   short: 'My Exposure',  group: 'Threat Landscape' },

  // Vulnerabilities
  { value: 'kev',          label: '🚨 KEV',            short: 'KEV',        group: 'Vulnerabilities' },
  { value: 'cve',          label: '🔴 CVE',            short: 'CVE',        group: 'Vulnerabilities' },
  { value: 'epss',         label: '🎯 EPSS Prob.',     short: 'EPSS',       group: 'Vulnerabilities' },
  { value: 'kill-chain',   label: '🔗 CVE Kill Chain', short: 'Kill Chain', group: 'Vulnerabilities' },
  { value: 'poc-exploits', label: '💣 PoC Exploits',   short: 'PoC',        group: 'Vulnerabilities' },

  // Detections
  { value: 'detection', label: '🔍 Detection',         short: 'Detection', group: 'Detections' },
  { value: 'sigma',     label: 'Σ Sigma Rules',        short: 'Sigma',     group: 'Detections' },
  { value: 'elastic',   label: '🟢 Elastic Rules',     short: 'Elastic',   group: 'Detections' },
  { value: 'splunk',    label: '🟠 Splunk Detections', short: 'Splunk',    group: 'Detections' },
  { value: 'wazuh',     label: '🔵 Wazuh XDR',         short: 'Wazuh',     group: 'Detections' },
  { value: 'm365',      label: '🔷 M365 Defender',     short: 'M365',      group: 'Detections' },
  { value: 'car',       label: '🔬 CAR',               short: 'CAR',       group: 'Detections' },
  { value: 'atomic',    label: '⚛ Atomic',            short: 'Atomic',    group: 'Detections' },

  // Frameworks
  { value: 'd3fend',        label: '🛡 D3FEND',        short: 'D3FEND',    group: 'Frameworks' },
  { value: 'engage',        label: '🎭 Engage',        short: 'Engage',    group: 'Frameworks' },
  { value: 'nist',          label: '🏛 NIST 800-53',   short: 'NIST',      group: 'Frameworks' },
  { value: 'veris',         label: '📋 VERIS Actions', short: 'VERIS',     group: 'Frameworks' },
  { value: 'cri',           label: '🏦 CRI Profile',   short: 'CRI',       group: 'Frameworks' },
  { value: 'csa-ccm',       label: '☁ CSA CCM',       short: 'CSA CCM',   group: 'Frameworks' },
  { value: 'm365-controls', label: '🔷 M365 Controls', short: 'M365 Ctl',  group: 'Frameworks' },
] as const;

export const HEATMAP_GROUPS = ['Coverage & Posture', 'Threat Landscape', 'Vulnerabilities', 'Detections', 'Frameworks'] as const;

export function heatmapShortLabel(mode: HeatmapMode): string {
  return HEATMAP_MODES.find(m => m.value === mode)?.short ?? mode;
}

export function nextHeatmapMode(mode: HeatmapMode): HeatmapMode {
  const values = HEATMAP_MODES.map(m => m.value);
  return values[(values.indexOf(mode) + 1) % values.length];
}
