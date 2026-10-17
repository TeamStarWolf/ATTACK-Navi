// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
// Type-only: FilterService imports HEATMAP_MODES from here to validate URL params,
// so this must not become a runtime import cycle. lens-sources.ts has no
// runtime imports of its own, so the one runtime import below is cycle-free.
import type { HeatmapMode } from '../services/filter.service';
import type { AttackDomain } from '../services/data.service';
import { LENS_SOURCES, domainLabel, type LensSourceId } from './lens-sources';

/**
 * The rung or dimension a lens's numbers belong to (product plan 4.1).
 * Known, Covered and Proven are the posture rungs; Threat (how much
 * adversaries care) and Exposure (reachable in your estate) are separate
 * dimensions that are never posture rungs, so they are named as such here
 * rather than being forced onto a rung.
 */
export type LensRung = 'Known' | 'Covered' | 'Proven' | 'Threat' | 'Exposure';

/** The qualifier a Covered lens always carries (4.1). */
export type CoveredQualifier = 'self-attested' | 'range';

/**
 * How the cell renderer maps a score onto the ramp's stops:
 * - absolute: the score indexes the stops directly (last stop = that count or more);
 * - relative: 0 takes the first stop, other scores are shaded by their share of
 *   the highest score in the loaded domain (quartiles);
 * - threshold: fixed numeric bands, as labelled;
 * - categorical: one colour per state.
 */
export type LensScale = 'absolute' | 'relative' | 'threshold' | 'categorical';

export interface LensRampStop {
  readonly color: string;
  readonly label: string;
}

export interface LensRamp {
  readonly scale: LensScale;
  /** Same colours, in the same order, as the cell renderer (technique-cell) paints. */
  readonly stops: readonly LensRampStop[];
}

export interface HeatmapModeDef {
  value: HeatmapMode;
  /** Menu label. Plain text: no emoji. */
  label: string;
  /** Short name for the trigger button (replaces the old 27-branch ternary). */
  short: string;
  group: 'Coverage & Posture' | 'Threat Landscape' | 'Vulnerabilities' | 'Detections' | 'Frameworks';
  /** The one question this lens answers, as the legend title states it. */
  question: string;
  rung: LensRung;
  /** Present exactly when rung is 'Covered'. */
  qualifier?: CoveredQualifier;
  /** How a technique's score is computed today, in words. */
  formula: string;
  /** The domains whose data this lens's sources actually cover. */
  domains: readonly AttackDomain[];
  /** Ids into the source inventory (lens-sources.ts). */
  sources: readonly LensSourceId[];
  /** What a zero (or blank, or lowest band) means for this lens. */
  zeroMeaning: string;
  ramp: LensRamp;
  /**
   * Why the lens has no data outside its domains, when naming its sources
   * would not say it (the lens is about one framework's own ids). Without it,
   * the reason names the sources and the domains they cover.
   */
  domainNote?: string;
}

const RELATIVE_LABELS = ['<25%', '25-49%', '50-74%', '75-100%'] as const;

/** A relative ramp: zero stop plus the renderer's four quartile colours. */
function relative(zero: string, colors: readonly [string, string, string, string], zeroLabel = '0'): LensRamp {
  return {
    scale: 'relative',
    stops: [{ color: zero, label: zeroLabel }, ...colors.map((color, i) => ({ color, label: RELATIVE_LABELS[i] }))],
  };
}

function stops(scale: LensScale, pairs: ReadonlyArray<readonly [string, string]>): LensRamp {
  return { scale, stops: pairs.map(([color, label]) => ({ color, label })) };
}

const ALL_ATTACK: readonly AttackDomain[] = ['enterprise', 'ics', 'mobile'];
const ENTERPRISE: readonly AttackDomain[] = ['enterprise'];

/**
 * Single source of truth for every heatmap mode. The heatmap dropdown, the
 * trigger-button label, mode cycling and the legend all read from this list;
 * adding a mode here (plus its scoring and colour) is the only registry edit.
 *
 * Labels follow the Known / Covered / Proven vocabulary (plan 4.1, E1.1): a
 * lens built from reference data says 'mapped', 'available' or 'reference
 * depth', never 'coverage'. The `value` ids are the heat= URL values and never
 * change, so old links keep working.
 */
export const HEATMAP_MODES: readonly HeatmapModeDef[] = [
  // Coverage & Posture
  { value: 'coverage', label: 'Mitigations mapped', short: 'Mitigations mapped', group: 'Coverage & Posture',
    question: 'How many ATT&CK mitigations are mapped to this technique?',
    rung: 'Known',
    formula: 'Count of ATT&CK mitigation relationships to the technique in the loaded bundle; 4 or more share the top colour. The colours follow the heatmap colour theme in Settings.',
    domains: ALL_ATTACK, sources: ['attack-bundle'],
    zeroMeaning: 'No mitigation is mapped in this ATT&CK release. Not known to us, not safe.',
    ramp: stops('absolute', [['#d32f2f', '0'], ['#b45309', '1'], ['#f9a825', '2'], ['#558b2f', '3'], ['#1b5e20', '4+']]) },
  { value: 'status', label: 'Status', short: 'Status', group: 'Coverage & Posture',
    question: 'What implementation status have you recorded for the mitigations of this technique?',
    rung: 'Covered', qualifier: 'self-attested',
    formula: 'The best status you set on any ATT&CK mitigation mapped to the technique: implemented, then in progress, then planned, then not started.',
    domains: ALL_ATTACK, sources: ['attack-bundle', 'workspace-local'],
    zeroMeaning: 'No status is recorded for any mapped mitigation. Not known to us, not safe.',
    ramp: stops('categorical', [['#90a4ae', 'none'], ['#e53935', 'not started'], ['#ff9800', 'in progress'], ['#2196f3', 'planned'], ['#4caf50', 'implemented']]) },
  { value: 'controls', label: 'Controls', short: 'Controls', group: 'Coverage & Posture',
    question: 'Which techniques do the security controls you declared address?',
    rung: 'Covered', qualifier: 'self-attested',
    formula: 'Covered when an implemented control you declared lists an ATT&CK mitigation mapped to the technique; planned when only planned controls do.',
    domains: ALL_ATTACK, sources: ['attack-bundle', 'workspace-local'],
    zeroMeaning: 'No declared control reaches this technique. Not known to us, not safe.',
    ramp: stops('categorical', [['#1c2b30', 'none'], ['#1565c0', 'planned'], ['#00c853', 'covered']]) },
  { value: 'unified', label: 'Reference depth', short: 'Reference depth', group: 'Coverage & Posture',
    question: 'How much defensive reference material is mapped to this technique, across frameworks?',
    rung: 'Known',
    formula: 'Weighted 0-100, rescaled from mitigations 15 (full at 4), Sigma and CAR content 20 (full at 5), control-framework mappings 15 (full at 4), D3FEND 10 (full at 2) and Atomic tests 10 (full at 3). Threat-side signals (groups, software, campaigns, KEV) are not inputs; the Threat lenses show them.',
    domains: ENTERPRISE,
    sources: ['attack-bundle', 'sigmahq', 'car', 'car-seed', 'ctid-nist-800-53', 'ctid-cri', 'cis-controls', 'ctid-csa-ccm', 'ctid-m365', 'd3fend-seed', 'atomic'],
    zeroMeaning: 'A low band means little reference material is mapped. Not known to us, not safe.',
    ramp: stops('threshold', [['#0e1b30', '0-15'], ['#143a5c', '16-30'], ['#1f6aa8', '31-50'], ['#2f95d8', '51-65'], ['#38bdf8', '66-80'], ['#a78bfa', '81-100']]) },
  { value: 'library', label: 'Library Layer', short: 'Library', group: 'Coverage & Posture',
    question: 'How does the active layer score this technique?',
    rung: 'Known',
    formula: 'The score from your imported layer when one is loaded, otherwise from the selected TeamStarWolf library layer; shaded by share of the layer maximum unless the layer sets its own colours.',
    domains: ALL_ATTACK, sources: ['library-layers', 'workspace-local'],
    zeroMeaning: 'The technique is not in the active layer. Not known to us, not safe.',
    ramp: relative('#12122a', ['#1e3a5f', '#2f6ab0', '#38bdf8', '#a78bfa'], 'not in layer') },
  { value: 'frequency', label: 'Frequency', short: 'Frequency', group: 'Coverage & Posture',
    question: 'How many ATT&CK groups are recorded using this technique?',
    rung: 'Threat',
    formula: 'Count of group (intrusion-set) uses of the technique in the loaded bundle.',
    domains: ALL_ATTACK, sources: ['attack-bundle'],
    zeroMeaning: 'No group use is recorded in this release. Not known to us, not safe.',
    ramp: relative('#1c2a38', ['#1e3a5f', '#1565c0', '#0ea5e9', '#38bdf8']) },

  // Threat Landscape
  { value: 'risk', label: 'Threat-weighted mapping gap', short: 'Threat-weighted gap', group: 'Threat Landscape',
    question: 'Where is recorded adversary use high and mapped mitigation thin?',
    rung: 'Threat',
    formula: 'Groups using the technique x (1 + 1 / (mapped mitigations + 1)).',
    domains: ALL_ATTACK, sources: ['attack-bundle'],
    zeroMeaning: 'No group use is recorded, so there is no score. Not known to us, not safe.',
    ramp: relative('#eceff1', ['#ff7043', '#e53935', '#b71c1c', '#4a0000']) },
  { value: 'exposure', label: 'Selected adversaries', short: 'Selected adversaries', group: 'Threat Landscape',
    question: 'How many of the adversary groups you selected use this technique?',
    rung: 'Threat',
    formula: 'Count of the groups in the active threat filter recorded using the technique; empty until groups are selected.',
    domains: ALL_ATTACK, sources: ['attack-bundle'],
    zeroMeaning: 'None of the selected groups is recorded using it, or no group is selected. Not known to us, not safe.',
    ramp: relative('#eceff1', ['#ffb74d', '#ff7043', '#e53935', '#b71c1c']) },
  { value: 'software', label: 'Software', short: 'Software', group: 'Threat Landscape',
    question: 'How many malware and tool families are recorded using this technique?',
    rung: 'Threat',
    formula: 'Count of software (malware and tool) uses of the technique in the loaded bundle.',
    domains: ALL_ATTACK, sources: ['attack-bundle'],
    zeroMeaning: 'No software use is recorded in this release. Not known to us, not safe.',
    ramp: relative('#eceff1', ['#ffb74d', '#ff7043', '#e53935', '#b71c1c']) },
  { value: 'campaign', label: 'Campaign', short: 'Campaign', group: 'Threat Landscape',
    question: 'How many campaigns are recorded using this technique?',
    rung: 'Threat',
    formula: 'Count of campaign uses of the technique in the loaded bundle.',
    domains: ALL_ATTACK, sources: ['attack-bundle'],
    zeroMeaning: 'No campaign use is recorded in this release. Not known to us, not safe.',
    ramp: relative('#eceff1', ['#ce93d8', '#ab47bc', '#7b1fa2', '#4a148c']) },
  { value: 'intelligence', label: 'Intelligence', short: 'Intelligence', group: 'Threat Landscape',
    question: 'How much threat intelligence links to this technique?',
    rung: 'Threat',
    formula: 'Groups recorded using the technique, plus 1 when the MISP galaxy has an attack-pattern cluster for it.',
    domains: ALL_ATTACK, sources: ['attack-bundle', 'misp-galaxy'],
    zeroMeaning: 'No group use and no MISP cluster is recorded. Not known to us, not safe.',
    ramp: relative('#0a1a2e', ['#1a3a7a', '#5a2d8b', '#8b1a5a', '#d32f2f']) },
  { value: 'my-exposure', label: 'My Exposure', short: 'My Exposure', group: 'Threat Landscape',
    question: 'How many of your assets map to this technique?',
    rung: 'Exposure',
    formula: 'For each asset in your inventory, its software keywords are matched to techniques through a hand-picked table and the CVE-to-technique mappings; the score is the number of matching assets.',
    domains: ENTERPRISE, sources: ['workspace-local', 'project-authored', 'ctid-attack-to-cve'],
    zeroMeaning: 'No asset in your inventory maps here, or the inventory is empty. Not known to us, not safe.',
    ramp: relative('#1a2332', ['#ff9800', '#f44336', '#d32f2f', '#b71c1c']) },

  // Vulnerabilities
  { value: 'kev', label: 'KEV', short: 'KEV', group: 'Vulnerabilities',
    question: 'How many CISA KEV CVEs link to this technique?',
    rung: 'Threat',
    formula: 'Distinct KEV CVEs linked to the technique through their CWE exploitation anchors or the CTID KEV mapping.',
    domains: ENTERPRISE, sources: ['cisa-kev', 'cwe-exploitation-anchor', 'ctid-kev'],
    zeroMeaning: 'No KEV CVE is linked, or the KEV catalogue did not load. Not known to us, not safe.',
    ramp: relative('#eceff1', ['#ffd54f', '#ffb300', '#ff7043', '#d32f2f']) },
  { value: 'cve', label: 'CVE', short: 'CVE', group: 'Vulnerabilities',
    question: 'How many CVEs does CTID map to this technique?',
    rung: 'Threat',
    formula: 'Count of CVEs mapped to the technique, or to its sub-techniques, in CTID attack_to_cve and the CTID KEV mapping.',
    domains: ENTERPRISE, sources: ['ctid-attack-to-cve', 'ctid-kev'],
    zeroMeaning: 'No CVE is mapped here. Not known to us, not safe.',
    ramp: relative('#1a2332', ['#4a1a4a', '#7b2d8b', '#a855b5', '#d946ef']) },
  { value: 'epss', label: 'EPSS Prob.', short: 'EPSS', group: 'Vulnerabilities',
    question: 'How likely, on average, are the CVEs mapped to this technique to be exploited soon?',
    rung: 'Threat',
    formula: 'Mean FIRST EPSS probability over the CVEs mapped to the technique that have a score.',
    domains: ENTERPRISE, sources: ['epss', 'ctid-attack-to-cve', 'ctid-kev'],
    zeroMeaning: 'No mapped CVE has an EPSS score, or EPSS did not load. Not known to us, not safe.',
    ramp: stops('threshold', [['#1a1a0a', 'none'], ['#5c4a00', '<1%'], ['#c17900', '1-5%'], ['#e65100', '5-20%'], ['#d32f2f', '20%+']]) },
  { value: 'kill-chain', label: 'CVE Kill Chain', short: 'Kill Chain', group: 'Vulnerabilities',
    question: 'How many CVE-to-CWE-to-CAPEC chains reach this technique?',
    rung: 'Threat',
    formula: 'Count of CVE2CAPEC chains that end at the technique.',
    domains: ENTERPRISE, sources: ['cve2capec'],
    zeroMeaning: 'No chain reaches this technique, or CVE2CAPEC did not load. Not known to us, not safe.',
    ramp: relative('#0e0a1a', ['#2d1a5e', '#5a2d8b', '#7b3faa', '#9c5cc5']) },
  { value: 'poc-exploits', label: 'PoC Exploits', short: 'PoC', group: 'Vulnerabilities',
    question: 'How many CVEs with a public proof-of-concept map to this technique?',
    rung: 'Threat',
    formula: 'Distinct CVEs listed in the trickest PoC index whose CTID mapping includes the technique or its sub-techniques.',
    domains: ENTERPRISE, sources: ['trickest-poc', 'ctid-attack-to-cve', 'ctid-kev'],
    zeroMeaning: 'No mapped CVE has a listed PoC, or the index did not load. Not known to us, not safe.',
    ramp: relative('#1a0e0a', ['#5c2a0a', '#a84a1a', '#d96a2a', '#ff8c3a']) },

  // Detections
  { value: 'detection', label: 'Detection content available', short: 'Detection content', group: 'Detections',
    question: 'How much detection and test content is available for this technique?',
    rung: 'Known',
    formula: 'Sigma rules x 3 + D3FEND countermeasures x 2 + CAR analytics x 2 + Atomic tests x 1.',
    domains: ENTERPRISE, sources: ['sigmahq', 'd3fend-seed', 'car-seed', 'atomic'],
    zeroMeaning: 'No detection or test content is available here. Not known to us, not safe.',
    ramp: relative('#1a2332', ['#0c2d2d', '#0d5e5e', '#0e8a7a', '#10b981']) },
  { value: 'sigma', label: 'Sigma Rules', short: 'Sigma', group: 'Detections',
    question: 'How many SigmaHQ rules are tagged with this technique?',
    rung: 'Known',
    formula: 'Rule count for the technique in the SigmaHQ ATT&CK coverage layer.',
    domains: ENTERPRISE, sources: ['sigmahq'],
    zeroMeaning: 'No SigmaHQ rule is tagged, or the coverage layer did not load. Not known to us, not safe.',
    ramp: relative('#0a1a1a', ['#0d4a3a', '#0d7a5e', '#0ea87a', '#10b981']) },
  { value: 'elastic', label: 'Elastic Rules', short: 'Elastic', group: 'Detections',
    question: 'How many Elastic detection rules reference this technique?',
    rung: 'Known',
    formula: 'Count of rule files in the elastic/detection-rules tree whose path names the technique or its sub-techniques.',
    domains: ENTERPRISE, sources: ['elastic'],
    zeroMeaning: 'No rule path names this technique, or the tree did not load. Not known to us, not safe.',
    ramp: relative('#0a1a0a', ['#1a3a1a', '#2a6a2a', '#3a9a3a', '#4caf50']) },
  { value: 'splunk', label: 'Splunk Detections', short: 'Splunk', group: 'Detections',
    question: 'How many Splunk security_content detections reference this technique?',
    rung: 'Known',
    formula: 'Count of detection files in the splunk/security_content tree whose path names the technique.',
    domains: ENTERPRISE, sources: ['splunk'],
    zeroMeaning: 'No detection path names this technique, or the tree did not load. Not known to us, not safe.',
    ramp: relative('#1a0a0a', ['#4a2a0a', '#7a4a1a', '#c06a20', '#ff9800']) },
  { value: 'wazuh', label: 'Wazuh stock rules (curated)', short: 'Wazuh stock rules', group: 'Detections',
    question: 'How many Wazuh stock rules carry this technique?',
    rung: 'Known',
    formula: 'Count of rules for the technique in the curated in-code Wazuh stock-rule table.',
    domains: ENTERPRISE, sources: ['wazuh-stock-rules'],
    zeroMeaning: 'No stock rule in the curated table carries it. Not known to us, not safe.',
    ramp: relative('#0a1520', ['#0d3a5c', '#1a6fa0', '#2196c8', '#3aabe0']) },
  { value: 'm365', label: 'M365 Defender', short: 'M365', group: 'Detections',
    question: 'How many Microsoft 365 Defender hunting queries reference this technique?',
    rung: 'Known',
    formula: 'Count of hunting-query files matched to the technique in the archived Microsoft-365-Defender-Hunting-Queries tree.',
    domains: ENTERPRISE, sources: ['m365-hunting'],
    zeroMeaning: 'No hunting query matches, or the tree did not load. Not known to us, not safe.',
    ramp: relative('#0a1a2e', ['#003a6e', '#005a9e', '#0078d4', '#4ca6ff']) },
  { value: 'car', label: 'CAR', short: 'CAR', group: 'Detections',
    question: 'How many MITRE CAR analytics cover this technique?',
    rung: 'Known',
    formula: 'The larger of the MITRE CAR ATT&CK layer count (sub-techniques rolled up) and the in-code CAR seed count.',
    domains: ENTERPRISE, sources: ['car', 'car-seed'],
    zeroMeaning: 'No CAR analytic is mapped, or the layer did not load. Not known to us, not safe.',
    ramp: relative('#0a0a1a', ['#0d2a4a', '#1a4a7a', '#2a6aaa', '#58a6ff']) },
  { value: 'atomic', label: 'Atomic', short: 'Atomic', group: 'Detections',
    question: 'How many Atomic Red Team tests exercise this technique?',
    rung: 'Known',
    formula: 'Test count for the technique in the Atomic Red Team ATT&CK layer.',
    domains: ENTERPRISE, sources: ['atomic'],
    zeroMeaning: 'No Atomic test is listed, or the layer did not load. Not known to us, not safe.',
    ramp: relative('#1a1a0a', ['#6d3a10', '#c06020', '#e08030', '#f0a040']) },

  // Frameworks
  { value: 'd3fend', label: 'D3FEND', short: 'D3FEND', group: 'Frameworks',
    question: 'How many D3FEND countermeasures are mapped to this technique?',
    rung: 'Known',
    formula: 'Countermeasure count for the technique in the in-code D3FEND seed; replaced per technique by the live D3FEND API answer once it has been fetched.',
    domains: ENTERPRISE, sources: ['d3fend-seed'],
    zeroMeaning: 'No countermeasure is in the seed for it. Not known to us, not safe.',
    ramp: relative('#d32f2f', ['#e64a19', '#f57c00', '#1565c0', '#1a6fba']) },
  { value: 'engage', label: 'Engage', short: 'Engage', group: 'Frameworks',
    question: 'How many MITRE Engage activities address this technique?',
    rung: 'Known',
    formula: 'Count of Engage activities mapped to the technique.',
    domains: ENTERPRISE, sources: ['engage'],
    zeroMeaning: 'No Engage activity is mapped, or Engage did not load. Not known to us, not safe.',
    ramp: relative('#0a1a0a', ['#4a3a10', '#906020', '#c08030', '#f0a040']) },
  { value: 'nist', label: 'NIST 800-53', short: 'NIST', group: 'Frameworks',
    question: 'How many NIST 800-53 rev5 controls does CTID map to this technique?',
    rung: 'Known',
    formula: 'Count of NIST 800-53 rev5 controls mapped to the technique in the CTID mapping.',
    domains: ENTERPRISE, sources: ['ctid-nist-800-53'],
    zeroMeaning: 'No control is mapped, or the mapping did not load. Not known to us, not safe.',
    ramp: relative('#0d1b2a', ['#1a4a7a', '#1565c0', '#1976d2', '#42a5f5']) },
  { value: 'veris', label: 'VERIS Actions', short: 'VERIS', group: 'Frameworks',
    question: 'How many VERIS actions does CTID map to this technique?',
    rung: 'Known',
    formula: 'Count of VERIS actions mapped to the technique in the CTID mapping.',
    domains: ENTERPRISE, sources: ['ctid-veris'],
    zeroMeaning: 'No VERIS action is mapped, or the mapping did not load. Not known to us, not safe.',
    ramp: relative('#1a0a0a', ['#5c1a1a', '#a83232', '#d64e4e', '#f28b8b']) },
  { value: 'cri', label: 'CRI Profile', short: 'CRI', group: 'Frameworks',
    question: 'How many CRI Profile controls does CTID map to this technique?',
    rung: 'Known',
    formula: 'Count of CRI Profile controls mapped to the technique in the CTID mapping.',
    domains: ENTERPRISE, sources: ['ctid-cri'],
    zeroMeaning: 'No CRI control is mapped, or the mapping did not load. Not known to us, not safe.',
    ramp: relative('#1a0a2e', ['#ce93d8', '#ab47bc', '#8e24aa', '#6a1b9a']) },
  { value: 'csa-ccm', label: 'CSA CCM', short: 'CSA CCM', group: 'Frameworks',
    question: 'How many CSA CCM controls does CTID map to this technique?',
    rung: 'Known',
    formula: 'Count of CSA Cloud Controls Matrix controls mapped to the technique in the CTID mapping.',
    domains: ENTERPRISE, sources: ['ctid-csa-ccm'],
    zeroMeaning: 'No CCM control is mapped, or the mapping did not load. Not known to us, not safe.',
    ramp: relative('#0a1a10', ['#1a4a2a', '#2a7a3a', '#3aaa4a', '#4cce5a']) },
  { value: 'm365-controls', label: 'M365 Controls', short: 'M365 Ctl', group: 'Frameworks',
    question: 'How many Microsoft 365 security capabilities does CTID map to this technique?',
    rung: 'Known',
    formula: 'Count of Microsoft 365 capabilities mapped to the technique in the CTID mapping.',
    domains: ENTERPRISE, sources: ['ctid-m365'],
    zeroMeaning: 'No capability is mapped, or the mapping did not load. Not known to us, not safe.',
    ramp: relative('#0a1028', ['#0a3068', '#0050a8', '#0070e8', '#40a0ff']) },
  { value: 'f3-origin', label: 'F3 Origin', short: 'F3 Origin', group: 'Frameworks',
    question: 'Is this F3 technique shared with ATT&CK or native to fraud?',
    rung: 'Known',
    formula: 'T-prefixed ids are shared with ATT&CK, F-prefixed ids are fraud-native; the prefix is the CTID isAttack flag.',
    domains: ['f3'], sources: ['attack-bundle'],
    domainNote: 'it sorts CTID F3 fraud-framework ids by their T or F prefix, so it exists for CTID F3 only',
    zeroMeaning: 'No zero state: every F3 technique is either shared or fraud-native.',
    ramp: stops('categorical', [['#1565c0', 'shared w/ ATT&CK'], ['#6a1b9a', 'fraud-native']]) },
] as const;

export const HEATMAP_GROUPS = ['Threat Landscape', 'Vulnerabilities', 'Detections', 'Frameworks', 'Coverage & Posture'] as const;

export function heatmapModeDef(mode: HeatmapMode): HeatmapModeDef | undefined {
  return HEATMAP_MODES.find(m => m.value === mode);
}

export function heatmapShortLabel(mode: HeatmapMode): string {
  return heatmapModeDef(mode)?.short ?? mode;
}

export function nextHeatmapMode(mode: HeatmapMode): HeatmapMode {
  const values = HEATMAP_MODES.map(m => m.value);
  return values[(values.indexOf(mode) + 1) % values.length];
}

/** The legend's rung badge text (4.7): KNOWN, COVERED self-attested, THREAT, EXPOSURE. */
export function lensRungBadge(def: Pick<HeatmapModeDef, 'rung' | 'qualifier'>): string {
  const rung = def.rung.toUpperCase();
  return def.qualifier ? `${rung} ${def.qualifier}` : rung;
}

/** Whether a lens has data for an ATT&CK domain, and if not, why (E1.2). */
export interface LensAvailability {
  readonly available: boolean;
  /** Short tag for a disabled control, e.g. 'n/a for ICS ATT&CK'; null when available. */
  readonly short: string | null;
  /** The full stated reason; null when available. */
  readonly reason: string | null;
}

const AVAILABLE: LensAvailability = { available: true, short: null, reason: null };

/**
 * Base colour of a cell whose lens has no data in the domain on screen. A
 * neutral grey that is in no lens ramp; the cell adds the diagonal hatch on
 * top (4.1 'n/a in this domain': diagonal hatch, never a ramp colour).
 */
export const LENS_NA_COLOR = '#9e9e9e';

/**
 * A lens is available in a domain exactly when that domain is in its
 * domains[] (the domains its sources actually cover). An unavailable lens is
 * disabled in the lens picker and rendered as 'n/a in this domain' (hatched,
 * never a ramp colour) instead of an all-zero map, so a missing source never
 * reads as a zero.
 */
export function lensAvailability(def: Pick<HeatmapModeDef, 'label' | 'domains' | 'sources' | 'domainNote'>, domain: AttackDomain): LensAvailability {
  if (def.domains.includes(domain)) return AVAILABLE;
  const short = `n/a for ${domainLabel(domain)}`;
  const why = def.domainNote
    ?? `its sources (${[...new Set(def.sources.map((id) => LENS_SOURCES[id].name))].join(', ')}) have data for ${def.domains.map(domainLabel).join(' and ')} only`;
  return { available: false, short, reason: `${def.label} is ${short}: ${why}.` };
}

/** True when the lens for `mode` has data in `domain` (unknown modes count as available). */
export function isLensAvailable(mode: HeatmapMode, domain: AttackDomain): boolean {
  const def = heatmapModeDef(mode);
  return !def || lensAvailability(def, domain).available;
}

/** Every lens that has no data in `domain`, in registry order. */
export function unavailableLenses(domain: AttackDomain): HeatmapModeDef[] {
  return HEATMAP_MODES.filter((m) => !lensAvailability(m, domain).available);
}

/** What each rung or dimension means (plan 4.1), as the definition card states it. */
export const LENS_RUNG_MEANING: Readonly<Record<LensRung, string>> = {
  Known: 'Reference data: the world knows how to mitigate, detect or test this. It makes no claim about your environment.',
  Covered: 'Something you declared is deployed for this, but it has not been shown to fire.',
  Proven: 'A named detection fired, or the technique was blocked, on a recorded date.',
  Threat: 'How much adversaries care about this. A threat dimension, never a posture rung.',
  Exposure: 'Whether this is reachable in your estate. An exposure dimension, never a posture rung.',
};
