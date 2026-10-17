// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// E1.1 relabel (plan P1 row E1.1, vocabulary 4.1): lens labels change, the
// heat= values do not, so every existing link keeps resolving.
import { HEATMAP_MODES, heatmapShortLabel } from './heatmap-modes';

/** The 33 heat= values as they stood before the relabel, in menu order. */
const HEAT_VALUES = [
  'coverage', 'status', 'controls', 'unified', 'library', 'frequency',
  'risk', 'exposure', 'software', 'campaign', 'intelligence', 'my-exposure',
  'kev', 'cve', 'epss', 'kill-chain', 'poc-exploits',
  'detection', 'sigma', 'elastic', 'splunk', 'wazuh', 'm365', 'car', 'atomic',
  'd3fend', 'engage', 'nist', 'veris', 'cri', 'csa-ccm', 'm365-controls', 'f3-origin',
];

describe('HEATMAP_MODES relabel (E1.1)', () => {
  it('keeps every heat= value and mode id unchanged', () => {
    expect<string[]>(HEATMAP_MODES.map(m => m.value)).toEqual(HEAT_VALUES);
  });

  const RELABEL: Array<[string, string, string]> = [
    // [heat= value, menu label words, trigger short label]
    ['unified', 'Reference depth', 'Reference depth'],
    ['coverage', 'Mitigations mapped', 'Mitigations mapped'],
    ['detection', 'Detection content available', 'Detection content'],
    ['exposure', 'Selected adversaries', 'Selected adversaries'],
    ['risk', 'Threat-weighted mapping gap', 'Threat-weighted gap'],
    ['wazuh', 'Wazuh stock rules (curated)', 'Wazuh stock rules'],
  ];

  for (const [value, label, short] of RELABEL) {
    it(`labels heat=${value} '${label}'`, () => {
      const def = HEATMAP_MODES.find(m => m.value === value);
      expect(def).withContext(value).toBeDefined();
      expect(def!.label).toContain(label);
      expect(heatmapShortLabel(def!.value)).toBe(short);
    });
  }

  it('no longer uses the old Unified / Coverage / Risk / XDR wording on the relabelled lenses', () => {
    for (const [value] of RELABEL) {
      const def = HEATMAP_MODES.find(m => m.value === value)!;
      expect(`${def.label} ${def.short}`).withContext(value).not.toMatch(/Unified|Coverage|\bRisk\b|XDR|Exposure/);
    }
  });
});
