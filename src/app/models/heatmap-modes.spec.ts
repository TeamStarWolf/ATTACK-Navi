// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// E1.1 relabel (plan P1 row E1.1, vocabulary 4.1): lens labels change, the
// heat= values do not, so every existing link keeps resolving.
//
// E1.2 acceptance: every lens is described in the registry (question, rung,
// formula, domains, sources, zero meaning, ramp), labels carry no emoji, every
// heat= id survives, and the legend ramp is the one the renderer paints.
import SNAPSHOTS from '../testing/__snapshots__/lens-snapshots.json';
import {
  HEATMAP_MODES, HeatmapModeDef, LENS_NA_COLOR, LENS_RUNG_MEANING, LensRung, heatmapModeDef, heatmapShortLabel,
  isLensAvailable, lensAvailability, lensRungBadge, nextHeatmapMode, unavailableLenses,
} from './heatmap-modes';
import { LENS_SOURCES, LensSourceId, lensSourceVintage } from './lens-sources';

const PICTOGRAPHIC = /\p{Extended_Pictographic}|️/u;
const RUNGS: readonly LensRung[] = ['Known', 'Covered', 'Proven', 'Threat', 'Exposure', 'Mixed'];
const DOMAINS = ['enterprise', 'ics', 'mobile', 'f3'];

/** Row names of the source inventory, product plan section 6.3, that lens sources point at. */
const INVENTORY_ROWS = [
  'ATT&CK Enterprise / ICS / Mobile / F3 bundles',
  'cve-technique-map.json (CVE to CWE to CAPEC to ATT&CK)',
  'CVE2CAPEC runtime fetch',
  'CTID attack_to_cve',
  'CISA KEV',
  'EPSS, NVD',
  'CTID mappings (NIST 800-53, CRI, CSA CCM, VERIS, AWS, Azure, GCP, M365)',
  'CIS Controls',
  'Sigma coverage, CAR, Atomic, CAPEC, MISP galaxy, Engage',
  'Elastic, Splunk vendor rule trees',
  'M365 Defender hunting queries',
  'trickest PoC tree',
  'cwe-exploitation-anchor.json',
  'D3FEND seed',
  'CAR seed, Wazuh stock-rule table (~22 ids), YARA, Zeek, Suricata, event-logging, IR playbooks',
  'Library layers and library.json',
];

/** Colours only the minimap (MatrixComponent.getCellColor) paints; the cells and the legend use the registry. */
const MINIMAP_ONLY: Partial<Record<string, string[]>> = { nist: ['var(--accent)'] };

function nonEmpty(v: unknown): boolean {
  if (typeof v === 'string') return v.trim().length > 0;
  if (Array.isArray(v)) return v.length > 0;
  return v !== undefined && v !== null;
}

describe('HEATMAP_MODES registry (E1.2 lens metadata)', () => {
  const FIELDS: (keyof HeatmapModeDef)[] = ['value', 'label', 'short', 'group', 'question', 'rung', 'formula', 'domains', 'sources', 'zeroMeaning', 'ramp'];

  it('describes 36 of 36 modes with every field non-empty', () => {
    expect(HEATMAP_MODES.length).toBe(36);
    const described = HEATMAP_MODES.filter((m) =>
      FIELDS.every((f) => nonEmpty(m[f])) && m.ramp.stops.length > 0 && m.ramp.stops.every((s) => nonEmpty(s.color) && nonEmpty(s.label)),
    );
    const missing = HEATMAP_MODES.filter((m) => !described.includes(m)).map((m) => m.value);
    expect(missing).withContext('modes with an empty field').toEqual([]);
    expect(described.length).toBe(36);
  });

  it('keeps every heat= id (the committed lens snapshot ids)', () => {
    const ids = HEATMAP_MODES.map((m) => m.value as string).sort();
    expect(ids).toEqual(Object.keys(SNAPSHOTS).sort());
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('carries no emoji in labels, short names or legend stop labels', () => {
    const offenders: string[] = [];
    for (const m of HEATMAP_MODES) {
      for (const text of [m.label, m.short, ...m.ramp.stops.map((s) => s.label)]) {
        if (PICTOGRAPHIC.test(text)) offenders.push(`${m.value}: ${text}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it('puts every lens on a 4.1 rung or dimension, with a qualifier exactly on Covered', () => {
    for (const m of HEATMAP_MODES) {
      expect(RUNGS).withContext(m.value).toContain(m.rung);
      expect(!!m.qualifier).withContext(`${m.value} qualifier`).toBe(m.rung === 'Covered');
    }
    expect(lensRungBadge(heatmapModeDef('status')!)).toBe('COVERED self-attested');
    expect(lensRungBadge(heatmapModeDef('coverage')!)).toBe('KNOWN');
    expect(lensRungBadge(heatmapModeDef('frequency')!)).toBe('THREAT');
    expect(lensRungBadge(heatmapModeDef('my-exposure')!)).toBe('EXPOSURE');
  });

  it('names only domains the app models', () => {
    for (const m of HEATMAP_MODES) {
      for (const d of m.domains) expect(DOMAINS).withContext(m.value).toContain(d);
    }
    expect(heatmapModeDef('f3-origin')!.domains).toEqual(['f3']);
    expect(heatmapModeDef('sigma')!.domains).not.toContain('ics');
    expect(heatmapModeDef('coverage')!.domains).toContain('ics');
    expect(heatmapModeDef('library')!.domains).toContain('ics');
  });

  it('points every source at a 6.3 inventory row or a stated non-inventory id', () => {
    for (const m of HEATMAP_MODES) {
      for (const id of m.sources) {
        const info = LENS_SOURCES[id];
        expect(info).withContext(`${m.value} -> ${id}`).toBeDefined();
        if (info.inventoryRow === null) {
          expect(['project-authored', 'workspace-local']).withContext(id).toContain(id);
        } else {
          expect(INVENTORY_ROWS).withContext(id).toContain(info.inventoryRow);
        }
      }
    }
  });

  it('says what zero means, and that blank is not safe, wherever a zero state exists', () => {
    for (const m of HEATMAP_MODES) {
      if (m.value === 'f3-origin') continue;
      expect(m.zeroMeaning).withContext(m.value).toContain('Not known to us, not safe.');
    }
  });

  it('legend ramps contain every colour the renderer paints in the committed lens snapshots', () => {
    const snaps = SNAPSHOTS as unknown as Record<string, Record<string, [unknown, string]>>;
    const drift: string[] = [];
    for (const m of HEATMAP_MODES) {
      const ramp = new Set([...m.ramp.stops.map((s) => s.color), ...(MINIMAP_ONLY[m.value] ?? [])]);
      for (const [, colour] of Object.values(snaps[m.value] ?? {})) {
        if (!ramp.has(colour)) drift.push(`${m.value}: ${colour}`);
      }
    }
    expect([...new Set(drift)]).toEqual([]);
  });

  it('cycles through every mode', () => {
    let mode = HEATMAP_MODES[0].value;
    const seen = new Set<string>();
    for (let i = 0; i < HEATMAP_MODES.length; i++) { seen.add(mode); mode = nextHeatmapMode(mode); }
    expect(seen.size).toBe(36);
    expect(mode).toBe(HEATMAP_MODES[0].value);
  });
});

describe('lensSourceVintage (SEAM for E1.3 SourceRegistry)', () => {
  const bundle = { domain: 'enterprise' as const, attackVersion: '19.2', freshness: 'bundled' as const };

  it('states the loaded ATT&CK release and where it came from', () => {
    expect(lensSourceVintage('attack-bundle', bundle)).toBe('Enterprise ATT&CK 19.2 (bundled)');
    expect(lensSourceVintage('attack-bundle', { domain: 'ics', attackVersion: '', freshness: null })).toBe('ICS ATT&CK');
  });

  it('states pinned versions and mapped-vs releases, and says when nothing is pinned', () => {
    expect(lensSourceVintage('ctid-nist-800-53', bundle)).toBe('CTID NIST 800-53 (rev5; mapped vs ATT&CK 16.1)');
    expect(lensSourceVintage('sigmahq', bundle)).toBe('SigmaHQ coverage (fetched at runtime, unpinned)');
    expect(lensSourceVintage('engage', bundle)).toContain('archived upstream');
  });

  it('gives every source a non-empty vintage', () => {
    for (const id of Object.keys(LENS_SOURCES) as LensSourceId[]) {
      expect(lensSourceVintage(id, bundle).length).withContext(id).toBeGreaterThan(0);
    }
  });
});

/** The heat= values in registry order: the 33 as they stood before the relabel, then 'posture' (P2-13), 'proven' and 'covered' (P2-14), appended. */
const HEAT_VALUES = [
  'coverage', 'status', 'controls', 'unified', 'library', 'frequency',
  'risk', 'exposure', 'software', 'campaign', 'intelligence', 'my-exposure',
  'kev', 'cve', 'epss', 'kill-chain', 'poc-exploits',
  'detection', 'sigma', 'elastic', 'splunk', 'wazuh', 'm365', 'car', 'atomic',
  'd3fend', 'engage', 'nist', 'veris', 'cri', 'csa-ccm', 'm365-controls', 'f3-origin',
  'posture', 'proven', 'covered',
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

// E1.2 PR 2 acceptance (plan P1 row E1.2): lenses without data for the current
// domain are disabled with a stated reason, about 23 of them on ICS today.
describe('lens availability per domain (E1.2 definition cards)', () => {
  const lacking = (domain: string) => HEATMAP_MODES.filter((m) => !(m.domains as readonly string[]).includes(domain));

  it('switching to ICS disables exactly the lenses whose domains[] lacks ics (23 today)', () => {
    const disabled = unavailableLenses('ics').map((m) => m.value);
    expect(disabled).toEqual(lacking('ics').map((m) => m.value));
    expect(disabled.length).toBe(23);
    // Every lens built only on the ATT&CK bundle or your own workspace stays on.
    for (const v of ['coverage', 'status', 'controls', 'library', 'frequency', 'risk', 'exposure', 'software', 'campaign', 'intelligence'] as const) {
      expect(isLensAvailable(v, 'ics')).withContext(v).toBeTrue();
    }
  });

  it('gives every disabled ICS lens a reason that names the lens, the domain and why', () => {
    for (const def of unavailableLenses('ics')) {
      const a = lensAvailability(def, 'ics');
      expect(a.available).withContext(def.value).toBeFalse();
      expect(a.short).withContext(def.value).toBe('n/a for ICS ATT&CK');
      expect(a.reason).withContext(def.value).toContain(def.label);
      expect(a.reason).withContext(def.value).toContain('ICS ATT&CK');
      // The why: either the lens's own domain note, or its sources and the domains they cover.
      const why = def.domainNote ?? LENS_SOURCES[def.sources[0]].name;
      expect(a.reason).withContext(def.value).toContain(why);
      expect(a.reason!.length).withContext(def.value).toBeGreaterThan(def.label.length + 30);
    }
  });

  it('states the domains a source-limited lens does cover', () => {
    const sigma = heatmapModeDef('sigma')!;
    expect(lensAvailability(sigma, 'mobile').reason).toBe(
      'Sigma Rules is n/a for Mobile ATT&CK: its sources (SigmaHQ coverage) have data for Enterprise ATT&CK only.',
    );
    expect(lensAvailability(heatmapModeDef('f3-origin')!, 'ics').reason).toContain('CTID F3 only');
  });

  it('disables nothing that has data: available lenses carry no reason', () => {
    for (const domain of DOMAINS) {
      for (const def of HEATMAP_MODES) {
        const a = lensAvailability(def, domain as HeatmapModeDef['domains'][number]);
        expect(a.available).withContext(`${def.value} in ${domain}`).toBe(def.domains.includes(domain as HeatmapModeDef['domains'][number]));
        if (a.available) {
          expect(a.reason).toBeNull();
          expect(a.short).toBeNull();
        }
      }
    }
    expect(unavailableLenses('enterprise').map((m) => m.value)).toEqual(['f3-origin']);
    expect(unavailableLenses('f3').map((m) => m.value)).toEqual(lacking('f3').map((m) => m.value));
  });

  it('paints n/a in a neutral colour that is in no lens ramp', () => {
    const rampColours = new Set(HEATMAP_MODES.flatMap((m) => m.ramp.stops.map((s) => s.color.toLowerCase())));
    expect(rampColours.has(LENS_NA_COLOR.toLowerCase())).toBeFalse();
  });

  it('explains every rung or dimension a lens can sit on', () => {
    for (const rung of RUNGS) expect(nonEmpty(LENS_RUNG_MEANING[rung])).withContext(rung).toBeTrue();
    expect(LENS_RUNG_MEANING.Threat).toContain('never a posture rung');
    expect(LENS_RUNG_MEANING.Exposure).toContain('never a posture rung');
  });
});
