// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The LensRegistry seam (Phase 2 design §2.5, §3 P2-13, P2-14): Posture,
// Proven and Covered are registry-hosted and appended last; of the 33 older
// entries, status and controls moved into the registry in P2-14 (re-derived
// through PostureService) and unified (Reference depth) in P2-15, a score-only
// lens; all three keep their index, and the other 30 stay legacy (no project,
// no color), so the matrix switchboard and the colour copies still serve them
// unchanged.
import {
  HEATMAP_MODES, LENS_RUNG_MEANING, type LensContext, REFERENCE_DEPTH_STOP_SCORES, heatmapModeDef, isLensAvailable, lensAvailability,
  lensRungBadge,
} from './heatmap-modes';
import { referenceDepthScore } from './reference-depth';
import {
  NO_OWNER_DATA_LINE, OWNER_DATA_LENSES, OWNER_WORD_LENSES, SCORE_ONLY_LENSES, isPostureCellLens, isRegistryLens, lensNameVisible, lensOnScreen,
  lensQuestion, registryCell, registryColor,
} from './lens-registry';
import type { Technique } from './technique';
import { lensLabel } from './posture/posture-vocabulary';
import { POSTURE_SCORE, postureFill } from './posture/posture-ramp';
import { stubState } from '../testing/posture-stub';

const T = { id: 'attack-pattern--1', attackId: 'T1001' } as Technique;

function ctx(bucket: Parameters<typeof stubState>[1], theme: 'dark' | 'light' = 'dark'): LensContext {
  return {
    posture: () => stubState('T1001', bucket),
    known: () => ({ mitigation: true, detection: false, control: false, d3fend: false, atomic: false }),
    knownCounts: () => ({ mitigations: 1, detectionContent: 0, controls: 0, d3fend: 0, atomic: 0 }),
    implView: () => ({ status: null, partialVia: null }),
    theme,
    colorblindSafe: false,
  };
}

describe('LensRegistry seam (P2-13)', () => {
  it('hosts status, controls and unified in place and posture, proven and covered appended after the 33 older entries', () => {
    const hosted = HEATMAP_MODES.filter(isRegistryLens).map(m => m.value);
    expect(hosted).toEqual(['status', 'controls', 'unified', 'posture', 'proven', 'covered']);
    expect(HEATMAP_MODES.findIndex(m => m.value === 'status')).toBe(1);
    expect(HEATMAP_MODES.findIndex(m => m.value === 'controls')).toBe(2);
    expect(HEATMAP_MODES.findIndex(m => m.value === 'unified')).toBe(3);
    expect(HEATMAP_MODES.findIndex(m => m.value === 'posture')).toBe(33);
    expect(HEATMAP_MODES.findIndex(m => m.value === 'proven')).toBe(34);
    expect(HEATMAP_MODES.findIndex(m => m.value === 'covered')).toBe(35);
    for (const def of HEATMAP_MODES.slice(0, 33).filter(d => !['status', 'controls', 'unified'].includes(d.value))) {
      expect(def.project).withContext(def.value).toBeUndefined();
      expect(def.color).withContext(def.value).toBeUndefined();
    }
  });

  it('is not fooled by a half-hosted or missing definition', () => {
    const coverage = heatmapModeDef('coverage')!;
    expect(isRegistryLens(undefined)).toBeFalse();
    expect(isRegistryLens(null)).toBeFalse();
    expect(isRegistryLens(coverage)).toBeFalse();
    expect(isRegistryLens({ ...coverage, project: () => ({ score: 0 }) })).toBeFalse();
  });

  it('refuses to project or colour a legacy lens', () => {
    const coverage = heatmapModeDef('coverage')!;
    expect(() => registryCell(coverage, ctx('known'), T)).toThrowError(/not registry-hosted/);
    expect(() => registryColor(coverage, { score: 0 }, { theme: 'dark', colorblindSafe: false })).toThrowError(/not registry-hosted/);
  });

  it('projects and colours the posture lens through its own functions', () => {
    const posture = heatmapModeDef('posture')!;
    for (const theme of ['dark', 'light'] as const) {
      for (const bucket of ['none', 'known', 'partial', 'covered', 'proven', 'stale'] as const) {
        const cell = registryCell(posture, ctx(bucket, theme), T);
        expect(cell.bucket).toBe(bucket);
        expect(cell.score).toBe(POSTURE_SCORE[bucket]);
        expect(registryColor(posture, cell, { theme, colorblindSafe: false })).toBe(postureFill(bucket, theme));
        // Settings > colorblind-safe has no effect on Posture (walk step 2): it is safe by default.
        expect(registryColor(posture, cell, { theme, colorblindSafe: true })).toBe(postureFill(bucket, theme));
      }
    }
  });
});

describe('the Reference depth lens in the registry (P2-15)', () => {
  const unified = heatmapModeDef('unified')!;

  /**
   * The colour TechniqueCellComponent.computeUnifiedColor painted before P2-15,
   * copied verbatim as the oracle (the minimap's threshold copy painted the
   * colorblindSafe-off column for every score, 0 included).
   */
  function preRegistryColour(score: number, colorblindSafe: boolean): string {
    if (colorblindSafe) {
      if (score <= 15) return '#440154';
      if (score <= 30) return '#414487';
      if (score <= 50) return '#2a788e';
      if (score <= 65) return '#22a884';
      if (score <= 80) return '#7ad151';
      return '#fde725';
    }
    if (score <= 15) return '#0e1b30';
    if (score <= 30) return '#143a5c';
    if (score <= 50) return '#1f6aa8';
    if (score <= 65) return '#2f95d8';
    if (score <= 80) return '#38bdf8';
    return '#a78bfa';
  }

  it('is a score-only registry lens: no posture cell, and the only one', () => {
    expect([...SCORE_ONLY_LENSES]).toEqual(['unified']);
    expect(isRegistryLens(unified)).toBeTrue();
    expect(isPostureCellLens(unified)).toBeFalse();
    expect(HEATMAP_MODES.filter(isPostureCellLens).map(m => m.value)).toEqual(['status', 'controls', 'posture', 'proven', 'covered']);
    expect(isPostureCellLens(heatmapModeDef('coverage'))).toBeFalse();
    expect(isPostureCellLens(undefined)).toBeFalse();
  });

  it('projects the Reference depth score of the saturating Known counts', () => {
    const counts = { mitigations: 3, detectionContent: 7, controls: 1, d3fend: 2, atomic: 0 };
    const c: LensContext = { ...ctx('known'), knownCounts: () => counts };
    expect(registryCell(unified, c, T)).toEqual({ score: referenceDepthScore(counts) });
    expect(registryCell(unified, ctx('known'), T).score).toBe(referenceDepthScore(ctx('known').knownCounts(T)));
  });

  it('paints every score exactly as before, colorblind-safe off and on, in both themes', () => {
    const scores = [...Array.from({ length: 101 }, (_, i) => i), -1, 100.5, 150, Number.NaN];
    for (const score of scores) {
      for (const colorblindSafe of [false, true]) {
        for (const theme of ['dark', 'light'] as const) {
          expect(registryColor(unified, { score }, { theme, colorblindSafe }))
            .withContext(`${score} cvd=${colorblindSafe} ${theme}`).toBe(preRegistryColour(score, colorblindSafe));
        }
      }
    }
  });

  it('keeps its six threshold stops, and each stop score paints that stop', () => {
    expect(unified.ramp.scale).toBe('threshold');
    expect(unified.ramp.stops.map(s => s.label)).toEqual(['0-15', '16-30', '31-50', '51-65', '66-80', '81-100']);
    expect(unified.ramp.stops.map(s => s.color)).toEqual(['#0e1b30', '#143a5c', '#1f6aa8', '#2f95d8', '#38bdf8', '#a78bfa']);
    expect(REFERENCE_DEPTH_STOP_SCORES.length).toBe(unified.ramp.stops.length);
    REFERENCE_DEPTH_STOP_SCORES.forEach((score, i) => {
      expect(registryColor(unified, { score }, { theme: 'dark', colorblindSafe: false })).toBe(unified.ramp.stops[i].color);
      expect(registryColor(unified, { score }, { theme: 'dark', colorblindSafe: true })).toBe(preRegistryColour(score, true));
    });
  });
});

describe('the Posture lens definition (P2-13)', () => {
  const def = heatmapModeDef('posture')!;

  it('is rung Mixed, in every domain, with its label from the vocabulary and the literal short name', () => {
    expect(def.rung).toBe('Mixed');
    expect(def.qualifier).toBeUndefined();
    expect(lensRungBadge(def)).toBe('MIXED');
    expect(def.label).toBe(lensLabel('posture'));
    expect(def.short).toBe('Posture');
    expect(def.group).toBe('Coverage & Posture');
    expect([...def.domains].sort()).toEqual(['enterprise', 'f3', 'ics', 'mobile']);
    for (const d of ['enterprise', 'ics', 'mobile', 'f3'] as const) {
      expect(isLensAvailable('posture', d)).withContext(d).toBeTrue();
      expect(lensAvailability(def, d).reason).toBeNull();
    }
  });

  it('asks its question and states its rung meaning with Covered qualified', () => {
    expect(def.question).toBe('What is covered (self-attested or range), and what has a recorded detection?');
    expect(LENS_RUNG_MEANING.Mixed).toBe('Each cell shows its own rung: Known, Covered (self-attested or range) or a recorded detection.');
    expect(def.zeroMeaning).toContain('Not known to us, not safe.');
  });

  it('reads the ATT&CK bundle and your workspace', () => {
    expect([...def.sources]).toEqual(['attack-bundle', 'workspace-local']);
  });
});

// P2-14 repair round 1 (§10.4 item 14): a lens whose name is a rung word is
// named only once owner data exists; every other lens is always named.
describe('lensNameVisible', () => {
  it('hides exactly the Proven and Covered lenses without owner data', () => {
    expect([...OWNER_WORD_LENSES].sort()).toEqual(['covered', 'proven']);
    const hidden = HEATMAP_MODES.filter(m => !lensNameVisible(m, false)).map(m => m.value).sort();
    expect(hidden).toEqual(['covered', 'proven']);
    for (const m of HEATMAP_MODES.filter(x => !lensNameVisible(x, false))) {
      expect(m.label).withContext(m.value).toMatch(/^(Covered|Proven)/);
    }
  });

  it('names every lens once owner data exists', () => {
    expect(HEATMAP_MODES.every(m => lensNameVisible(m, true))).toBeTrue();
  });

  it('never hides a lens whose label carries no rung word', () => {
    for (const m of HEATMAP_MODES.filter(x => !/covered|proven/i.test(x.label))) {
      expect(lensNameVisible(m, false)).withContext(m.value).toBeTrue();
    }
  });
});

describe('lensOnScreen', () => {
  it('shows the fallback for Proven and Covered with no owner data, and the lens itself otherwise', () => {
    for (const m of HEATMAP_MODES) {
      const hidden = OWNER_WORD_LENSES.has(m.value);
      expect(lensOnScreen(m.value, false, 'frequency')).withContext(m.value).toBe(hidden ? 'frequency' : m.value);
      expect(lensOnScreen(m.value, true, 'frequency')).withContext(m.value).toBe(m.value);
    }
  });
});

describe('lensQuestion', () => {
  it('titles an owner-data lens with NO_OWNER_DATA_LINE while no owner data exists', () => {
    for (const m of HEATMAP_MODES) {
      const expected = OWNER_DATA_LENSES.has(m.value) ? NO_OWNER_DATA_LINE : m.question;
      expect(lensQuestion(m, false)).withContext(m.value).toBe(expected);
      expect(lensQuestion(m, true)).withContext(m.value).toBe(m.question);
    }
    expect([...OWNER_DATA_LENSES].sort()).toEqual(['covered', 'posture', 'proven']);
  });

  it('never titles a lens with a rung word for an empty user', () => {
    for (const m of HEATMAP_MODES) {
      expect(lensQuestion(m, false)).withContext(m.value).not.toMatch(/\b(?:covered|proven)\b/i);
    }
  });
});
