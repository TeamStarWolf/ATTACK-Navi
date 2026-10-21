// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The LensRegistry seam (Phase 2 design §2.5, §3 P2-13): exactly one lens is
// registry-hosted, appended last; the 33 older entries keep their index and
// stay legacy (no project, no color), so the matrix switchboard and the three
// colour copies still serve them unchanged.
import {
  HEATMAP_MODES, LENS_RUNG_MEANING, type LensContext, heatmapModeDef, isLensAvailable, lensAvailability, lensRungBadge,
} from './heatmap-modes';
import { isRegistryLens, registryCell, registryColor } from './lens-registry';
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
    theme,
    colorblindSafe: false,
  };
}

describe('LensRegistry seam (P2-13)', () => {
  it('hosts exactly one lens, posture, appended after the 33 legacy entries', () => {
    const hosted = HEATMAP_MODES.filter(isRegistryLens).map(m => m.value);
    expect(hosted).toEqual(['posture']);
    expect(HEATMAP_MODES.findIndex(m => m.value === 'posture')).toBe(33);
    for (const def of HEATMAP_MODES.slice(0, 33)) {
      expect(def.project).withContext(def.value).toBeUndefined();
      expect(def.color).withContext(def.value).toBeUndefined();
    }
  });

  it('is not fooled by a half-hosted or missing definition', () => {
    const status = heatmapModeDef('status')!;
    expect(isRegistryLens(undefined)).toBeFalse();
    expect(isRegistryLens(null)).toBeFalse();
    expect(isRegistryLens(status)).toBeFalse();
    expect(isRegistryLens({ ...status, project: () => ({ score: 0 }) })).toBeFalse();
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
