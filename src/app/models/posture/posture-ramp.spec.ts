// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The Posture lens's ramp tokens, projection and stop words (P2-13). The CVD
// guarantee itself is posture-ramp.cvd.spec.ts.
import { HEATMAP_MODES, LENS_NA_COLOR, heatmapModeDef } from '../heatmap-modes';
import { hexContrast, mixHex } from '../cvd';
import type { Technique } from '../technique';
import { PROVEN, postureBadge, scenarioOutcomeLabel } from './posture-vocabulary';
import {
  POSTURE_BUCKETS, POSTURE_PATTERN_CLASS, POSTURE_SCORE, POSTURE_SURFACE, POSTURE_TOKENS, STALE_MIX, type PostureTheme,
  postureColor, postureFill, postureHasCheck, postureLegendStops, postureLensCell, posturePatterns, postureProject,
  postureCellLabel, postureRampStops, postureStopLabel, CONTRADICTED_SPOKEN_LENSES, CONTRADICTED_WORDS,
} from './posture-ramp';
import { stubState } from '../../testing/posture-stub';
import { isPostureCellLens } from '../lens-registry';
import { lensExplain } from '../lens-explain';
import type { LensContext } from '../heatmap-modes';
import type { PostureState } from './posture.types';

const THEMES: readonly PostureTheme[] = ['dark', 'light'];
const T = { id: 'attack-pattern--1', attackId: 'T1001' } as Technique;

describe('posture ramp tokens (P2-13)', () => {
  it('none is the surface, partial is the Known fill, stale is proven mixed 50% toward the surface', () => {
    for (const theme of THEMES) {
      expect(postureFill('none', theme)).toBe(POSTURE_SURFACE[theme]);
      expect(postureFill('partial', theme)).toBe(postureFill('known', theme));
      expect(STALE_MIX).toBe(0.5);
      expect(postureFill('stale', theme)).toBe(mixHex(postureFill('proven', theme), POSTURE_SURFACE[theme], 0.5));
      expect(postureFill('stale', theme)).not.toBe(postureFill('proven', theme));
    }
  });

  it('gives every bucket a fill and a text colour in both themes, distinct per ordinal hue', () => {
    for (const theme of THEMES) {
      const t = POSTURE_TOKENS[theme];
      expect(Object.keys(t).sort()).toEqual([...POSTURE_BUCKETS].sort());
      const hues = new Set([t.none.fill, t.known.fill, t.covered.fill, t.proven.fill, t.stale.fill]);
      expect(hues.size).withContext(theme).toBe(5);
      for (const b of POSTURE_BUCKETS) expect(['#000000', '#ffffff']).toContain(t[b].text);
    }
  });

  it('picks the text colour that reads better on each fill', () => {
    for (const theme of THEMES) {
      for (const b of POSTURE_BUCKETS) {
        const { fill, text } = POSTURE_TOKENS[theme][b];
        const other = text === '#000000' ? '#ffffff' : '#000000';
        expect(hexContrast(fill, text)).withContext(`${theme} ${b}`).toBeGreaterThanOrEqual(hexContrast(fill, other));
      }
    }
  });

  it('never uses the n/a colour, which stays the lensUnavailable hatch', () => {
    const fills = THEMES.flatMap(theme => POSTURE_BUCKETS.map(b => postureFill(b, theme).toLowerCase()));
    expect(fills).not.toContain(LENS_NA_COLOR.toLowerCase());
  });
});

describe('posture projection and colour (§2.5)', () => {
  it('projects the technique\'s own state through ctx.posture', () => {
    const state = { ...stubState('T1001', 'stale'), subStates: ['stale' as const] };
    const cell = postureProject({ posture: () => state }, T);
    expect(cell).toEqual({ score: POSTURE_SCORE.stale, bucket: 'stale', subStates: ['stale'], proofScope: 'own-run' });
  });

  it('orders the score by rung, with stale below fresh proof', () => {
    const order = [...POSTURE_BUCKETS].sort((a, b) => POSTURE_SCORE[a] - POSTURE_SCORE[b]);
    expect(order).toEqual(['none', 'known', 'partial', 'covered', 'stale', 'proven']);
  });

  it('colours by bucket and theme, and ignores the colorblind-safe setting (safe by default)', () => {
    for (const theme of THEMES) {
      for (const b of POSTURE_BUCKETS) {
        const cell = { score: POSTURE_SCORE[b], bucket: b };
        expect(postureColor(cell, { theme, colorblindSafe: false })).toBe(postureFill(b, theme));
        expect(postureColor(cell, { theme, colorblindSafe: true })).toBe(postureFill(b, theme));
      }
    }
    expect(postureColor({ score: 0 }, { theme: 'dark', colorblindSafe: false })).toBe(POSTURE_SURFACE.dark);
  });

  it('rebuilds a LensCell from the cell input, and none for no input', () => {
    expect(postureLensCell(null)).toEqual({ score: 0, bucket: 'none', subStates: [], proofScope: null });
    expect(postureLensCell({ bucket: 'proven', subStates: [], proofScope: 'range', label: 'x' }))
      .toEqual({ score: POSTURE_SCORE.proven, bucket: 'proven', subStates: [], proofScope: 'range' });
  });

  it('draws patterns for partial, contradicted and not reproducible, and the check mark on recorded detections', () => {
    expect(posturePatterns({ bucket: 'partial', subStates: ['partial', 'contradicted', 'not-reproducible'] }))
      .toEqual(['partial', 'contradicted', 'not-reproducible']);
    expect(posturePatterns({ bucket: 'known', subStates: ['planned', 'telemetry-observed'] })).toEqual([]);
    expect(POSTURE_BUCKETS.filter(postureHasCheck)).toEqual(['proven', 'stale']);
  });
});

describe('posture stop words and legend stops', () => {
  it('takes every rung word from the vocabulary module, Covered always with its qualifier', () => {
    expect(postureStopLabel('none')).toBe(scenarioOutcomeLabel('none'));
    expect(postureStopLabel('known')).toBe(scenarioOutcomeLabel('known'));
    expect(postureStopLabel('covered')).toBe(scenarioOutcomeLabel('covered'));
    expect(postureStopLabel('partial')).toBe(`${scenarioOutcomeLabel('covered')}, partial`);
    expect(postureStopLabel('proven')).toBe(PROVEN);
    expect(postureStopLabel('stale')).toBe(`${PROVEN} (stale)`);
    for (const key of [...POSTURE_BUCKETS, 'contradicted', 'not-reproducible'] as const) {
      expect(postureStopLabel(key)).not.toMatch(/\bcovered\b(?!\s*\((?:self-attested|range))/i);
    }
  });

  it('lists the six buckets then the two sub-state patterns, with their pattern classes', () => {
    for (const theme of THEMES) {
      const stops = postureLegendStops(theme);
      expect(stops.map(s => s.key)).toEqual([...POSTURE_BUCKETS, 'contradicted', 'not-reproducible']);
      expect(stops.map(s => s.patternClass)).toEqual([
        null, null, POSTURE_PATTERN_CLASS.partial, null, null, null,
        POSTURE_PATTERN_CLASS.contradicted, POSTURE_PATTERN_CLASS['not-reproducible'],
      ]);
      expect(stops.filter(s => s.check).map(s => s.key)).toEqual(['proven', 'stale']);
      for (const s of stops.slice(0, 6)) expect(s.fill).toBe(postureFill(s.key as typeof POSTURE_BUCKETS[number], theme));
    }
  });

  it('is the registry\'s ramp for the posture lens (dark fills, the minimap\'s starting theme)', () => {
    const def = heatmapModeDef('posture')!;
    expect(def.ramp.scale).toBe('categorical');
    expect(def.ramp.stops).toEqual(postureRampStops());
    expect(def.ramp.stops.map(s => s.color)).toEqual(POSTURE_BUCKETS.map(b => postureFill(b, 'dark')));
    expect(HEATMAP_MODES[33]).toBe(def);   // appended by P2-13; P2-14 appends proven and covered after it
  });
});

// §7 Decay, Rendering: a stale cell's aria-label and tooltip read
// "stale (N days; window W)"; every other cell reads postureBadge(state).
describe('posture cell label (§7)', () => {
  const WINDOWS = { range: 90, production: 180, 'own-run': 90 } as const;

  it('names the proof age and the decay window on a stale cell', () => {
    const s = stubState('T1078', 'stale');
    expect(s.proofAge).toBe(120);
    expect(postureCellLabel(s, WINDOWS)).toBe(`${PROVEN} (your run), stale (120 days; window 90)`);
    expect(postureCellLabel({ ...s, proofScope: 'production', proofAge: 200 }, WINDOWS)).toBe(`${PROVEN} in production, stale (200 days; window 180)`);
    expect(postureCellLabel({ ...s, proofScope: 'range', proofAge: 95 }, { ...WINDOWS, range: 30 })).toBe(`${PROVEN} in range, stale (95 days; window 30)`);
  });

  it('is the badge on every other bucket, and on a stale state with no age', () => {
    for (const bucket of POSTURE_BUCKETS.filter(b => b !== 'stale')) {
      const s = stubState('T1078', bucket);
      expect(postureCellLabel(s, WINDOWS)).withContext(bucket).toBe(postureBadge(s));
    }
    const ageless = { ...stubState('T1078', 'stale'), proofAge: null };
    expect(postureCellLabel(ageless, WINDOWS)).toBe(postureBadge(ageless));
  });

  // RP-F decision 11: one builder and one phrase. A contradicted cell names the
  // legend's words on Posture, Covered and Status, the way a stale cell names its age.
  describe('a contradicted state (RP-F decision 11)', () => {
    const contradicted = (bucket: Parameters<typeof stubState>[1]) =>
      ({ ...stubState('T1078', bucket), subStates: ['contradicted' as const] });

    it("uses the legend stop's phrase", () => {
      expect(CONTRADICTED_WORDS).toBe('contradicted by a later failed run');
      expect(postureStopLabel('contradicted')).toBe(CONTRADICTED_WORDS);
      expect([...CONTRADICTED_SPOKEN_LENSES]).toEqual(['posture', 'covered', 'proven', 'status']);
    });

    it('appends it to the Posture words, after a stale age', () => {
      const known = contradicted('known');
      expect(postureCellLabel(known, WINDOWS)).toBe(`${postureBadge(known)}, ${CONTRADICTED_WORDS}`);
      const stale = contradicted('stale');
      expect(postureCellLabel(stale, WINDOWS))
        .toBe(`${PROVEN} (your run), stale (120 days; window 90), ${CONTRADICTED_WORDS}`);
    });

    it("appends it to a Covered, Proven or Status lens's own words; Controls keeps its own (RP-F decision 17)", () => {
      const s = contradicted('known');
      expect(postureCellLabel(s, WINDOWS, { value: 'status', words: 'Status: implemented' }))
        .toBe(`Status: implemented, ${CONTRADICTED_WORDS}`);
      expect(postureCellLabel(s, WINDOWS, { value: 'covered', words: 'None' })).toBe(`None, ${CONTRADICTED_WORDS}`);
      expect(postureCellLabel(s, WINDOWS, { value: 'proven', words: 'no recorded detection' }))
        .toBe(`no recorded detection, ${CONTRADICTED_WORDS}`);
      expect(postureCellLabel(s, WINDOWS, { value: 'controls', words: 'Controls: none' })).toBe('Controls: none');
    });

    // RP-F decision 17: paints implies speaks. The Proven lens drew the hatch on 6 of 6
    // contradicted cells in round 3 while its aria-label said only "no recorded detection".
    describe('paints implies speaks, over every posture-cell lens (RP-F decision 17)', () => {
      const FULL = {
        qualifier: 'self-attested' as const, basis: 'mitigation-implemented' as const, strength: 'full' as const, via: 'M1015', source: 'manual' as const,
      };
      const PARTIAL = { ...FULL, strength: 'partial' as const, via: 'M1038' };
      const RUN = { runId: 'f1', status: 'failed', date: '2026-10-20T15:00:00.000Z', source: 'manual' as const };
      const base = stubState('T1078', 'known');
      /**
       * The contradicted shapes derivePosture produces: a contradicted full mark (T1078: M1015
       * and a later failed run), with and without partial marks, and a proof a later failed
       * run outranked (T1010, RP-F decision 16).
       */
      const SHAPES: Record<string, PostureState> = {
        'contradicted mark, Known': { ...base, subStates: ['contradicted'], covered: [FULL], runsWithoutProof: [RUN] },
        'contradicted mark, partial': {
          ...base, rung: 'covered', bucket: 'partial', qualifiers: ['self-attested'], subStates: ['contradicted', 'partial'],
          covered: [FULL, PARTIAL], runsWithoutProof: [RUN],
        },
        'outranked proof, None': {
          ...stubState('T1010', 'none'), subStates: ['contradicted'], runsWithoutProof: [RUN],
          supersededProof: {
            latest: RUN,
            earlier: { scope: 'own-run', detectionRef: 'sigma:1', outcome: 'alerted', date: '2026-10-18T15:00:00.000Z', source: 'manual', runId: 'p1' },
            earlierStatus: 'passed',
          },
        },
      };
      const ctx = (s: PostureState): LensContext => ({
        posture: () => s,
        known: () => ({ mitigation: true, detection: false, control: false, d3fend: false, atomic: false }),
        knownCounts: () => ({ mitigations: 1, detectionContent: 0, controls: 0, d3fend: 0, atomic: 0 }),
        implView: () => ({ status: 'implemented', partialVia: null }),
        theme: 'dark', colorblindSafe: false,
      } as unknown as LensContext);
      const lenses = HEATMAP_MODES.filter(d => isPostureCellLens(d));
      const paints = (def: (typeof HEATMAP_MODES)[number], s: PostureState): boolean => {
        const cell = def.project!(ctx(s), T);
        return posturePatterns({ bucket: cell.bucket ?? 'none', subStates: cell.subStates ?? [] }).includes('contradicted');
      };

      it('covers the five posture-cell lenses; Posture, Covered and Proven paint the hatch', () => {
        expect(lenses.map(d => d.value).sort()).toEqual(['controls', 'covered', 'posture', 'proven', 'status']);
        expect(lenses.filter(d => paints(d, SHAPES['contradicted mark, Known'])).map(d => d.value).sort())
          .toEqual(['covered', 'posture', 'proven']);
      });

      for (const [shape, s] of Object.entries(SHAPES)) {
        it(`${shape}: every lens whose cell paints the contradicted hatch is in the spoken set; spoken lenses say it in label and why line`, () => {
          for (const def of lenses) {
            const cell = def.project!(ctx(s), T);
            const label = postureCellLabel(s, WINDOWS, def.value === 'posture' ? { value: 'posture' } : { value: def.value, words: cell.label });
            const why = lensExplain(def, cell, { state: s });
            if (paints(def, s)) {
              expect(CONTRADICTED_SPOKEN_LENSES.has(def.value)).withContext(`${def.value} paints the hatch`).toBeTrue();
            }
            if (CONTRADICTED_SPOKEN_LENSES.has(def.value)) {
              expect(label).withContext(`${def.value} aria-label`).toContain(CONTRADICTED_WORDS);
              expect(why).withContext(`${def.value} why line`).toMatch(/contradict/);
            }
          }
        });
      }

      it('Status paints no hatch, yet its label and why line name the contradiction', () => {
        const s = SHAPES['contradicted mark, Known'];
        const def = heatmapModeDef('status')!;
        expect(paints(def, s)).toBeFalse();
        expect(lensExplain(def, def.project!(ctx(s), T), { state: s })).toBe(`Status: implemented; ${CONTRADICTED_WORDS}`);
      });

      it('the Proven lens names the outranked proof, or the contradicted marks, in its why line', () => {
        const def = heatmapModeDef('proven')!;
        const s = SHAPES['outranked proof, None'];
        expect(lensExplain(def, def.project!(ctx(s), T), { state: s }))
          .toMatch(/^No recorded detection for this technique; contradicted: latest run failed on \d+\/\d+\/26; an earlier run passed on \d+\/\d+\/26$/);
        const marks = SHAPES['contradicted mark, Known'];
        expect(lensExplain(def, def.project!(ctx(marks), T), { state: marks }))
          .toBe(`No recorded detection for this technique; ${CONTRADICTED_WORDS}`);
      });
    });

    it('adds nothing without the contradicted sub-state', () => {
      const s = { ...stubState('T1078', 'known'), subStates: ['not-reproducible' as const] };
      expect(postureCellLabel(s, WINDOWS)).toBe(postureBadge(s));
      expect(postureCellLabel(s, WINDOWS, { value: 'status', words: 'Status: implemented' })).toBe('Status: implemented');
    });
  });
});
