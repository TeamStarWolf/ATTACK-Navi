// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The Threat gaps predicate and the My marks bucket (P2-17, E2.2-d; design
// §3 P2-17, S5, §10.4 items 6 and 13).
import type { PostureBucket, PostureState, PostureSubState } from './posture.types';
import { POSTURE_TOKENS } from './posture-ramp';
import {
  MY_MARKS_TOGGLE_LABEL, MY_MARK_CONTRADICTED, THREAT_GAP_EXPOSURE_NOTE, THREAT_GAP_TOGGLE_LABEL,
  isThreatGap, myMarkBucket, myMarkFill, threatGapThreshold,
} from './gap';

type GapInput = Pick<PostureState, 'bucket' | 'subStates' | 'threatWeight' | 'exposureWeight' | 'excluded'>;

const state = (bucket: PostureBucket, over: Partial<GapInput> = {}): GapInput => ({
  bucket, subStates: [], threatWeight: 10, exposureWeight: 0, excluded: false, ...over,
});

describe('Threat gaps (P2-17)', () => {
  it('uses the exact toggle label and legend line', () => {
    expect(THREAT_GAP_TOGGLE_LABEL).toBe('Threat gaps: threat-relevant, posture None, Known only or contradicted');
    expect(THREAT_GAP_EXPOSURE_NOTE).toBe('Exposure counts on Enterprise only');
    expect(MY_MARKS_TOGGLE_LABEL).toBe('My marks');
  });

  describe('the predicate table (threat-relevant: weight 10 at q75 5)', () => {
    const contradicted: PostureSubState[] = ['contradicted'];
    const rows: Array<[string, GapInput, boolean]> = [
      ['none', state('none'), true],
      ['known', state('known'), true],
      ['contradicted (known after a later failed run)', state('known', { subStates: contradicted }), true],
      ['contradicted (none after a later failed run)', state('none', { subStates: contradicted }), true],
      ['partial', state('partial', { subStates: ['partial'] }), false],
      ['covered', state('covered'), false],
      ['proven', state('proven'), false],
      ['stale', state('stale', { subStates: ['stale'] }), false],
      ['excluded (not reproducible, known)', state('known', { excluded: true, subStates: ['not-reproducible'] }), false],
      ['excluded (not reproducible, none)', state('none', { excluded: true, subStates: ['not-reproducible'] }), false],
    ];
    for (const [name, s, gap] of rows) {
      it(`${name}: ${gap ? 'a gap' : 'not a gap'}`, () => {
        expect(isThreatGap(s, 5)).toBe(gap);
      });
    }
  });

  describe('threat relevance', () => {
    it('counts a weight at or above q75, not below it', () => {
      expect(isThreatGap(state('none', { threatWeight: 5 }), 5)).toBeTrue();
      expect(isThreatGap(state('none', { threatWeight: 4 }), 5)).toBeFalse();
    });

    it('counts any exposure, whatever the weight', () => {
      expect(isThreatGap(state('known', { threatWeight: 0, exposureWeight: 1 }), 5)).toBeTrue();
      expect(isThreatGap(state('covered', { threatWeight: 0, exposureWeight: 3 }), 5)).toBeFalse();
    });

    it('never counts a weight of 0, even when q75 is below 1', () => {
      expect(isThreatGap(state('none', { threatWeight: 0 }), 0)).toBeFalse();
      expect(isThreatGap(state('none', { threatWeight: 1 }), 0)).toBeTrue();
    });
  });

  describe('threatGapThreshold (q75: nearest-rank 75th percentile of non-zero weights, minimum 1)', () => {
    const weights = (w: Record<string, number>) => (id: string): number => w[id] ?? 0;

    it('takes the nearest-rank 75th percentile of the non-zero weights of the parents', () => {
      // Non-zero, sorted: 1 2 3 4 5 6 7 8; rank ceil(0.75 * 8) = 6 -> 6.
      const w = { a: 3, b: 1, c: 8, d: 5, e: 2, f: 7, g: 4, h: 6, zero: 0 };
      expect(threatGapThreshold(Object.keys(w), weights(w))).toBe(6);
    });

    it('reads only the profile parent set', () => {
      const w = { a: 1, b: 2, c: 100 };
      expect(threatGapThreshold(['a', 'b'], weights(w))).toBe(2);
    });

    it('is 1 for an empty profile or one with only zero weights', () => {
      expect(threatGapThreshold([], () => 7)).toBe(1);
      expect(threatGapThreshold(['a', 'b'], () => 0)).toBe(1);
    });

    it('is the one weight when there is one', () => {
      expect(threatGapThreshold(new Set(['a']), () => 9)).toBe(9);
    });

    it('never falls below 1 (fractional weights)', () => {
      expect(threatGapThreshold(['a', 'b'], () => 0.5)).toBe(1);
    });
  });
});

describe('My marks (P2-17)', () => {
  it('draws a bar for partial, covered, proven and stale, and for contradicted', () => {
    expect(myMarkBucket(state('partial'))).toBe('partial');
    expect(myMarkBucket(state('covered'))).toBe('covered');
    expect(myMarkBucket(state('proven'))).toBe('proven');
    expect(myMarkBucket(state('stale'))).toBe('stale');
    expect(myMarkBucket(state('known', { subStates: ['contradicted'] }))).toBe('contradicted');
    expect(myMarkBucket(state('none', { subStates: ['contradicted'] }))).toBe('contradicted');
  });

  it('draws no bar for none or known (a fresh profile renders no change)', () => {
    expect(myMarkBucket(state('none'))).toBeNull();
    expect(myMarkBucket(state('known'))).toBeNull();
    expect(myMarkBucket(state('known', { subStates: ['not-reproducible'] }))).toBeNull();
  });

  it('colours each bucket from the posture ramp tokens in both themes', () => {
    for (const theme of ['dark', 'light'] as const) {
      const t = POSTURE_TOKENS[theme];
      expect(myMarkFill('covered', theme)).toBe(t.covered.fill);
      expect(myMarkFill('partial', theme)).toBe(t.covered.fill);
      expect(myMarkFill('proven', theme)).toBe(t.proven.fill);
      expect(myMarkFill('stale', theme)).toBe(t.stale.fill);
      expect(myMarkFill('contradicted', theme)).toBe(MY_MARK_CONTRADICTED);
    }
  });
});
