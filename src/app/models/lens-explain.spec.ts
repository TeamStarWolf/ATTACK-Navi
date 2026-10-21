// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// lensExplain (P2-18, E2.3-b): "Why this colour" for the registry lenses from
// PostureState, and 'score N of max M: <formula>' for the legacy lenses.
import { heatmapModeDef } from './heatmap-modes';
import type { HeatmapMode } from '../services/filter.service';
import type { CoveredMark, PostureState, ProofRecord } from './posture/posture.types';
import { DEFAULT_POSTURE_RULES } from './posture/derive-posture';
import { basisWords, formatScore, lensExplain, postureExplain } from './lens-explain';

const def = (mode: HeatmapMode) => heatmapModeDef(mode)!;

const MIT_FULL: CoveredMark = { qualifier: 'self-attested', basis: 'mitigation-implemented', strength: 'full', via: 'M1036', source: 'manual' };
const MIT_PARTIAL: CoveredMark = { qualifier: 'self-attested', basis: 'mitigation-implemented', strength: 'partial', via: 'M1038', source: 'manual' };
const RUN: ProofRecord = {
  scope: 'own-run', detectionRef: 'sigma:4688-encoded', outcome: 'alerted', date: '2026-10-21T09:30:00.000Z', source: 'manual', runId: 'r1',
};

function state(over: Partial<PostureState>): PostureState {
  return {
    ref: 'attack/enterprise/T1078@19.2', rung: 'known', bucket: 'known', qualifiers: [], subStates: [], covered: [], proof: [],
    proofScope: null, proofAge: null, knownSignals: 3, threatWeight: 1, exposureWeight: 0, excluded: false, ...over,
  };
}

const PROVEN_STATE = state({ rung: 'proven', bucket: 'proven', proof: [RUN], proofScope: 'own-run', proofAge: 0 });
const COVERED_STATE = state({ rung: 'covered', bucket: 'covered', qualifiers: ['self-attested'], covered: [MIT_FULL] });
const PARTIAL_STATE = state({ rung: 'covered', bucket: 'partial', subStates: ['partial'], covered: [MIT_PARTIAL] });

describe('lensExplain (P2-18): Why this colour', () => {
  describe('the Posture lens explains from PostureState', () => {
    it('a fresh own run: the reviewer-walk sentence', () => {
      expect(lensExplain(def('posture'), { score: 0, bucket: 'proven' }, { state: PROVEN_STATE }))
        .toBe('Proven (your run) on 2026-10-21 by manual; 1 rule fired');
    });

    it('counts distinct rules and names the window of a stale record', () => {
      const stale = state({
        rung: 'proven', bucket: 'stale', subStates: ['stale'], proofScope: 'range', proofAge: 120,
        proof: [{ ...RUN, scope: 'range', source: 'lylat-range:CORNERIA-ROOT-01', date: '2026-06-01' },
          { ...RUN, scope: 'range', detectionRef: 'wazuh:990003', date: '2026-05-30' }],
      });
      expect(postureExplain(stale, DEFAULT_POSTURE_RULES.decayDays))
        .toBe('Proven in range (stale) on 2026-06-01 by lylat-range:CORNERIA-ROOT-01; 2 rules fired; older than its 90-day window');
    });

    it('Covered names its qualifier and the marks behind it', () => {
      expect(lensExplain(def('posture'), { score: 0, bucket: 'covered' }, { state: COVERED_STATE }))
        .toBe('Covered (self-attested) from mitigation implemented via M1036');
    });

    it('partial names the broad mitigation (D16)', () => {
      expect(postureExplain(PARTIAL_STATE)).toBe(
        'Covered (self-attested, partial via M1038): reached only through a mitigation or control mapped to more techniques than the breadth threshold');
    });

    it('Known counts the reference families; None says nothing is recorded', () => {
      expect(postureExplain(state({}))).toBe('Known: mapped (3 of 5 reference families)');
      expect(postureExplain(state({ rung: 'none', bucket: 'none', knownSignals: 0 })))
        .toBe('None: no reference data mapped and nothing of yours recorded');
    });

    // RP-F round 1: a contradicted mark or a not-reproducible verdict is the owner's
    // record, so the None line no longer says nothing of theirs is recorded.
    it('None with a contradicted mark or an excluded technique does not say nothing is recorded', () => {
      expect(postureExplain(state({ rung: 'none', bucket: 'none', knownSignals: 0, subStates: ['contradicted'] })))
        .toBe('None: no reference data mapped; a later failed run contradicts the marks');
      expect(postureExplain(state({ rung: 'none', bucket: 'none', knownSignals: 0, subStates: ['not-reproducible'], excluded: true })))
        .toBe('None: no reference data mapped; not reproducible, so left out of the denominator');
    });

    it('notes a contradicting run and an excluded technique', () => {
      const s = state({ subStates: ['contradicted', 'not-reproducible'], excluded: true });
      expect(postureExplain(s)).toBe(
        'Known: mapped (3 of 5 reference families); a later failed run contradicts the marks; not reproducible, so left out of the denominator');
    });
  });

  describe('the Proven and Covered lenses explain their own cell', () => {
    it('Proven: the proof line, or no recorded detection', () => {
      expect(lensExplain(def('proven'), { score: 2, bucket: 'proven', proofScope: 'own-run' }, { state: PROVEN_STATE }))
        .toBe('Proven (your run) on 2026-10-21 by manual; 1 rule fired');
      expect(lensExplain(def('proven'), { score: 0, bucket: 'none' }, { state: state({}) }))
        .toBe('No recorded detection for this technique');
    });

    it('Covered: full, partial and none', () => {
      expect(lensExplain(def('covered'), { score: 2, label: 'Covered (self-attested or range)' }, { state: COVERED_STATE }))
        .toBe('Covered (self-attested or range) from mitigation implemented via M1036');
      expect(lensExplain(def('covered'), { score: 1, label: 'Covered (self-attested or range), partial via M1038' }, { state: PARTIAL_STATE }))
        .toBe('Covered (self-attested or range), partial via M1038: reached only through a mitigation or control mapped to more techniques than the breadth threshold');
      expect(lensExplain(def('covered'), { score: 0, label: 'None' }, { state: state({ rung: 'none', bucket: 'none', knownSignals: 0 }) }))
        .toBe('None: nothing of yours reaches this technique');
    });

    // RP-F item 2: the Covered lens on a technique with no covered mark used to say
    // 'nothing of yours reaches this technique' while the same card's Proven block
    // listed a run. It now names the block that holds the evidence.
    describe('Covered, no covered mark (RP-F item 2)', () => {
      const NOT_NOTHING = /nothing of yours reaches this technique/;

      it('a Proven technique (fresh run) points to the Proven block', () => {
        const text = lensExplain(def('covered'), { score: 0, label: 'None' }, { state: PROVEN_STATE });
        expect(text).toBe('None: no covered (self-attested or range) mark; see the Proven block for its recorded result');
        expect(text).not.toMatch(NOT_NOTHING);
      });

      it('a stale-run technique points to the Proven block too', () => {
        const stale = state({ rung: 'proven', bucket: 'stale', subStates: ['stale'], proof: [{ ...RUN, date: '2026-01-02' }], proofScope: 'own-run', proofAge: 290 });
        const text = lensExplain(def('covered'), { score: 0, label: 'None' }, { state: stale });
        expect(text).toBe('None: no covered (self-attested or range) mark; see the Proven block for its recorded result');
        expect(text).not.toMatch(NOT_NOTHING);
      });

      it('a run with no reference data still points to the Proven block, and keeps the posture notes', () => {
        const s = state({ rung: 'proven', bucket: 'proven', proof: [RUN], proofScope: 'own-run', knownSignals: 0, excluded: true });
        expect(lensExplain(def('covered'), { score: 0, label: 'None' }, { state: s }))
          .toBe('None: no covered (self-attested or range) mark; see the Proven block for its recorded result; not reproducible, so left out of the denominator');
      });

      it('a Known-only technique points to the Known block with its family count', () => {
        const text = lensExplain(def('covered'), { score: 0, label: 'None' }, { state: state({}) });
        expect(text).toBe('None: no covered (self-attested or range) mark; see the Known block for its reference data (3 of 5 reference families)');
        expect(text).not.toMatch(NOT_NOTHING);
      });

      // RP-F round 1: the card read 'None: nothing of yours reaches this technique; a
      // later failed run contradicts the marks', contradicting itself.
      it('a contradicted full mark says the mark is contradicted, not "nothing of yours"', () => {
        const s = state({ rung: 'none', bucket: 'none', knownSignals: 0, subStates: ['contradicted'] });
        const text = lensExplain(def('covered'), { score: 0, label: 'None' }, { state: s });
        expect(text).toBe('None: a later failed run contradicts your covered (self-attested or range) marks');
        expect(text).not.toMatch(NOT_NOTHING);
      });

      it('a contradicted mark with Known data names the contradiction once, then the Known block', () => {
        const s = state({ rung: 'known', bucket: 'known', subStates: ['contradicted'] });
        const text = lensExplain(def('covered'), { score: 0, label: 'None' }, { state: s });
        expect(text).toBe('None: a later failed run contradicts your covered (self-attested or range) marks; see the Known block for its reference data (3 of 5 reference families)');
        expect(text).not.toContain('no covered');
      });

      it('a not-reproducible verdict is named, not "nothing of yours"', () => {
        const s = state({ rung: 'none', bucket: 'none', knownSignals: 0, subStates: ['not-reproducible'], excluded: true });
        const text = lensExplain(def('covered'), { score: 0, label: 'None' }, { state: s });
        expect(text).toBe('None: no covered (self-attested or range) mark; not reproducible, so left out of the denominator');
        expect(text).not.toMatch(NOT_NOTHING);
      });

      it('a technique with nothing keeps the old wording, which is true there', () => {
        expect(lensExplain(def('covered'), { score: 0, label: 'None' }, { state: state({ rung: 'none', bucket: 'none', knownSignals: 0 }) }))
          .toBe('None: nothing of yours reaches this technique');
      });
    });

    it('status and controls read their cell label', () => {
      expect(lensExplain(def('status'), { score: 4, label: 'Status: implemented, partial via M1038' }, { state: PARTIAL_STATE }))
        .toBe('Status: implemented, partial via M1038');
      expect(lensExplain(def('controls'), { score: 0 }, { state: state({}) })).toBe('score 0');
    });
  });

  describe("legacy lenses say 'score N of max M: <formula>'", () => {
    it('Mitigations mapped (the reviewer walk, heat=coverage)', () => {
      const text = lensExplain(def('coverage'), { score: 3 }, { state: state({}), max: 4 });
      expect(text).toBe(`score 3 of max 4: ${def('coverage').formula}`);
      expect(text).toMatch(/^score 3 of max 4: Count of ATT&CK mitigation relationships/);
    });

    it('a relative lens with a fractional score', () => {
      expect(lensExplain(def('risk'), { score: 12.5 }, { state: state({}), max: 40.333 }))
        .toBe(`score 12.5 of max 40.33: ${def('risk').formula}`);
    });

    it('a lens the matrix has not scored says how it is computed', () => {
      expect(lensExplain(def('sigma'), null, { state: state({}) }))
        .toBe(`not scored on the matrix in this session; ${def('sigma').formula}`);
      expect(lensExplain(def('frequency'), { score: 2 }, { state: state({}), max: null }))
        .toBe(`not scored on the matrix in this session; ${def('frequency').formula}`);
    });

    it('Reference depth (a score-only registry lens) is out of 100', () => {
      expect(lensExplain(def('unified'), { score: 45 }, { state: state({}) }))
        .toBe(`score 45 of max 100: ${def('unified').formula}`);
    });
  });

  it('formatScore and basisWords', () => {
    expect(formatScore(3)).toBe('3');
    expect(formatScore(1 / 3)).toBe('0.33');
    expect(basisWords('range-detection-authored')).toBe('detection authored in the range');
    expect(basisWords('own-run-blocked')).toBe('blocked in your run, no named rule');
  });
});
