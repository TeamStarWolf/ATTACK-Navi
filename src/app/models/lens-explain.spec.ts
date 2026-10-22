// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// lensExplain (P2-18, E2.3-b): "Why this colour" for the registry lenses from
// PostureState, and 'score N of max M: <formula>' for the legacy lenses.
import { heatmapModeDef } from './heatmap-modes';
import type { HeatmapMode } from '../services/filter.service';
import type { CoveredMark, PostureInputs, PostureState, ProofRecord, RunSummary } from './posture/posture.types';
import { DEFAULT_POSTURE_RULES, derivePosture } from './posture/derive-posture';
import { basisWords, formatScore, lensExplain, postureExplain, runsClause } from './lens-explain';

const def = (mode: HeatmapMode) => heatmapModeDef(mode)!;

const MIT_FULL: CoveredMark = { qualifier: 'self-attested', basis: 'mitigation-implemented', strength: 'full', via: 'M1036', source: 'manual' };
const MIT_PARTIAL: CoveredMark = { qualifier: 'self-attested', basis: 'mitigation-implemented', strength: 'partial', via: 'M1038', source: 'manual' };
const RUN: ProofRecord = {
  scope: 'own-run', detectionRef: 'sigma:4688-encoded', outcome: 'alerted', date: '2026-10-21T09:30:00.000Z', source: 'manual', runId: 'r1',
};

function state(over: Partial<PostureState>): PostureState {
  return {
    ref: 'attack/enterprise/T1078@19.2', rung: 'known', bucket: 'known', qualifiers: [], subStates: [], covered: [], proof: [],
    proofScope: null, proofAge: null, knownSignals: 3, threatWeight: 1, exposureWeight: 0, excluded: false, runsWithoutProof: [], ...over,
  };
}

const PROVEN_STATE = state({ rung: 'proven', bucket: 'proven', proof: [RUN], proofScope: 'own-run', proofAge: 0 });
const COVERED_STATE = state({ rung: 'covered', bucket: 'covered', qualifiers: ['self-attested'], covered: [MIT_FULL] });
const PARTIAL_STATE = state({ rung: 'covered', bucket: 'partial', subStates: ['partial'], covered: [MIT_PARTIAL] });

describe('lensExplain (P2-18): Why this colour', () => {
  describe('the Posture lens explains from PostureState', () => {
    it('a fresh own run: the reviewer-walk sentence', () => {
      expect(lensExplain(def('posture'), { score: 0, bucket: 'proven' }, { state: PROVEN_STATE }))
        .toBe('Proven (your run) on 10/21/26 by manual; 1 rule fired');
    });

    it('counts distinct rules and names the window of a stale record', () => {
      const stale = state({
        rung: 'proven', bucket: 'stale', subStates: ['stale'], proofScope: 'range', proofAge: 120,
        proof: [{ ...RUN, scope: 'range', source: 'lylat-range:CORNERIA-ROOT-01', date: '2026-06-01' },
          { ...RUN, scope: 'range', detectionRef: 'wazuh:990003', date: '2026-05-30' }],
      });
      expect(postureExplain(stale, DEFAULT_POSTURE_RULES.decayDays))
        .toBe('Proven in range (stale) on 6/1/26 by lylat-range:CORNERIA-ROOT-01; 2 rules fired; older than its 90-day window');
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
        .toBe('Proven (your run) on 10/21/26 by manual; 1 rule fired');
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

  // RP-F decision 9: a run of yours that yields no rung is acknowledged with its count,
  // latest status and date, and points to Detection Validation; it never reads as a rung.
  describe('runs of yours without proof (RP-F decision 9)', () => {
    const TODAY = new Date('2026-10-21T12:00:00.000Z');
    const run = (runId: string, status: string, date: string): RunSummary => ({ runId, status, date, source: 'manual' });
    /** The state derivePosture gives the technique, so the words follow the real derivation. */
    const derived = (attackId: string, over: Partial<PostureInputs>): PostureState => derivePosture(
      `attack/enterprise/${attackId}@19.2`,
      { knownSignals: 0, covered: [], proof: [], verdicts: [], threatWeight: 0, exposureWeight: 0, ...over },
      DEFAULT_POSTURE_RULES, TODAY);
    const RUNG_WORDS = /\bcovered\b|\bproven\b|\bdefended\b|\bvalidated\b/i;

    it('an untested run on T1069 (the Record Run defaults): None names the run, on Posture and on Covered', () => {
      const s = derived('T1069', { runs: [run('u1', 'untested', '2026-10-21T08:00:00.000Z')] });
      expect([s.bucket, s.runsWithoutProof.length]).toEqual(['none', 1]);
      const posture = lensExplain(def('posture'), { score: 0, bucket: 'none' }, { state: s });
      expect(posture).toBe('None: no reference data mapped; 1 run of yours recorded, latest untested on 10/21/26; see Detection Validation');
      expect(posture).not.toMatch(RUNG_WORDS);
      expect(lensExplain(def('covered'), { score: 0 }, { state: s }))
        .toBe('None: no covered (self-attested or range) mark; 1 run of yours recorded, latest untested on 10/21/26; see Detection Validation');
    });

    it('a seeded failed run (no marks, no rule): None names it with the latest status and date', () => {
      const s = derived('T1069', {
        runs: [run('f1', 'failed', '2026-10-20T08:00:00.000Z'), run('u0', 'untested', '2026-10-01T08:00:00.000Z')],
        verdicts: [{ date: '2026-10-20T08:00:00.000Z', failed: true, notReproducible: false, source: 'manual' }],
      });
      expect(postureExplain(s))
        .toBe('None: no reference data mapped; 2 runs of yours recorded, latest failed on 10/20/26; see Detection Validation');
      expect(lensExplain(def('covered'), { score: 0 }, { state: s })).not.toContain('nothing of yours reaches this technique');
    });

    it('a passed run with no named rule on T1059.001: the Known line gains the run, and the Covered fallback names it', () => {
      const s = derived('T1059.001', { knownSignals: 4, runs: [run('p1', 'passed', '2026-10-21T09:00:00.000Z')] });
      expect(s.bucket).toBe('known');
      const known = postureExplain(s);
      expect(known).toBe('Known: mapped (4 of 5 reference families); 1 run of yours recorded, latest passed on 10/21/26; see Detection Validation');
      expect(known).not.toMatch(RUNG_WORDS);
      expect(lensExplain(def('covered'), { score: 0 }, { state: s })).toBe(
        'None: no covered (self-attested or range) mark; see the Known block for its reference data (4 of 5 reference families); '
        + '1 run of yours recorded, latest passed on 10/21/26; see Detection Validation');
    });

    it('a run with a named rule is proof, not a run without proof; the Proven line is unchanged', () => {
      const s = derived('T1059.001', { knownSignals: 4, runs: [run('r1', 'passed', RUN.date)], proof: [RUN] });
      expect(s.runsWithoutProof).toEqual([]);
      expect(postureExplain(s)).toBe('Proven (your run) on 10/21/26 by manual; 1 rule fired');
    });

    // RP-F decision 16a: the UTC day of the timestamp (date.slice(0, 10)) read a day late.
    it('a run and a proof recorded after 19:00 local time print their local day, as the Validation pill does', () => {
      const late = new Date(2026, 9, 21, 19, 49).toISOString();
      expect(runsClause(derived('T1069', { runs: [run('f1', 'failed', late)] }))).toBe('1 run of yours recorded, latest failed on 10/21/26');
      const proven = derived('T1078', { runs: [run('p1', 'passed', late)], proof: [{ ...RUN, runId: 'p1', date: late }] });
      expect(postureExplain(proven)).toBe('Proven (your run) on 10/21/26 by manual; 1 rule fired');
    });

    it('a technique with no runs keeps the old wording', () => {
      expect(postureExplain(derived('T1069', {}))).toBe('None: no reference data mapped and nothing of yours recorded');
      expect(postureExplain(derived('T1059.001', { knownSignals: 4 }))).toBe('Known: mapped (4 of 5 reference families)');
      expect(lensExplain(def('covered'), { score: 0 }, { state: derived('T1069', {}) })).toBe('None: nothing of yours reaches this technique');
      expect(runsClause(derived('T1069', {}))).toBe('');
    });

    it('a contradicted mark with a failed run names the run, then the contradiction note', () => {
      const s = state({
        rung: 'none', bucket: 'none', knownSignals: 0, subStates: ['contradicted'], covered: [{ ...MIT_FULL, at: '2026-10-01' }],
        runsWithoutProof: [run('f1', 'failed', '2026-10-20')],
      });
      expect(postureExplain(s)).toBe('None: no reference data mapped; 1 run of yours recorded, latest failed on 10/20/26; '
        + 'see Detection Validation; a later failed run contradicts the marks');
      expect(lensExplain(def('covered'), { score: 0 }, { state: s })).toBe('None: a later failed run contradicts your covered '
        + '(self-attested or range) marks; 1 run of yours recorded, latest failed on 10/20/26; see Detection Validation');
    });
  });

  it('formatScore and basisWords', () => {
    expect(formatScore(3)).toBe('3');
    expect(formatScore(1 / 3)).toBe('0.33');
    expect(basisWords('range-detection-authored')).toBe('detection authored in the range');
    expect(basisWords('own-run-blocked')).toBe('blocked in your run, no named rule');
  });
});
