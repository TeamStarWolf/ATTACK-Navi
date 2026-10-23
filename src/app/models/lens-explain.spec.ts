// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// lensExplain (P2-18, E2.3-b): "Why this colour" for the registry lenses from
// PostureState, and 'score N of max M: <formula>' for the legacy lenses.
import { heatmapModeDef } from './heatmap-modes';
import type { HeatmapMode } from '../services/filter.service';
import type { CoveredMark, PostureInputs, PostureState, ProofRecord, RunSummary } from './posture/posture.types';
import { DEFAULT_POSTURE_RULES, PROVING_STATUSES, derivePosture } from './posture/derive-posture';
import { provingStatusWords } from './posture/proof-gap';
import { basisWords, formatScore, laterRunClause, lensExplain, postureExplain, provenNoneLine, runsClause, supersededClause } from './lens-explain';

const def = (mode: HeatmapMode) => heatmapModeDef(mode)!;

const MIT_FULL: CoveredMark = { qualifier: 'self-attested', basis: 'mitigation-implemented', strength: 'full', via: 'M1036', source: 'manual' };
const MIT_PARTIAL: CoveredMark = { qualifier: 'self-attested', basis: 'mitigation-implemented', strength: 'partial', via: 'M1038', source: 'manual', partialCause: 'breadth' };
/** A range telemetry-observed row's mark (RP-F decision 31), as runInputs produces it. */
const TELEMETRY_PARTIAL: CoveredMark = {
  qualifier: 'range', basis: 'range-telemetry-observed', strength: 'partial', via: 'wazuh:5', source: 'lylat-range:SYNTH-MISSION-T',
  at: '2026-10-21', partialCause: 'telemetry',
};
const BREADTH_SENTENCE = 'reached only through a mitigation or control mapped to more techniques than the breadth threshold';
const TELEMETRY_WORDS = 'range telemetry observed via wazuh:5: partial, no detection alerted';
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
        .toBe('Proven in a range run (stale) on 6/1/26 by lylat-range:CORNERIA-ROOT-01; 2 rules fired; older than its 90-day window');
    });

    // RP-F decision 30b, round 1 repair: the Proven line names the best record's RUN's
    // fired-rule count (runRulesFired, set by runInputs), never a count of the records
    // that stand, and never a count that mixes in another run's records.
    it("names the best record's run's own fired-rule count, even when only one of its records stands", () => {
      const partlyRemoved = state({ rung: 'proven', bucket: 'proven', proofScope: 'own-run', proofAge: 20, proof: [{ ...RUN, runRulesFired: 2 }] });
      expect(postureExplain(partlyRemoved)).toBe('Proven (your run) on 10/21/26 by manual; 2 rules fired');
    });

    it("a record without its run count counts the best run's standing records only, never another run's", () => {
      const twoRuns = state({
        rung: 'proven', bucket: 'proven', proofScope: 'own-run', proofAge: 0,
        proof: [{ ...RUN, runId: 'rB', detectionRef: 'sigma:y' },
          { ...RUN, runId: 'rA', detectionRef: 'sigma:x', date: '2026-10-01T09:30:00.000Z' },
          { ...RUN, runId: 'rA', detectionRef: 'sigma:z', date: '2026-10-01T09:30:00.000Z' }],
      });
      expect(postureExplain(twoRuns)).toBe('Proven (your run) on 10/21/26 by manual; 1 rule fired');
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

    // RP-F decision 31: the partial reason follows the marks' typed cause. Round 6 read
    // the breadth sentence for a telemetry-only range row (T1200) beside a Covered
    // block saying "telemetry observed in the range via wazuh:5 partial".
    describe('partial causes (RP-F decision 31)', () => {
      const telemetry = state({ rung: 'covered', bucket: 'partial', qualifiers: ['range'], subStates: ['partial', 'telemetry-observed'], covered: [TELEMETRY_PARTIAL], partialCauses: ['telemetry'] });
      const label = 'Covered (self-attested or range), partial via wazuh:5';

      it('a range telemetry partial reads the telemetry words on Posture and Covered, never the threshold sentence', () => {
        expect(postureExplain(telemetry)).toBe(`Covered (range, partial via wazuh:5) from ${TELEMETRY_WORDS}`);
        expect(lensExplain(def('covered'), { score: 1, label }, { state: telemetry })).toBe(`${label} from ${TELEMETRY_WORDS}`);
        for (const line of [postureExplain(telemetry), lensExplain(def('covered'), { score: 1, label }, { state: telemetry })]) {
          expect(line).not.toContain('breadth threshold');
        }
      });

      it('a breadth partial keeps its threshold sentence; both causes say both', () => {
        expect(postureExplain(PARTIAL_STATE)).toBe(`Covered (self-attested, partial via M1038): ${BREADTH_SENTENCE}`);
        const both = state({ rung: 'covered', bucket: 'partial', subStates: ['partial'], covered: [MIT_PARTIAL, TELEMETRY_PARTIAL] });
        expect(postureExplain(both)).toBe(`Covered (self-attested, range, partial via M1038, wazuh:5): ${BREADTH_SENTENCE}; ${TELEMETRY_WORDS}`);
      });

      it('reads the cause from the marks of a hand-built state, and names none for a mark without one', () => {
        const fromMarks = state({ rung: 'covered', bucket: 'partial', subStates: ['partial'], covered: [TELEMETRY_PARTIAL] });
        expect(postureExplain(fromMarks)).toBe(`Covered (range, partial via wazuh:5) from ${TELEMETRY_WORDS}`);
        const noRule = state({ rung: 'covered', bucket: 'partial', subStates: ['partial'], covered: [{ ...TELEMETRY_PARTIAL, via: undefined }] });
        expect(postureExplain(noRule)).toBe('Covered (range, partial) from range telemetry observed: partial, no detection alerted');
        const unnamed = state({ rung: 'covered', bucket: 'partial', subStates: ['partial'], covered: [{ ...MIT_PARTIAL, partialCause: undefined }] });
        expect(postureExplain(unnamed)).toBe('Covered (self-attested, partial via M1038)');
      });
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

    // RP-F decision 16b: a run's status governs its proof, and the latest run governs the rung.
    describe('the latest run governs (RP-F decision 16b)', () => {
      const at = (day: number, hour = 10) => new Date(2026, 9, day, hour, 0).toISOString();
      const fired = (runId: string, date: string) => ({ ...RUN, runId, date });

      it('T1135 shape: a failed run with a fired rule is not Proven; the line names the failed run', () => {
        const s = derived('T1135', { knownSignals: 2, runs: [run('f1', 'failed', at(20))], proof: [fired('f1', at(20))] });
        const posture = postureExplain(s);
        expect(posture).toBe('Known: mapped (2 of 5 reference families); 1 run of yours recorded, latest failed on 10/20/26; see Detection Validation');
        expect(posture).not.toMatch(RUNG_WORDS);
        expect(lensExplain(def('proven'), { score: 0 }, { state: s })).toBe('No recorded detection for this technique');
      });

      it('T1010 shape: passed then failed is not Proven, and the why line names both runs', () => {
        const s = derived('T1010', {
          knownSignals: 3,
          runs: [run('p1', 'passed', at(18)), run('f1', 'failed', at(20, 20))],
          proof: [fired('p1', at(18))],
          verdicts: [{ date: at(20, 20), failed: true, notReproducible: false, source: 'manual' }],
        });
        expect(s.bucket).toBe('known');
        const posture = postureExplain(s);
        expect(posture).toBe('Known: mapped (3 of 5 reference families); contradicted: latest run failed, no rule named, on 10/20/26; '
          + 'an earlier run passed on 10/18/26; see Detection Validation');
        expect(posture).not.toMatch(RUNG_WORDS);
        expect(posture).not.toContain('contradicts the marks');
        expect(lensExplain(def('proven'), { score: 0 }, { state: s }))
          .toBe('No recorded detection for this technique; contradicted: latest run failed, no rule named, on 10/20/26; an earlier run passed on 10/18/26');
        expect(lensExplain(def('covered'), { score: 0 }, { state: s })).toBe('None: no covered (self-attested or range) mark; '
          + 'see the Known block for its reference data (3 of 5 reference families); contradicted: latest run failed, no rule named, on 10/20/26; '
          + 'an earlier run passed on 10/18/26; see Detection Validation');
      });

      // RP-F decision 29: a run with no telemetry never removes proof; the why line names it.
      it('a run with no telemetry after a pass leaves it Proven and is named as a later run, not as a contradiction', () => {
        const s = derived('T1010', { runs: [run('p1', 'passed', at(18)), run('n1', 'no-telemetry', at(19))], proof: [fired('p1', at(18))] });
        expect(s.subStates).toEqual([]);
        expect(postureExplain(s)).toBe('Proven (your run) on 10/18/26 by manual; 1 rule fired; a later run on 10/19/26 had no telemetry');
      });

      it('a superseded proof with partial marks still names both runs', () => {
        const s = derived('T1078', {
          runs: [run('p1', 'passed', at(18)), run('f1', 'failed', at(20))], proof: [fired('p1', at(18))],
          covered: [{ ...MIT_FULL, strength: 'partial', via: 'M1038' }],
        });
        expect(s.bucket).toBe('partial');
        expect(postureExplain(s)).toContain('; contradicted: latest run failed, no rule named, on 10/20/26; an earlier run passed on 10/18/26; see Detection Validation');
      });

      it('a partial earlier run yields no proof (RP-F decision 23): the lines name both runs, never as passed', () => {
        const s = derived('T1010', {
          knownSignals: 3,
          runs: [run('r1', 'partial', at(18)), run('f1', 'failed', at(20))],
          proof: [fired('r1', at(18))],
          verdicts: [{ date: at(20), failed: true, notReproducible: false, source: 'manual' }],
        });
        expect(s.supersededProof).toBeNull();
        expect(s.proof).toEqual([]);
        const clause = '2 runs of yours recorded, latest failed on 10/20/26';
        expect(supersededClause(s)).toBe('');
        expect(postureExplain(s)).toBe(`Known: mapped (3 of 5 reference families); ${clause}; see Detection Validation`);
        expect(lensExplain(def('covered'), { score: 0 }, { state: s })).toContain(`; ${clause}; see Detection Validation`);
        for (const line of [postureExplain(s), lensExplain(def('proven'), { score: 0 }, { state: s })]) {
          expect(line).not.toContain('passed');
        }
      });

      // RP-F decision 28: a newer untested or not-reproducible run after a pass is named in the
      // why line by its status (round 4's T1518 stayed Proven and its why line said nothing).
      // RP-F decision 29: the untested run no longer removes the proof (supersession is per
      // rule, and only a failed or not-reproducible run of the rule removes it); it is named.
      it('a newer untested run after a pass is named as a later run; a not-reproducible one as the latest run, by its status', () => {
        const untested = derived('T1518', {
          knownSignals: 2, runs: [run('p1', 'passed', at(18)), run('u1', 'untested', at(20))], proof: [fired('p1', at(18))],
        });
        expect(untested.rung).toBe('proven');
        expect(postureExplain(untested)).toBe('Proven (your run) on 10/18/26 by manual; 1 rule fired; a later untested run on 10/20/26');
        const notRepro = derived('T1082', {
          knownSignals: 2, runs: [run('p1', 'passed', at(18)), run('n1', 'not-reproducible', at(20))], proof: [fired('p1', at(18))],
          verdicts: [{ date: at(20), failed: false, notReproducible: true, source: 'manual' }],
        });
        expect(supersededClause(notRepro)).toBe('latest run was not reproducible, no rule named, on 10/20/26; an earlier run passed on 10/18/26');
        expect(lensExplain(def('proven'), { score: 0 }, { state: notRepro }))
          .toBe('No recorded detection for this technique; latest run was not reproducible, no rule named, on 10/20/26; an earlier run passed on 10/18/26'
            + '; not reproducible, so left out of the denominator');
      });

      // RP-F decision 28: the Proven lens never says "No recorded detection" beside a run that fired a rule.
      it('a run that fired a rule without proof is named, with its date and status, instead of "No recorded detection"', () => {
        const s = derived('T1018', { knownSignals: 2, runs: [{ ...run('s12', 'untested', at(15)), rulesFired: 1 }], proof: [fired('s12', at(15))] });
        const line = 'No proof: 1 rule fired in your run on 10/15/26 (status untested); a run is proof only when its status is passed';
        expect(provenNoneLine(s)).toBe(line);
        expect(lensExplain(def('proven'), { score: 0 }, { state: s })).toBe(line);
        expect(provenNoneLine(state({ runsWithoutProof: [{ ...run('x', 'failed', at(15)), rulesFired: 2 }] })))
          .toBe('No proof: 2 rules fired in your run on 10/15/26 (status failed); a run is proof only when its status is passed');
        expect(provenNoneLine(state({ runsWithoutProof: [run('u', 'untested', at(15))] }))).toBe('No recorded detection for this technique');
      });

      // RP-F round 4 repair: a passed run whose proof a later run outranked fired a rule the pill
      // still shows ("range-run rules: siem:curated"), so the Proven block names it too (S27 T1059.001).
      it('a passed run whose proof a later run outranked is named, never "No recorded detection"', () => {
        const s = derived('T1059.001', {
          knownSignals: 2,
          runs: [{ ...run('m1', 'passed', at(18)), rulesFired: 1 }, run('f', 'failed', at(20))],
          proof: [fired('m1', at(18))],
        });
        expect(s.proof.length).toBe(0);
        expect(provenNoneLine(s)).toBe('No proof: 1 rule fired in your run on 10/18/26 (status passed); a later run outranks it');
        expect(lensExplain(def('proven'), { score: 0 }, { state: s })).not.toContain('No recorded detection');
        // A passed run whose date cannot be read is sorted oldest, flagged, and named with why it is not proof.
        expect(provenNoneLine(state({ runsWithoutProof: [{ ...run('y', 'passed', 'yesterday'), rulesFired: 1 }] })))
          .toBe("No proof: 1 rule fired in your run on 'yesterday' (unreadable date, sorted oldest) (status passed); "
            + 'a run is proof only with a readable date');
      });

      // RP-F decision 23: the proof rule is read from the one allow-list, never a status literal.
      it('the "proof only when" words follow PROVING_STATUSES', () => {
        expect(provingStatusWords()).toBe([...PROVING_STATUSES].join(' or '));
        expect(provenNoneLine(state({ runsWithoutProof: [{ ...run('x', 'partial', at(15)), rulesFired: 1 }] })))
          .toContain(`a run is proof only when its status is ${provingStatusWords()}`);
      });

      it('the runs-without-proof clause flags a run whose date cannot be read (RP-F decision 24)', () => {
        expect(runsClause(state({ runsWithoutProof: [run('y', 'failed', 'yesterday')] })))
          .toBe("1 run of yours recorded, latest failed on 'yesterday' (unreadable date, sorted oldest)");
      });

      // RP-F decision 39 (round 7): a manual failed run recorded without a rule id is matched
      // on source plus technique (decision 29), so it is never called a run "of the rule".
      it('a manual run with no rule id reads "latest run failed, no rule named"; a run that names its rule keeps "of the rule"', () => {
        const clause = (latest: ReturnType<typeof run>) => supersededClause({
          subStates: ['contradicted'], supersededProof: { latest, earlier: fired('p1', at(18)), earlierStatus: 'passed' },
        });
        expect(clause(run('f1', 'failed', at(20)))).toBe('contradicted: latest run failed, no rule named, on 10/20/26; an earlier run passed on 10/18/26');
        expect(clause({ ...run('f1', 'failed', at(20)), rules: [] })).not.toContain('of the rule');
        expect(clause({ ...run('f1', 'failed', at(20)), rules: ['sigma:4688'] }))
          .toBe('contradicted: latest run of the rule failed on 10/20/26; an earlier run passed on 10/18/26');
        expect(supersededClause({ subStates: [], supersededProof: { latest: run('n1', 'not-reproducible', at(20)), earlier: fired('p1', at(18)), earlierStatus: 'passed' } }))
          .toBe('latest run was not reproducible, no rule named, on 10/20/26; an earlier run passed on 10/18/26');
      });

      it('an earlier untested or not-reproducible run is named by its status; a record with no run listed names the rule only', () => {
        const words = (status: string | null) => supersededClause({
          subStates: [],
          supersededProof: { latest: run('f1', 'failed', at(20)), earlier: fired('r1', at(18)), earlierStatus: status },
        });
        expect(words('untested')).toBe('latest run failed, no rule named, on 10/20/26; an earlier run was untested on 10/18/26');
        expect(words('not-reproducible')).toBe('latest run failed, no rule named, on 10/20/26; an earlier run was not reproducible on 10/18/26');
        expect(words('passed')).toBe('latest run failed, no rule named, on 10/20/26; an earlier run passed on 10/18/26');
        expect(words(null)).toBe('latest run failed, no rule named, on 10/20/26; an earlier named rule fired on 10/18/26');
        const unlisted = derived('T1010', { runs: [run('f1', 'failed', at(20))], proof: [fired('other', at(18))] });
        expect(unlisted.supersededProof!.earlierStatus).toBeNull();
      });

      // RP-F decision 29 (#236, journey 3): the P2-20 fixture's T1003.001 has an alerted run
      // and a later telemetry-observed run of ANOTHER rule. It stays Proven, and the why line
      // names the later run, so the cell never hides the run the pill shows.
      it('T1003.001 shape: Proven, and the why line names the later telemetry-only run of another rule', () => {
        const RANGE = 'lylat-range:SYNTH-MISSION-A' as const;
        const s = derived('T1003.001', {
          runs: [
            { runId: 'a1', status: 'passed', date: '2026-10-15', source: RANGE, rules: ['wazuh:990001'] },
            { runId: 't1', status: 'partial', date: '2026-10-18', source: RANGE, rules: ['wazuh:990004'] },
          ],
          proof: [{ scope: 'range', detectionRef: 'wazuh:990001', outcome: 'alerted', date: '2026-10-15', source: RANGE, runId: 'a1' }],
        });
        expect(s.bucket).toBe('proven');
        const line = postureExplain(s);
        expect(line).toMatch(/ on 10\/15\/26 by lylat-range:SYNTH-MISSION-A; 1 rule fired; a later run on 10\/18\/26 observed telemetry only$/);
        expect(lensExplain(def('proven'), { score: 3 }, { state: s })).toBe(line);
      });

      it('passed then failed of the SAME rule: not Proven, "latest run of the rule failed"; of a DIFFERENT rule: Proven, the failed run named', () => {
        const ruled = (runId: string, status: string, date: string, rules: string[]): RunSummary => ({ ...run(runId, status, date), rules });
        const ref = RUN.detectionRef;
        const same = derived('T1010', {
          knownSignals: 2, runs: [ruled('p1', 'passed', at(18), [ref]), ruled('f1', 'failed', at(20), [ref])], proof: [fired('p1', at(18))],
        });
        expect(same.rung).toBe('known');
        expect(postureExplain(same)).toContain('latest run of the rule failed on 10/20/26; an earlier run passed on 10/18/26');
        const other = derived('T1010', {
          knownSignals: 2, runs: [ruled('p1', 'passed', at(18), [ref]), ruled('f1', 'failed', at(20), ['sigma:other'])], proof: [fired('p1', at(18))],
        });
        expect(other.rung).toBe('proven');
        expect(postureExplain(other)).toBe('Proven (your run) on 10/18/26 by manual; 1 rule fired; a later run of another rule failed on 10/20/26');
      });

      // RP-F round 4 repair: the remover is the latest run OF THE RULE; a newer run that
      // removed nothing (the one the Detection Validation pill shows) is named after it.
      it('passed R, failed R, then a later untested run: the remover is the latest run of the rule, and the untested run is named', () => {
        const ruled = (runId: string, status: string, date: string, rules: string[]): RunSummary => ({ ...run(runId, status, date), rules });
        const ref = RUN.detectionRef;
        const s = derived('T1010', {
          knownSignals: 2,
          runs: [ruled('p1', 'passed', at(18), [ref]), ruled('f1', 'failed', at(20), [ref]), run('u1', 'untested', at(21))],
          proof: [fired('p1', at(18))],
        });
        expect(s.rung).toBe('known');
        expect(s.supersededProof!.latest.runId).toBe('f1');
        expect(s.laterRuns!.map(r => r.runId)).toEqual(['u1']);
        expect(postureExplain(s)).toBe('Known: mapped (2 of 5 reference families); contradicted: latest run of the rule failed on 10/20/26; '
          + 'an earlier run passed on 10/18/26; a later untested run on 10/21/26; see Detection Validation');
        expect(postureExplain(s)).not.toMatch(RUNG_WORDS);
        expect(lensExplain(def('proven'), { score: 0 }, { state: s })).toBe('No recorded detection for this technique; '
          + 'contradicted: latest run of the rule failed on 10/20/26; an earlier run passed on 10/18/26; a later untested run on 10/21/26');

        // Several newer runs: the newest is named and the rest counted, with one pointer to Detection Validation.
        const more = derived('T1010', {
          knownSignals: 2,
          runs: [ruled('p1', 'passed', at(18), [ref]), ruled('f1', 'failed', at(20), [ref]),
            ruled('o1', 'failed', at(21), ['sigma:other']), run('p2', 'passed', at(22))],
          proof: [fired('p1', at(18))],
        });
        expect(more.laterRuns!.map(r => r.runId)).toEqual(['p2', 'o1']);
        expect(postureExplain(more)).toBe('Known: mapped (2 of 5 reference families); contradicted: latest run of the rule failed on 10/20/26; '
          + 'an earlier run passed on 10/18/26; a later run passed on 10/22/26 with no proof record (1 more later run); see Detection Validation');
        expect(supersededClause(more)).not.toContain('; see Detection Validation');

        // No run after the remover: nothing is appended.
        const none = derived('T1010', {
          knownSignals: 2, runs: [ruled('p1', 'passed', at(18), [ref]), ruled('f1', 'failed', at(20), [ref])], proof: [fired('p1', at(18))],
        });
        expect(none.laterRuns).toEqual([]);
        expect(supersededClause(none)).toBe('contradicted: latest run of the rule failed on 10/20/26; an earlier run passed on 10/18/26');
      });

      it('the later-run clause: each status in words, the count of further later runs, and none when there is none', () => {
        const clause = (...runs: RunSummary[]) => laterRunClause({ laterRuns: runs });
        expect(clause(run('r', 'partial', at(20)))).toBe('a later partial run on 10/20/26');
        expect(clause({ ...run('t', 'partial', at(20)), source: 'lylat-range:M' })).toBe('a later run on 10/20/26 observed telemetry only');
        expect(clause(run('n', 'not-reproducible', at(20)))).toBe('a later run of another rule was not reproducible on 10/20/26');
        expect(clause(run('u', 'untested', at(20)), run('f', 'failed', at(19))))
          .toBe('a later untested run on 10/20/26 (1 more later run; see Detection Validation)');
        expect(clause(run('u', 'untested', at(20)), run('f', 'failed', at(19)), run('g', 'failed', at(19))))
          .toBe('a later untested run on 10/20/26 (2 more later runs; see Detection Validation)');
        expect(clause()).toBe('');
        expect(laterRunClause({})).toBe('');
      });

      it('passed then passed: Proven on the latest date; failed then passed: Proven', () => {
        const twice = derived('T1078', { runs: [run('p1', 'passed', at(18)), run('p2', 'passed', at(20))], proof: [fired('p1', at(18)), fired('p2', at(20))] });
        expect(postureExplain(twice)).toBe('Proven (your run) on 10/20/26 by manual; 1 rule fired');
        const recovered = derived('T1078', { runs: [run('f1', 'failed', at(18)), run('p1', 'passed', at(20))], proof: [fired('p1', at(20))] });
        expect(postureExplain(recovered)).toBe('Proven (your run) on 10/20/26 by manual; 1 rule fired');
      });
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
