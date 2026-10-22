// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// One row per branch of the rung derivation (Phase 2 design §2.2). CI gates
// this file's subject at 100% branch coverage (scripts/check-branch-coverage.mjs).
import { DEFAULT_POSTURE_RULES, derivePosture, tallyPosture } from './derive-posture';
import type { CoveredMark, PostureInputs, PostureState, ProofRecord, ProofScope, RunSummary, RunVerdict } from './posture.types';
import type { TechniqueRefKey } from '../technique-ref';

/** POSTURE_TODAY, pinned (§7, R14): every date below is relative to it. */
const TODAY = new Date('2026-10-01T12:00:00.000Z');
const daysAgo = (n: number): string => new Date(Date.UTC(2026, 9, 1) - n * 86_400_000).toISOString().slice(0, 10);
const REF: TechniqueRefKey = 'attack/enterprise/T1059.001@19.2';
const RULES = DEFAULT_POSTURE_RULES;

const input = (over: Partial<PostureInputs> = {}): PostureInputs => ({
  knownSignals: 0, covered: [], proof: [], verdicts: [], threatWeight: 0, exposureWeight: 0, ...over,
});

const proof = (scope: ProofScope, ageDays: number, over: Partial<ProofRecord> = {}): ProofRecord => ({
  scope, detectionRef: 'wazuh:990003', outcome: 'alerted', date: daysAgo(ageDays), source: 'lylat-range:CORNERIA-ROOT-01',
  runId: `${scope}-${ageDays}`, ...over,
});

const mark = (over: Partial<CoveredMark> = {}): CoveredMark => ({
  qualifier: 'self-attested', basis: 'mitigation-implemented', strength: 'full', via: 'M1047', source: 'manual', ...over,
});

const verdict = (ageDays: number, over: Partial<RunVerdict> = {}): RunVerdict => ({
  date: daysAgo(ageDays), failed: false, notReproducible: false, source: 'manual', ...over,
});

const derive = (over: Partial<PostureInputs> = {}): PostureState => derivePosture(REF, input(over), RULES, TODAY);

describe('derivePosture (Phase 2 design §2.2)', () => {
  it('ships the D16 / D10 defaults: threshold 15; range 90, production 180, own-run 90', () => {
    expect(DEFAULT_POSTURE_RULES).toEqual({ mitigationBreadthThreshold: 15, decayDays: { production: 180, range: 90, 'own-run': 90 } });
  });

  it('copies the ref, the marks and the weights onto the state', () => {
    const covered = [mark()];
    const s = derive({ covered, knownSignals: 3, threatWeight: 4, exposureWeight: 2 });
    expect(s.ref).toBe(REF);
    expect(s.covered).toBe(covered);
    expect([s.knownSignals, s.threatWeight, s.exposureWeight]).toEqual([3, 4, 2]);
  });

  describe('1. proof', () => {
    it('fresh proof: rung and bucket proven, scope and age of the best record, no qualifiers', () => {
      const s = derive({ proof: [proof('range', 10)], covered: [mark()], knownSignals: 2 });
      expect([s.rung, s.bucket]).toEqual(['proven', 'proven']);
      expect([s.proofScope, s.proofAge]).toEqual(['range', 10]);
      expect(s.qualifiers).toEqual([]);
      expect(s.subStates).toEqual([]);
      expect(s.excluded).toBeFalse();
    });

    it('a blocked outcome qualifies as well as an alert', () => {
      expect(derive({ proof: [proof('own-run', 1, { outcome: 'blocked' })] }).bucket).toBe('proven');
    });

    it('the window is inclusive: age equal to decayDays is fresh, one more day is stale', () => {
      expect(derive({ proof: [proof('range', 90)] }).bucket).toBe('proven');
      expect(derive({ proof: [proof('range', 91)] }).bucket).toBe('stale');
      expect(derive({ proof: [proof('production', 180)] }).bucket).toBe('proven');
      expect(derive({ proof: [proof('production', 181)] }).bucket).toBe('stale');
    });

    it('stale proof: rung stays proven, bucket stale, the stale sub-state, newest record first', () => {
      const s = derive({ proof: [proof('production', 400), proof('range', 200), proof('own-run', 300)] });
      expect([s.rung, s.bucket]).toEqual(['proven', 'stale']);
      expect(s.subStates).toEqual(['stale']);
      expect(s.proof.map(p => p.runId)).toEqual(['range-200', 'own-run-300', 'production-400']);
      expect([s.proofScope, s.proofAge]).toEqual(['range', 200]);
    });

    it('mixed: a fresh record beats any stale one, whatever the scope', () => {
      const s = derive({ proof: [proof('production', 200), proof('own-run', 5)] });
      expect(s.bucket).toBe('proven');
      expect(s.proofScope).toBe('own-run');
      expect(s.proof.map(p => p.runId)).toEqual(['own-run-5', 'production-200']);
    });

    it('scope precedence among fresh records: production, then range, then own run, then newest', () => {
      const s = derive({ proof: [proof('own-run', 1), proof('range', 30), proof('production', 100), proof('range', 2)] });
      expect(s.proof.map(p => p.runId)).toEqual(['production-100', 'range-2', 'range-30', 'own-run-1']);
      expect([s.proofScope, s.proofAge]).toEqual(['production', 100]);
    });

    it('same scope and same date: ordered by runId, so the order is stable', () => {
      const s = derive({ proof: [proof('range', 3, { runId: 'b' }), proof('range', 3, { runId: 'a' })] });
      expect(s.proof.map(p => p.runId)).toEqual(['a', 'b']);
    });

    it('a future date counts as age 0', () => {
      expect(derive({ proof: [proof('range', -5)] }).proofAge).toBe(0);
    });

    it('reads an ISO timestamp (runDate) as well as a YYYY-MM-DD date (validated_at)', () => {
      const s = derive({ proof: [proof('own-run', 0, { date: '2026-09-21T23:59:00.000Z' })] });
      expect(s.proofAge).toBe(9);
    });

    it('does not qualify: no detectionRef, a blank detectionRef, another outcome, an unparseable or empty date', () => {
      const bad: ProofRecord[] = [
        proof('range', 1, { detectionRef: '' }),
        proof('range', 1, { detectionRef: '   ' }),
        proof('range', 1, { detectionRef: undefined as unknown as string }),
        proof('range', 1, { outcome: 'failed' as unknown as 'alerted' }),
        proof('range', 1, { date: 'not a date' }),
        proof('range', 1, { date: '' }),
      ];
      for (const p of bad) {
        const s = derive({ proof: [p], knownSignals: 1 });
        expect([s.rung, s.bucket]).withContext(JSON.stringify(p)).toEqual(['known', 'known']);
        expect(s.proof).toEqual([]);
        expect([s.proofScope, s.proofAge]).toEqual([null, null]);
      }
    });

    it("'own-run-blocked' gives covered, not proven (S4: blocked + no rule is not proven)", () => {
      const s = derive({
        proof: [proof('own-run', 1, { outcome: 'blocked', detectionRef: '' })],
        covered: [mark({ basis: 'own-run-blocked', via: undefined })],
      });
      expect([s.rung, s.bucket]).toEqual(['covered', 'covered']);
      expect(s.qualifiers).toEqual(['self-attested']);
      expect(s.proof).toEqual([]);
    });
  });

  describe('2. not reproducible', () => {
    it('without proof: excluded, the sub-state set, and the rung falls through for display', () => {
      const s = derive({ verdicts: [verdict(3, { notReproducible: true })], covered: [mark()] });
      expect(s.excluded).toBeTrue();
      expect(s.subStates).toEqual(['not-reproducible']);
      expect([s.rung, s.bucket]).toEqual(['covered', 'covered']);
      const t = tallyPosture([s, derive({ knownSignals: 1 })]);
      expect([t.total, t.assessable, t.notReproducible]).withContext('total unchanged, assessable -1').toEqual([2, 1, 1]);
    });

    it('with proof: the proof wins, so the technique is not excluded and stays in the denominator', () => {
      const s = derive({ verdicts: [verdict(3, { notReproducible: true })], proof: [proof('range', 1)] });
      expect(s.excluded).toBeFalse();
      expect(s.bucket).toBe('proven');
      expect(s.subStates).toEqual([]);
      const t = tallyPosture([s, derive({ knownSignals: 1 })]);
      expect([t.total, t.assessable, t.notReproducible]).toEqual([2, 2, 0]);
    });

    it('without proof or marks: excluded, and still known or none for display', () => {
      expect(derive({ verdicts: [verdict(1, { notReproducible: true })], knownSignals: 2 }).bucket).toBe('known');
      const none = derive({ verdicts: [verdict(1, { notReproducible: true })] });
      expect([none.bucket, none.excluded]).toEqual(['none', true]);
    });
  });

  describe('3. covered marks', () => {
    it('full marks: rung and bucket covered, with the distinct qualifiers in a fixed order', () => {
      const s = derive({ covered: [mark({ qualifier: 'range', basis: 'range-deployed' }), mark(), mark({ via: 'M1026' })] });
      expect([s.rung, s.bucket]).toEqual(['covered', 'covered']);
      expect(s.qualifiers).toEqual(['self-attested', 'range']);
      expect(s.subStates).toEqual([]);
    });

    it('qualifier union: one qualifier when every full mark shares it', () => {
      expect(derive({ covered: [mark({ qualifier: 'range', basis: 'range-detection-authored' })] }).qualifiers).toEqual(['range']);
      expect(derive({ covered: [mark(), mark({ basis: 'control-implemented' })] }).qualifiers).toEqual(['self-attested']);
    });

    it('full marks outrank partial marks: covered, no partial sub-state, qualifiers from the full marks only', () => {
      const s = derive({ covered: [mark({ strength: 'partial', qualifier: 'range' }), mark()] });
      expect(s.bucket).toBe('covered');
      expect(s.qualifiers).toEqual(['self-attested']);
      expect(s.subStates).toEqual([]);
    });

    it('partial marks only: rung covered, bucket partial, the partial sub-state', () => {
      const s = derive({ covered: [mark({ strength: 'partial', via: 'M1038' })], knownSignals: 2 });
      expect([s.rung, s.bucket]).toEqual(['covered', 'partial']);
      expect(s.qualifiers).toEqual(['self-attested']);
      expect(s.subStates).toEqual(['partial']);
    });

    it('planned marks only: no Covered rung, the planned sub-state on known or none', () => {
      const known = derive({ covered: [mark({ strength: 'planned' })], knownSignals: 1 });
      expect([known.rung, known.bucket, known.qualifiers]).toEqual(['known', 'known', []]);
      expect(known.subStates).toEqual(['planned']);
      const none = derive({ covered: [mark({ strength: 'planned' })] });
      expect([none.bucket, none.subStates]).toEqual(['none', ['planned']]);
    });

    it('planned is set in every branch, and the sub-states are sorted and unique', () => {
      const s = derive({
        covered: [mark({ strength: 'planned' }), mark({ strength: 'planned', via: 'M1026' }), mark({ strength: 'partial' })],
        verdicts: [verdict(1, { notReproducible: true }), verdict(2, { notReproducible: true })],
      });
      expect(s.subStates).toEqual(['not-reproducible', 'partial', 'planned']);
      expect(derive({ covered: [mark({ strength: 'planned' })], proof: [proof('range', 1)] }).subStates).toEqual(['planned']);
    });

    it('telemetry-observed is set from range telemetry marks, on any rung', () => {
      const tele = mark({ qualifier: 'range', basis: 'range-telemetry-observed', via: 'Sysmon::1' });
      const s = derive({ covered: [tele] });
      expect(s.subStates).toEqual(['telemetry-observed']);
      expect([s.bucket, s.qualifiers]).toEqual(['covered', ['range']]);
      expect(derive({ covered: [tele], proof: [proof('range', 200)] }).subStates).toEqual(['stale', 'telemetry-observed']);
    });

    describe('contradicted', () => {
      it('dated: a failed verdict newer than the newest dated full mark contradicts it', () => {
        const s = derive({ covered: [mark({ at: daysAgo(20) }), mark({ at: daysAgo(10) })], verdicts: [verdict(5, { failed: true })], knownSignals: 1 });
        expect(s.subStates).toEqual(['contradicted']);
        expect([s.rung, s.bucket, s.qualifiers]).toEqual(['known', 'known', []]);
      });

      it('undated: any failed verdict contradicts a full mark that has no date', () => {
        const s = derive({ covered: [mark({ at: daysAgo(1) }), mark({ at: undefined })], verdicts: [verdict(400, { failed: true })] });
        expect(s.subStates).toEqual(['contradicted']);
        expect(s.bucket).toBe('none');
        expect(derive({ covered: [mark({ at: 'not a date' })], verdicts: [verdict(400, { failed: true })] }).subStates)
          .withContext('an unparseable date is undated').toEqual(['contradicted']);
      });

      it('a run older than the mark does not contradict it', () => {
        const s = derive({ covered: [mark({ at: daysAgo(10) })], verdicts: [verdict(30, { failed: true }), verdict(1)] });
        expect(s.subStates).toEqual([]);
        expect(s.bucket).toBe('covered');
      });

      it('a failed run on the same day as the mark does not contradict it (newer means strictly newer)', () => {
        expect(derive({ covered: [mark({ at: daysAgo(10) })], verdicts: [verdict(10, { failed: true })] }).bucket).toBe('covered');
      });

      it('a failed verdict without a parseable date never outranks a dated mark', () => {
        expect(derive({ covered: [mark({ at: daysAgo(10) })], verdicts: [verdict(0, { failed: true, date: 'unknown' })] }).bucket).toBe('covered');
      });

      it('passing verdicts never contradict, even with undated marks', () => {
        expect(derive({ covered: [mark()], verdicts: [verdict(1)] }).bucket).toBe('covered');
      });

      it('contradicted full marks leave partial marks standing: bucket partial', () => {
        const s = derive({ covered: [mark(), mark({ strength: 'partial', via: 'M1038' })], verdicts: [verdict(1, { failed: true })] });
        expect(s.bucket).toBe('partial');
        expect(s.subStates).toEqual(['contradicted', 'partial']);
      });

      it('failed verdicts with no full marks set nothing', () => {
        expect(derive({ covered: [mark({ strength: 'partial' })], verdicts: [verdict(1, { failed: true })] }).subStates).toEqual(['partial']);
        expect(derive({ verdicts: [verdict(1, { failed: true })] }).subStates).toEqual([]);
      });
    });
  });

  describe('4. known and none', () => {
    it('known when there is a Known reference signal', () => {
      const s = derive({ knownSignals: 1 });
      expect([s.rung, s.bucket, s.qualifiers, s.subStates, s.excluded]).toEqual(['known', 'known', [], [], false]);
      expect([s.proof, s.proofScope, s.proofAge]).toEqual([[], null, null]);
    });

    it('none otherwise', () => {
      const s = derive();
      expect([s.rung, s.bucket]).toEqual(['none', 'none']);
    });
  });

  // RP-F decision 9: the runs of yours that yield no qualifying proof record, newest first.
  describe('runs without proof', () => {
    const run = (runId: string, ageDays: number | null, status = 'untested'): RunSummary => ({
      runId, status, date: ageDays === null ? 'not a date' : daysAgo(ageDays), source: 'manual',
    });

    it('no runs input: an empty list in every branch', () => {
      expect(derive().runsWithoutProof).toEqual([]);
      expect(derive({ proof: [proof('own-run', 1)] }).runsWithoutProof).toEqual([]);
    });

    it('an untested run (no proof, no mark) is listed and leaves the rung at none', () => {
      const s = derive({ runs: [run('u1', 2)] });
      expect([s.rung, s.bucket]).toEqual(['none', 'none']);
      expect(s.runsWithoutProof.map(r => [r.runId, r.status])).toEqual([['u1', 'untested']]);
    });

    it('a run with a qualifying proof record is out; its sibling without one is in, on a proven state', () => {
      const s = derive({
        runs: [run('own-run-1', 1, 'passed'), run('f1', 3, 'failed')],
        proof: [proof('own-run', 1)],
      });
      expect(s.bucket).toBe('proven');
      expect(s.runsWithoutProof.map(r => r.runId)).toEqual(['f1']);
    });

    it('a run whose only record does not qualify (no parseable date) is still a run without proof', () => {
      const s = derive({ runs: [run('bad', 1, 'passed')], proof: [proof('own-run', 1, { runId: 'bad', date: 'never' })], knownSignals: 2 });
      expect(s.bucket).toBe('known');
      expect(s.runsWithoutProof.map(r => r.runId)).toEqual(['bad']);
    });

    it('newest first; an undated run sorts last; equal dates by runId', () => {
      const s = derive({ runs: [run('old', 20), run('undated', null), run('b', 5), run('new', 1), run('a', 5), run('undated-2', null)] });
      expect(s.runsWithoutProof.map(r => r.runId)).toEqual(['new', 'a', 'b', 'old', 'undated', 'undated-2']);
    });
  });

  it('every state honours the invariant: qualifiers non-empty exactly when the bucket is partial or covered', () => {
    const states = [
      derive(), derive({ knownSignals: 1 }), derive({ covered: [mark()] }), derive({ covered: [mark({ strength: 'partial' })] }),
      derive({ proof: [proof('range', 1)], covered: [mark()] }), derive({ proof: [proof('range', 300)] }),
    ];
    for (const s of states) {
      expect(s.qualifiers.length > 0).withContext(s.bucket).toBe(s.bucket === 'partial' || s.bucket === 'covered');
    }
  });
});

describe('tallyPosture', () => {
  it('counts one bucket per state, summing to total; excluded leaves total and lowers assessable', () => {
    const states = [
      derive(),
      derive({ knownSignals: 2 }),
      derive({ knownSignals: 2, verdicts: [verdict(1, { notReproducible: true })] }),
      derive({ covered: [mark({ strength: 'partial' })] }),
      derive({ covered: [mark()] }),
      derive({ covered: [mark({ at: daysAgo(9) })], verdicts: [verdict(1, { failed: true })], knownSignals: 1 }),
      derive({ proof: [proof('production', 3)] }),
      derive({ proof: [proof('range', 120)] }),
    ];
    const t = tallyPosture(states);
    expect(t).toEqual({
      total: 8, assessable: 7, none: 1, known: 3, partial: 1, covered: 1, proven: 1, stale: 1, contradicted: 1, notReproducible: 1,
    });
    expect(t.none + t.known + t.partial + t.covered + t.proven + t.stale).toBe(t.total);
  });

  it('is all zeros for no states, and accepts any iterable', () => {
    expect(tallyPosture([])).toEqual({
      total: 0, assessable: 0, none: 0, known: 0, partial: 0, covered: 0, proven: 0, stale: 0, contradicted: 0, notReproducible: 0,
    });
    const set = new Set([derive({ knownSignals: 1 })]);
    expect(tallyPosture(set.values()).known).toBe(1);
  });
});
