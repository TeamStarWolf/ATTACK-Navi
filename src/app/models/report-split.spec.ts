// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// E1.1 and P2-07: the Report's split. Known: mapped and its Theoretical
// sub-line come from reference mapping; Covered, partial, Proven and stale come
// from the posture rollup the other count surfaces read. Nothing that is
// reference-only may read as Covered. The old isTechniqueImplemented and
// allMappedImplemented cases are gone with those functions (Revision 3): the
// per-technique answer is PostureService.stateFor, asserted by
// testing/posture-count-equality.spec.ts.

import { Domain } from './domain';
import { makeSplitDomain } from '../testing/report-split-fixture';
import { makePostureStub } from '../testing/posture-stub';
import type { PostureBucket } from './posture/posture.types';
import {
  computeReportSplit,
  coveredCardLines,
  coveredSplitLabels,
  isTechniqueMapped,
  partialCardLines,
  REPORT_SPLIT_LABELS,
} from './report-split';

/** The rollup of the posture stub over the split fixture with these buckets. */
function rollup(domain: Domain, buckets: Record<string, PostureBucket> = {}) {
  return makePostureStub(() => domain, buckets).rollup();
}

describe('computeReportSplit (E1.1 Theoretical sub-line, P2-07 posture rollup)', () => {
  it('counts Theoretical from reference mapping only, over parent techniques', () => {
    const domain = makeSplitDomain();
    const split = computeReportSplit(domain, rollup(domain), 0);
    expect(split.total).toBe(5);
    expect(split.theoretical).toBe(3);
    expect(split.theoreticalPct).toBe(60);
    expect(split.unmapped).toBe(2);
  });

  it('takes Known: mapped from the rollup, not from the mitigation count', () => {
    const domain = makeSplitDomain();
    const r = rollup(domain, { T3: 'known' });
    const split = computeReportSplit(domain, r, 0);
    expect(split.known).toBe(r.overall.mapped);
    expect(split.known).toBe(4);
    expect(split.knownPct).toBe(80);
    expect(split.theoretical).withContext('the Theoretical sub-line still counts mitigations only').toBe(3);
  });

  it('reports 0 Covered, partial and Proven when the owner has recorded nothing, however much is mapped', () => {
    const domain = makeSplitDomain();
    const split = computeReportSplit(domain, rollup(domain), 0);
    expect([split.covered, split.coveredPct, split.partial, split.proven, split.stale]).toEqual([0, 0, 0, 0, 0]);
    for (const t of split.byTactic) {
      expect([t.covered, t.coveredPct, t.partial, t.proven, t.stale]).withContext(t.name).toEqual([0, 0, 0, 0, 0]);
    }
  });

  it('copies every posture bucket of the rollup, overall and per tactic', () => {
    const domain = makeSplitDomain();
    const r = rollup(domain, { T1: 'covered', T2: 'partial', T4: 'proven', T5: 'stale' });
    const split = computeReportSplit(domain, r, 2);
    expect([split.covered, split.partial, split.proven, split.stale]).toEqual([1, 1, 1, 1]);
    expect(split.coveredPct).toBe(20);
    expect(split.implementedMitigations).toBe(2);
    expect(split.byTactic.map(t => [t.name, t.covered, t.partial, t.proven, t.stale]))
      .toEqual(r.byTactic.map(t => [t.tacticName, t.covered, t.partial, t.proven, t.stale]));
  });

  it('R16: divides Covered by assessable (total minus excluded), overall and per tactic; Known keeps total', () => {
    const domain = makeSplitDomain();
    const stub = makePostureStub(() => domain, { T1: 'covered', T4: 'covered' });
    const before = computeReportSplit(domain, stub.rollup(), 1);
    expect([before.total, before.assessable, before.covered, before.coveredPct]).toEqual([5, 5, 2, 40]);
    // T3 (Execution) is excluded: out of the Covered denominator only.
    stub.exclude(['T3']);
    const split = computeReportSplit(domain, stub.rollup(), 1);
    expect([split.total, split.assessable, split.covered, split.coveredPct]).toEqual([5, 4, 2, 50]);
    expect([split.known, split.knownPct, split.theoretical, split.theoreticalPct])
      .withContext('Known and Theoretical still divide by total').toEqual([before.known, before.knownPct, before.theoretical, before.theoreticalPct]);
    expect(split.byTactic.map(t => [t.shortname, t.total, t.assessable, t.covered, t.coveredPct])).toEqual([
      ['execution', 3, 2, 1, 50],
      ['persistence', 2, 2, 1, 50],
    ]);
    expect(split.byTactic[0].theoreticalPct).withContext('the tactic Theoretical share keeps total').toBe(67);
  });

  it('gives a 0% Covered share, not NaN, when every technique is excluded', () => {
    const domain = makeSplitDomain();
    const stub = makePostureStub(() => domain);
    stub.exclude(['T1', 'T2', 'T3', 'T4', 'T5']);
    const split = computeReportSplit(domain, stub.rollup(), 0);
    expect([split.total, split.assessable, split.coveredPct]).toEqual([5, 0, 0]);
    expect(split.byTactic.map(t => [t.assessable, t.coveredPct])).toEqual([[0, 0], [0, 0]]);
  });

  it('falls back to the column count as the Covered denominator for a tactic the rollup lacks', () => {
    const domain = makeSplitDomain();
    const split = computeReportSplit(domain, { ...rollup(domain), byTactic: [] }, 0);
    expect(split.byTactic.map(t => [t.total, t.assessable])).toEqual([[3, 3], [2, 2]]);
  });

  it('keeps partial separate from Covered: a broad mitigation never adds to Covered', () => {
    const domain = makeSplitDomain();
    const split = computeReportSplit(domain, rollup(domain, { T1: 'partial', T2: 'partial', T4: 'partial' }), 1);
    expect(split.covered).toBe(0);
    expect(split.partial).toBe(3);
  });

  // RP-F decision 36 (round 7, letter G): the Report Builder stated a breadth cause for
  // telemetry-only range partials. The split now carries the partial count by cause.
  it('a report built from telemetry-only range rows names the telemetry cause and counts it', () => {
    const domain = makeSplitDomain();
    const stub = makePostureStub(() => domain, { T1: 'partial', T2: 'partial' });
    stub.telemetry(['T1', 'T2']);
    const split = computeReportSplit(domain, stub.rollup(), 0);
    expect(split.partial).toBe(2);
    expect(split.partialByCause).toEqual({ breadth: 0, telemetry: 2 });
    expect(partialCardLines(split)).toEqual(['partial (range telemetry, no alert credited): 2']);
    expect(partialCardLines(split).join(' ')).not.toContain('broad mitigation');
  });

  // RP-F decision 43 (round 8): Covered splits by source, with a count per source; a
  // range-only Covered technique is never counted under the self-attested label.
  it('a report with a range-only, a self-attested and a mixed Covered technique counts each source', () => {
    const domain = makeSplitDomain();
    const stub = makePostureStub(() => domain, { T1: 'covered', T2: 'covered', T4: 'covered' });
    stub.coveredBy({ T1: 'range', T4: 'both' });
    const split = computeReportSplit(domain, stub.rollup(), 0);
    expect(split.covered).toBe(3);
    expect(split.coveredBySource).toEqual({ 'self-attested': 2, range: 2 });
    expect(coveredCardLines(split)).toEqual([
      'Covered (self-attested: mitigation, control, confirmation or your run): 2',
      'Covered (range: lab-validated detection): 2',
    ]);
    stub.coveredBy({ T1: 'range', T2: 'range', T4: 'range' });
    expect(coveredCardLines(computeReportSplit(domain, stub.rollup(), 0))).toEqual(['Covered (range: lab-validated detection): 3']);
    expect(REPORT_SPLIT_LABELS.coveredCard).toBe('Covered (self-attested or range), by source');
    // A hand-built rollup with no count by source lists no source line rather than guess one.
    expect(coveredCardLines(computeReportSplit(domain, { ...stub.rollup(), overall: { ...stub.rollup().overall, coveredBySource: undefined } }, 0))).toEqual([]);
  });

  // PR #241 round 1 (decision 43 on every Covered label): the walk read 'Covered
  // (self-attested) 3 of 222' and 'A technique you recorded ... Not validated.' around a
  // range-only profile's counts. The Covered words follow the sources the count includes.
  it('the Covered heading, notes and column words never call a count with a range source self-attested', () => {
    const domain = makeSplitDomain();
    const stub = makePostureStub(() => domain, { T1: 'covered', T2: 'covered', T4: 'covered' });
    stub.coveredBy({ T1: 'range', T2: 'range', T4: 'range' });
    const rangeOnly = coveredSplitLabels(computeReportSplit(domain, stub.rollup(), 0));
    expect(rangeOnly.covered).toBe('Covered (range)');
    expect(rangeOnly.coveredNote).toBe('A technique the range reports a deployed or authored detection for: a lab detection row, not a proof.');
    expect(rangeOnly.assessableNote).toMatch(/^Covered \(range\) shares divide by assessable parent techniques/);
    for (const words of Object.values(rangeOnly)) {
      expect(words).not.toContain('self-attested');
      expect(words).not.toContain('you recorded');
    }
    stub.coveredBy({ T1: 'range', T4: 'both' });
    const mixed = coveredSplitLabels(computeReportSplit(domain, stub.rollup(), 0));
    expect(mixed.covered).toBe('Covered (self-attested or range)');
    expect(mixed.coveredNote).toContain('self-attested, not validated');
    expect(mixed.coveredNote).toContain('range: a lab detection row, not a proof');
    expect(mixed.assessableNote).toMatch(/^Covered \(self-attested or range\) shares divide/);
    stub.coveredBy({});
    expect(coveredSplitLabels(computeReportSplit(domain, stub.rollup(), 0))).toEqual({
      covered: REPORT_SPLIT_LABELS.covered, coveredNote: REPORT_SPLIT_LABELS.coveredNote, assessableNote: REPORT_SPLIT_LABELS.assessableNote,
    });
    expect(coveredSplitLabels({ coveredBySource: null }).covered).toBe('Covered (self-attested)');
  });

  it('a breadth partial still names the mitigation cause, with a count per cause beside a telemetry one', () => {
    const domain = makeSplitDomain();
    const stub = makePostureStub(() => domain, { T1: 'partial', T2: 'partial', T4: 'partial' });
    stub.telemetry(['T4']);
    const split = computeReportSplit(domain, stub.rollup(), 0);
    expect(partialCardLines(split)).toEqual([
      'partial (broad mitigation, not confirmed per technique): 2',
      'partial (range telemetry, no alert credited): 1',
    ]);
    // A hand-built rollup with no count by cause lists no cause line rather than guess one.
    expect(partialCardLines(computeReportSplit(domain, { ...stub.rollup(), overall: { ...stub.rollup().overall, partialByCause: undefined } }, 0))).toEqual([]);
  });

  it('leaves Known and Theoretical unchanged when the posture changes', () => {
    const domain = makeSplitDomain();
    const before = computeReportSplit(domain, rollup(domain), 0);
    const after = computeReportSplit(domain, rollup(domain, { T1: 'covered', T4: 'proven' }), 2);
    expect([after.known, after.theoretical, after.theoreticalPct]).toEqual([before.known, before.theoretical, before.theoreticalPct]);
    expect(after.byTactic.map(t => [t.known, t.theoretical])).toEqual(before.byTactic.map(t => [t.known, t.theoretical]));
    expect(after.covered).toBeGreaterThan(before.covered);
  });

  it('splits each tactic column and lists its unmapped techniques', () => {
    const domain = makeSplitDomain();
    const split = computeReportSplit(domain, rollup(domain, { T4: 'covered' }), 1);
    expect(split.byTactic).toEqual([
      {
        name: 'Execution', shortname: 'execution', total: 3, assessable: 3, known: 2, knownPct: 67, theoretical: 2, theoreticalPct: 67,
        covered: 0, coveredPct: 0, partial: 0, proven: 0, stale: 0, unmappedIds: ['T3'],
      },
      {
        name: 'Persistence', shortname: 'persistence', total: 2, assessable: 2, known: 1, knownPct: 50, theoretical: 1, theoreticalPct: 50,
        covered: 1, coveredPct: 50, partial: 0, proven: 0, stale: 0, unmappedIds: ['T5'],
      },
    ]);
  });

  it('matches tactic rows by shortname and falls back to zeros for a tactic the rollup lacks', () => {
    const domain = makeSplitDomain();
    const r = rollup(domain, { T4: 'covered' });
    const split = computeReportSplit(domain, { ...r, byTactic: [...r.byTactic].reverse() }, 1);
    expect(split.byTactic.map(t => t.covered)).toEqual([0, 1]);
    const none = computeReportSplit(domain, { ...r, byTactic: [] }, 1);
    expect(none.byTactic.map(t => [t.known, t.covered, t.partial, t.proven, t.stale])).toEqual([[0, 0, 0, 0, 0], [0, 0, 0, 0, 0]]);
  });

  it('returns zeros, not NaN, for an empty domain', () => {
    const empty = { techniques: [], tacticColumns: [] } as unknown as Domain;
    const split = computeReportSplit(empty, rollup(empty), 0);
    expect(split).toEqual(jasmine.objectContaining({
      total: 0, assessable: 0, known: 0, knownPct: 0, theoretical: 0, theoreticalPct: 0, covered: 0, coveredPct: 0, partial: 0, unmapped: 0,
    }));
  });

  it('isTechniqueMapped is the mitigation-count test of the Theoretical sub-line', () => {
    const domain = makeSplitDomain();
    expect(domain.techniques.filter(t => !t.isSubtechnique).filter(isTechniqueMapped).map(t => t.attackId)).toEqual(['T1', 'T2', 'T4']);
  });

  it('labels Known and Theoretical as reference mapping and Covered as self-attested', () => {
    expect(REPORT_SPLIT_LABELS.known).toBe('Known: mapped');
    expect(REPORT_SPLIT_LABELS.theoretical).toMatch(/^Theoretical/);
    expect(REPORT_SPLIT_LABELS.theoretical).toContain('mapped');
    expect(REPORT_SPLIT_LABELS.theoreticalNote).toMatch(/reference/i);
    expect(REPORT_SPLIT_LABELS.covered).toBe('Covered (self-attested)');
    expect(REPORT_SPLIT_LABELS.assessable).toBe('assessable');
    expect(REPORT_SPLIT_LABELS.assessableNote).toMatch(/not-reproducible/);
    expect(REPORT_SPLIT_LABELS.partialCard).toBe('partial, by cause');
    expect(REPORT_SPLIT_LABELS.partialNote).toBe('a broad mitigation not confirmed per technique, or range telemetry with no alert credited, counts as partial');
    // The CSV column header is unchanged.
    expect(REPORT_SPLIT_LABELS.implemented).toBe('Implemented (self-attested)');
    // No Known or Theoretical wording may read as implemented, covered or protected.
    const referenceWords = [REPORT_SPLIT_LABELS.known, REPORT_SPLIT_LABELS.knownNote, REPORT_SPLIT_LABELS.theoretical,
      REPORT_SPLIT_LABELS.theoreticalShort, REPORT_SPLIT_LABELS.theoreticalNote, REPORT_SPLIT_LABELS.unmapped,
      REPORT_SPLIT_LABELS.fresh].join(' ');
    expect(referenceWords).not.toMatch(/implement|cover|protect|defend|risk/i);
  });
});
