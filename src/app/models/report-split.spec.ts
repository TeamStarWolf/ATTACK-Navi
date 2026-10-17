// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// E1.1: the Report's Theoretical / Implemented split. Theoretical is
// reference mapping (Known); Implemented is owner-attested (Covered,
// self-attested). Nothing that is reference-only may read as implemented.

import { Domain } from './domain';
import { makeSplitDomain } from '../testing/report-split-fixture';
import { ImplStatus } from '../services/implementation.service';
import {
  computeReportSplit,
  isTechniqueImplemented,
  isTechniqueMapped,
  REPORT_SPLIT_LABELS,
} from './report-split';

const status = (entries: Array<[string, ImplStatus]>): Map<string, ImplStatus> =>
  new Map(entries.map(([m, s]) => [`course-of-action--${m}`, s]));

describe('computeReportSplit (E1.1 Theoretical / Implemented)', () => {
  it('counts Theoretical from reference mapping only, over parent techniques', () => {
    const split = computeReportSplit(makeSplitDomain(), new Map());
    expect(split.total).toBe(5);
    expect(split.theoretical).toBe(3);
    expect(split.theoreticalPct).toBe(60);
    expect(split.unmapped).toBe(2);
  });

  it('reports 0 Implemented when the owner has recorded nothing, however much is mapped', () => {
    const split = computeReportSplit(makeSplitDomain(), new Map());
    expect(split.implemented).toBe(0);
    expect(split.implementedPct).toBe(0);
    expect(split.allMappedImplemented).toBe(0);
    for (const t of split.byTactic) {
      expect(t.implemented).withContext(t.name).toBe(0);
      expect(t.implementedPct).withContext(t.name).toBe(0);
    }
  });

  it('counts a technique as Implemented only through a mapped mitigation marked implemented', () => {
    const split = computeReportSplit(makeSplitDomain(), status([['M1', 'implemented']]));
    // M1 maps to T1 and T2 (and the sub-technique, which never counts).
    expect(split.implemented).toBe(2);
    expect(split.implementedPct).toBe(40);
    expect(split.implementedMitigations).toBe(1);
    // T2's only mitigation is M1; T1 also has M2, which is not implemented.
    expect(split.allMappedImplemented).toBe(1);
  });

  it('does not count planned, in-progress or not-started mitigations as Implemented', () => {
    const split = computeReportSplit(makeSplitDomain(), status([
      ['M1', 'planned'],
      ['M2', 'in-progress'],
      ['M3', 'not-started'],
    ]));
    expect(split.implemented).toBe(0);
    expect(split.implementedMitigations).toBe(0);
  });

  it('never counts an unmapped technique as Implemented, even for an implemented mitigation id it lacks', () => {
    const domain = makeSplitDomain();
    const all = status([['M1', 'implemented'], ['M2', 'implemented'], ['M3', 'implemented']]);
    const split = computeReportSplit(domain, all);
    expect(split.implemented).toBe(split.theoretical);
    const t3 = domain.techniques.find(t => t.attackId === 'T3')!;
    const t5 = domain.techniques.find(t => t.attackId === 'T5')!;
    expect(isTechniqueImplemented(domain, t3, all)).toBeFalse();
    expect(isTechniqueImplemented(domain, t5, all)).toBeFalse();
    expect(isTechniqueMapped(t3)).toBeFalse();
  });

  it('keeps Implemented a subset of Theoretical for every status combination', () => {
    const domain = makeSplitDomain();
    const statuses: Array<ImplStatus | undefined> = [undefined, 'implemented', 'in-progress', 'planned', 'not-started'];
    for (const a of statuses) {
      for (const b of statuses) {
        for (const c of statuses) {
          const entries: Array<[string, ImplStatus]> = [];
          if (a) entries.push(['M1', a]);
          if (b) entries.push(['M2', b]);
          if (c) entries.push(['M3', c]);
          const split = computeReportSplit(domain, status(entries));
          expect(split.implemented).toBeLessThanOrEqual(split.theoretical);
          expect(split.allMappedImplemented).toBeLessThanOrEqual(split.implemented);
          for (const t of split.byTactic) {
            expect(t.implemented).toBeLessThanOrEqual(t.theoretical);
          }
        }
      }
    }
  });

  it('leaves Theoretical unchanged when the owner changes implementation statuses', () => {
    const domain = makeSplitDomain();
    const before = computeReportSplit(domain, new Map());
    const after = computeReportSplit(domain, status([['M1', 'implemented'], ['M3', 'implemented']]));
    expect(after.theoretical).toBe(before.theoretical);
    expect(after.theoreticalPct).toBe(before.theoreticalPct);
    expect(after.byTactic.map(t => t.theoretical)).toEqual(before.byTactic.map(t => t.theoretical));
    expect(after.implemented).toBeGreaterThan(before.implemented);
  });

  it('splits each tactic column and lists its unmapped techniques', () => {
    const split = computeReportSplit(makeSplitDomain(), status([['M3', 'implemented']]));
    expect(split.byTactic).toEqual([
      { name: 'Execution', total: 3, theoretical: 2, theoreticalPct: 67, implemented: 0, implementedPct: 0, unmappedIds: ['T3'] },
      { name: 'Persistence', total: 2, theoretical: 1, theoreticalPct: 50, implemented: 1, implementedPct: 50, unmappedIds: ['T5'] },
    ]);
  });

  it('returns zeros, not NaN, for an empty domain', () => {
    const empty = { techniques: [], tacticColumns: [], mitigationsByTechnique: new Map() } as unknown as Domain;
    const split = computeReportSplit(empty, new Map());
    expect(split).toEqual(jasmine.objectContaining({
      total: 0, theoretical: 0, theoreticalPct: 0, implemented: 0, implementedPct: 0, unmapped: 0,
    }));
  });

  it('labels Theoretical as reference mapping and Implemented as self-attested', () => {
    expect(REPORT_SPLIT_LABELS.theoretical).toMatch(/^Theoretical/);
    expect(REPORT_SPLIT_LABELS.theoretical).toContain('mapped');
    expect(REPORT_SPLIT_LABELS.theoreticalNote).toMatch(/reference/i);
    expect(REPORT_SPLIT_LABELS.implemented).toBe('Implemented (self-attested)');
    // No Theoretical wording may read as implemented, covered or protected.
    const theoreticalWords = [REPORT_SPLIT_LABELS.theoretical, REPORT_SPLIT_LABELS.theoreticalShort, REPORT_SPLIT_LABELS.theoreticalNote, REPORT_SPLIT_LABELS.unmapped].join(' ');
    expect(theoreticalWords).not.toMatch(/implement|cover|protect|defend|risk/i);
  });
});
