// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The D16 breadth guard (Phase 2 design §6) at the pure level. CI gates this
// file's subject at 100% branch coverage (scripts/check-branch-coverage.mjs).
import { rollupMitigations } from './mitigation-rollup';
import type { ImplStatus } from '../../services/implementation.service';
import type { Technique } from '../technique';

/** n techniques with STIX ids `${prefix}-0..n-1` (only `id` is read). */
const techs = (prefix: string, n: number): Technique[] =>
  Array.from({ length: n }, (_, i) => ({ id: `attack-pattern--${prefix}-${i}` }) as Technique);

const ATTACK_IDS: Record<string, string> = {
  'course-of-action--narrow': 'M1047', 'course-of-action--broad': 'M1038', 'course-of-action--five': 'M1015',
  'course-of-action--six': 'M1026', 'course-of-action--sixteen': 'M1036',
};
const mitAttackId = (stix: string) => ATTACK_IDS[stix] ?? stix;

describe('rollupMitigations (D16 breadth guard)', () => {
  const narrow = techs('narrow', 15);
  const broad = techs('broad', 16);
  const byMit = new Map<string, readonly Technique[]>([
    ['course-of-action--narrow', narrow],
    ['course-of-action--broad', broad],
    ['course-of-action--five', techs('five', 5)],
    ['course-of-action--six', techs('six', 6)],
    ['course-of-action--sixteen', techs('broad', 16)],
  ]);
  const one = (mit: string, status: ImplStatus) => new Map<string, ImplStatus>([[mit, status]]);

  it('[AC] a mitigation mapped to 15 techniques, implemented, marks exactly those techniques, every mark full', () => {
    const out = rollupMitigations(one('course-of-action--narrow', 'implemented'), byMit, mitAttackId, 15);
    expect([...out.keys()].sort()).toEqual(narrow.map(t => t.id).sort());
    const marks = [...out.values()].flat();
    expect(marks.length).toBe(15);
    expect(marks.every(m => m.strength === 'full')).toBeTrue();
    expect(marks[0]).toEqual({ qualifier: 'self-attested', basis: 'mitigation-implemented', strength: 'full', via: 'M1047', source: 'manual' });
  });

  it('[AC] a broader mitigation (16 techniques) produces partial marks only: 16 partial, 0 full', () => {
    const out = rollupMitigations(one('course-of-action--broad', 'implemented'), byMit, mitAttackId, 15);
    const marks = [...out.values()].flat();
    expect([...out.keys()].sort()).toEqual(broad.map(t => t.id).sort());
    expect(marks.filter(m => m.strength === 'partial').length).toBe(16);
    expect(marks.filter(m => m.strength === 'full').length).toBe(0);
    expect(marks.every(m => m.via === 'M1038')).toBeTrue();
  });

  it('threshold edges: 15 and 16 at threshold 15, 16 at threshold 16, and a custom 5', () => {
    const strengths = (mit: string, threshold: number) =>
      [...new Set([...rollupMitigations(one(mit, 'implemented'), byMit, mitAttackId, threshold).values()].flat().map(m => m.strength))];
    expect(strengths('course-of-action--narrow', 15)).toEqual(['full']);
    expect(strengths('course-of-action--broad', 15)).toEqual(['partial']);
    expect(strengths('course-of-action--narrow', 14)).toEqual(['partial']);
    expect(strengths('course-of-action--broad', 16)).toEqual(['full']);
    expect(strengths('course-of-action--five', 5)).toEqual(['full']);
    expect(strengths('course-of-action--six', 5)).toEqual(['partial']);
    expect(strengths('course-of-action--narrow', 5)).toEqual(['partial']);
  });

  it("'in-progress' and 'planned' give planned marks whatever the breadth", () => {
    for (const status of ['in-progress', 'planned'] as const) {
      for (const mit of ['course-of-action--narrow', 'course-of-action--broad']) {
        const marks = [...rollupMitigations(one(mit, status), byMit, mitAttackId, 15).values()].flat();
        expect(marks.length).withContext(`${status} ${mit}`).toBeGreaterThan(0);
        expect(marks.every(m => m.strength === 'planned')).withContext(`${status} ${mit}`).toBeTrue();
      }
    }
  });

  it("'not-started' gives no mark, nor does a status this version does not know", () => {
    expect(rollupMitigations(one('course-of-action--narrow', 'not-started'), byMit, mitAttackId, 15).size).toBe(0);
    expect(rollupMitigations(one('course-of-action--narrow', 'retired' as ImplStatus), byMit, mitAttackId, 15).size).toBe(0);
  });

  it('a mitigation the loaded domain does not map gives no mark', () => {
    expect(rollupMitigations(one('course-of-action--not-in-domain', 'implemented'), byMit, mitAttackId, 15).size).toBe(0);
  });

  it('a technique reached by two mitigations carries one mark for each, in status-map order', () => {
    const impl = new Map<string, ImplStatus>([
      ['course-of-action--broad', 'implemented'],
      ['course-of-action--sixteen', 'planned'],
      ['course-of-action--narrow', 'not-started'],
    ]);
    const out = rollupMitigations(impl, byMit, mitAttackId, 15);
    expect(out.size).toBe(16);
    const marks = out.get(broad[0].id)!;
    expect(marks.map(m => [m.via, m.strength])).toEqual([['M1038', 'partial'], ['M1036', 'planned']]);
  });

  it('is empty for an empty status map', () => {
    expect(rollupMitigations(new Map(), byMit, mitAttackId, 15).size).toBe(0);
  });
});
