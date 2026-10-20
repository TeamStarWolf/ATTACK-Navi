// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// The navi.v2.technique-marks store (Phase 2 design §3 P2-05): persists on the
// v2 envelope; replaceSource replaces one 'layer:' source only.
import { TestBed } from '@angular/core/testing';
import { TECHNIQUE_MARKS_KEY, TechniqueMarkRecord, TechniqueMarksService, sanitizeMark } from './technique-marks.service';
import { WorkspaceBundleService } from './workspace-bundle.service';

const REF_A = 'attack/enterprise/T1059.001@19.2' as const;
const REF_B = 'attack/enterprise/T1003@19.2' as const;
const REF_ICS = 'attack/ics/T0807@19.2' as const;

describe('TechniqueMarksService (P2-05)', () => {
  const fresh = (): TechniqueMarksService => {
    TestBed.resetTestingModule();
    return TestBed.inject(TechniqueMarksService);
  };

  beforeEach(() => localStorage.removeItem(TECHNIQUE_MARKS_KEY));
  afterEach(() => localStorage.removeItem(TECHNIQUE_MARKS_KEY));

  it('starts empty and emits synchronously', () => {
    const svc = fresh();
    let seen: readonly TechniqueMarkRecord[] | null = null;
    svc.marks$.subscribe(m => (seen = m)).unsubscribe();
    expect(seen as unknown).toEqual([]);
  });

  it('persists confirmations on the v2 envelope across instances', () => {
    const svc = fresh();
    expect(svc.confirm(REF_A, { via: 'M1038' })).toBeTrue();
    expect(svc.confirm(REF_ICS, { status: 'planned' })).toBeTrue();
    const raw = JSON.parse(localStorage.getItem(TECHNIQUE_MARKS_KEY)!);
    expect(raw.schema).toBe(2);
    expect(raw.tombstones).toEqual([]);
    const again = fresh();
    expect(again.all.map(m => [m.ref, m.status, m.via ?? null, m.source, m.domain, m.attackVersion])).toEqual([
      [REF_A, 'implemented', 'M1038', 'manual', 'enterprise', '19.2'],
      [REF_ICS, 'planned', null, 'manual', 'ics', '19.2'],
    ]);
  });

  it('keeps one mark per technique per source, and clear() removes only that source', () => {
    const svc = fresh();
    svc.confirm(REF_A);
    const created = svc.all[0].createdAt;
    svc.confirm(REF_A, { status: 'in-progress' });
    svc.confirm(REF_A, { source: 'layer:red team' });
    expect(svc.all.length).toBe(2);
    expect(svc.all[0]).toEqual(jasmine.objectContaining({ status: 'in-progress', createdAt: created }));
    svc.clear(REF_A);
    expect(svc.all.map(m => m.source)).toEqual(['layer:red team']);
    svc.clear(REF_A, 'layer:red team');
    expect(svc.all).toEqual([]);
  });

  it('refuses a malformed ref or source', () => {
    const svc = fresh();
    expect(svc.confirm('T1059.001' as never)).toBeFalse();
    expect(svc.confirm(REF_A, { source: 'wizard' as never })).toBeFalse();
    expect(svc.all).toEqual([]);
    expect(localStorage.getItem(TECHNIQUE_MARKS_KEY)).toBeNull();
  });

  it('replaceSource replaces one layer: source only', () => {
    const svc = fresh();
    svc.confirm(REF_A);
    expect(svc.replaceSource('layer:one', [{ ref: REF_A, status: 'implemented' }, { ref: REF_B, status: 'planned' }])).toBe(2);
    expect(svc.replaceSource('layer:two', [{ ref: REF_B, status: 'implemented' }])).toBe(1);
    expect(svc.replaceSource('layer:one', [{ ref: REF_B, status: 'implemented', via: 'M1026' }, { ref: 'bad' as never, status: 'implemented' }])).toBe(1);
    expect(svc.all.map(m => [m.source, m.ref, m.status])).toEqual([
      ['manual', REF_A, 'implemented'],
      ['layer:two', REF_B, 'implemented'],
      ['layer:one', REF_B, 'implemented'],
    ]);
    expect(svc.replaceSource('manual' as never, [])).toBe(-1);
    expect(svc.all.length).toBe(3);
  });

  it('drops stored records that fail the allowlist, and re-derives the envelope from the ref', () => {
    localStorage.setItem(TECHNIQUE_MARKS_KEY, JSON.stringify({
      schema: 2, tombstones: [],
      records: [
        { ref: REF_A, status: 'implemented', source: 'manual', domain: 'ics', attackVersion: '1', createdAt: 'a', updatedAt: 'b', extra: 'x' },
        { ref: REF_B, status: 'done', source: 'manual', createdAt: 'a', updatedAt: 'b' },
        { ref: REF_B, status: 'implemented', source: 'lylat-range:m1', createdAt: 'a', updatedAt: 'b' },
        { ref: 'nope', status: 'implemented', source: 'manual', createdAt: 'a', updatedAt: 'b' },
      ],
    }));
    const svc = fresh();
    expect(svc.all).toEqual([{
      ref: REF_A, status: 'implemented', source: 'manual', domain: 'enterprise', attackVersion: '19.2', createdAt: 'a', updatedAt: 'b',
    }]);
    expect(sanitizeMark(null)).toBeNull();
  });

  it('is in the workspace bundle', () => {
    expect(WorkspaceBundleService.BUNDLED_KEYS).toContain(TECHNIQUE_MARKS_KEY);
    expect(new Set(WorkspaceBundleService.BUNDLED_KEYS).size).toBe(WorkspaceBundleService.BUNDLED_KEYS.length);
  });
});
