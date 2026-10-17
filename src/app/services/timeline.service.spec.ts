// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { TimelineService, snapshotBasisLabel } from './timeline.service';
import { MappedRollup } from './enrichment.service';

describe('TimelineService', () => {
  let service: TimelineService;

  beforeEach(() => {
    localStorage.clear();
    TestBed.configureTestingModule({});
    service = TestBed.inject(TimelineService);
  });

  afterEach(() => localStorage.clear());

  describe('getAll / getLatest', () => {
    it('starts empty', () => {
      expect(service.getAll()).toEqual([]);
      expect(service.getLatest()).toBeNull();
    });
  });

  describe('getStorageSizeKb', () => {
    it('returns a non-negative number', () => {
      expect(service.getStorageSizeKb()).toBeGreaterThanOrEqual(0);
    });
  });

  describe('deleteSnapshot', () => {
    it('is a no-op when no snapshots exist', () => {
      expect(() => service.deleteSnapshot('nonexistent')).not.toThrow();
    });
  });

  describe('takeSnapshot (Known-tier mapped rollup, E1.7)', () => {
    const rollup: MappedRollup = {
      overall: { total: 10, mapped: 7, pct: 70 },
      byTactic: [
        { tacticId: 'x-ta-1', tacticName: 'Execution', shortname: 'execution', total: 4, mapped: 3, pct: 75 },
        { tacticId: 'x-ta-2', tacticName: 'Discovery', shortname: 'discovery', total: 6, mapped: 4, pct: 67 },
      ],
    };

    it('stores the rollup it is given, per tactic, on the reference-mapped basis', () => {
      const snap = service.takeSnapshot('  Q1  ', rollup, new Map([['m1', 'implemented'], ['m2', 'planned']]), ' n ');
      expect(snap).toEqual(jasmine.objectContaining({
        label: 'Q1', totalTechniques: 10, coveredTechniques: 7, coveragePct: 70, basis: 'reference-mapped', notes: 'n',
        implCounts: { implemented: 1, inProgress: 0, planned: 1, notStarted: 0 },
      }));
      expect(snap.tacticCoverage).toEqual([
        { tacticName: 'Execution', tacticId: 'x-ta-1', covered: 3, total: 4, pct: 75 },
        { tacticName: 'Discovery', tacticId: 'x-ta-2', covered: 4, total: 6, pct: 67 },
      ]);
      expect(service.getLatest()).toEqual(snap);
    });

    it('labels the count basis, treating a snapshot without one as mitigations only', () => {
      expect(snapshotBasisLabel({ basis: 'reference-mapped' })).toBe('mapped (defensive reference inputs)');
      expect(snapshotBasisLabel({})).toBe('mitigations only (older snapshot)');
    });
  });

  describe('updateLabel / updateNotes', () => {
    it('are no-ops when snapshot is missing', () => {
      expect(() => service.updateLabel('nope', 'new')).not.toThrow();
      expect(() => service.updateNotes('nope', 'note')).not.toThrow();
    });
  });
});
