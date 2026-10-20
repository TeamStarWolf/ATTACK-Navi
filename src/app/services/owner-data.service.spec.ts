// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { BehaviorSubject } from 'rxjs';
import { HEATMAP_MODES } from '../models/heatmap-modes';
import { DataService } from './data.service';
import { DEFAULT_HEATMAP_MODE, HeatmapMode } from './filter.service';
import { ImplStatus, ImplementationService } from './implementation.service';
import {
  OwnerDataService,
  PREVALENCE_BANNER_TEXT,
  hasOwnerData,
  showPrevalenceBanner,
} from './owner-data.service';
import { TECHNIQUE_MARKS_KEY, TechniqueMarkRecord, TechniqueMarksService } from './technique-marks.service';
import { VALIDATION_RUNS_V2_KEY, ValidationRun, ValidationService } from './validation.service';
import { resetBrowserState } from '../testing/lens-harness';

// Plan E1.5, decision D4: the default lens is Prevalence, with a one-line
// banner until owner data exists. Phase 2 design P2-05 (S10, R11; Revision 3)
// makes D4 exact: one validation run, or one implemented mitigation, wizard
// technique rating or technique mark. Updated on purpose: a profile whose only
// data is 'planned' (or any status but 'implemented') no longer has owner data.
describe('owner data and the Prevalence banner (E1.5, D4)', () => {
  describe('hasOwnerData (D4 exact)', () => {
    const MIT = 'course-of-action--0f4a0c76-ab2d-4cb0-85d3-3f0efb8cba0d';
    const TECH = 'attack-pattern--970a3432-3237-47ad-bcca-7d8cbb217736';
    const none = { statuses: new Map<string, ImplStatus>(), runs: 0, marks: [] };

    it('is false for an empty profile', () => {
      expect(hasOwnerData(none)).toBeFalse();
    });

    it('is true for one validation run', () => {
      expect(hasOwnerData({ ...none, runs: 1 })).toBeTrue();
    });

    it("is true for one implemented 'course-of-action--*' key", () => {
      expect(hasOwnerData({ ...none, statuses: new Map<string, ImplStatus>([[MIT, 'implemented']]) })).toBeTrue();
    });

    it("is true for one implemented 'attack-pattern--*' (wizard) key", () => {
      expect(hasOwnerData({ ...none, statuses: new Map<string, ImplStatus>([[TECH, 'implemented']]) })).toBeTrue();
    });

    it("is true for one technique mark with status 'implemented'", () => {
      expect(hasOwnerData({ ...none, marks: [{ status: 'implemented' }] })).toBeTrue();
    });

    it("is false when every status is 'planned', 'in-progress' or 'not-started' (mitigation or technique)", () => {
      const statuses = new Map<string, ImplStatus>([[MIT, 'planned'], [TECH, 'in-progress'], ['course-of-action--x', 'not-started']]);
      expect(hasOwnerData({ statuses, runs: 0, marks: [{ status: 'planned' }, { status: 'not-started' }] })).toBeFalse();
    });

    it("is false for a junk key 'M1036' set to implemented", () => {
      const statuses = new Map<string, ImplStatus>([['M1036', 'implemented'], ['course-of-action--', 'implemented']]);
      expect(hasOwnerData({ ...none, statuses })).toBeFalse();
    });
  });

  describe('showPrevalenceBanner', () => {
    it('shows on the default lens when no owner data exists', () => {
      expect(DEFAULT_HEATMAP_MODE).toBe('frequency');
      expect(showPrevalenceBanner(DEFAULT_HEATMAP_MODE, false)).toBeTrue();
    });

    it('hides once owner data exists', () => {
      expect(showPrevalenceBanner('frequency', true)).toBeFalse();
    });

    it('hides on every other lens, where its first words would be untrue', () => {
      const others = HEATMAP_MODES.map(m => m.value as HeatmapMode).filter(m => m !== 'frequency');
      expect(others.length).toBe(32);
      for (const mode of others) {
        expect(showPrevalenceBanner(mode, false)).withContext(mode).toBeFalse();
      }
    });

    it('says what the lens is and that it is reference data, in one line', () => {
      expect(PREVALENCE_BANNER_TEXT).toContain('adversary prevalence');
      expect(PREVALENCE_BANNER_TEXT).toContain('reference data');
      expect(PREVALENCE_BANNER_TEXT).toContain('Tell Navi about your environment to see your posture.');
      expect(PREVALENCE_BANNER_TEXT).not.toContain('\n');
      expect(PREVALENCE_BANNER_TEXT).not.toMatch(/\bcovered\b|\bprotected\b|\bdefended\b|low risk/i);
    });
  });

  describe('OwnerDataService', () => {
    let statuses: BehaviorSubject<Map<string, ImplStatus>>;
    let runs: BehaviorSubject<ValidationRun[]>;
    let marks: BehaviorSubject<readonly TechniqueMarkRecord[]>;
    let service: OwnerDataService;
    let seen: boolean[];
    const MIT = 'course-of-action--1';

    beforeEach(() => {
      statuses = new BehaviorSubject(new Map<string, ImplStatus>());
      runs = new BehaviorSubject<ValidationRun[]>([]);
      marks = new BehaviorSubject<readonly TechniqueMarkRecord[]>([]);
      TestBed.configureTestingModule({
        providers: [
          { provide: ImplementationService, useValue: { status$: statuses.asObservable() } },
          { provide: ValidationService, useValue: { runs$: runs.asObservable() } },
          { provide: TechniqueMarksService, useValue: { marks$: marks.asObservable() } },
        ],
      });
      service = TestBed.inject(OwnerDataService);
      seen = [];
      service.hasOwnerData$.subscribe(v => seen.push(v));
    });

    it('reports no owner data for empty stores', () => {
      expect(seen).toEqual([false]);
    });

    it('turns true on the first implemented mitigation and back when it is cleared', () => {
      statuses.next(new Map<string, ImplStatus>([[MIT, 'implemented']]));
      expect(seen).toEqual([false, true]);
      statuses.next(new Map());
      expect(seen).toEqual([false, true, false]);
    });

    it("stays false for a 'planned'-only profile (updated on purpose: D4 exact)", () => {
      statuses.next(new Map<string, ImplStatus>([[MIT, 'planned']]));
      marks.next([{ status: 'planned' } as TechniqueMarkRecord]);
      expect(seen).toEqual([false]);
    });

    it('turns true on the first validation run', () => {
      runs.next([{ id: 'r1', techniqueId: 'T1059.001' } as ValidationRun]);
      expect(seen).toEqual([false, true]);
    });

    it('turns true on an implemented technique mark from any source', () => {
      marks.next([{ status: 'implemented', source: 'layer:x' } as unknown as TechniqueMarkRecord]);
      expect(seen).toEqual([false, true]);
    });

    it('emits only on change', () => {
      statuses.next(new Map<string, ImplStatus>([[MIT, 'implemented']]));
      runs.next([{ id: 'r1', techniqueId: 'T1059.001' } as ValidationRun]);
      statuses.next(new Map<string, ImplStatus>([[MIT, 'implemented'], ['course-of-action--2', 'planned']]));
      expect(seen).toEqual([false, true]);
    });

    it('keeps the display counts shape (every implementation status counts there)', () => {
      const counts: unknown[] = [];
      service.counts$.subscribe(c => counts.push(c));
      statuses.next(new Map<string, ImplStatus>([[MIT, 'planned']]));
      expect(counts.at(-1)).toEqual({ implementation: 1, validation: 0, stack: 0 });
    });
  });

  // The eight D4 cases on the real stores (Revision 3). Every read is
  // synchronous and domain-free, so the predicate is right at construction,
  // before any domain loads.
  describe('OwnerDataService on the real stores, no domain loaded', () => {
    const MIT = 'course-of-action--b045d015-6bed-4490-bd38-56b41ece59a0';
    const TECH = 'attack-pattern--970a3432-3237-47ad-bcca-7d8cbb217736';

    function firstValue(seed: () => void): boolean {
      TestBed.resetTestingModule();
      resetBrowserState();
      seed();
      TestBed.configureTestingModule({ providers: [provideHttpClient(withXhr()), provideHttpClientTesting()] });
      let value: boolean | undefined;
      TestBed.inject(OwnerDataService).hasOwnerData$.subscribe(v => (value = v)).unsubscribe();
      expect(TestBed.inject(DataService).getCurrentDomain()).withContext('no domain loaded').toBeNull();
      expect(value).withContext('synchronous first emission').toBeDefined();
      return value!;
    }
    const impl = (entries: [string, string][]) => () => localStorage.setItem('mitre-nav-impl-v1', JSON.stringify(entries));
    const markStore = (source: string, status: string) => () => localStorage.setItem(TECHNIQUE_MARKS_KEY, JSON.stringify({
      schema: 2, tombstones: [],
      records: [{ ref: 'attack/enterprise/T1059.001@19.2', status, source, createdAt: 'a', updatedAt: 'a' }],
    }));

    afterEach(() => resetBrowserState());

    it('a run gives true', () => {
      expect(firstValue(() => localStorage.setItem(VALIDATION_RUNS_V2_KEY, JSON.stringify({
        schema: 2, tombstones: [],
        records: [{
          id: 'r1', techniqueId: 'T1059.001', runDate: '2026-09-01T00:00:00.000Z', status: 'passed', attackResult: 'executed',
          source: 'manual', domain: null, attackVersion: 'unknown', createdAt: 'a', updatedAt: 'a', techniqueRef: null,
          outcomes: [], proofScope: 'own-run', statusFromSource: false,
        }],
      })))).toBeTrue();
    });

    it("one implemented 'course-of-action--*' gives true", () => {
      expect(firstValue(impl([[MIT, 'implemented']]))).toBeTrue();
    });

    it("one implemented 'attack-pattern--*' (wizard) key gives true", () => {
      expect(firstValue(impl([[TECH, 'implemented']]))).toBeTrue();
    });

    it("one technique mark with status 'implemented' gives true, from manual and from layer:x", () => {
      expect(firstValue(markStore('manual', 'implemented'))).toBeTrue();
      expect(firstValue(markStore('layer:x', 'implemented'))).toBeTrue();
    });

    it("only 'planned' (mitigation or technique) gives false", () => {
      expect(firstValue(() => {
        impl([[MIT, 'planned'], [TECH, 'planned']])();
        markStore('manual', 'planned')();
      })).toBeFalse();
    });

    it("a junk key 'M1036' set to implemented gives false", () => {
      expect(firstValue(impl([['M1036', 'implemented']]))).toBeFalse();
    });

    it('one implemented control only gives false (§10.4 item 3)', () => {
      expect(firstValue(() => localStorage.setItem('mitre-nav-controls-v1', JSON.stringify([{
        id: 'c1', name: 'c', framework: 'Custom', controlRef: 'c', description: '', mitigationIds: [MIT], status: 'implemented',
      }])))).toBeFalse();
    });

    it('is true synchronously at construction with no domain loaded', () => {
      expect(firstValue(impl([[MIT, 'implemented']]))).toBeTrue();
    });
  });
});
