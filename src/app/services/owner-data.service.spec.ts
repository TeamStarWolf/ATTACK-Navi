// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { HEATMAP_MODES } from '../models/heatmap-modes';
import { DEFAULT_HEATMAP_MODE, HeatmapMode } from './filter.service';
import { ImplStatus, ImplementationService } from './implementation.service';
import {
  OwnerDataService,
  PREVALENCE_BANNER_TEXT,
  hasOwnerData,
  showPrevalenceBanner,
} from './owner-data.service';
import { ValidationRun, ValidationService } from './validation.service';

// Plan E1.5, decision D4: the default lens is Prevalence, with a one-line
// banner until owner data (any Implementation, Validation or stack record) exists.
describe('owner data and the Prevalence banner (E1.5, D4)', () => {
  describe('hasOwnerData', () => {
    it('is false for an empty profile', () => {
      expect(hasOwnerData({ implementation: 0, validation: 0, stack: 0 })).toBeFalse();
    });

    it('is true for any one Implementation, Validation or stack record', () => {
      expect(hasOwnerData({ implementation: 1, validation: 0, stack: 0 })).toBeTrue();
      expect(hasOwnerData({ implementation: 0, validation: 1, stack: 0 })).toBeTrue();
      expect(hasOwnerData({ implementation: 0, validation: 0, stack: 1 })).toBeTrue();
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
    let service: OwnerDataService;
    let seen: boolean[];

    beforeEach(() => {
      statuses = new BehaviorSubject(new Map<string, ImplStatus>());
      runs = new BehaviorSubject<ValidationRun[]>([]);
      TestBed.configureTestingModule({
        providers: [
          { provide: ImplementationService, useValue: { status$: statuses.asObservable() } },
          { provide: ValidationService, useValue: { runs$: runs.asObservable() } },
        ],
      });
      service = TestBed.inject(OwnerDataService);
      seen = [];
      service.hasOwnerData$.subscribe(v => seen.push(v));
    });

    it('reports no owner data for empty stores', () => {
      expect(seen).toEqual([false]);
    });

    it('turns true on the first implementation record and back when it is cleared', () => {
      statuses.next(new Map([['M1036', 'planned']]));
      expect(seen).toEqual([false, true]);
      statuses.next(new Map());
      expect(seen).toEqual([false, true, false]);
    });

    it('turns true on the first validation run', () => {
      runs.next([{ id: 'r1', techniqueId: 'T1059.001' } as ValidationRun]);
      expect(seen).toEqual([false, true]);
    });

    it('emits only on change', () => {
      statuses.next(new Map([['M1036', 'implemented']]));
      runs.next([{ id: 'r1', techniqueId: 'T1059.001' } as ValidationRun]);
      statuses.next(new Map([['M1036', 'implemented'], ['M1042', 'planned']]));
      expect(seen).toEqual([false, true]);
    });
  });
});
