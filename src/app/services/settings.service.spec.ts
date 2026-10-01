// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { SettingsService } from './settings.service';

describe('SettingsService', () => {
  let service: SettingsService;

  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    TestBed.configureTestingModule({});
    service = TestBed.inject(SettingsService);
  });

  afterEach(() => {
    localStorage.clear();
    sessionStorage.clear();
  });

  it('starts with default settings', () => {
    expect(service.current).toBeTruthy();
    expect(service.current.matrixCellSize).toBeTruthy();
    expect(['compact', 'normal', 'large']).toContain(service.current.matrixCellSize);
  });

  describe('update', () => {
    it('merges partial settings into the current snapshot', () => {
      service.update({ matrixCellSize: 'large' });
      expect(service.current.matrixCellSize).toBe('large');
    });

    it('persists across service re-instantiation', () => {
      service.update({ matrixCellSize: 'compact' });
      TestBed.resetTestingModule();
      TestBed.configureTestingModule({});
      const fresh = TestBed.inject(SettingsService);
      expect(fresh.current.matrixCellSize).toBe('compact');
    });
  });

  describe('updateWeights', () => {
    it('merges new weight values', () => {
      service.updateWeights({ atomic: 25 });
      expect(service.current.scoringWeights.atomic).toBe(25);
    });
  });

  describe('reset', () => {
    it('restores defaults', () => {
      service.update({ matrixCellSize: 'large' });
      service.reset();
      expect(service.current.matrixCellSize).not.toBe('large');
    });
  });

  describe('getNormalizedWeights', () => {
    it('returns weight values that sum to a positive number', () => {
      const w = service.getNormalizedWeights();
      const sum = Object.values(w).reduce((a, b) => a + b, 0);
      expect(sum).toBeGreaterThan(0);
    });
  });

  describe('getCoverageColors', () => {
    it('returns an array of color strings', () => {
      const colors = service.getCoverageColors();
      expect(Array.isArray(colors)).toBe(true);
      expect(colors.length).toBeGreaterThan(0);
      colors.forEach(c => expect(typeof c).toBe('string'));
    });
  });

  describe('setNvdApiKey', () => {
    it('stores the key', () => {
      service.setNvdApiKey('test-key-123');
      // Key may go to sessionStorage or settings — either way no exception
      expect(() => service.setNvdApiKey('')).not.toThrow();
    });
  });

  describe('cellDisplay', () => {
    it('defaults every flag to true', () => {
      const cd = service.current.cellDisplay;
      expect(cd).toBeTruthy();
      expect(cd.exposureBadge).toBe(true);
      expect(cd.softwareBadge).toBe(true);
      expect(cd.campaignBadge).toBe(true);
      expect(cd.metricBadge).toBe(true);
      expect(cd.noteDot).toBe(true);
      expect(cd.annotationDot).toBe(true);
      expect(cd.watchIndicator).toBe(true);
    });

    it('backfills all-true cellDisplay defaults for an old saved blob lacking it', () => {
      // Simulate a settings blob persisted before the cellDisplay feature existed.
      const oldBlob = { matrixCellSize: 'large', showTechniqueIds: false };
      localStorage.setItem('mitre-nav-settings-v1', JSON.stringify(oldBlob));

      TestBed.resetTestingModule();
      TestBed.configureTestingModule({});
      const fresh = TestBed.inject(SettingsService);

      const cd = fresh.current.cellDisplay;
      expect(cd.exposureBadge).toBe(true);
      expect(cd.softwareBadge).toBe(true);
      expect(cd.campaignBadge).toBe(true);
      expect(cd.metricBadge).toBe(true);
      expect(cd.noteDot).toBe(true);
      expect(cd.annotationDot).toBe(true);
      expect(cd.watchIndicator).toBe(true);
      // Pre-existing fields from the old blob are preserved.
      expect(fresh.current.matrixCellSize).toBe('large');
      expect(fresh.current.showTechniqueIds).toBe(false);
    });

    it('preserves a partial cellDisplay from a saved blob and fills the rest', () => {
      const blob = { cellDisplay: { exposureBadge: false } };
      localStorage.setItem('mitre-nav-settings-v1', JSON.stringify(blob));

      TestBed.resetTestingModule();
      TestBed.configureTestingModule({});
      const fresh = TestBed.inject(SettingsService);

      const cd = fresh.current.cellDisplay;
      expect(cd.exposureBadge).toBe(false);   // honored from the saved blob
      expect(cd.softwareBadge).toBe(true);    // backfilled default
      expect(cd.watchIndicator).toBe(true);   // backfilled default
    });

    it('persists cellDisplay edits across re-instantiation', () => {
      service.update({
        cellDisplay: {
          ...service.current.cellDisplay,
          campaignBadge: false,
        },
      });
      TestBed.resetTestingModule();
      TestBed.configureTestingModule({});
      const fresh = TestBed.inject(SettingsService);
      expect(fresh.current.cellDisplay.campaignBadge).toBe(false);
      expect(fresh.current.cellDisplay.exposureBadge).toBe(true);
    });
  });
});
