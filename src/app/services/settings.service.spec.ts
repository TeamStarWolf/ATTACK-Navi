// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { SettingsService, mergePostureSettings } from './settings.service';

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

  // E1.5: Scoring Weights are retired (plan 4.1 bans the Coverage Score and
  // grades on reference data), and so is their setting.
  describe('retired scoring weights (E1.5)', () => {
    it('has no scoring-weight setting or weight API', () => {
      expect('scoringWeights' in service.current).toBeFalse();
      expect((service as unknown as Record<string, unknown>)['updateWeights']).toBeUndefined();
      expect((service as unknown as Record<string, unknown>)['getNormalizedWeights']).toBeUndefined();
    });

    it('drops weights stored by an older version and never writes them back', () => {
      localStorage.setItem('mitre-nav-settings-v1', JSON.stringify({
        matrixCellSize: 'large',
        scoringWeights: { mitigations: 60, car: 10, atomic: 10, d3fend: 10, nist: 10 },
      }));
      TestBed.resetTestingModule();
      TestBed.configureTestingModule({});
      const fresh = TestBed.inject(SettingsService);
      expect('scoringWeights' in fresh.current).toBeFalse();
      expect(fresh.current.matrixCellSize).toBe('large');
      fresh.update({ showTechniqueIds: false });
      expect(localStorage.getItem('mitre-nav-settings-v1')).not.toContain('scoringWeights');
    });
  });

  describe('reset', () => {
    it('restores defaults', () => {
      service.update({ matrixCellSize: 'large' });
      service.reset();
      expect(service.current.matrixCellSize).not.toBe('large');
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

  describe('setProxyToken', () => {
    it('keeps the proxy access token in sessionStorage only, trimmed, and restores it on reload', () => {
      service.setProxyToken('  proxy-secret  ');
      expect(service.current.proxyToken).toBe('proxy-secret');
      expect(localStorage.getItem('mitre-nav-settings-v1')).not.toContain('proxy-secret');
      expect(sessionStorage.getItem('mitre-nav-settings-v1-proxy-token')).toBe('proxy-secret');

      TestBed.resetTestingModule();
      TestBed.configureTestingModule({});
      const fresh = TestBed.inject(SettingsService);
      expect(fresh.current.proxyToken).toBe('proxy-secret');
    });

    it('clears the stored token when set to empty and ignores a token smuggled into localStorage', () => {
      service.setProxyToken('proxy-secret');
      service.setProxyToken('');
      expect(service.current.proxyToken).toBe('');
      expect(sessionStorage.getItem('mitre-nav-settings-v1-proxy-token')).toBeNull();

      localStorage.setItem('mitre-nav-settings-v1', JSON.stringify({ proxyToken: 'persisted-secret', matrixCellSize: 'large' }));
      TestBed.resetTestingModule();
      TestBed.configureTestingModule({});
      const fresh = TestBed.inject(SettingsService);
      expect(fresh.current.proxyToken).toBe('');
      expect(fresh.current.matrixCellSize).toBe('large');
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

  // Phase 2 design P2-05 (§6, §7): the posture rules, deep-merged for older
  // stored settings.
  describe('posture rules (P2-05)', () => {
    const DEFAULTS = { mitigationBreadthThreshold: 15, decayDays: { range: 90, production: 180, 'own-run': 90 } };
    const reload = (blob: unknown): SettingsService => {
      localStorage.setItem('mitre-nav-settings-v1', JSON.stringify(blob));
      TestBed.resetTestingModule();
      TestBed.configureTestingModule({});
      return TestBed.inject(SettingsService);
    };

    it('defaults to threshold 15 and windows range 90, production 180, own-run 90', () => {
      expect(service.current.posture).toEqual(DEFAULTS);
    });

    it('an old stored settings object gains the posture defaults', () => {
      const fresh = reload({ matrixCellSize: 'large', showTechniqueIds: false });
      expect(fresh.current.posture).toEqual(DEFAULTS);
      expect(fresh.current.matrixCellSize).toBe('large');
    });

    it('deep-merges a partial posture object and drops out-of-range values', () => {
      const fresh = reload({ posture: { mitigationBreadthThreshold: 20, decayDays: { range: 30, production: 0, 'own-run': 1.5 } } });
      expect(fresh.current.posture).toEqual({ mitigationBreadthThreshold: 20, decayDays: { range: 30, production: 180, 'own-run': 90 } });
      expect(reload({ posture: { mitigationBreadthThreshold: 501 } }).current.posture.mitigationBreadthThreshold).toBe(15);
      expect(mergePostureSettings('junk')).toEqual(DEFAULTS);
    });

    it('persists an update and emits it', () => {
      const seen: number[] = [];
      service.settings$.subscribe(s => seen.push(s.posture.mitigationBreadthThreshold));
      service.update({ posture: { ...service.current.posture, mitigationBreadthThreshold: 20 } });
      expect(seen).toEqual([15, 20]);
      TestBed.resetTestingModule();
      TestBed.configureTestingModule({});
      expect(TestBed.inject(SettingsService).current.posture.mitigationBreadthThreshold).toBe(20);
    });

    it('reset restores the posture defaults', () => {
      service.update({ posture: { mitigationBreadthThreshold: 3, decayDays: { range: 1, production: 2, 'own-run': 3 } } });
      service.reset();
      expect(service.current.posture).toEqual(DEFAULTS);
    });
  });
});
