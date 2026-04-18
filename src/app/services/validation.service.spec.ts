// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { ValidationService, ValidationStatus } from './validation.service';

const STORAGE_KEY = 'attacknavi.validation-runs.v1';

const baseRun = {
  techniqueId: 'T1003.001',
  techniqueName: 'LSASS Memory',
  operator: 'tester',
  telemetryRequired: ['Sysmon Event 10'],
  telemetryAvailable: ['Sysmon Event 10'],
  atomicTestId: 'AT-001',
  atomicCommand: 'powershell -c "Get-Process lsass"',
  attackResult: 'executed' as const,
  detectionsExpected: ['sigma:lsass-dump'],
  detectionsFired: ['sigma:lsass-dump'],
  responsePlaybook: 'ir-playbook:T1003.001',
  responseActions: ['isolated host'],
  evidenceLinks: ['https://example.com/evidence/123'],
  notes: 'OK',
};

describe('ValidationService', () => {
  let service: ValidationService;

  beforeEach(() => {
    localStorage.clear();
    TestBed.configureTestingModule({});
    service = TestBed.inject(ValidationService);
  });

  afterEach(() => localStorage.clear());

  describe('record', () => {
    it('assigns id, runDate, and computed status', () => {
      const r = service.record(baseRun);
      expect(r.id).toBeTruthy();
      expect(r.runDate).toBeTruthy();
      const expected: ValidationStatus = 'passed';
      expect(r.status).toBe(expected);
    });

    it('persists to localStorage', () => {
      service.record(baseRun);
      const stored = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? '[]');
      expect(stored.length).toBe(1);
    });
  });

  describe('computeStatus', () => {
    it('returns "passed" when all expected detections fired', () => {
      expect(service.computeStatus({
        telemetryRequired: ['x'], telemetryAvailable: ['x'],
        detectionsExpected: ['a', 'b'], detectionsFired: ['a', 'b'],
      })).toBe('passed');
    });

    it('returns "failed" when no detections fired', () => {
      expect(service.computeStatus({
        telemetryRequired: ['x'], telemetryAvailable: ['x'],
        detectionsExpected: ['a'], detectionsFired: [],
      })).toBe('failed');
    });

    it('returns "partial" when some detections fired', () => {
      expect(service.computeStatus({
        telemetryRequired: ['x'], telemetryAvailable: ['x'],
        detectionsExpected: ['a', 'b'], detectionsFired: ['a'],
      })).toBe('partial');
    });

    it('returns "no-telemetry" when telemetry was required but absent', () => {
      expect(service.computeStatus({
        telemetryRequired: ['x'], telemetryAvailable: [],
        detectionsExpected: ['a'], detectionsFired: ['a'],
      })).toBe('no-telemetry');
    });

    it('returns "untested" when no detections expected', () => {
      expect(service.computeStatus({
        telemetryRequired: [], telemetryAvailable: [],
        detectionsExpected: [], detectionsFired: [],
      })).toBe('untested');
    });
  });

  describe('forTechnique / latestFor', () => {
    it('forTechnique filters to matching ID', () => {
      service.record(baseRun);
      service.record({ ...baseRun, techniqueId: 'T9999' });
      expect(service.forTechnique('T1003.001').length).toBe(1);
    });

    it('latestFor returns the newest by runDate', () => {
      const a = service.record({ ...baseRun, runDate: '2026-01-01T00:00:00Z' });
      const b = service.record({ ...baseRun, runDate: '2026-04-01T00:00:00Z' });
      expect(service.latestFor('T1003.001')!.id).toBe(b.id);
    });

    it('latestFor returns null when no runs exist', () => {
      expect(service.latestFor('T9999')).toBeNull();
    });
  });

  describe('update', () => {
    it('mutates by id and recomputes status when inputs change', () => {
      const r = service.record(baseRun);
      service.update(r.id, { detectionsFired: [] });
      const after = service.all.find(x => x.id === r.id)!;
      expect(after.status).toBe('failed');
    });
  });

  describe('delete', () => {
    it('removes by id', () => {
      const r = service.record(baseRun);
      service.delete(r.id);
      expect(service.all).toEqual([]);
    });
  });

  describe('statusCounts + uniqueTechniqueCount', () => {
    it('aggregates counts across all runs', () => {
      service.record(baseRun);
      service.record({ ...baseRun, techniqueId: 'T9999', detectionsFired: [] });
      const counts = service.statusCounts();
      expect(counts.passed).toBe(1);
      expect(counts.failed).toBe(1);
      expect(service.uniqueTechniqueCount()).toBe(2);
    });
  });

  describe('exportJson + importJson round-trip', () => {
    it('preserves runs across export/import', () => {
      service.record(baseRun);
      const json = service.exportJson();
      // Wipe storage then re-import
      localStorage.clear();
      TestBed.resetTestingModule();
      TestBed.configureTestingModule({});
      const fresh = TestBed.inject(ValidationService);
      const result = fresh.importJson(json);
      expect(result.ok).toBe(true);
      expect(result.imported).toBe(1);
      expect(fresh.all.length).toBe(1);
    });

    it('importJson handles malformed input gracefully', () => {
      const result = service.importJson('not-valid-json');
      expect(result.ok).toBe(false);
      expect(result.imported).toBe(0);
    });
  });

  describe('buildNavigatorLayer', () => {
    it('produces a Navigator-shaped object with technique entries', () => {
      service.record(baseRun);
      const layer = service.buildNavigatorLayer('enterprise-attack') as any;
      expect(layer.domain).toBe('enterprise-attack');
      expect(Array.isArray(layer.techniques)).toBe(true);
      expect(layer.techniques[0].techniqueID).toBe('T1003.001');
      expect(layer.techniques[0].color).toBeTruthy();
      expect(Array.isArray(layer.legendItems)).toBe(true);
    });

    it('only includes the latest run per technique', () => {
      service.record({ ...baseRun, runDate: '2026-01-01T00:00:00Z', detectionsFired: [] });
      service.record({ ...baseRun, runDate: '2026-04-01T00:00:00Z' });
      const layer = service.buildNavigatorLayer('enterprise-attack') as any;
      expect(layer.techniques.length).toBe(1);
      expect(layer.techniques[0].comment).toContain('passed');
    });
  });
});
