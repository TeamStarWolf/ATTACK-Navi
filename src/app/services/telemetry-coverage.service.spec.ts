// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { TelemetryCoverageService, telemetryKey } from './telemetry-coverage.service';
import { EventLoggingService } from './event-logging.service';

describe('TelemetryCoverageService', () => {
  let svc: TelemetryCoverageService;
  let eventLog: EventLoggingService;

  beforeEach(() => {
    localStorage.clear();
    TestBed.configureTestingModule({});
    svc = TestBed.inject(TelemetryCoverageService);
    eventLog = TestBed.inject(EventLoggingService);
  });

  afterEach(() => localStorage.clear());

  it('starts with no sources configured', () => {
    const s = svc.summary();
    expect(s.configured).toBe(0);
    expect(s.total).toBeGreaterThan(0);
    expect(s.pct).toBe(0);
  });

  it('builds a matrix that covers every mapped technique', () => {
    const matrix = svc.buildMatrix();
    expect(matrix.length).toBeGreaterThan(0);
    const techniquesInMatrix = new Set(matrix.flatMap(r => r.techniques));
    for (const t of eventLog.getAllMappedTechniques()) {
      expect(techniquesInMatrix.has(t)).withContext(`technique ${t} should appear`).toBe(true);
    }
  });

  it('matrix rows are sorted by impact (most-needed first)', () => {
    const matrix = svc.buildMatrix();
    for (let i = 1; i < matrix.length; i++) {
      expect(matrix[i - 1].techniques.length).toBeGreaterThanOrEqual(matrix[i].techniques.length);
    }
  });

  it('toggle flips state and round-trips through localStorage', () => {
    const matrix = svc.buildMatrix();
    const target = matrix[0].key;
    expect(svc.isConfigured(target)).toBe(false);
    svc.toggle(target);
    expect(svc.isConfigured(target)).toBe(true);

    // simulate fresh load via a brand-new TestBed (which re-inject()s deps)
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({});
    const reloaded = TestBed.inject(TelemetryCoverageService);
    expect(reloaded.isConfigured(target)).toBe(true);
  });

  it('setStatus enforces explicit value', () => {
    const k = telemetryKey('PowerShell ScriptBlock Logging', '4104');
    svc.setStatus(k, true);
    expect(svc.isConfigured(k)).toBe(true);
    svc.setStatus(k, false);
    expect(svc.isConfigured(k)).toBe(false);
  });

  it('clearAll wipes coverage', () => {
    const matrix = svc.buildMatrix();
    svc.toggle(matrix[0].key);
    svc.toggle(matrix[1].key);
    expect(svc.summary().configured).toBe(2);
    svc.clearAll();
    expect(svc.summary().configured).toBe(0);
  });

  it('techniqueCoverage returns 100 for techniques with no mapping', () => {
    const c = svc.techniqueCoverage('T9999.999');
    expect(c.required).toBe(0);
    expect(c.pct).toBe(100);
  });

  it('techniqueCoverage reflects toggled sources', () => {
    // T1059.001 has 3 logging configs in EventLoggingService
    const before = svc.techniqueCoverage('T1059.001');
    expect(before.required).toBeGreaterThan(0);
    expect(before.configured).toBe(0);

    const configs = eventLog.getLoggingConfig('T1059.001');
    svc.setStatus(telemetryKey(configs[0].source, configs[0].eventId), true);
    const after = svc.techniqueCoverage('T1059.001');
    expect(after.configured).toBe(1);
    expect(after.pct).toBeGreaterThan(0);
  });

  it('emits on status$ when toggled', (done) => {
    const matrix = svc.buildMatrix();
    const target = matrix[0].key;
    const seen: Array<Set<string>> = [];
    const sub = svc.status$.subscribe(s => {
      seen.push(s);
      if (seen.length === 2) {
        expect(seen[1].has(target)).toBe(true);
        sub.unsubscribe();
        done();
      }
    });
    svc.toggle(target);
  });

  it('survives malformed localStorage', () => {
    localStorage.setItem('attacknavi.telemetry-coverage.v1', '{not valid json');
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({});
    const fresh = TestBed.inject(TelemetryCoverageService);
    expect(fresh.summary().configured).toBe(0);
  });
});
