// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { BehaviorSubject, firstValueFrom } from 'rxjs';
import {
  ValidationService, ValidationStatus, ValidationRunV2, describeImportResult,
  VALIDATION_RUNS_V1_KEY, VALIDATION_RUNS_V2_KEY,
} from './validation.service';
import { AttackIdResolverService } from './attack-id-resolver.service';
import { DataService, AttackDomain } from './data.service';
import { ImplementationService } from './implementation.service';
import { OwnerDataService } from './owner-data.service';
import { WorkspaceBundleService } from './workspace-bundle.service';
import { fingerprint } from '../models/storage-envelope';
import { runMatches } from '../models/posture/run-match';

const STORAGE_KEY = VALIDATION_RUNS_V2_KEY;

/**
 * A stand-in for the loaded domain: `loaded` null means no domain has loaded
 * yet (the resolver is then the identity and record() writes techniqueRef null).
 */
const fakeData = {
  id: 'enterprise' as AttackDomain,
  loaded: null as { attackVersion: string } | null,
  getCurrentDomain(): unknown { return this.loaded; },
  getCurrentAttackDomain(): AttackDomain { return this.id; },
};
function loadDomain(id: AttackDomain, attackVersion: string): void {
  fakeData.id = id;
  fakeData.loaded = { attackVersion };
}

function configure(): void {
  TestBed.configureTestingModule({ providers: [{ provide: DataService, useValue: fakeData }] });
}

/** A fresh ValidationService, as after a reload: storage is kept, the injector is new. */
function rebuild(): ValidationService {
  TestBed.resetTestingModule();
  configure();
  return TestBed.inject(ValidationService);
}

/** A v1 record as the pre-P2-02 app stored it. */
function v1Run(id: string, techniqueId: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id, techniqueId, techniqueName: 'n', runDate: '2026-03-01T00:00:00.000Z', operator: 'op',
    telemetryRequired: [], telemetryAvailable: [], atomicTestId: '', atomicCommand: '',
    attackResult: 'executed', detectionsExpected: ['sigma:a'], detectionsFired: ['sigma:a'],
    responsePlaybook: '', responseActions: [], evidenceLinks: [], notes: '', status: 'passed',
    ...extra,
  };
}

/** A range row as "Import range results" (P2-20) hands it to importRows. */
function rangeRow(id: string, techniqueId: string): ValidationRunV2 {
  return {
    ...(v1Run(id, techniqueId) as unknown as ValidationRunV2),
    domain: 'enterprise', attackVersion: '19.2', source: 'lylat-range:x',
    createdAt: '2026-03-01T00:00:00.000Z', updatedAt: '2026-03-01T00:00:00.000Z',
    techniqueRef: `attack/enterprise/${techniqueId}@19.2`, proofScope: 'range',
    outcomes: [{ detectionRef: 'wazuh:990003', outcome: 'alerted' }], statusFromSource: true,
  };
}

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
    fakeData.id = 'enterprise';
    fakeData.loaded = null;
    configure();
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
      // P2-02: new records go to the v2 store (design §5.7); the v1 key is never written again (§5.2).
      const stored = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? '{}');
      expect(stored.records.length).toBe(1);
      expect(localStorage.getItem(VALIDATION_RUNS_V1_KEY)).toBeNull();
    });

    it('writes a v2 manual own run keyed to the loaded domain', () => {
      loadDomain('enterprise', '19.2');
      const r = service.record(baseRun);
      expect(r.source).toBe('manual');
      expect(r.proofScope).toBe('own-run');
      expect(r.statusFromSource).toBe(false);
      expect(r.domain).toBe('enterprise');
      expect(r.attackVersion).toBe('19.2');
      expect(r.techniqueRef).toBe('attack/enterprise/T1003.001@19.2');
      expect(r.outcomes).toEqual([{ detectionRef: 'sigma:lsass-dump', outcome: 'alerted' }]);
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

    // P2-02 round 1: outcomes follow detectionsFired / attackResult (§5.2), as status follows the inputs.
    it('re-derives outcomes on a manual run when detectionsFired or attackResult changes', () => {
      const r = service.record(baseRun);
      expect(r.outcomes).toEqual([{ detectionRef: 'sigma:lsass-dump', outcome: 'alerted' }]);
      service.update(r.id, { detectionsFired: [] });
      expect(service.all[0].outcomes).toEqual([]);
      service.update(r.id, { attackResult: 'blocked' });
      expect(service.all[0].outcomes).toEqual([{ detectionRef: null, outcome: 'blocked' }]);
      expect(rebuild().all[0].outcomes).toEqual([{ detectionRef: null, outcome: 'blocked' }]);
    });

    it('re-keys techniqueRef when techniqueId changes, so runMatches follows the new technique', () => {
      loadDomain('enterprise', '19.2');
      const r = service.record(baseRun);
      expect(r.techniqueRef).toBe('attack/enterprise/T1003.001@19.2');
      service.update(r.id, { techniqueId: 'T1110' });
      const after = rebuild();
      expect(after.all[0].techniqueRef).toBe('attack/enterprise/T1110@19.2');
      expect(after.forTechnique('T1003.001')).toEqual([]);
      expect(after.forTechnique('T1110').map(x => x.id)).toEqual([r.id]);
      // With no domain loaded the ref is cleared and the bare id matches lazily.
      fakeData.loaded = null;
      after.update(r.id, { techniqueId: 'T1059.001' });
      expect(after.all[0].techniqueRef).toBeNull();
      expect(after.forTechnique('T1059.001').map(x => x.id)).toEqual([r.id]);
    });

    it('patches only the v1 fields, never id, source, proofScope or outcomes', () => {
      const r = service.record(baseRun);
      service.update(r.id, { notes: 'n2', id: 'x', source: 'lylat-range:m', proofScope: 'production',
        outcomes: [], statusFromSource: true } as never);
      const after = service.all[0];
      expect(after.id).toBe(r.id);
      expect(after.notes).toBe('n2');
      expect(after.source).toBe('manual');
      expect(after.proofScope).toBe('own-run');
      expect(after.statusFromSource).toBe(false);
      expect(after.outcomes).toEqual(r.outcomes);
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
    // Updated on purpose (P2-02): importJson no longer replaces every stored
    // run; it merges by source (design §5.8), and its result reports per source.
    it('preserves runs across export/import', () => {
      service.record(baseRun);
      const json = service.exportJson();
      // Wipe storage then re-import
      localStorage.clear();
      const fresh = rebuild();
      const result = fresh.importJson(json);
      expect(result.ok).toBe(true);
      expect(result.bySource).toEqual({ manual: { added: 1, replaced: 0 } });
      expect(fresh.all.length).toBe(1);
    });

    it('merges manual rows by id instead of replacing the existing runs', () => {
      const kept = service.record(baseRun);
      const edited = service.record({ ...baseRun, techniqueId: 'T1059.001' });
      const file = JSON.stringify({ runs: [v1Run(edited.id, 'T1059.001', { notes: 'edited' }), v1Run('new-1', 'T1110')] });
      const result = service.importJson(file);
      expect(result.bySource).toEqual({ manual: { added: 1, replaced: 1 } });
      expect(service.all.map(r => r.id)).toEqual([kept.id, edited.id, 'new-1']);
      expect(service.all.find(r => r.id === edited.id)!.notes).toBe('edited');
    });

    it('importJson handles malformed input gracefully', () => {
      const result = service.importJson('not-valid-json');
      expect(result.ok).toBe(false);
      expect(result.bySource).toEqual({});
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
  describe('merge by source (P2-02)', () => {
    it('[AC] re-importing a source replaces only that source', () => {
      const m1 = service.record(baseRun);
      const m2 = service.record({ ...baseRun, techniqueId: 'T1059.001' });
      expect(service.importRows([rangeRow('a1', 'T1110'), rangeRow('a2', 'T1078')], 'lylat-range:mission-a').ok).toBe(true);
      expect(service.importRows([rangeRow('b1', 'T1110'), rangeRow('b2', 'T1003'), rangeRow('b3', 'T1021')], 'lylat-range:mission-b').ok)
        .toBe(true);
      const snapshot = (source: string) => JSON.stringify(service.all.filter(r => r.source === source));
      const missionB = snapshot('lylat-range:mission-b');
      const manual = snapshot('manual');
      expect(JSON.parse(manual).map((r: ValidationRunV2) => r.id)).toEqual([m1.id, m2.id]);
      expect(JSON.parse(missionB).length).toBe(3);

      const result = service.importRows([rangeRow('a3', 'T1110')], 'lylat-range:mission-a');

      expect(result).toEqual({ ok: true, bySource: { 'lylat-range:mission-a': { added: 1, replaced: 2 } }, dropped: [] });
      expect(snapshot('lylat-range:mission-b')).toBe(missionB);
      expect(snapshot('manual')).toBe(manual);
      expect(service.all.filter(r => r.source === 'lylat-range:mission-a').map(r => r.id)).toEqual(['a3']);
      // Storage holds the same records (one commit path).
      expect(JSON.parse(localStorage.getItem(STORAGE_KEY)!).records.length).toBe(6);
    });

    it('refuses a Lylat contract file and points to "Import range results"', () => {
      const result = service.importJson(JSON.stringify({ schema: 'lylat-validated-detections/1', detections: [] }));
      expect(result.ok).toBe(false);
      expect(result.error).toContain('Import range results');
      expect(service.all).toEqual([]);
    });

    it('does not persist unknown row fields (hostname), and drops rows missing required fields', () => {
      const result = service.importJson(JSON.stringify({ runs: [v1Run('h1', 'T1110', { hostname: 'x' }), { id: 'bad' }] }));
      expect(result.ok).toBe(true);
      expect(result.bySource).toEqual({ manual: { added: 1, replaced: 0 } });
      expect(result.dropped).toEqual([{ row: 1, reason: 'missing techniqueId' }]);
      expect(describeImportResult(result)).toContain('manual: 1 added');
      expect('hostname' in service.all[0]).toBe(false);
      expect(localStorage.getItem(STORAGE_KEY)).not.toContain('hostname');
      expect('hostname' in rebuild().all[0]).toBe(false);
    });

    // P2-02 round 1: proofScope and statusFromSource follow the source, never the row.
    it('a row cannot raise its own proof scope: manual is own-run, lylat-range is range', () => {
      const res = service.importJson(JSON.stringify({ runs: [
        v1Run('m1', 'T1110', { source: 'manual', proofScope: 'production', statusFromSource: true }),
        v1Run('m2', 'T1110', { proofScope: 'range' }),
      ] }));
      expect(res.bySource).toEqual({ manual: { added: 2, replaced: 0 } });
      service.importRows([
        { ...rangeRow('r1', 'T1110'), proofScope: 'production' },
        { ...rangeRow('r2', 'T1110'), proofScope: 'own-run', statusFromSource: false },
      ], 'lylat-range:mission-a');
      for (const svc of [service, rebuild()]) {
        const byId = new Map(svc.all.map(r => [r.id, r]));
        expect(byId.get('m1')!.proofScope).toBe('own-run');
        expect(byId.get('m1')!.statusFromSource).toBe(false);
        expect(byId.get('m2')!.proofScope).toBe('own-run');
        expect(byId.get('r1')!.proofScope).toBe('range');
        expect(byId.get('r2')!.proofScope).toBe('range');
        expect(byId.get('r2')!.statusFromSource).toBe(true);
      }
      expect(localStorage.getItem(STORAGE_KEY)).not.toContain('production');
    });

    it('update() does not recompute status when statusFromSource is set', () => {
      service.importRows([{ ...rangeRow('r1', 'T1110'), status: 'not-reproducible' }], 'lylat-range:mission-a');
      service.update('r1', { detectionsFired: [], notes: 'checked' });
      const after = service.all.find(r => r.id === 'r1')!;
      expect(after.statusFromSource).toBe(true);
      expect(after.status).toBe('not-reproducible');
      expect(after.notes).toBe('checked');
    });
  });

  describe('copy-forward from v1 (P2-02, design §5.2)', () => {
    const v1 = JSON.stringify([v1Run('v1-a', 'T1003.001'), v1Run('v1-b', 'T1110', { attackResult: 'blocked', detectionsFired: [] })]);

    it('the first runs$ emission already holds the migrated runs; once, idempotent, v1 untouched', async () => {
      localStorage.setItem(VALIDATION_RUNS_V1_KEY, v1);
      const svc = rebuild();
      const first = await firstValueFrom(svc.runs$);
      expect(first.map(r => r.id)).toEqual(['v1-a', 'v1-b']);
      for (const r of first) {
        expect(r.techniqueRef).toBeNull();
        expect(r.domain).toBeNull();
        expect(r.source).toBe('manual');
        expect(r.proofScope).toBe('own-run');
        expect(r.statusFromSource).toBe(false);
        expect(r.attackVersion).toBe('unknown');
        expect(r.createdAt).toBe(r.runDate);
        expect(r.updatedAt).toBe(r.runDate);
      }
      expect(first[0].outcomes).toEqual([{ detectionRef: 'sigma:a', outcome: 'alerted' }]);
      expect(first[1].outcomes).toEqual([{ detectionRef: null, outcome: 'blocked' }]);
      const store = JSON.parse(localStorage.getItem(STORAGE_KEY)!);
      expect(store.schema).toBe(2);
      expect(store.migratedFromV1Fingerprint).toMatch(/^[0-9a-f]{8}:\d+$/);
      expect(store.migratedFromV1Fingerprint).toBe(fingerprint(v1));
      const written = localStorage.getItem(STORAGE_KEY);

      // Idempotent: a second construction copies nothing and writes nothing.
      const again = rebuild();
      expect(again.all.map(r => r.id)).toEqual(['v1-a', 'v1-b']);
      expect(localStorage.getItem(STORAGE_KEY)).toBe(written);
      expect(localStorage.getItem(VALIDATION_RUNS_V1_KEY)).toBe(v1);

      // Edits and deletes never touch the v1 key.
      again.update('v1-a', { notes: 'edited' });
      again.delete('v1-b');
      expect(localStorage.getItem(VALIDATION_RUNS_V1_KEY)).toBe(v1);
    });

    // P2-02 round 1: the pre-P2-02 importJson stored rows unvalidated; the v1 app
    // still listed them, so the copy-forward carries what it can (§5.11).
    it('carries v1 rows without a valid status, attackResult or id, and repeated ids; names the rest', async () => {
      const loose = [
        v1Run('s1', 'T1110', { status: undefined }),                       // status computed: passed
        v1Run('a1', 'T1110', { attackResult: 'exploded' }),                 // attackResult 'executed'
        { ...v1Run('x', 'T1021'), id: undefined },                          // id generated from content
        v1Run('dup', 'T1003.001'),
        v1Run('dup', 'T1059.001'),                                          // repeated id: dup~2
        v1Run('t1', ''),                                                    // no techniqueId: named
        'not a run',                                                        // not an object: named
      ];
      const raw = JSON.stringify(loose);
      localStorage.setItem(VALIDATION_RUNS_V1_KEY, raw);
      const svc = rebuild();
      const ids = (await firstValueFrom(svc.runs$)).map(r => r.id);
      expect(ids.length).toBe(5);
      expect(ids.slice(0, 2)).toEqual(['s1', 'a1']);
      expect(ids[2]).toMatch(/^v1-[0-9a-f]{8}-\d+$/);
      expect(ids.slice(3)).toEqual(['dup', 'dup~2']);
      expect(svc.all[0].status).toBe('passed');
      expect(svc.all[1].attackResult).toBe('executed');
      expect(svc.all[4].techniqueId).toBe('T1059.001');
      expect(svc.migrationDropped).toEqual([
        { row: 5, reason: 'missing techniqueId' },
        { row: 6, reason: 'not an object' },
      ]);
      // Deterministic: a reload copies nothing more, keeps the same ids, and still names the rows.
      const again = rebuild();
      expect(again.all.map(r => r.id)).toEqual(ids);
      expect(again.migrationDropped.length).toBe(2);
      expect(localStorage.getItem(VALIDATION_RUNS_V1_KEY)).toBe(raw);
    });

    it('OwnerDataService run count is unchanged after copy-forward', async () => {
      localStorage.setItem(VALIDATION_RUNS_V1_KEY, v1);
      TestBed.resetTestingModule();
      TestBed.configureTestingModule({
        providers: [
          { provide: DataService, useValue: fakeData },
          { provide: ImplementationService, useValue: { status$: new BehaviorSubject(new Map()).asObservable() } },
        ],
      });
      const counts = await firstValueFrom(TestBed.inject(OwnerDataService).counts$);
      expect(counts.validation).toBe(2);
    });
  });

  describe('workspace bundle restore (P2-02, design §5.5, R20)', () => {
    const bundle = (data: Record<string, string>) =>
      JSON.stringify({ format: 'attack-navi-workspace', version: 1, data });
    const restore = (data: Record<string, string>) => new WorkspaceBundleService().importBundle(bundle(data));

    beforeEach(() => {
      localStorage.setItem(VALIDATION_RUNS_V1_KEY, JSON.stringify([v1Run('A', 'T1003.001')]));
      service = rebuild();                                   // migrates A
    });

    it('a bundle carrying only v1 with a new run id upserts it', () => {
      const written = restore({ [VALIDATION_RUNS_V1_KEY]: JSON.stringify([v1Run('A', 'T1003.001'), v1Run('B', 'T1110')]) });
      expect(written).toEqual([VALIDATION_RUNS_V1_KEY]);
      expect(rebuild().all.map(r => r.id)).toEqual(['A', 'B']);
    });

    it('does not overwrite a v2 run with the same id that was edited after migration', () => {
      service.update('A', { notes: 'edited in v2' });
      restore({ [VALIDATION_RUNS_V1_KEY]: JSON.stringify([v1Run('A', 'T1003.001', { notes: 'v1 text' }), v1Run('B', 'T1110')]) });
      const after = rebuild();
      expect(after.all.find(r => r.id === 'A')!.notes).toBe('edited in v2');
      expect(after.all.map(r => r.id)).toEqual(['A', 'B']);
    });

    it('does not resurrect a tombstoned id', () => {
      service.delete('A');
      restore({ [VALIDATION_RUNS_V1_KEY]: JSON.stringify([v1Run('A', 'T1003.001'), v1Run('B', 'T1110')]) });
      expect(rebuild().all.map(r => r.id)).toEqual(['B']);
    });

    it('a bundle carrying v2 is authoritative: no v1 upsert runs, even when the local v1 fingerprint differs', () => {
      const v2 = JSON.stringify({
        schema: 2, migratedFromV1Fingerprint: 'deadbeef:1', tombstones: [],
        records: [{ ...v1Run('C', 'T1110'), domain: null, attackVersion: 'unknown', source: 'manual',
          createdAt: '2026-03-01T00:00:00.000Z', updatedAt: '2026-03-01T00:00:00.000Z', techniqueRef: null,
          proofScope: 'own-run', outcomes: [], statusFromSource: false }],
      });
      // The local v1 now differs from anything the bundle's store migrated.
      localStorage.setItem(VALIDATION_RUNS_V1_KEY, JSON.stringify([v1Run('A', 'T1003.001'), v1Run('L', 'T1021')]));
      const written = restore({ [VALIDATION_RUNS_V2_KEY]: v2 });
      expect(written).toEqual([VALIDATION_RUNS_V2_KEY]);
      expect(rebuild().all.map(r => r.id)).toEqual(['C']);
      expect(JSON.parse(localStorage.getItem(STORAGE_KEY)!).migratedFromV1Fingerprint)
        .toBe(fingerprint(localStorage.getItem(VALIDATION_RUNS_V1_KEY)!));
    });
  });

  describe('technique matching through runMatches (P2-02, design §8, R6)', () => {
    it('forTechnique(T1562.001) finds a run after the resolver maps it to T1685', () => {
      loadDomain('enterprise', '19.2');
      const keyed = service.record({ ...baseRun, techniqueId: 'T1685' });
      expect(keyed.techniqueRef).toBe('attack/enterprise/T1685@19.2');
      service.importJson(JSON.stringify({ runs: [v1Run('old', 'T1562.001')] }));     // a bare-id run
      expect(service.forTechnique('T1562.001').map(r => r.id)).toEqual(['old']);
      TestBed.inject(AttackIdResolverService).setSupersededBy(new Map([['T1562.001', 'T1685']]));
      expect(service.forTechnique('T1562.001').map(r => r.id)).toEqual([keyed.id, 'old']);
      expect(service.forTechnique('T1685').map(r => r.id)).toEqual([keyed.id, 'old']);
      expect(service.latestFor('T1562.001')).not.toBeNull();
    });

    it('parity, ICS: a T0807 run with techniqueRef null is found after a reload once ICS loads', () => {
      const r = service.record({ ...baseRun, techniqueId: 'T0807' });   // no domain loaded yet
      expect(r.techniqueRef).toBeNull();
      expect(r.domain).toBeNull();
      const reloaded = rebuild();
      loadDomain('ics', '17.1');
      expect(reloaded.forTechnique('T0807').map(x => x.id)).toEqual([r.id]);
      // The run was matched lazily, never re-keyed to the domain that loaded.
      expect(reloaded.all[0].techniqueRef).toBeNull();
    });

    it('parity, F3: an Enterprise T1110 run is found under F3 after a reload, by forTechnique and by runMatches', () => {
      loadDomain('enterprise', '19.2');
      const r = service.record({ ...baseRun, techniqueId: 'T1110' });
      expect(r.techniqueRef).toBe('attack/enterprise/T1110@19.2');
      const reloaded = rebuild();                                        // the run is read back from storage
      loadDomain('f3', '1.0');
      const stored = reloaded.all[0];
      expect(stored.id).toBe(r.id);
      expect(stored.techniqueRef).toBe('attack/enterprise/T1110@19.2');
      const resolve = (id: string) => TestBed.inject(AttackIdResolverService).resolve(id);
      expect(reloaded.forTechnique('T1110').map(x => x.id)).toEqual([r.id]);
      expect(runMatches(stored, { attackId: 'T1110' }, 'f3', resolve)).toBe(true);
      expect(runMatches(stored, { attackId: 'F1001' }, 'f3', resolve)).toBe(false);
      loadDomain('ics', '17.1');
      expect(reloaded.forTechnique('T1110')).toEqual([]);   // ICS ids never equal Enterprise ids
    });
  });

  describe('buildNavigatorLayer version (P2-02)', () => {
    it('uses the loaded domain version, else the run version, instead of a hard-coded 17', () => {
      service.importRows([rangeRow('r1', 'T1110')], 'lylat-range:mission-a');      // attackVersion 19.2
      expect((service.buildNavigatorLayer('enterprise-attack') as any).versions.attack).toBe('19.2');
      loadDomain('enterprise', '19.3');
      expect((service.buildNavigatorLayer('enterprise-attack') as any).versions.attack).toBe('19.3');
    });

    it('labels the new status in the legend', () => {
      const legend = (service.buildNavigatorLayer('enterprise-attack') as any).legendItems.map((l: any) => l.label);
      expect(legend).toContain('not-reproducible');
      expect(service.statusCounts()['not-reproducible']).toBe(0);
    });
  });
});
