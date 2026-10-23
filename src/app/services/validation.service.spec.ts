// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { BehaviorSubject, firstValueFrom } from 'rxjs';
import {
  ATTACK_DID_NOT_EXECUTE, ValidationService, ValidationStatus, ValidationRunV2, describeImportResult,
  VALIDATION_RUNS_V1_KEY, VALIDATION_RUNS_V2_KEY, sanitizeRun, statusFromInputs, storedUntestedWords,
} from './validation.service';
import { DEFAULT_POSTURE_RULES, derivePosture } from '../models/posture/derive-posture';
import { AttackIdResolverService } from './attack-id-resolver.service';
import { DataService, AttackDomain } from './data.service';
import { ImplementationService } from './implementation.service';
import { OwnerDataService } from './owner-data.service';
import { WorkspaceBundleService } from './workspace-bundle.service';
import { fingerprint } from '../models/storage-envelope';
import { runMatches } from '../models/posture/run-match';
import { runInputs } from './posture-adapters';
import LYLAT_FIXTURE from '../../testing/fixtures/lylat/validated-detections.fixture.json';
import LYLAT_FIXTURE_B from '../../testing/fixtures/lylat/validated-detections.mission-b.fixture.json';
import LYLAT_INVALID_IP from '../../testing/fixtures/lylat/invalid/ip-evidence.json';
import LYLAT_INVALID_HOSTNAME from '../../testing/fixtures/lylat/invalid/hostname.json';

const STORAGE_KEY = VALIDATION_RUNS_V2_KEY;

/**
 * A stand-in for the loaded domain: `loaded` null means no domain has loaded
 * yet (the resolver is then the identity and record() writes techniqueRef null).
 */
const fakeData = {
  id: 'enterprise' as AttackDomain,
  loaded: null as { attackVersion: string; techniques?: { attackId: string }[] } | null,
  getCurrentDomain(): unknown { return this.loaded; },
  getCurrentAttackDomain(): AttackDomain { return this.id; },
};
function loadDomain(id: AttackDomain, attackVersion: string, techniques?: readonly string[]): void {
  fakeData.id = id;
  fakeData.loaded = { attackVersion, techniques: techniques?.map(attackId => ({ attackId })) };
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

  // RP-F decision 32: a run whose attack did not execute stores untested, never
  // passed, whatever rules are ticked. Round 6 recorded "Failed prerequisite" with its
  // rule ticked and stored 'passed', a proof the allow-list of decision 23 accepted.
  describe('a run whose attack did not execute (RP-F decision 32)', () => {
    const allFired = {
      telemetryRequired: ['x'], telemetryAvailable: ['x'], detectionsExpected: ['sigma:a'], detectionsFired: ['sigma:a'],
    };
    const EXPECTED: Readonly<Record<ValidationRunV2['attackResult'], ValidationStatus>> = {
      executed: 'passed', blocked: 'passed', 'failed-prereq': 'untested', errored: 'untested',
    };

    for (const [attackResult, status] of Object.entries(EXPECTED) as [ValidationRunV2['attackResult'], ValidationStatus][]) {
      it(`attackResult '${attackResult}' with every rule ticked computes '${status}'`, () => {
        expect(ATTACK_DID_NOT_EXECUTE[attackResult]).toBe(status === 'untested');
        expect(statusFromInputs({ ...allFired, attackResult })).toBe(status);
        // Whatever else the inputs say, a run that did not execute is untested.
        if (status === 'untested') {
          expect(statusFromInputs({ ...allFired, telemetryAvailable: [], attackResult })).toBe('untested');
          expect(statusFromInputs({ ...allFired, detectionsFired: [], attackResult })).toBe('untested');
        }
      });
    }

    for (const attackResult of ['failed-prereq', 'errored'] as const) {
      it(`record(): '${attackResult}' with its rule ticked stores untested, yields no proof, and the latest run reads untested`, () => {
        const run = service.record({ ...baseRun, attackResult });
        expect(run.status).toBe('untested');
        expect(service.latestFor('T1003.001')!.status).toBe('untested');
        const inputs = runInputs(run);
        const s = derivePosture('attack/enterprise/T1003.001@19.2', {
          knownSignals: 0, covered: inputs.covered, proof: inputs.proof, verdicts: inputs.verdicts, runs: [inputs.summary],
          threatWeight: 0, exposureWeight: 0,
        }, DEFAULT_POSTURE_RULES, new Date('2026-10-22T00:00:00.000Z'));
        expect(s.bucket).not.toBe('proven');
        expect(s.proof).toEqual([]);
        expect(s.runsWithoutProof.map(r => r.status)).toEqual(['untested']);
      });
    }

    it('update(): changing the outcome recomputes the status both ways', () => {
      const run = service.record(baseRun);
      expect(run.status).toBe('passed');
      service.update(run.id, { attackResult: 'errored' });
      expect(service.all[0].status).toBe('untested');
      service.update(run.id, { attackResult: 'executed' });
      expect(service.all[0].status).toBe('passed');
    });

    it('a v1 row with no status and a non-executed outcome is carried as untested', () => {
      localStorage.setItem(VALIDATION_RUNS_V1_KEY, JSON.stringify([v1Run('fp', 'T1110', { status: undefined, attackResult: 'failed-prereq' })]));
      expect(rebuild().all[0].status).toBe('untested');
    });
  });

  // RP-F decision 37 (round 7, letter G): decision 32 on every write path. Import JSON
  // kept an explicit status 'passed' with attackResult errored or failed-prereq, so
  // T1027 and T1486 read Proven (2/2).
  describe('every write path re-derives a non-executed run as untested (RP-F decision 37)', () => {
    const exportOf = (...runs: Record<string, unknown>[]) => JSON.stringify({ schemaVersion: '2.0', runs });
    const T1027 = v1Run('r7-t1027', 'T1027', { attackResult: 'errored', status: 'passed', source: 'manual' });
    const T1486 = v1Run('r7-t1486', 'T1486', { attackResult: 'failed-prereq', status: 'passed', source: 'manual' });
    const EXECUTED = v1Run('r7-t1059', 'T1059', { attackResult: 'executed', status: 'passed', source: 'manual' });

    function proofOf(run: ValidationRunV2) {
      const inputs = runInputs(run);
      return derivePosture(`attack/enterprise/${run.techniqueId}@19.2`, {
        knownSignals: 0, covered: inputs.covered, proof: inputs.proof, verdicts: inputs.verdicts, runs: [inputs.summary],
        threatWeight: 0, exposureWeight: 0,
      }, DEFAULT_POSTURE_RULES, new Date('2026-03-02T00:00:00.000Z'));
    }

    it('Import JSON: T1027 (errored) and T1486 (failed-prereq) with status passed store untested and never prove; the summary names the count', () => {
      const result = service.importJson(exportOf(T1027, T1486, EXECUTED));
      expect(result.ok).toBeTrue();
      expect(result.storedUntested).toBe(2);
      const byId = new Map(service.all.map(r => [r.id, r]));
      expect(byId.get('r7-t1027')!.status).toBe('untested');
      expect(byId.get('r7-t1486')!.status).toBe('untested');
      expect(service.latestFor('T1027')!.status).toBe('untested');
      for (const id of ['r7-t1027', 'r7-t1486']) {
        const s = proofOf(byId.get(id)!);
        expect(s.bucket).withContext(id).not.toBe('proven');
        expect(s.proof).withContext(id).toEqual([]);
        expect(s.runsWithoutProof.map(r => r.status)).withContext(id).toEqual(['untested']);
      }
      // A passed run whose attack executed is untouched, and still proves.
      expect(byId.get('r7-t1059')!.status).toBe('passed');
      expect(proofOf(byId.get('r7-t1059')!).bucket).toBe('proven');
      expect(describeImportResult(result)).toBe('Imported manual: 3 added, 0 replaced. 2 runs stored untested: the attack did not execute.');
      // A reload reads the stored status back unchanged.
      expect(new Map(rebuild().all.map(r => [r.id, r.status])).get('r7-t1027')).toBe('untested');
    });

    it('the summary names one run in the singular, and says nothing when every run executed', () => {
      expect(describeImportResult(service.importJson(exportOf(T1027)))).toBe('Imported manual: 1 added, 0 replaced. 1 run stored untested: the attack did not execute.');
      const plain = service.importJson(exportOf(EXECUTED));
      expect(plain.storedUntested).toBeUndefined();
      expect(describeImportResult(plain)).toBe('Imported manual: 1 added, 0 replaced.');
      expect(storedUntestedWords(0)).toBe('');
      expect(storedUntestedWords(3)).toBe('3 runs stored untested: the attack did not execute');
    });

    it('a run already untested is not counted; any other explicit status with a non-executed attack is re-derived', () => {
      const res = service.importJson(exportOf(
        v1Run('u1', 'T1027', { attackResult: 'errored', status: 'untested' }),
        v1Run('f1', 'T1486', { attackResult: 'failed-prereq', status: 'failed' }),
        v1Run('p1', 'T1486', { attackResult: 'errored', status: 'partial' }),
      ));
      expect(res.storedUntested).toBe(2);
      expect(service.all.map(r => r.status)).toEqual(['untested', 'untested', 'untested']);
    });

    it('the v1 copy-forward stores a non-executed passed row untested and counts it', () => {
      localStorage.setItem(VALIDATION_RUNS_V1_KEY, JSON.stringify([
        v1Run('v1-t1027', 'T1027', { attackResult: 'errored', status: 'passed' }), v1Run('v1-ok', 'T1059'),
      ]));
      const svc = rebuild();
      expect(svc.all.map(r => [r.id, r.status])).toEqual([['v1-t1027', 'untested'], ['v1-ok', 'passed']]);
      expect(svc.migrationStoredUntested).toBe(1);
      // A later construction (no copy-forward) still names it while the v1 key exists.
      expect(rebuild().migrationStoredUntested).toBe(1);
    });

    it('a range import (importRows, the contract path) with a non-executed passed row stores it untested', () => {
      const res = service.importRows([{ ...rangeRow('lylat:x:enterprise:0', 'T1486'), attackResult: 'errored', status: 'passed' }], 'lylat-range:x');
      expect(res.ok).toBeTrue();
      expect(res.storedUntested).toBe(1);
      expect(service.all[0].status).toBe('untested');
      expect(service.all[0].statusFromSource).toBeTrue();
    });

    // PR #240 round 1: update() is a write path too. It recomputed the status only when an
    // input field changed and never for a statusFromSource run, so these two patches stored
    // a passed run of an attack that did not execute until the next boot's sanitizeRun.
    for (const attackResult of ['errored', 'failed-prereq'] as const) {
      it(`update(): a patch of { status: 'passed' } alone on a manual '${attackResult}' run stores untested`, () => {
        const run = service.record({ ...baseRun, attackResult });
        expect(run.status).toBe('untested');
        service.update(run.id, { status: 'passed' });
        expect(service.all[0].status).toBe('untested');
        expect(proofOf(service.all[0]).bucket).not.toBe('proven');
        expect(service.latestFor('T1003.001')!.status).toBe('untested');
      });

      it(`update(): a patch of { attackResult: '${attackResult}' } on an imported passed run stores untested`, () => {
        service.importRows([{ ...rangeRow('imp1', 'T1486'), status: 'passed' }], 'lylat-range:x');
        expect(service.all[0].status).toBe('passed');
        expect(service.all[0].statusFromSource).toBeTrue();
        service.update('imp1', { attackResult });
        const after = service.all[0];
        expect(after.status).toBe('untested');
        expect(after.statusFromSource).toBeTrue();
        expect(after.attackResult).toBe(attackResult);
        expect(proofOf(after).bucket).not.toBe('proven');
      });
    }

    it("update(): an executed run's explicit status patch is kept (only a non-executed attack is forced untested)", () => {
      const run = service.record({ ...baseRun, attackResult: 'executed' });
      service.update(run.id, { status: 'failed' });
      expect(service.all[0].status).toBe('failed');
    });

    it('a stored record written before this rule reads back untested (the store reader sanitises too)', () => {
      const run = (sanitizeRun(v1Run('old', 'T1027', { status: 'passed', attackResult: 'executed' })) as { run: ValidationRunV2 }).run;
      localStorage.setItem(STORAGE_KEY, JSON.stringify({ schema: 2, tombstones: [], records: [{ ...run, attackResult: 'errored', status: 'passed' }] }));
      expect(rebuild().all[0].status).toBe('untested');
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

    // RP-F decision 24: latestFor uses the one latest-run comparator the posture
    // derivation uses (latest-run.ts), never a runDate string compare.
    it('S19 T1007: an offset timestamp is ordered by its instant, not its string', () => {
      service.record({ ...baseRun, runDate: '2026-10-21T01:30:00+09:00', detectionsFired: ['sigma:a'] });
      const later = service.record({ ...baseRun, runDate: '2026-10-20T20:00:00Z', detectionsFired: [] });
      expect(service.latestFor('T1003.001')!.id).toBe(later.id);
      expect(later.status).toBe('failed');
    });

    it('S18 T1049: on the same instant the failed run is the latest, whichever was recorded first', () => {
      const at = '2026-10-20T15:00:00.000Z';
      const failed = service.record({ ...baseRun, runDate: at, detectionsFired: [] });
      service.record({ ...baseRun, runDate: at });
      expect(service.latestFor('T1003.001')!.id).toBe(failed.id);
    });

    it("S22 T1497: a runDate that is not a date ('yesterday') is the oldest run", () => {
      const dated = service.record({ ...baseRun, runDate: '2026-10-19T10:00:00.000Z' });
      service.record({ ...baseRun, runDate: 'yesterday', detectionsFired: [] });
      expect(service.latestFor('T1003.001')!.id).toBe(dated.id);
    });

    it('the Navigator layer export colours each technique by the same latest run', () => {
      const at = '2026-10-20T15:00:00.000Z';
      service.record({ ...baseRun, runDate: at });
      service.record({ ...baseRun, runDate: at, detectionsFired: [] });
      const layer = service.buildNavigatorLayer('enterprise-attack') as { techniques: { techniqueID: string; comment?: string; color?: string }[] };
      expect(layer.techniques.find(t => t.techniqueID === 'T1003.001')!.color).toBe('#ef4444');
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

    // RP-F decision 24 (round 4 repair): the newest run's ATT&CK version is picked with the one
    // latest-run comparator, never a runDate string compare (an offset timestamp sorted ahead).
    it("with no domain loaded, the version is the newest run's by instant, not by runDate string", () => {
      loadDomain('enterprise', '18.1');
      service.record({ ...baseRun, runDate: '2026-10-21T01:30:00+09:00' });   // 2026-10-20T16:30Z
      loadDomain('enterprise', '19.2');
      service.record({ ...baseRun, runDate: '2026-10-20T20:00:00Z' });        // later instant, smaller string
      loadDomain('enterprise', '17.0');
      service.record({ ...baseRun, runDate: 'yesterday' });                    // unreadable: the oldest
      fakeData.loaded = null;
      const layer = service.buildNavigatorLayer('enterprise-attack') as { versions: { attack?: string } };
      expect(layer.versions.attack).toBe('19.2');
    });
  });

  describe('latestFor with an unreadable date (RP-F decision 24)', () => {
    it('returns an undated run only while no dated run exists; a dated run then wins', () => {
      const undated = service.record({ ...baseRun, runDate: 'yesterday' });
      expect(service.latestFor('T1003.001')!.id).toBe(undated.id);
      const dated = service.record({ ...baseRun, runDate: '2026-10-19T10:00:00.000Z' });
      expect(service.latestFor('T1003.001')!.id).toBe(dated.id);
      expect(service.latestFor('T9999')).toBeNull();
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

    // RP-F decision 29: the rule lists are normalised at import and at load (trimmed,
    // empties dropped, each rule once), so the Validation pill's "N of M detection rules
    // fired" (latest.detectionsFired.length) and the evidence card's fired-rule count
    // (runInputs summary.rulesFired) read the same rules.
    it("normalises detectionsFired and detectionsExpected at import and load: ['siem:a','siem:a',''] is one rule on the pill and the card", () => {
      const dup = { detectionsExpected: [' siem:a ', 'siem:a', ''], detectionsFired: ['siem:a', 'siem:a', ''] };
      const res = service.importJson(JSON.stringify({ runs: [v1Run('d1', 'T1110', dup)] }));
      expect(res.ok).toBe(true);
      for (const svc of [service, rebuild()]) {
        const run = svc.latestFor('T1110')!;
        expect(run.detectionsFired).toEqual(['siem:a']);
        expect(run.detectionsExpected).toEqual(['siem:a']);
        const pill = run.detectionsFired.length;
        const card = runInputs(run).summary.rulesFired;
        expect([pill, card]).toEqual([1, 1]);
      }
      // The v1 copy-forward reads through the same normaliser.
      localStorage.clear();
      localStorage.setItem(VALIDATION_RUNS_V1_KEY, JSON.stringify([v1Run('v1', 'T1110', dup)]));
      const upgraded = rebuild().latestFor('T1110')!;
      expect([upgraded.detectionsFired.length, runInputs(upgraded).summary.rulesFired]).toEqual([1, 1]);
      expect(upgraded.detectionsExpected).toEqual(['siem:a']);
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

  describe('importRangeContract (P2-20)', () => {
    const text = () => JSON.stringify(LYLAT_FIXTURE);
    const rangeRuns = (svc: ValidationService) => svc.all.filter(r => r.source === 'lylat-range:SYNTH-MISSION-A');

    beforeEach(() => loadDomain('enterprise', '19.2'));

    it('[AC] imports the fixture as range-scoped runs, keyed like a manual run', () => {
      const res = service.importRangeContract(text());
      expect(res.ok).toBeTrue();
      const stored = rangeRuns(service);
      expect(stored.length).toBe(8);
      expect(stored.every(r => r.proofScope === 'range' && r.statusFromSource)).toBeTrue();
      const t1059 = stored.find(r => r.techniqueId === 'T1059.001')!;
      expect(t1059.techniqueRef).toBe('attack/enterprise/T1059.001@19.2');
      expect(t1059.outcomes![0].coverageState).toBe('validated');
      // Survives a reload.
      expect(rangeRuns(rebuild()).length).toBe(8);
    });

    it('[AC-R7] re-importing the same file replaces by source: the denominator holds', () => {
      service.importRangeContract(text());
      const first = rangeRuns(service).length;
      const res = service.importRangeContract(text());
      expect(res.ok).toBeTrue();
      expect(rangeRuns(service).length).toBe(first);
      expect(first).toBe(8);
      // replace-by-source counts every prior run of the source as replaced and
      // every incoming run as added; the stored denominator stays 8 (no doubling).
      expect(res.bySource['lylat-range:SYNTH-MISSION-A']).toEqual({ added: 8, replaced: 8 });
    });

    // Minimal valid contract builders, so these tests control rows and missions.
    const cRow = (mission: string, id: string, det: string, step: number) => ({
      mission_id: mission,
      technique_ref: { domain: 'enterprise', id, attack_version: '19.2' },
      detection_ref: det, coverage_state: 'validated', outcome: 'alerted',
      negative_control: 'detection-only', validated_at: '2026-10-18', evidence_ref: `${mission}-step${step}`,
    });
    const contract = (rows: unknown[]) => JSON.stringify({
      schema: 'lylat-validated-detections/1', range_build_ref: 'a1b2c3d', generated_at: '2026-10-18T00:00:00Z', rows,
    });

    // AC2 (domain existence), at the service seam: with a domain that lists its
    // techniques, a well-formed id that names none of them is dropped by row.
    it('[AC] drops a row whose technique is not in the loaded domain, keyed to its export row', () => {
      loadDomain('enterprise', '19.2', ['T1059.001']); // only T1059.001 exists
      const res = service.importRangeContract(contract([
        cRow('MISSION-A', 'T1059.001', 'wazuh:1', 0),
        cRow('MISSION-A', 'T9999.999', 'wazuh:2', 1),
      ]));
      expect(res.ok).toBeTrue();
      expect(rangeRuns(service).length).toBe(0); // mission SYNTH-MISSION-A from the fixture: none here
      expect(service.all.map(r => r.techniqueId)).toEqual(['T1059.001']);
      expect(res.dropped).toEqual([{ row: 1, reason: jasmine.stringContaining('not a technique of the loaded') }]);
    });

    // Round 2 (item 4): a row for a different ATT&CK domain than the loaded one
    // (a mobile row while Enterprise is loaded) is dropped by row with a clear
    // reason — v1 keys every run to the one loaded domain.
    it('[AC] drops a row whose domain is not the loaded domain, keyed to its export row', () => {
      const mobileRow = { ...cRow('MISSION-A', 'T1409', 'wazuh:9', 1), technique_ref: { domain: 'mobile', id: 'T1409', attack_version: '19.2' } };
      const res = service.importRangeContract(contract([cRow('MISSION-A', 'T1059.001', 'wazuh:1', 0), mobileRow]));
      expect(res.ok).toBeTrue();
      expect(service.all.map(r => r.techniqueId)).toEqual(['T1059.001']);
      expect(res.dropped).toEqual([{ row: 1, reason: jasmine.stringContaining('row domain mobile is not the loaded domain') }]);
    });

    // Round 2 (item 1): with no domain loaded, the import is refused outright
    // ("ATT&CK data still loading") rather than keying every row to nothing and
    // silently dropping them. Nothing is stored.
    it('refuses the whole import when no domain is loaded, storing nothing', () => {
      fakeData.loaded = null;
      const res = service.importRangeContract(text());
      expect(res.ok).toBeFalse();
      expect(res.error).toContain('ATT&CK data still loading');
      expect(service.all).toEqual([]);
    });

    // Round 2 (item 8): a multi-mission file whose LATER mission carries an invalid
    // row fails validation as a whole, so the entire file is refused and nothing —
    // not even the valid earlier mission — is stored.
    it('refuses the whole file when a later mission has an invalid row, storing nothing', () => {
      const bad = { ...cRow('MISSION-B', 'T1003.001', 'wazuh:3', 2), coverage_state: 'not-a-state' };
      const res = service.importRangeContract(contract([
        cRow('MISSION-A', 'T1059.001', 'wazuh:1', 0),
        cRow('MISSION-A', 'T1087.002', 'wazuh:2', 1),
        bad,
      ]));
      expect(res.ok).toBeFalse();
      expect(res.error).toContain('Invalid range results');
      expect(service.all).toEqual([]);
    });

    // AC4 (atomic): a multi-mission file commits in ONE emission, and every drop is
    // reported against the row index the reader sees in the export (not a per-group one).
    it('[AC] imports every mission in one atomic commit, dropping by export row index', () => {
      let emissions = 0;
      const sub = service.runs$.subscribe(() => emissions++);
      emissions = 0; // discard the BehaviorSubject replay
      const res = service.importRangeContract(contract([
        cRow('MISSION-A', 'T1059.001', 'wazuh:1', 0),
        { ...cRow('MISSION-A', 'AML.T0001', 'wazuh:2', 1), technique_ref: { domain: 'atlas', id: 'AML.T0001', attack_version: '1.0' } },
        cRow('MISSION-B', 'T1003.001', 'wazuh:3', 2),
        { ...cRow('MISSION-B', 'AML.T0002', 'wazuh:4', 3), technique_ref: { domain: 'atlas', id: 'AML.T0002', attack_version: '1.0' } },
      ]));
      sub.unsubscribe();
      expect(res.ok).toBeTrue();
      expect(emissions).toBe(1); // one commit for both missions, not one per mission
      expect(res.dropped.map(d => d.row)).toEqual([1, 3]); // export indices of the two atlas rows
      expect(service.all.filter(r => r.source === 'lylat-range:MISSION-A').map(r => r.techniqueId)).toEqual(['T1059.001']);
      expect(service.all.filter(r => r.source === 'lylat-range:MISSION-B').map(r => r.techniqueId)).toEqual(['T1003.001']);
    });

    // A refused file leaves pre-existing manual AND range runs byte-for-byte
    // untouched. hostname.json is refused STRUCTURALLY (a top-level extra key), a
    // different refusal path from the privacy-regex one below.
    it('a refused file stores nothing and leaves existing manual and range runs intact', () => {
      service.record({ ...baseRun, techniqueId: 'T1003.001' });
      service.importRows([rangeRow('r1', 'T1110')], 'lylat-range:mission-x');
      const before = JSON.stringify(service.all);
      const res = service.importRangeContract(JSON.stringify(LYLAT_INVALID_HOSTNAME));
      expect(res.ok).toBeFalse();
      expect(JSON.stringify(service.all)).toBe(before);
    });

    // R7, in full (round 2 item 7, sharpened round 3 item 2): import the 8-row
    // FIXTURE as mission A and a SEPARATE two-row mission B file (10 runs total),
    // add a manual run, then re-import the SAME A fixture — only A's rows are
    // replaced; mission B's two runs and the manual run stay byte-for-byte.
    it('[AC-R7] mission A fixture + a separate mission B file = 10 runs; re-importing A replaces only A', () => {
      expect(service.importRangeContract(text()).ok).toBeTrue();                            // the 8-row fixture = mission A
      expect(service.importRangeContract(JSON.stringify(LYLAT_FIXTURE_B)).ok).toBeTrue();   // a separate 2-row mission B file
      expect(service.all.filter(r => r.source === 'lylat-range:SYNTH-MISSION-A').length).toBe(8);
      expect(service.all.filter(r => r.source === 'lylat-range:SYNTH-MISSION-B').length).toBe(2);
      expect(service.all.length).toBe(10);

      service.record({ ...baseRun, techniqueId: 'T1021.002' });                             // a manual run beside the imports
      const missionBBefore = JSON.stringify(service.all.filter(r => r.source === 'lylat-range:SYNTH-MISSION-B'));
      const manualBefore = JSON.stringify(service.all.filter(r => r.source === 'manual'));

      const res = service.importRangeContract(text());                                      // re-import the SAME mission A fixture
      expect(res.ok).toBeTrue();
      expect(service.all.filter(r => r.source === 'lylat-range:SYNTH-MISSION-A').length).toBe(8);
      expect(service.all.filter(r => r.source === 'lylat-range:SYNTH-MISSION-B').length).toBe(2);
      expect(JSON.stringify(service.all.filter(r => r.source === 'lylat-range:SYNTH-MISSION-B'))).toBe(missionBBefore);
      expect(JSON.stringify(service.all.filter(r => r.source === 'manual'))).toBe(manualBefore);
    });

    // Round 3 (item 1): the range replace is DOMAIN-SCOPED. A mission that spans
    // Enterprise and ICS is brought in by loading each domain and re-importing the
    // same file: the second domain's rows are ADDED (not swapped for the first's),
    // and re-importing under one domain replaces only that domain's rows — nothing
    // is lost. (The describe loads Enterprise with no technique list, so isKnown is
    // always true; loadDomain switches the loaded domain mid-session.)
    const mixMission = 'MISSION-MIX';
    const mixed = (firstDet: string) => contract([
      cRow(mixMission, 'T1059.001', firstDet, 0),
      { ...cRow(mixMission, 'T0883', 'wazuh:701', 1), technique_ref: { domain: 'ics', id: 'T0883', attack_version: '19.2' } },
      cRow(mixMission, 'T1003.001', 'wazuh:702', 2),
    ]);
    const mixRuns = () => service.all.filter(r => r.source === `lylat-range:${mixMission}`);

    it('[AC item 1] accumulates a mixed-domain mission across domains; a re-import replaces only the loaded domain', () => {
      // (a) Enterprise loaded: the two Enterprise rows store; the ICS row is skipped.
      loadDomain('enterprise', '19.2');
      const ra = service.importRangeContract(mixed('wazuh:700'));
      expect(ra.ok).toBeTrue();
      expect(mixRuns().length).toBe(2);
      expect(mixRuns().every(r => r.domain === 'enterprise')).toBeTrue();
      expect(ra.dropped.map(d => d.row)).toEqual([1]);                 // the ICS row, by export index

      // (b) ICS loaded, the SAME file: the ICS row is ADDED; the Enterprise rows remain.
      loadDomain('ics', '19.2');
      const rb = service.importRangeContract(mixed('wazuh:700'));
      expect(rb.ok).toBeTrue();
      expect(mixRuns().length).toBe(3);                               // 2 enterprise + 1 ics — nothing lost
      expect(mixRuns().filter(r => r.domain === 'enterprise').length).toBe(2);
      expect(mixRuns().filter(r => r.domain === 'ics').length).toBe(1);
      expect(rb.bySource[`lylat-range:${mixMission}`]).toEqual({ added: 1, replaced: 0 }); // enterprise rows not replaced
      expect(rb.dropped.map(d => d.row)).toEqual([0, 2]);             // the two enterprise rows, skipped under ICS

      // (c) Enterprise loaded again, one Enterprise row changed: only the Enterprise
      // rows are replaced; the ICS row is byte-for-byte untouched.
      loadDomain('enterprise', '19.2');
      const icsBefore = JSON.stringify(mixRuns().filter(r => r.domain === 'ics'));
      const rc = service.importRangeContract(mixed('wazuh:999'));     // the first Enterprise row's detection changed
      expect(rc.ok).toBeTrue();
      expect(mixRuns().length).toBe(3);                              // still 3: 2 enterprise replaced in place, 1 ics kept
      expect(mixRuns().filter(r => r.domain === 'enterprise').length).toBe(2);
      expect(JSON.stringify(mixRuns().filter(r => r.domain === 'ics'))).toBe(icsBefore);
      expect(service.all.find(r => r.id === `lylat:${mixMission}:enterprise:0`)!.detectionsExpected).toEqual(['wazuh:999']);
      expect(rc.bySource[`lylat-range:${mixMission}`]).toEqual({ added: 2, replaced: 2 }); // only the 2 enterprise replaced
    });

    it('[AC item 1] a domain-keyed run id never collides across domains; delete hits one domain only', () => {
      // A re-export with a NEW Enterprise row inserted at the front shifts the
      // original rows down, so without the domain in the id the re-import's
      // Enterprise run at index 1 would collide with the ICS run keyed at the
      // original index 1 (lylat:MISSION-MIX:1 stored twice). The domain segment
      // (lylat:<mission>:<domain>:<i>) stops it.
      const mixedFront = (firstDet: string) => contract([
        cRow(mixMission, 'T1047', firstDet, 9),                         // inserted Enterprise row at the front
        cRow(mixMission, 'T1059.001', 'wazuh:700', 0),
        { ...cRow(mixMission, 'T0883', 'wazuh:701', 1), technique_ref: { domain: 'ics', id: 'T0883', attack_version: '19.2' } },
        cRow(mixMission, 'T1003.001', 'wazuh:702', 2),
      ]);

      loadDomain('enterprise', '19.2'); service.importRangeContract(mixed('wazuh:700'));   // [E,I,E] under Enterprise
      loadDomain('ics', '19.2');        service.importRangeContract(mixed('wazuh:700'));   // + the ICS row
      loadDomain('enterprise', '19.2'); const rc = service.importRangeContract(mixedFront('wazuh:700'));
      expect(rc.ok).toBeTrue();

      const ids = mixRuns().map(r => r.id);
      expect(new Set(ids).size).toBe(ids.length);                        // (i) every stored id unique across domains
      expect(ids).toContain(`lylat:${mixMission}:ics:1`);                // the ICS run keeps its domain-keyed id
      expect(ids).toContain(`lylat:${mixMission}:enterprise:1`);         // the re-import's Enterprise row at the same index
      expect(ids.every(id => id !== `lylat:${mixMission}:1`)).toBeTrue();// the pre-fix collision shape is gone
      expect(mixRuns().filter(r => r.domain === 'enterprise').length).toBe(3);
      expect(mixRuns().filter(r => r.domain === 'ics').length).toBe(1);

      // (ii) deleting the Enterprise run at index 1 leaves the ICS run at the same
      // index intact — pre-fix, delete(lylat:MISSION-MIX:1) removed both and
      // tombstoned the shared id.
      service.delete(`lylat:${mixMission}:enterprise:1`);
      expect(mixRuns().find(r => r.id === `lylat:${mixMission}:ics:1`)).toBeDefined();
      expect(mixRuns().filter(r => r.domain === 'ics').length).toBe(1);
      expect(mixRuns().filter(r => r.domain === 'enterprise').length).toBe(2);
    });

    it('refuses a privacy-leaking file and stores nothing', () => {
      const res = service.importRangeContract(JSON.stringify(LYLAT_INVALID_IP));
      expect(res.ok).toBeFalse();
      expect(res.error).toContain('Invalid range results');
      expect(service.all).toEqual([]);
    });

    it('refuses a non-contract file without touching the store', () => {
      expect(service.importRangeContract(JSON.stringify({ schema: 'something-else' })).ok).toBeFalse();
      expect(service.importRangeContract('not-json').ok).toBeFalse();
      expect(service.all).toEqual([]);
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
