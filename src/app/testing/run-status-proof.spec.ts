// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// RP-F decision 23: proof is an ALLOW-list of run statuses. For every status
// spelling the store accepts, and every run shape (a fired rule, a blocked outcome
// with no named rule, neither), the rung derived from the run agrees with the
// Detection Validation pill the drawer shows for the same run: only a run the pill
// calls PASS can read Proven, or Covered (self-attested) from a blocked outcome.
// Round 4 found Proven beside UNTESTED (S12 T1018) and Not reproducible (S13
// T1082) pills, and Covered beside FAIL (S26 T1027) and, through Record Run's
// "Blocked by control", UNTESTED (T1069) pills.
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { ValidationStatusPillComponent } from '../components/validation-status-pill/validation-status-pill.component';
import { ValidationService, sanitizeRun, type ValidationRunV2 } from '../services/validation.service';
import { DataService, type AttackDomain } from '../services/data.service';
import { runInputs } from '../services/posture-adapters';
import { DEFAULT_POSTURE_RULES, derivePosture } from '../models/posture/derive-posture';
import type { PostureState } from '../models/posture/posture.types';
import { writeV2 } from '../models/storage-envelope';

const KEY = 'navi.v2.validation-runs';
const NOW = new Date('2026-10-21T12:00:00.000Z');

const fakeData = {
  getCurrentDomain: (): unknown => null,
  getCurrentAttackDomain: (): AttackDomain => 'enterprise',
};

/** Every spelling a status might arrive in; the store keeps exactly the six it accepts. */
const SPELLINGS = [
  'passed', 'failed', 'partial', 'no-telemetry', 'untested', 'not-reproducible',
  'PASSED', 'Passed', ' passed', 'pass', 'not_reproducible', 'notReproducible', 'no telemetry', 'blocked', '',
];

type Shape = 'fired rule' | 'blocked outcome' | 'neither';
const SHAPES: readonly Shape[] = ['fired rule', 'blocked outcome', 'neither'];

function row(id: string, techniqueId: string, status: string, shape: Shape): Record<string, unknown> {
  return {
    id, techniqueId, techniqueName: '', runDate: '2026-10-15T15:00:00.000Z', operator: 'op',
    telemetryRequired: [], telemetryAvailable: [], atomicTestId: '', atomicCommand: '',
    attackResult: shape === 'blocked outcome' ? 'blocked' : 'executed',
    detectionsExpected: [], detectionsFired: shape === 'fired rule' ? ['siem:curated'] : [],
    responsePlaybook: '', responseActions: [], evidenceLinks: [], notes: '', status,
    outcomes: shape === 'blocked outcome' ? [{ detectionRef: null, outcome: 'blocked' }]
      : shape === 'fired rule' ? [{ detectionRef: 'siem:curated', outcome: 'alerted' }] : [],
    domain: 'enterprise', attackVersion: '19.2', source: 'manual',
    createdAt: '2026-10-15T15:00:00.000Z', updatedAt: '2026-10-15T15:00:00.000Z', techniqueRef: null,
  };
}

/** The state PostureService derives from one technique's runs (posture.service.ts), knownSignals 2. */
function deriveFrom(runs: readonly ValidationRunV2[]): PostureState {
  const inputs = runs.map(runInputs);
  return derivePosture('attack/enterprise/T1018@19.2', {
    knownSignals: 2, threatWeight: 0, exposureWeight: 0,
    covered: inputs.flatMap(i => i.covered), proof: inputs.flatMap(i => i.proof),
    verdicts: inputs.flatMap(i => i.verdicts), runs: inputs.map(i => i.summary),
  }, DEFAULT_POSTURE_RULES, NOW);
}

describe('run status governs proof: the derived rung agrees with the Validation pill (RP-F decision 23)', () => {
  beforeEach(() => {
    localStorage.clear();
    TestBed.configureTestingModule({ providers: [provideRouter([]), { provide: DataService, useValue: fakeData }] });
  });
  afterEach(() => localStorage.clear());

  /** The pill's status label for the technique, as the drawer renders it. */
  function pillFor(attackId: string): string {
    const pill = TestBed.createComponent(ValidationStatusPillComponent);
    pill.componentInstance.attackId = attackId;
    pill.componentInstance.ngOnChanges({});
    pill.detectChanges();
    return ((pill.nativeElement as HTMLElement).querySelector('.vsp-status')?.textContent ?? '').trim();
  }

  it('the store accepts exactly six status spellings', () => {
    const accepted = SPELLINGS.filter(s => 'run' in sanitizeRun(row('x', 'T1', s, 'neither')));
    expect(accepted).toEqual(['passed', 'failed', 'partial', 'no-telemetry', 'untested', 'not-reproducible']);
  });

  const accepted = SPELLINGS.filter(s => 'run' in sanitizeRun(row('x', 'T1', s, 'neither')));
  for (const status of accepted) {
    for (const shape of SHAPES) {
      it(`${status} x ${shape}: the rung follows the pill`, () => {
        writeV2(KEY, { schema: 2, tombstones: [], records: [row('r1', 'T1018', status, shape)] as never[] });
        const service = TestBed.inject(ValidationService);
        const pill = pillFor('T1018');
        const s = deriveFrom(service.forTechnique('T1018'));
        const pass = pill === 'PASS';
        expect(pass).toBe(status === 'passed');
        // Proven only beside a PASS pill, and then only from a named rule.
        expect(s.rung === 'proven').withContext(`pill ${pill}`).toBe(pass && shape === 'fired rule');
        // Covered (self-attested, own-run-blocked) only beside a PASS pill.
        const blockedMark = s.covered.some(m => m.basis === 'own-run-blocked');
        expect(blockedMark).withContext(`pill ${pill}`).toBe(pass && shape === 'blocked outcome');
        expect(s.bucket === 'covered').toBe(pass && shape === 'blocked outcome');
        if (!pass) {
          expect([s.rung, s.bucket]).toEqual(['known', 'known']);
          expect(s.runsWithoutProof.map(r => r.status)).toEqual([status]);
        }
      });
    }
  }

  it('S12 T1018: untested with one fired rule beside UNTESTED 1 of 0 is not Proven', () => {
    writeV2(KEY, { schema: 2, tombstones: [], records: [row('s12', 'T1018', 'untested', 'fired rule')] as never[] });
    const service = TestBed.inject(ValidationService);
    expect(pillFor('T1018')).toBe('UNTESTED');
    expect(deriveFrom(service.forTechnique('T1018')).rung).toBe('known');
  });

  it('S13 T1082: not reproducible with one fired rule is not Proven, and is out of the denominator', () => {
    writeV2(KEY, { schema: 2, tombstones: [], records: [row('s13', 'T1082', 'not-reproducible', 'fired rule')] as never[] });
    const service = TestBed.inject(ValidationService);
    expect(pillFor('T1082')).toBe('Not reproducible (patched target)');
    const s = deriveFrom(service.forTechnique('T1082'));
    expect([s.rung, s.excluded]).toEqual(['known', true]);
  });

  it('S26 T1027: a failed run with a blocked outcome and no named rule is not Covered beside FAIL', () => {
    writeV2(KEY, { schema: 2, tombstones: [], records: [row('s26', 'T1027', 'failed', 'blocked outcome')] as never[] });
    const service = TestBed.inject(ValidationService);
    expect(pillFor('T1027')).toBe('FAIL');
    const s = deriveFrom(service.forTechnique('T1027'));
    expect(s.covered).toEqual([]);
    expect(s.bucket).toBe('known');
  });

  it("T1069 through Record Run: 'Blocked by control' with no expected rule stores untested, and attests nothing", () => {
    const service = TestBed.inject(ValidationService);
    const run = service.record({
      techniqueId: 'T1069', techniqueName: 'Permission Groups Discovery', operator: 'op',
      telemetryRequired: [], telemetryAvailable: [], atomicTestId: '', atomicCommand: '',
      attackResult: 'blocked', detectionsExpected: [], detectionsFired: [],
      responsePlaybook: '', responseActions: [], evidenceLinks: [], notes: '',
    });
    expect(run.status).toBe('untested');
    expect(pillFor('T1069')).toBe('UNTESTED');
    const s = deriveFrom(service.forTechnique('T1069'));
    expect(s.covered).toEqual([]);
    expect(s.bucket).toBe('known');
  });
});
