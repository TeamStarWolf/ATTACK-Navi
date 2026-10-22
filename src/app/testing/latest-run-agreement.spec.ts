// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// RP-F decision 24: the Detection Validation pill and the posture derivation pick
// the SAME latest run, with one comparator, and print its day with one reading of
// the date, in any zone. Round 4 found them apart on four shapes: S18 T1049 (same
// instant: pill FAIL, card Proven), S19 T1007 (offset timestamps: pill PASS, card
// "contradicted: latest run failed"), S22 T1497 (runDate 'yesterday': pill FAIL,
// card Proven) and S27 T1059.001 (a date-only range run beside a timestamped manual
// run in Chicago: the why line put a later day on the earlier run). Each shape runs
// here in America/Chicago and Asia/Tokyo (setRunDateZoneForSpecs: a browser test
// cannot set TZ, so the comparator and the formatter read a fixed offset).
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { ValidationStatusPillComponent } from '../components/validation-status-pill/validation-status-pill.component';
import { ValidationService, type ValidationRunV2 } from '../services/validation.service';
import { DataService, type AttackDomain } from '../services/data.service';
import { runInputs } from '../services/posture-adapters';
import { DEFAULT_POSTURE_RULES, derivePosture } from '../models/posture/derive-posture';
import type { PostureState } from '../models/posture/posture.types';
import { postureExplain, runsClause } from '../models/lens-explain';
import { setRunDateZoneForSpecs, validationDay } from '../models/local-date';
import { writeV2 } from '../models/storage-envelope';

const KEY = 'navi.v2.validation-runs';
const NOW = new Date('2026-10-21T12:00:00.000Z');
const ZONES = [['America/Chicago', -300], ['Asia/Tokyo', 540]] as const;

const fakeData = {
  getCurrentDomain: (): unknown => null,
  getCurrentAttackDomain: (): AttackDomain => 'enterprise',
};

interface RowSpec { id: string; techniqueId: string; runDate: string; status: 'passed' | 'failed'; source?: string }

function row(r: RowSpec): Record<string, unknown> {
  const range = r.source?.startsWith('lylat-range:');
  return {
    id: r.id, techniqueId: r.techniqueId, techniqueName: '', runDate: r.runDate, operator: 'op',
    telemetryRequired: [], telemetryAvailable: [], atomicTestId: '', atomicCommand: '', attackResult: 'executed',
    detectionsExpected: ['siem:curated'], detectionsFired: r.status === 'passed' ? ['siem:curated'] : [],
    responsePlaybook: '', responseActions: [], evidenceLinks: [], notes: '', status: r.status,
    outcomes: r.status === 'passed'
      ? [{ detectionRef: 'siem:curated', outcome: 'alerted', ...(range ? { coverageState: 'validated' } : {}) }]
      : [{ detectionRef: null, outcome: 'none' }],
    domain: 'enterprise', attackVersion: '19.2', source: r.source ?? 'manual',
    createdAt: '2026-10-01T00:00:00.000Z', updatedAt: '2026-10-01T00:00:00.000Z', techniqueRef: null,
    ...(range ? { missionId: 'm1' } : {}),
  };
}

function derive(runs: readonly ValidationRunV2[]): PostureState {
  const inputs = runs.map(runInputs);
  return derivePosture('attack/enterprise/T1049@19.2', {
    knownSignals: 2, threatWeight: 0, exposureWeight: 0,
    covered: inputs.flatMap(i => i.covered), proof: inputs.flatMap(i => i.proof),
    verdicts: inputs.flatMap(i => i.verdicts), runs: inputs.map(i => i.summary),
  }, DEFAULT_POSTURE_RULES, NOW);
}

/** 'M/D/YY' as a comparable number. */
function dayNumber(day: string): number {
  const [m, d, y] = day.split('/').map(Number);
  return y * 10_000 + m * 100 + d;
}

const SHAPES: { name: string; techniqueId: string; rows: RowSpec[] }[] = [
  {
    name: 'S18 T1049 (same instant)', techniqueId: 'T1049', rows: [
      { id: 'a-pass', techniqueId: 'T1049', runDate: '2026-10-20T15:00:00.000Z', status: 'passed' },
      { id: 'b-fail', techniqueId: 'T1049', runDate: '2026-10-20T15:00:00.000Z', status: 'failed' },
    ],
  },
  {
    name: 'S19 T1007 (offset timestamps)', techniqueId: 'T1007', rows: [
      { id: 'pass', techniqueId: 'T1007', runDate: '2026-10-21T01:30:00+09:00', status: 'passed' },
      { id: 'fail', techniqueId: 'T1007', runDate: '2026-10-20T20:00:00Z', status: 'failed' },
    ],
  },
  {
    name: "S22 T1497 (runDate 'yesterday')", techniqueId: 'T1497', rows: [
      { id: 'pass', techniqueId: 'T1497', runDate: '2026-10-19T10:00:00.000Z', status: 'passed' },
      { id: 'fail', techniqueId: 'T1497', runDate: 'yesterday', status: 'failed' },
    ],
  },
  {
    name: 'S27 T1059.001 (a date-only range run beside a timestamped manual run)', techniqueId: 'T1059.001', rows: [
      { id: 'range', techniqueId: 'T1059.001', runDate: '2026-10-19', status: 'passed', source: 'lylat-range:m1' },
      { id: 'manual', techniqueId: 'T1059.001', runDate: '2026-10-18T22:00:00-05:00', status: 'failed' },
    ],
  },
];

/** What each shape's pill shows, by zone (the latest run's status label). */
const EXPECTED_PILL: Readonly<Record<string, Readonly<Record<string, string>>>> = {
  'S18 T1049 (same instant)': { 'America/Chicago': 'FAIL', 'Asia/Tokyo': 'FAIL' },
  'S19 T1007 (offset timestamps)': { 'America/Chicago': 'FAIL', 'Asia/Tokyo': 'FAIL' },
  "S22 T1497 (runDate 'yesterday')": { 'America/Chicago': 'PASS', 'Asia/Tokyo': 'PASS' },
  'S27 T1059.001 (a date-only range run beside a timestamped manual run)': { 'America/Chicago': 'PASS', 'Asia/Tokyo': 'FAIL' },
};

describe('the pill and the card pick the same latest run, in any zone (RP-F decision 24)', () => {
  beforeEach(() => {
    localStorage.clear();
    TestBed.configureTestingModule({ providers: [provideRouter([]), { provide: DataService, useValue: fakeData }] });
  });
  afterEach(() => {
    localStorage.clear();
    setRunDateZoneForSpecs(null);
  });

  function pill(attackId: string): { status: string; when: string } {
    const fixture = TestBed.createComponent(ValidationStatusPillComponent);
    fixture.componentInstance.attackId = attackId;
    fixture.componentInstance.ngOnChanges({});
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    const text = (sel: string) => (el.querySelector(sel)?.textContent ?? '').replace(/\s+/g, ' ').trim();
    return { status: text('.vsp-status'), when: text('.vsp-when') };
  }

  for (const [zone, offset] of ZONES) {
    for (const shape of SHAPES) {
      it(`${shape.name} in ${zone}`, () => {
        setRunDateZoneForSpecs(offset);
        writeV2(KEY, { schema: 2, tombstones: [], records: shape.rows.map(row) as never[] });
        const service = TestBed.inject(ValidationService);
        const latest = service.latestFor(shape.techniqueId)!;
        const shown = pill(shape.techniqueId);
        expect(shown.status).toBe(EXPECTED_PILL[shape.name][zone]);

        const s = derive(service.forTechnique(shape.techniqueId));
        // The card's rung follows the pill's run: Proven exactly when that run passed.
        expect(s.rung === 'proven').toBe(latest.status === 'passed');
        if (latest.status === 'passed') {
          expect(s.proof[0].runId).toBe(latest.id);
          expect(postureExplain(s)).toContain(`on ${validationDay(latest.runDate)} by`);
        } else {
          // The why line names the pill's run as the latest, and never a later day on the earlier run.
          expect(s.supersededProof!.latest.runId).toBe(latest.id);
          const clause = runsClause(s);
          expect(clause).toContain(`latest run of the rule failed on ${validationDay(latest.runDate)}`);
          const [later, earlier] = [...clause.matchAll(/on (\d+\/\d+\/\d+)/g)].map(m => m[1]);
          expect(dayNumber(later)).toBeGreaterThanOrEqual(dayNumber(earlier));
        }
        // The pill's "last run" day is the day the card prints for the same run.
        if (validationDay(latest.runDate) !== latest.runDate) {
          expect(shown.when).toContain(`last run ${validationDay(latest.runDate)}`);
        }
      });
    }
  }
});
