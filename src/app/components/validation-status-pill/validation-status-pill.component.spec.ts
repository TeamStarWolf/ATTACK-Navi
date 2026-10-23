// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter, Router } from '@angular/router';
import { ValidationStatusPillComponent } from './validation-status-pill.component';
import { ValidationService, type ValidationRunV2 } from '../../services/validation.service';
import { runInputs } from '../../services/posture-adapters';
import { DEFAULT_POSTURE_RULES, derivePosture } from '../../models/posture/derive-posture';
import { postureExplain } from '../../models/lens-explain';

describe('ValidationStatusPillComponent', () => {
  let component: ValidationStatusPillComponent;
  let fixture: ComponentFixture<ValidationStatusPillComponent>;
  let validation: any;

  beforeEach(() => {
    validation = {
      runs$: new BehaviorSubject([]),
      forTechnique: jasmine.createSpy('forTechnique').and.returnValue([]),
      latestFor: jasmine.createSpy('latestFor').and.returnValue(null),
    };
    TestBed.configureTestingModule({
      imports: [ValidationStatusPillComponent],
      providers: [
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        provideRouter([]),
        { provide: ValidationService, useValue: validation },
      ],
    });
    fixture = TestBed.createComponent(ValidationStatusPillComponent);
    component = fixture.componentInstance;
  });

  it('starts with no latest run when attackId is empty', () => {
    fixture.detectChanges();
    expect(component.latest).toBeNull();
    expect(component.allRuns).toEqual([]);
  });

  it('queries the validation service for the bound attackId', () => {
    component.attackId = 'T1003.001';
    fixture.detectChanges();
    expect(validation.forTechnique).toHaveBeenCalledWith('T1003.001');
    expect(validation.latestFor).toHaveBeenCalledWith('T1003.001');
  });

  it('openValidationPanel navigates to the validation route', () => {
    const router = TestBed.inject(Router);
    const navigateSpy = spyOn(router, 'navigate').and.resolveTo(true);
    component.openValidationPanel();
    expect(navigateSpy).toHaveBeenCalledWith(['/detect', 'validation'], jasmine.any(Object));
  });

  it('statusLabel returns short uppercase labels', () => {
    expect(component.statusLabel('passed')).toBe('PASS');
    expect(component.statusLabel('failed')).toBe('FAIL');
    expect(component.statusLabel('partial')).toBe('PARTIAL');
  });

  function rangeRun(detectionRef: string, runDate = '2026-10-18'): any {
    return {
      id: `lylat:SYNTH-MISSION-A:${detectionRef}`, techniqueId: 'T1558.003', status: 'passed',
      detectionsExpected: [detectionRef], detectionsFired: [detectionRef], runDate,
      proofScope: 'range', source: 'lylat-range:SYNTH-MISSION-A', statusFromSource: true,
      outcomes: [{ detectionRef, outcome: 'alerted', coverageState: 'validated' }],
    };
  }

  it('marks a range-scoped run with the lab badge and lists each proof record with its date, newest first', () => {
    // Deliberately out of order: the older run is listed first in the input.
    const runs = [rangeRun('wazuh:990001', '2026-10-18'), rangeRun('wazuh:990002', '2026-10-20')];
    validation.forTechnique.and.returnValue(runs);
    validation.latestFor.and.returnValue(runs[1]);
    component.attackId = 'T1558.003';
    fixture.detectChanges();

    expect(component.labRange).toBeTrue();
    // Each entry is a record (ref + the date it was validated), newest first.
    expect(component.labProofRecords).toEqual([
      { ref: 'wazuh:990002', date: '2026-10-20' },
      { ref: 'wazuh:990001', date: '2026-10-18' },
    ]);
    const text = (fixture.nativeElement as HTMLElement).textContent ?? '';
    expect(text).toContain('lab');
    expect(text).toContain('wazuh:990001');
    expect(text).toContain('wazuh:990002');
    expect(text).toContain('Oct 20, 2026'); // the date renders beside the ref
  });

  it('does not show the lab badge for an own-run manual record', () => {
    const manual = { ...rangeRun('sigma:a'), proofScope: 'own-run', source: 'manual', outcomes: [] };
    validation.forTechnique.and.returnValue([manual]);
    validation.latestFor.and.returnValue(manual);
    component.attackId = 'T1558.003';
    fixture.detectChanges();

    expect(component.labRange).toBeFalse();
    expect(component.labProofRecords).toEqual([]);
    expect((fixture.nativeElement as HTMLElement).textContent ?? '').not.toContain('range-run rules');
  });

  // RP-F decision 30b: round 5's T1113 shape. A passed run whose only rule is a blocked
  // outcome (detectionsFired empty) read "0 of 0 detection rules fired" on the pill beside
  // a card reading "1 rule fired". Both now count through firedRules.
  describe('the pill and the evidence card count the same fired rules (RP-F decision 30b)', () => {
    function t1113(over: Partial<ValidationRunV2>): ValidationRunV2 {
      return {
        id: 'rpf30b', techniqueId: 'T1113', techniqueName: 'Screen Capture', runDate: '2026-10-20T10:00:00.000Z', operator: '',
        telemetryRequired: [], telemetryAvailable: [], atomicTestId: '', atomicCommand: '',
        attackResult: 'executed', detectionsExpected: [], detectionsFired: [],
        responsePlaybook: '', responseActions: [], evidenceLinks: [], notes: '', status: 'passed',
        domain: 'enterprise', attackVersion: '19.2', source: 'manual',
        createdAt: '2026-10-20T10:00:00.000Z', updatedAt: '2026-10-20T10:00:00.000Z',
        techniqueRef: 'attack/enterprise/T1113@19.2', proofScope: 'own-run', outcomes: [], statusFromSource: false,
        ...over,
      };
    }
    // A fresh pill per run: the pill reads its runs when attackId is first bound.
    const pillLine = (r: ValidationRunV2): string => {
      validation.forTechnique.and.returnValue([r]);
      validation.latestFor.and.returnValue(r);
      const f = TestBed.createComponent(ValidationStatusPillComponent);
      f.componentInstance.attackId = 'T1113';
      f.detectChanges();
      return ((f.nativeElement as HTMLElement).querySelector('.vsp-meta')?.textContent ?? '').replace(/\s+/g, ' ').trim();
    };
    const cardLine = (r: ValidationRunV2): string => {
      const i = runInputs(r);
      return postureExplain(derivePosture('attack/enterprise/T1113@19.2', {
        knownSignals: 2, threatWeight: 1, exposureWeight: 0, covered: i.covered, proof: i.proof, verdicts: i.verdicts, runs: [i.summary],
      }, DEFAULT_POSTURE_RULES, new Date('2026-10-21T00:00:00.000Z')));
    };

    // RP-F decision 33: more rules fired than expected reads 'N fired, M expected', never '1 of 0'.
    it("T1113, outcome {edr:x, blocked} and empty detectionsFired: pill '1 fired, 0 expected', card '1 rule fired'", () => {
      const r = t1113({ outcomes: [{ detectionRef: 'edr:x', outcome: 'blocked' }] });
      expect(pillLine(r)).toBe('detection rules: 1 fired, 0 expected');
      expect(pillLine(r)).not.toMatch(/\d+ of \d+/);
      expect(cardLine(r)).toBe('Proven (your run) on 10/20/26 by manual; 1 rule fired');
      expect(pillLine(t1113({ detectionsExpected: ['edr:x'], outcomes: [{ detectionRef: 'edr:x', outcome: 'blocked' }] })))
        .toBe('1 of 1 detection rules fired');
    });

    it('duplicates and blanks collapse, and a rule in both lists counts once, on the pill and the card alike', () => {
      const r = t1113({
        detectionsExpected: ['siem:a', 'edr:x', 'siem:c'], detectionsFired: ['siem:a', ' siem:a ', '', 'edr:x'],
        outcomes: [{ detectionRef: 'edr:x', outcome: 'blocked' }, { detectionRef: ' siem:a', outcome: 'alerted' }, { detectionRef: '', outcome: 'alerted' }],
      });
      expect(component.firedCount(r)).toBe(2);
      expect(pillLine(r)).toBe('2 of 3 detection rules fired');
      expect(cardLine(r)).toBe('Proven (your run) on 10/20/26 by manual; 2 rules fired');
    });

    // Round 1 repair: the card counts the best record's RUN (firedRules over the run),
    // never the records of it that stand, and never another run's records.
    const cardLineOf = (runs: readonly ValidationRunV2[]): string => {
      const ins = runs.map(runInputs);
      return postureExplain(derivePosture('attack/enterprise/T1113@19.2', {
        knownSignals: 2, threatWeight: 1, exposureWeight: 0,
        covered: ins.flatMap(i => i.covered), proof: ins.flatMap(i => i.proof), verdicts: ins.flatMap(i => i.verdicts), runs: ins.map(i => i.summary),
      }, DEFAULT_POSTURE_RULES, new Date('2026-10-21T00:00:00.000Z')));
    };
    const pillLineOf = (runs: ValidationRunV2[], latest: ValidationRunV2): string => {
      validation.forTechnique.and.returnValue(runs);
      validation.latestFor.and.returnValue(latest);
      const f = TestBed.createComponent(ValidationStatusPillComponent);
      f.componentInstance.attackId = 'T1113';
      f.detectChanges();
      return ((f.nativeElement as HTMLElement).querySelector('.vsp-meta')?.textContent ?? '').replace(/\s+/g, ' ').trim();
    };

    it("a partly superseded run: a later failed run of one rule leaves the other standing, and the card still names the run's 2 rules", () => {
      const a = t1113({ id: 'rA', runDate: '2026-10-01T10:00:00.000Z', detectionsExpected: ['siem:x', 'siem:y'], detectionsFired: ['siem:x', 'siem:y'] });
      const b = t1113({ id: 'rB', runDate: '2026-10-10T10:00:00.000Z', status: 'failed', detectionsExpected: ['siem:y'] });
      expect(component.firedCount(a)).toBe(2);
      expect(cardLineOf([a, b])).toBe('Proven (your run) on 10/1/26 by manual; 2 rules fired; a later run of another rule failed on 10/10/26');
      expect(pillLineOf([b, a], b)).toBe('0 of 1 detection rules fired');
    });

    it("fired exceeds expected on a non-passed run too: 'detection rules: 2 fired, 1 expected' (round 6: 'UNTESTED 2 of 1')", () => {
      const r = t1113({ status: 'untested', detectionsExpected: ['siem:a'], detectionsFired: ['siem:a', 'siem:b'] });
      expect(pillLine(r)).toBe('detection rules: 2 fired, 1 expected');
      expect(component.tally(r)).toEqual({ fired: 2, expected: 1, exceeds: true, words: '2 fired, 1 expected' });
    });

    it("two passed runs: the card names the best run's own count, never the rules of both runs", () => {
      const a = t1113({ id: 'rA', runDate: '2026-10-01T10:00:00.000Z', detectionsExpected: ['siem:x', 'siem:z'], detectionsFired: ['siem:x', 'siem:z'] });
      const b = t1113({ id: 'rB', runDate: '2026-10-10T10:00:00.000Z', detectionsExpected: ['siem:y'], detectionsFired: ['siem:y'] });
      expect(cardLineOf([a, b])).toBe('Proven (your run) on 10/10/26 by manual; 1 rule fired');
      expect(pillLineOf([b, a], b)).toBe('1 of 1 detection rules fired');
    });
  });
});
