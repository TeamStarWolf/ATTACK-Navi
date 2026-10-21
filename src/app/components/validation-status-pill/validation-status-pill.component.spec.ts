// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter, Router } from '@angular/router';
import { ValidationStatusPillComponent } from './validation-status-pill.component';
import { ValidationService } from '../../services/validation.service';

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
});
