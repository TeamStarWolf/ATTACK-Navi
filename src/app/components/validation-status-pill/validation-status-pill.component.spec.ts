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

  function rangeRun(detectionRef: string): any {
    return {
      id: 'lylat:SYNTH-MISSION-A:0', techniqueId: 'T1558.003', status: 'passed',
      detectionsExpected: [detectionRef], detectionsFired: [detectionRef], runDate: '2026-10-18',
      proofScope: 'range', source: 'lylat-range:SYNTH-MISSION-A', statusFromSource: true,
      outcomes: [{ detectionRef, outcome: 'alerted', coverageState: 'validated' }],
    };
  }

  it('marks a range-scoped run as lab-proven and lists its rule ids', () => {
    const runs = [rangeRun('wazuh:990001'), rangeRun('wazuh:990002')];
    validation.forTechnique.and.returnValue(runs);
    validation.latestFor.and.returnValue(runs[0]);
    component.attackId = 'T1558.003';
    fixture.detectChanges();

    expect(component.labProven).toBeTrue();
    expect(component.labRuleRefs).toEqual(['wazuh:990001', 'wazuh:990002']);
    const text = (fixture.nativeElement as HTMLElement).textContent ?? '';
    expect(text).toContain('lab');
    expect(text).toContain('wazuh:990001');
  });

  it('does not mark an own-run manual record as lab-proven', () => {
    const manual = { ...rangeRun('sigma:a'), proofScope: 'own-run', source: 'manual', outcomes: [] };
    validation.forTechnique.and.returnValue([manual]);
    validation.latestFor.and.returnValue(manual);
    component.attackId = 'T1558.003';
    fixture.detectChanges();

    expect(component.labProven).toBeFalse();
    expect(component.labRuleRefs).toEqual([]);
    expect((fixture.nativeElement as HTMLElement).textContent ?? '').not.toContain('range-validated');
  });
});
