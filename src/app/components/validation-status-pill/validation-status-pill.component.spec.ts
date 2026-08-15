// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { provideHttpClient } from '@angular/common/http';
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
        provideHttpClient(),
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
});
