// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { OnboardingComponent } from './onboarding.component';
import { FilterService } from '../../services/filter.service';

describe('OnboardingComponent', () => {
  let component: OnboardingComponent;
  let fixture: ComponentFixture<OnboardingComponent>;

  beforeEach(() => {
    localStorage.clear();
    TestBed.configureTestingModule({
      imports: [OnboardingComponent],
      providers: [
        { provide: FilterService, useValue: { setActivePanel: jasmine.createSpy('setActivePanel') } },
      ],
    });
    fixture = TestBed.createComponent(OnboardingComponent);
    component = fixture.componentInstance;
  });

  afterEach(() => localStorage.clear());

  it('shows on first visit', () => {
    expect(component.visible).toBe(true);
  });

  it('exposes 4 quick-start cards', () => {
    expect(component.quickCards.length).toBe(4);
    expect(component.totalSteps).toBe(3);
  });

  describe('nextStep / prevStep', () => {
    it('advances current step but never past the last', () => {
      component.nextStep();
      expect(component.currentStep).toBe(1);
      component.nextStep();
      component.nextStep();
      component.nextStep(); // overshoot
      expect(component.currentStep).toBe(component.totalSteps - 1);
    });

    it('rewinds but never before 0', () => {
      component.nextStep();
      component.prevStep();
      expect(component.currentStep).toBe(0);
      component.prevStep(); // undershoot
      expect(component.currentStep).toBe(0);
    });
  });
});
