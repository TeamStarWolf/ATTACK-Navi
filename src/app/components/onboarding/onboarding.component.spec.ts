// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { OnboardingComponent } from './onboarding.component';
import { FilterService } from '../../services/filter.service';
import { textContrast } from '../../testing/contrast';
import { defaultRailSections } from '../nav-rail/nav-rail.component';

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

  // The welcome step describes the rail as it is: three labelled sections with
  // their default workspaces in order, and Help and Settings at the bottom.
  describe('welcome step describes the current rail', () => {
    const welcomeText = (): string => {
      component.currentStep = 0;
      fixture.detectChanges();
      return (fixture.nativeElement.querySelector('.step-content')?.textContent ?? '').replace(/\s+/g, ' ');
    };

    it('names each rail section with its workspaces in the default order', () => {
      const text = welcomeText();
      const sections = defaultRailSections();
      expect(sections.length).toBe(3);
      for (const s of sections) expect(text).toContain(`${s.label} (${s.items.join(', ')})`);
      expect(text).toContain('Help and Settings sit at the bottom of the rail');
    });

    it('no longer gives a flat workspace list or count', () => {
      expect(welcomeText()).not.toMatch(/\b(ten|nine|eleven|\d+) workspaces\b/i);
    });
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

  // Plan E1.5, light-mode leak 1: the onboarding titles were a fixed near-white
  // (#f0f4f8) that vanished on the light card (1.0:1). Every text node of every
  // step now reads at 4.5:1 or better in both themes.
  describe('text contrast in both themes (E1.5)', () => {
    afterEach(() => document.body.classList.remove('light-mode'));

    for (const theme of ['dark', 'light'] as const) {
      it(`titles, copy and buttons are >= 4.5:1 on every step in the ${theme} theme`, () => {
        document.body.classList.toggle('light-mode', theme === 'light');
        const failures: string[] = [];
        for (let step = 0; step < component.totalSteps; step++) {
          component.currentStep = step;
          fixture.detectChanges();
          const nodes = fixture.nativeElement.querySelectorAll('.step-title, .step-desc, .btn-primary, .btn-secondary');
          expect(nodes.length).toBeGreaterThan(0);
          for (const el of Array.from(nodes) as Element[]) {
            const ratio = textContrast(el);
            if (ratio < 4.5) failures.push(`step ${step} .${el.className}: ${ratio.toFixed(2)}:1`);
          }
        }
        expect(failures).toEqual([]);
      });
    }
  });
});
