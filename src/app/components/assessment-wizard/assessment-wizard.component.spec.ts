// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { AssessmentWizardComponent } from './assessment-wizard.component';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { ImplementationService } from '../../services/implementation.service';
import { CveService } from '../../services/cve.service';
import { EpssService } from '../../services/epss.service';
import { ThreatProfileService } from '../../services/threat-profile.service';

describe('AssessmentWizardComponent', () => {
  let component: AssessmentWizardComponent;
  let fixture: ComponentFixture<AssessmentWizardComponent>;

  beforeEach(() => {
    const emptyProfile = { source: { kind: 'top-groups' as const, n: 20 }, parentTechniqueIds: new Set<string>() };
    TestBed.configureTestingModule({
      imports: [AssessmentWizardComponent],
      providers: [
        { provide: FilterService, useValue: {
            activePanel$: new BehaviorSubject<string | null>(null),
            setActivePanel: jasmine.createSpy(),
        }},
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
        { provide: ImplementationService, useValue: { status$: new BehaviorSubject(new Map()) }},
        { provide: CveService, useValue: { kev$: new BehaviorSubject([]), getCachedCves: () => [] } },
        { provide: EpssService, useValue: { fetchScores: () => ({ subscribe: () => {} }) } },
        { provide: ThreatProfileService, useValue: {
            get current() { return emptyProfile; },
            profile$: new BehaviorSubject(emptyProfile),
            setSource: jasmine.createSpy(),
        }},
      ],
    });
    fixture = TestBed.createComponent(AssessmentWizardComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created', () => {
    expect(component).toBeTruthy();
  });
});
