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

describe('AssessmentWizardComponent', () => {
  let component: AssessmentWizardComponent;
  let fixture: ComponentFixture<AssessmentWizardComponent>;

  beforeEach(() => {
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
