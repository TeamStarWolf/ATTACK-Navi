// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { ScenarioPanelComponent } from './scenario-panel.component';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { ImplementationService } from '../../services/implementation.service';
import { CARService } from '../../services/car.service';
import { AtomicService } from '../../services/atomic.service';
import { D3fendService } from '../../services/d3fend.service';
import { ThreatSimulationService } from '../../services/threat-simulation.service';
import { EmulationPlanService } from '../../services/emulation-plan.service';

describe('ScenarioPanelComponent', () => {
  let component: ScenarioPanelComponent;
  let fixture: ComponentFixture<ScenarioPanelComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [ScenarioPanelComponent],
      providers: [
        { provide: FilterService, useValue: {
            activePanel$: new BehaviorSubject<string | null>(null),
            setActivePanel: jasmine.createSpy(),
        }},
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
        { provide: ImplementationService, useValue: { status$: new BehaviorSubject(new Map()) }},
        { provide: CARService, useValue: { getAnalytics: () => [] } },
        { provide: AtomicService, useValue: { getTests: () => [] } },
        { provide: D3fendService, useValue: { getCountermeasures: () => [] } },
        { provide: ThreatSimulationService, useValue: { simulateActor: () => null, simulateMultipleActors: () => [] } },
        { provide: EmulationPlanService, useValue: { generatePlan: () => null } },
      ],
    });
    fixture = TestBed.createComponent(ScenarioPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created', () => {
    expect(component).toBeTruthy();
  });
});
