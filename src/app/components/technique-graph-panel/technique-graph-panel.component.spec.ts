// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { TechniqueGraphPanelComponent } from './technique-graph-panel.component';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { AttackCveService } from '../../services/attack-cve.service';

describe('TechniqueGraphPanelComponent', () => {
  let component: TechniqueGraphPanelComponent;
  let fixture: ComponentFixture<TechniqueGraphPanelComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [TechniqueGraphPanelComponent],
      providers: [
        { provide: FilterService, useValue: {
            activePanel$: new BehaviorSubject<string | null>(null),
            selectedTechnique$: new BehaviorSubject(null),
            setActivePanel: jasmine.createSpy(),
        }},
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
        { provide: AttackCveService, useValue: { getCvesForTechnique: () => [], loaded$: new BehaviorSubject(true) } },
      ],
    });
    fixture = TestBed.createComponent(TechniqueGraphPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created', () => {
    expect(component).toBeTruthy();
  });
});
