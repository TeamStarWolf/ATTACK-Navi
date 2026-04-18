// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { PurpleTeamPanelComponent } from './purple-team-panel.component';
import { FilterService } from '../../services/filter.service';
import { D3fendService } from '../../services/d3fend.service';
import { EngageService } from '../../services/engage.service';
import { CARService } from '../../services/car.service';
import { AtomicService } from '../../services/atomic.service';
import { DataService } from '../../services/data.service';

describe('PurpleTeamPanelComponent', () => {
  let component: PurpleTeamPanelComponent;
  let fixture: ComponentFixture<PurpleTeamPanelComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [PurpleTeamPanelComponent],
      providers: [
        { provide: FilterService, useValue: {
            activePanel$: new BehaviorSubject<string | null>(null),
            selectedTechnique$: new BehaviorSubject(null),
            setActivePanel: jasmine.createSpy('setActivePanel'),
        }},
        { provide: D3fendService, useValue: { getCountermeasures: () => [] } },
        { provide: EngageService, useValue: { getActivities: () => [] } },
        { provide: CARService, useValue: { getAnalytics: () => [] } },
        { provide: AtomicService, useValue: { getTests: () => [] } },
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
      ],
    });
    fixture = TestBed.createComponent(PurpleTeamPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created and starts closed', () => {
    expect(component).toBeTruthy();
    expect(component.open).toBe(false);
  });
});
