// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { DetectionPanelComponent } from './detection-panel.component';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { CARService } from '../../services/car.service';
import { AtomicService } from '../../services/atomic.service';
import { D3fendService } from '../../services/d3fend.service';

describe('DetectionPanelComponent', () => {
  let component: DetectionPanelComponent;
  let fixture: ComponentFixture<DetectionPanelComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [DetectionPanelComponent],
      providers: [
        { provide: FilterService, useValue: {
            activePanel$: new BehaviorSubject<string | null>(null),
            selectedTechnique$: new BehaviorSubject(null),
            setActivePanel: jasmine.createSpy(),
        }},
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
        { provide: CARService, useValue: { getAnalytics: () => [] } },
        { provide: AtomicService, useValue: { getTests: () => [] } },
        { provide: D3fendService, useValue: { getCountermeasures: () => [] } },
      ],
    });
    fixture = TestBed.createComponent(DetectionPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created and starts hidden', () => {
    expect(component).toBeTruthy();
    expect(component.visible).toBe(false);
  });
});
