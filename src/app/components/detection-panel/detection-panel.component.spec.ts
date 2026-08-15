// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { DetectionPanelComponent } from './detection-panel.component';
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

  it('is created with the overview tab active', () => {
    expect(component).toBeTruthy();
    expect(component.activeTab).toBe('overview');
  });
});
