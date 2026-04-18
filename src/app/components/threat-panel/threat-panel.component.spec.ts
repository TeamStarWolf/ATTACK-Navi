// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { ThreatPanelComponent } from './threat-panel.component';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { CveService } from '../../services/cve.service';

describe('ThreatPanelComponent', () => {
  let component: ThreatPanelComponent;
  let fixture: ComponentFixture<ThreatPanelComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [ThreatPanelComponent],
      providers: [
        { provide: FilterService, useValue: {
            activePanel$: new BehaviorSubject<string | null>(null),
            activeThreatGroupIds$: new BehaviorSubject(new Set()),
            setActivePanel: jasmine.createSpy(),
            toggleThreatGroup: jasmine.createSpy(),
        }},
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
        { provide: CveService, useValue: { getCachedCves: () => [], kev$: new BehaviorSubject([]), kevTechScores$: new BehaviorSubject(new Map()) } },
      ],
    });
    fixture = TestBed.createComponent(ThreatPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created and starts hidden', () => {
    expect(component).toBeTruthy();
    expect(component.visible).toBe(false);
  });
});
