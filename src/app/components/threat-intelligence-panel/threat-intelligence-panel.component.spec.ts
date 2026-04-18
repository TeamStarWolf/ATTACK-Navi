// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { ThreatIntelligencePanelComponent } from './threat-intelligence-panel.component';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { MispService } from '../../services/misp.service';
import { OpenCtiService } from '../../services/opencti.service';

describe('ThreatIntelligencePanelComponent', () => {
  let component: ThreatIntelligencePanelComponent;
  let fixture: ComponentFixture<ThreatIntelligencePanelComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [ThreatIntelligencePanelComponent],
      providers: [
        { provide: FilterService, useValue: {
            activePanel$: new BehaviorSubject<string | null>(null),
            setActivePanel: jasmine.createSpy(),
        }},
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
        { provide: MispService, useValue: { isConnected: () => false, connected$: new BehaviorSubject(false), total$: new BehaviorSubject(0), fetchEvents: () => ({ subscribe: () => {} }) } },
        { provide: OpenCtiService, useValue: { isConnected: () => false, connected$: new BehaviorSubject(false) } },
      ],
    });
    fixture = TestBed.createComponent(ThreatIntelligencePanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created', () => {
    expect(component).toBeTruthy();
  });
});
