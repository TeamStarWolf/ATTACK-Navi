// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { CampaignTimelinePanelComponent } from './campaign-timeline-panel.component';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';

describe('CampaignTimelinePanelComponent', () => {
  let component: CampaignTimelinePanelComponent;
  let fixture: ComponentFixture<CampaignTimelinePanelComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [CampaignTimelinePanelComponent],
      providers: [
        { provide: FilterService, useValue: {
            activePanel$: new BehaviorSubject<string | null>(null),
            activeCampaignIds$: new BehaviorSubject(new Set()),
            setActivePanel: jasmine.createSpy(),
        }},
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
      ],
    });
    fixture = TestBed.createComponent(CampaignTimelinePanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created', () => {
    expect(component).toBeTruthy();
  });
});
