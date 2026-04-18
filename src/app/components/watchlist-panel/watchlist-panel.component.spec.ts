// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { WatchlistPanelComponent } from './watchlist-panel.component';
import { FilterService } from '../../services/filter.service';
import { WatchlistService } from '../../services/watchlist.service';
import { DataService } from '../../services/data.service';

describe('WatchlistPanelComponent', () => {
  let component: WatchlistPanelComponent;
  let fixture: ComponentFixture<WatchlistPanelComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [WatchlistPanelComponent],
      providers: [
        { provide: FilterService, useValue: {
            activePanel$: new BehaviorSubject<string | null>(null),
            setActivePanel: jasmine.createSpy(),
            selectTechnique: jasmine.createSpy(),
        }},
        { provide: WatchlistService, useValue: { entries$: new BehaviorSubject([]) }},
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
      ],
    });
    fixture = TestBed.createComponent(WatchlistPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created and starts hidden', () => {
    expect(component).toBeTruthy();
    expect(component.visible).toBe(false);
  });
});
