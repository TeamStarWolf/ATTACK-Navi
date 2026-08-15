// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
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
        provideRouter([]),
        { provide: FilterService, useValue: {
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

  it('is created', () => {
    expect(component).toBeTruthy();
  });
});
