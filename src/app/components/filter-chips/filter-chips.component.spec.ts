// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { FilterChipsComponent } from './filter-chips.component';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';

describe('FilterChipsComponent', () => {
  let component: FilterChipsComponent;
  let fixture: ComponentFixture<FilterChipsComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [FilterChipsComponent],
      providers: [
        { provide: FilterService, useValue: {
            activeMitigationFilters$: new BehaviorSubject([]),
            techniqueQuery$: new BehaviorSubject(''),
            platformFilter$: new BehaviorSubject(null),
            dimUncovered$: new BehaviorSubject(false),
            hiddenTacticIds$: new BehaviorSubject(new Set()),
            activeThreatGroupIds$: new BehaviorSubject(new Set()),
            activeSoftwareIds$: new BehaviorSubject(new Set()),
            implStatusFilter$: new BehaviorSubject(null),
            activeMitigationFiltersValue: () => [],
            clearAll: jasmine.createSpy(),
        }},
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
      ],
    });
    fixture = TestBed.createComponent(FilterChipsComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created', () => {
    expect(component).toBeTruthy();
  });
});
