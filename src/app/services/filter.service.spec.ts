// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { DataService } from './data.service';
import { FilterService } from './filter.service';

describe('FilterService', () => {
  let service: FilterService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        FilterService,
        {
          provide: DataService,
          useValue: {
            domain$: new BehaviorSubject(null),
          },
        },
      ],
    });

    service = TestBed.inject(FilterService);
  });

  it('should reset advanced filter state in clearAll', () => {
    service.setHeatmapMode('risk');
    service.setImplStatusFilter('implemented');
    service.setSearchScope('full');
    service.toggleSearchFilterMode();
    service.toggleTacticVisibility('ta0001');
    service.setCveFilter(['tech-1']);
    service.setTechniqueSearch('powershell');

    service.clearAll();

    expect(service.getStateSnapshot().heatmapMode).toBe('coverage');
    expect(service.getStateSnapshot().hiddenTacticIds).toEqual([]);
    expect(service.getTechniqueSearch()).toBe('');

    service.implStatusFilter$.subscribe(value => expect(value).toBeNull());
    service.searchScope$.subscribe(value => expect(value).toBe('name'));
    service.searchFilterMode$.subscribe(value => expect(value).toBeFalse());
    service.cveTechniqueIds$.subscribe(value => expect(value.size).toBe(0));
  });
});
