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

  describe('applyUrlState validation', () => {
    const apply = (query: string) => service.applyUrlState(new URLSearchParams(query));

    it('applies a known heatmap mode, scope and implementation status', () => {
      apply('heat=kev&scope=full&impl=planned');
      expect(service.getStateSnapshot().heatmapMode).toBe('kev');
      service.searchScope$.subscribe(v => expect(v).toBe('full')).unsubscribe();
      service.implStatusFilter$.subscribe(v => expect(v).toBe('planned')).unsubscribe();
    });

    it('ignores a heat value that is not a heatmap mode', () => {
      // A retired or mistyped mode used to put the matrix in an unknown mode with
      // the wrong legend and none of the mode's loaders running.
      apply('heat=mitigations');
      expect(service.getStateSnapshot().heatmapMode).toBe('unified');
      apply('heat=bogus');
      expect(service.getStateSnapshot().heatmapMode).toBe('unified');
    });

    it('ignores unknown scope and impl values but still applies the rest of the link', () => {
      apply('scope=everything&impl=done&heat=risk&tq=T1059');
      service.searchScope$.subscribe(v => expect(v).toBe('name')).unsubscribe();
      service.implStatusFilter$.subscribe(v => expect(v).toBeNull()).unsubscribe();
      expect(service.getStateSnapshot().heatmapMode).toBe('risk');
      service.techniqueQuery$.subscribe(v => expect(v).toBe('T1059')).unsubscribe();
    });

    it('does not serialize a value that was rejected', () => {
      apply('heat=bogus&scope=everything');
      const params = service.serializeUrlState();
      expect(params['heat']).toBeUndefined();
      expect(params['scope']).toBeUndefined();
    });
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

    expect(service.getStateSnapshot().heatmapMode).toBe('unified');
    expect(service.getStateSnapshot().hiddenTacticIds).toEqual([]);
    expect(service.getTechniqueSearch()).toBe('');

    service.implStatusFilter$.subscribe(value => expect(value).toBeNull());
    service.searchScope$.subscribe(value => expect(value).toBe('name'));
    service.searchFilterMode$.subscribe(value => expect(value).toBeFalse());
    service.cveTechniqueIds$.subscribe(value => expect(value.size).toBe(0));
  });
});
