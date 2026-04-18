// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { UrlStateService } from './url-state.service';
import { FilterService } from './filter.service';

describe('UrlStateService', () => {
  let service: UrlStateService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        UrlStateService,
        { provide: FilterService, useValue: {} },
      ],
    });
    service = TestBed.inject(UrlStateService);
  });

  it('restoreFromUrl is a no-op (FilterService already wires URL state)', () => {
    expect(() => service.restoreFromUrl()).not.toThrow();
  });

  it('syncToUrl is a no-op (FilterService owns sync)', () => {
    expect(() => service.syncToUrl()).not.toThrow();
  });

  it('getShareUrl returns whatever the browser currently has', () => {
    const url = service.getShareUrl();
    expect(typeof url).toBe('string');
    expect(url.length).toBeGreaterThan(0);
  });

  it('clearUrl calls history.replaceState without a hash', () => {
    spyOn(history, 'replaceState');
    service.clearUrl();
    expect(history.replaceState).toHaveBeenCalled();
    const args = (history.replaceState as jasmine.Spy).calls.mostRecent().args;
    // 3rd arg is the URL — shouldn't contain a "#"
    expect(args[2]).not.toContain('#');
  });
});
