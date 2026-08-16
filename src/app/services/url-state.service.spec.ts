// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, fakeAsync, tick } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { Router, provideRouter } from '@angular/router';
import { UrlStateService } from './url-state.service';
import { FilterService } from './filter.service';
import { DataService } from './data.service';

describe('UrlStateService', () => {
  let service: UrlStateService;
  let filterService: FilterService;
  let router: Router;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), provideRouter([])],
    });
    service = TestBed.inject(UrlStateService);
    filterService = TestBed.inject(FilterService);
    router = TestBed.inject(Router);
  });

  /** Completes the router's initial navigation so the writer starts. */
  function completeInitialNavigation(): void {
    void router.navigateByUrl('/');
    tick(400); // NavigationEnd + the writer's initial debounced emission
  }

  it('writes filter state into router query params (replaceUrl, no history spam)', fakeAsync(() => {
    service.init();
    completeInitialNavigation();
    const navigateSpy = spyOn(router, 'navigateByUrl').and.resolveTo(true);
    filterService.setHeatmapMode('kev');
    tick(400);
    expect(navigateSpy).toHaveBeenCalled();
    const [tree, extras] = navigateSpy.calls.mostRecent().args;
    expect((tree as import('@angular/router').UrlTree).queryParams['heat']).toBe('kev');
    expect(extras?.replaceUrl).toBeTrue();
  }));

  it('does not rewrite the URL when serialized state is unchanged', fakeAsync(() => {
    service.init();
    completeInitialNavigation();
    const navigateSpy = spyOn(router, 'navigateByUrl').and.resolveTo(true);
    filterService.setHeatmapMode('kev');
    tick(400);
    const callsAfterFirst = navigateSpy.calls.count();
    filterService.setHeatmapMode('kev');
    tick(400);
    expect(navigateSpy.calls.count()).toBe(callsAfterFirst);
  }));

  it('REGRESSION: never navigates before the initial navigation completes (deep-link boot race)', fakeAsync(() => {
    // The writer once subscribed immediately; its first debounced emission
    // fired while a deep link's lazy route was still loading, navigated to
    // the not-yet-resolved '/' and cancelled the user's navigation (only
    // reproducible on slow machines — CI's 2-core runners lost the race
    // every time, fast dev machines never did).
    const navigateSpy = spyOn(router, 'navigateByUrl').and.resolveTo(true);
    service.init();
    filterService.setHeatmapMode('kev');
    tick(1000);
    expect(navigateSpy).not.toHaveBeenCalled();
  }));

  it('round-trips: serialized params apply back to identical state', () => {
    filterService.setHeatmapMode('kev');
    filterService.toggleDimUncovered();
    const params = filterService.serializeUrlState();
    expect(params['heat']).toBe('kev');
    expect(params['dim']).toBe('1');

    const fresh = new FilterService(TestBed.inject(DataService));
    fresh.applyUrlState(new URLSearchParams(params));
    const roundTripped = fresh.serializeUrlState();
    expect(roundTripped['heat']).toBe('kev');
    expect(roundTripped['dim']).toBe('1');
  });

  it('clearUrl keeps the route path and clears only query params', () => {
    const navigateSpy = spyOn(router, 'navigateByUrl').and.resolveTo(true);
    service.clearUrl();
    expect(navigateSpy).toHaveBeenCalled();
    const [tree, extras] = navigateSpy.calls.mostRecent().args;
    expect(Object.keys((tree as import('@angular/router').UrlTree).queryParams).length).toBe(0);
    expect(extras?.replaceUrl).toBeTrue();
  });

  it('getShareUrl returns the full current URL', () => {
    expect(service.getShareUrl()).toBe(window.location.href);
  });
});
