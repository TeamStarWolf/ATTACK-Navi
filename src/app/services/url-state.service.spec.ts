// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, fakeAsync, tick } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { Component } from '@angular/core';
import { Router, provideRouter } from '@angular/router';
import { UrlStateService } from './url-state.service';
import { FilterService } from './filter.service';
import { DataService } from './data.service';
import { Domain } from '../models/domain';

describe('UrlStateService', () => {
  let service: UrlStateService;
  let filterService: FilterService;
  let router: Router;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(withXhr()), provideHttpClientTesting(), provideRouter([])],
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

  // E2.3 (P2-04): the writer replaces the whole query, and it used to drop tech=
  // about 300 ms after load because serializeUrlState never wrote it.
  describe('tech= survives the first writer pass (E2.3)', () => {
    const query = () => router.parseUrl(router.url).queryParams;

    it('while the domain is still loading (the pending link id is serialized)', fakeAsync(() => {
      service.init();
      void router.navigateByUrl('/?tech=T1059.001');
      tick(); // NavigationEnd: the reader applies the link, the writer starts
      tick(300); // the writer's first debounced pass
      tick(); // its replaceUrl navigation completes
      // The pass ran (it added heat and dom, which tech forces) and kept tech.
      expect(query()).toEqual({ tech: 'T1059.001', heat: 'frequency', dom: 'enterprise' });
    }));

    it('once the technique is selected from the loaded domain', fakeAsync(() => {
      const domain = {
        name: 'Enterprise ATT&CK',
        techniques: [{ id: 'attack-pattern--1', attackId: 'T1059.001', name: 'PowerShell' }],
        mitigations: [], groups: [], software: [], campaigns: [], dataComponents: [],
      } as unknown as Domain;
      (TestBed.inject(DataService) as unknown as { domainSubject: { next(d: Domain): void } }).domainSubject.next(domain);
      service.init();
      void router.navigateByUrl('/?heat=kev&tech=T1059.001');
      tick();
      let selected: string | undefined;
      filterService.selectedTechnique$.subscribe(t => (selected = t?.attackId)).unsubscribe();
      expect(selected).toBe('T1059.001');
      tick(300);
      tick();
      expect(query()).toEqual({ tech: 'T1059.001', heat: 'kev', dom: 'enterprise' });
    }));
  });

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

// RP-F 5 follow-up: a filter change whose debounced write lands while a
// navigation is in flight used to be dropped until the NEXT state change, so
// the last lens pick of a sequence could leave heat= stale for good.
describe('UrlStateService: a write skipped during a navigation', () => {
  @Component({ template: '' })
  class BlankComponent {}

  let service: UrlStateService;
  let filterService: FilterService;
  let router: Router;
  const query = () => router.parseUrl(router.url).queryParams;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withXhr()), provideHttpClientTesting(),
        provideRouter([
          { path: '', component: BlankComponent },
          // A route whose guard holds the navigation open for 1 s.
          { path: 'slow', component: BlankComponent,
            canActivate: [() => new Promise<boolean>((resolve) => setTimeout(() => resolve(true), 1000))] },
        ]),
      ],
    });
    service = TestBed.inject(UrlStateService);
    filterService = TestBed.inject(FilterService);
    router = TestBed.inject(Router);
  });

  it('is written once that navigation settles, with no later state change', fakeAsync(() => {
    service.init();
    void router.navigateByUrl('/');
    tick(400); // initial NavigationEnd + the writer's first pass
    tick();
    void router.navigateByUrl('/slow');
    tick(10);
    expect(router.getCurrentNavigation()).not.toBeNull();
    filterService.setHeatmapMode('kev');
    tick(400); // the debounced write fires mid-navigation and is held
    expect(router.url.startsWith('/slow')).toBeFalse();
    expect(query()['heat']).not.toBe('kev');
    tick(1000); // the guard resolves: NavigationEnd, then the held write
    tick();
    expect(router.url.startsWith('/slow')).toBeTrue();
    expect(query()['heat']).toBe('kev');
  }));

  it('is retried after a cancelled navigation too', fakeAsync(() => {
    service.init();
    void router.navigateByUrl('/');
    tick(400);
    tick();
    void router.navigateByUrl('/slow');
    tick(10);
    filterService.setHeatmapMode('kev');
    tick(400); // held
    void router.navigateByUrl('/'); // supersedes /slow: NavigationCancel, then NavigationEnd
    tick(1000);
    tick();
    expect(query()['heat']).toBe('kev');
  }));

  it('does not schedule a retry when no write was held', fakeAsync(() => {
    service.init();
    void router.navigateByUrl('/');
    tick(400);
    tick();
    const navigateSpy = spyOn(router, 'navigateByUrl').and.callThrough();
    void router.navigateByUrl('/slow');
    tick(1000);
    tick();
    expect(navigateSpy.calls.count()).toBe(1); // only the /slow navigation itself
  }));
});
