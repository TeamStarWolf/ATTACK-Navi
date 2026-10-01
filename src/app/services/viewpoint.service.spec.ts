// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed } from '@angular/core/testing';
import { Router, provideRouter } from '@angular/router';
import { ViewpointService } from './viewpoint.service';
import { FilterService } from './filter.service';

const STORAGE_KEY = 'attack-navi-viewpoint';

describe('ViewpointService', () => {
  let service: ViewpointService;
  let filterService: jasmine.SpyObj<Pick<FilterService, 'setHeatmapMode'>>;
  let router: Router;

  beforeEach(() => {
    filterService = jasmine.createSpyObj('FilterService', ['setHeatmapMode']);

    TestBed.configureTestingModule({
      providers: [
        provideRouter([]),
        { provide: FilterService, useValue: filterService },
      ],
    });

    try {
      localStorage.removeItem(STORAGE_KEY);
    } catch {
      /* ignore */
    }

    service = TestBed.inject(ViewpointService);
    router = TestBed.inject(Router);
  });

  afterEach(() => {
    try {
      localStorage.removeItem(STORAGE_KEY);
    } catch {
      /* ignore */
    }
    // Clear any heat param a test wrote into the fragment.
    window.location.hash = '';
  });

  it('defaults to the analyst viewpoint', () => {
    expect(service.current.id).toBe('analyst');
    expect(service.current.defaultLens).toBe('unified');
    expect(service.current.homeRoute).toBe('/matrix');
  });

  it('exposes every viewpoint in the table', () => {
    const ids = service.viewpoints.map((v) => v.id);
    expect(ids).toEqual([
      'analyst', 'red', 'detection', 'defense', 'cti', 'vuln', 'exec', 'deception',
    ]);
  });

  it('setViewpoint sets the role default lens, persists, emits, and navigates', () => {
    const navSpy = spyOn(router, 'navigateByUrl').and.resolveTo(true);
    let emitted = '';
    service.viewpoint$.subscribe((v) => (emitted = v.id));

    service.setViewpoint('red');

    expect(filterService.setHeatmapMode).toHaveBeenCalledOnceWith('atomic');
    expect(service.current.id).toBe('red');
    expect(emitted).toBe('red');
    expect(localStorage.getItem(STORAGE_KEY)).toBe('red');
    expect(navSpy).toHaveBeenCalledWith('/matrix');
  });

  it('setViewpoint navigates to the role home route', () => {
    const navSpy = spyOn(router, 'navigateByUrl').and.resolveTo(true);
    service.setViewpoint('detection');
    expect(navSpy).toHaveBeenCalledWith('/detect');
  });

  it('setViewpoint with { navigate: false } does not navigate', () => {
    const navSpy = spyOn(router, 'navigateByUrl').and.resolveTo(true);
    service.setViewpoint('vuln', { navigate: false });
    expect(filterService.setHeatmapMode).toHaveBeenCalledOnceWith('kev');
    expect(navSpy).not.toHaveBeenCalled();
  });

  it('setViewpoint ignores an unknown id', () => {
    const navSpy = spyOn(router, 'navigateByUrl').and.resolveTo(true);
    service.setViewpoint('nope' as any);
    expect(filterService.setHeatmapMode).not.toHaveBeenCalled();
    expect(navSpy).not.toHaveBeenCalled();
    expect(service.current.id).toBe('analyst');
  });

  it('restore applies the stored lens without navigating', () => {
    const navSpy = spyOn(router, 'navigateByUrl').and.resolveTo(true);
    localStorage.setItem(STORAGE_KEY, 'red');

    service.restore();

    expect(service.current.id).toBe('red');
    expect(filterService.setHeatmapMode).toHaveBeenCalledOnceWith('atomic');
    expect(navSpy).not.toHaveBeenCalled();
  });

  it('restore respects an explicit heat query param (does not override the lens)', () => {
    window.location.hash = '#/matrix?heat=kev';
    localStorage.setItem(STORAGE_KEY, 'red');

    service.restore();

    // Viewpoint identity is still restored so the switcher reflects the role…
    expect(service.current.id).toBe('red');
    // …but the deep link's explicit lens is left untouched.
    expect(filterService.setHeatmapMode).not.toHaveBeenCalled();
  });

  it('restore does nothing when nothing is stored (stays analyst)', () => {
    service.restore();
    expect(service.current.id).toBe('analyst');
    expect(filterService.setHeatmapMode).not.toHaveBeenCalled();
  });

  it('restore ignores an invalid stored value (stays analyst)', () => {
    localStorage.setItem(STORAGE_KEY, 'bogus');
    service.restore();
    expect(service.current.id).toBe('analyst');
    expect(filterService.setHeatmapMode).not.toHaveBeenCalled();
  });

  it('restore swallows a localStorage read that throws', () => {
    const getItem = spyOn(Storage.prototype, 'getItem').and.throwError('blocked');
    expect(() => service.restore()).not.toThrow();
    expect(service.current.id).toBe('analyst');
    getItem.and.callThrough();
  });

  it('persist swallows a localStorage write that throws', () => {
    spyOn(router, 'navigateByUrl').and.resolveTo(true);
    const setItem = spyOn(Storage.prototype, 'setItem').and.throwError('blocked');
    expect(() => service.setViewpoint('cti')).not.toThrow();
    expect(service.current.id).toBe('cti');
    setItem.and.callThrough();
  });

  it('isFeaturedLens reflects the active viewpoint featured lenses', () => {
    spyOn(router, 'navigateByUrl').and.resolveTo(true);
    expect(service.isFeaturedLens('unified')).toBeTrue(); // analyst featured
    expect(service.isFeaturedLens('kev')).toBeFalse();

    service.setViewpoint('vuln');
    expect(service.isFeaturedLens('kev')).toBeTrue();
    expect(service.isFeaturedLens('unified')).toBeFalse();
  });
});
