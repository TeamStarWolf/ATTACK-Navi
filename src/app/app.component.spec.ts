// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Component } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideRouter, Router } from '@angular/router';
import { AppComponent } from './app.component';
import { FilterService } from './services/filter.service';
import { PanelNavService } from './services/panel-nav.service';

@Component({ standalone: true, template: '' })
class Blank {}

type Tech = Parameters<FilterService['selectTechnique']>[0];
const TECH = { attackId: 'T1059', id: 'T1059', name: 'Command Interpreter' } as unknown as Tech;

describe('AppComponent', () => {
  let router: Router;
  let filter: FilterService;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [AppComponent],
      providers: [
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        provideRouter([
          { path: 'matrix', component: Blank },
          { path: 'exposure/risk', component: Blank },
          { path: 'exposure/graph', component: Blank },
          { path: '**', component: Blank },
        ]),
      ],
    }).compileComponents();
    router = TestBed.inject(Router);
    filter = TestBed.inject(FilterService);
  });

  /** Create the component and wire ONLY the drawer route-scope subscription
   *  (not the full ngOnInit, which loads data over HTTP). */
  function appWithRouteScope(): void {
    const app = TestBed.createComponent(AppComponent).componentInstance as unknown as {
      initDrawerRouteScope(): void;
    };
    app.initDrawerRouteScope();
  }

  function current(): Tech {
    let v: Tech = null as unknown as Tech;
    filter.selectedTechnique$.subscribe((t) => (v = t as Tech)).unsubscribe();
    return v;
  }

  it('should create the app', () => {
    expect(TestBed.createComponent(AppComponent).componentInstance).toBeTruthy();
  });

  it('closes a leftover drawer on a real path change', async () => {
    appWithRouteScope();
    await router.navigateByUrl('/matrix');
    filter.selectTechnique(TECH);
    expect(current()).toBe(TECH);
    await router.navigateByUrl('/exposure/risk');
    expect(current()).toBeNull();
  });

  it('keeps the drawer on a same-path replaceUrl query write', async () => {
    appWithRouteScope();
    await router.navigateByUrl('/matrix');
    filter.selectTechnique(TECH);
    await router.navigateByUrl('/matrix?heat=kev', { replaceUrl: true });
    expect(current()).toBe(TECH);
  });

  it('keeps a selection made for the destination (select-then-open matrix)', async () => {
    appWithRouteScope();
    await router.navigateByUrl('/exposure/risk');
    filter.selectTechnique(TECH); // selected FOR the matrix we are about to open
    await router.navigate(['/matrix'], { state: { keepTechniqueSelection: true } });
    expect(current()).toBe(TECH);
  });

  it('keeps the selection when opening the technique graph', async () => {
    appWithRouteScope();
    await router.navigateByUrl('/matrix');
    filter.selectTechnique(TECH);
    await router.navigate(['/exposure/graph'], { state: { keepTechniqueSelection: true } });
    expect(current()).toBe(TECH);
  });

  it('PanelNavService.open forwards keepTechniqueSelection as navigation state', () => {
    const panelNav = TestBed.inject(PanelNavService);
    const nav = spyOn(router, 'navigate').and.resolveTo(true);
    panelNav.open('matrix', { keepTechniqueSelection: true });
    expect(nav).toHaveBeenCalled();
    expect(nav.calls.mostRecent().args[1]?.state).toEqual({ keepTechniqueSelection: true });

    nav.calls.reset();
    panelNav.open('matrix');
    expect(nav.calls.mostRecent().args[1]?.state).toBeUndefined();
  });
});
