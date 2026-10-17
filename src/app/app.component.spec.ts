// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Component } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { NavigationEnd, provideRouter, Router } from '@angular/router';
import { filter, firstValueFrom, take } from 'rxjs';
import { AppComponent } from './app.component';
import { FilterService } from './services/filter.service';
import { PanelNavService } from './services/panel-nav.service';
import { ActorProfilePanelComponent } from './components/actor-profile-panel/actor-profile-panel.component';
import { SidebarComponent } from './components/sidebar/sidebar.component';

@Component({ standalone: true, template: '' })
class Blank {}

type Tech = Parameters<FilterService['selectTechnique']>[0];
const TECH = { attackId: 'T1059', id: 'T1059', name: 'Command Interpreter' } as unknown as Tech;

describe('AppComponent — technique drawer route scope', () => {
  let router: Router;
  let filter_: FilterService;

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
    filter_ = TestBed.inject(FilterService);
  });

  /** Wire ONLY the drawer route-scope subscription (not the HTTP-heavy full ngOnInit). */
  function wireHandler(): void {
    (TestBed.createComponent(AppComponent).componentInstance as unknown as {
      initDrawerRouteScope(): void;
    }).initDrawerRouteScope();
  }

  function current(): Tech {
    let v: Tech = null as unknown as Tech;
    filter_.selectedTechnique$.subscribe((t) => (v = t as Tech)).unsubscribe();
    return v;
  }

  /** Run `action` and resolve on the navigation it triggers. */
  async function onNav(action: () => void): Promise<void> {
    const done = firstValueFrom(router.events.pipe(filter((e) => e instanceof NavigationEnd), take(1)));
    action();
    await done;
  }

  it('should create the app', () => {
    expect(TestBed.createComponent(AppComponent).componentInstance).toBeTruthy();
  });

  it('closes a leftover drawer on a real path change', async () => {
    wireHandler();
    await router.navigateByUrl('/matrix');
    filter_.selectTechnique(TECH);
    expect(current()).toBe(TECH);
    await router.navigateByUrl('/exposure/risk');
    expect(current()).toBeNull();
  });

  it('keeps the drawer on a same-path replaceUrl query write', async () => {
    wireHandler();
    await router.navigateByUrl('/matrix');
    filter_.selectTechnique(TECH);
    await router.navigateByUrl('/matrix?heat=kev', { replaceUrl: true });
    expect(current()).toBe(TECH);
  });

  it('keeps a selection made for the destination (state flag at router level)', async () => {
    wireHandler();
    await router.navigateByUrl('/exposure/risk');
    filter_.selectTechnique(TECH);
    await router.navigate(['/matrix'], { state: { keepTechniqueSelection: true } });
    expect(current()).toBe(TECH);
  });

  // Real call site: actor-profile selectTechnique() -> real PanelNavService.open('matrix',
  // {keepTechniqueSelection:true}) -> real router. Fails if the flag is dropped at the call site.
  it('keeps the selection through the REAL actor-profile select-then-open flow', async () => {
    wireHandler();
    await router.navigateByUrl('/exposure/risk');
    const actor = TestBed.createComponent(ActorProfilePanelComponent).componentInstance;
    await onNav(() => actor.selectTechnique(TECH!));
    expect(current()).toBe(TECH);
  });

  // Real call site: sidebar openTechniqueGraph() -> real open('technique-graph', {keep}) -> graph.
  // Fails if the flag is dropped at sidebar.component.ts.
  it('keeps the selection through the REAL sidebar openTechniqueGraph flow', async () => {
    wireHandler();
    await router.navigateByUrl('/matrix');
    const sidebar = TestBed.createComponent(SidebarComponent).componentInstance;
    filter_.selectTechnique(TECH);
    await onNav(() => sidebar.openTechniqueGraph());
    expect(current()).toBe(TECH);
  });

  // Back/Forward must NOT resurrect a leftover drawer: on popstate the router restores the
  // matrix history entry's saved keepTechniqueSelection, so the handler must ignore the flag
  // on popstate. (Driving a real popstate through the bare TestBed router is unreliable — the
  // location-change listener does not emit — so the guard is asserted directly; the imperative
  // path is covered end-to-end by the router-backed cases above.)
  it('ignores the keep flag on Back/Forward (popstate), honors it imperatively', () => {
    const app = TestBed.createComponent(AppComponent).componentInstance as unknown as {
      shouldKeepSelection(t: string, s: Record<string, unknown> | undefined): boolean;
    };
    const flag = { keepTechniqueSelection: true };
    expect(app.shouldKeepSelection('imperative', flag)).toBeTrue();
    expect(app.shouldKeepSelection('popstate', flag)).toBeFalse(); // Back must not resurrect
    expect(app.shouldKeepSelection('hashchange', flag)).toBeTrue();
    expect(app.shouldKeepSelection('imperative', undefined)).toBeFalse();
  });

  it('PanelNavService.open forwards keepTechniqueSelection as navigation state', () => {
    const panelNav = TestBed.inject(PanelNavService);
    const nav = spyOn(router, 'navigate').and.resolveTo(true);
    panelNav.open('matrix', { keepTechniqueSelection: true });
    expect(nav.calls.mostRecent().args[1]?.state).toEqual({ keepTechniqueSelection: true });
    nav.calls.reset();
    panelNav.open('matrix');
    expect(nav.calls.mostRecent().args[1]?.state).toBeUndefined();
  });
});
