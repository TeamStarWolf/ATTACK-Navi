// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Component } from '@angular/core';
import { Location } from '@angular/common';
import { TestBed } from '@angular/core/testing';
import { provideHttpClient, withXhr } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { provideLocationMocks } from '@angular/common/testing';
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
const OTHER = { attackId: 'T1003', id: 'T1003', name: 'OS Credential Dumping' } as unknown as Tech;
const tick = (ms = 30): Promise<void> => new Promise((r) => setTimeout(r, ms));

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
          { path: 'dashboard/analytics', component: Blank },
          { path: 'intel/actors', component: Blank },
          { path: 'intel/groups', component: Blank },
          { path: 'detect/sigma', component: Blank },
          { path: 'detect/validation', component: Blank },
          { path: '**', component: Blank },
        ]),
        provideLocationMocks(),
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

  // Back/Forward must NOT resurrect a leftover drawer. A real popstate IS drivable in TestBed
  // via provideLocationMocks() + Router.setUpLocationChangeListener(): PanelNavService pushes the
  // /matrix entry WITH keepTechniqueSelection, so on Back the router restores that saved state —
  // the handler must ignore the flag on popstate. This fails if the NavigationStart handler's
  // navigationTrigger check (app.component.ts) is mutated to a constant.
  it('does not resurrect a leftover drawer on Back (real popstate)', async () => {
    wireHandler();
    router.setUpLocationChangeListener();
    const location = TestBed.inject(Location);
    const panelNav = TestBed.inject(PanelNavService);
    await router.navigateByUrl('/dashboard/analytics');
    filter_.selectTechnique(TECH);
    panelNav.open('matrix', { keepTechniqueSelection: true }); // pushes /matrix WITH keep state
    await tick();
    expect(router.url).toBe('/matrix');
    expect(current()).toBe(TECH);
    await router.navigateByUrl('/intel/actors'); // leave matrix -> leftover clears
    expect(current()).toBeNull();
    filter_.selectTechnique(OTHER); // a fresh selection on the new workspace
    location.back(); // Back to the flagged /matrix entry (its keep state is restored)
    await tick(80);
    expect(router.url).toBe('/matrix');
    expect(current()).toBeNull(); // leftover NOT resurrected
  });

  it('shouldKeepSelection ignores the flag on popstate, honors it imperatively (unit)', () => {
    const app = TestBed.createComponent(AppComponent).componentInstance as unknown as {
      shouldKeepSelection(t: string, s: Record<string, unknown> | undefined): boolean;
    };
    const flag = { keepTechniqueSelection: true };
    expect(app.shouldKeepSelection('imperative', flag)).toBeTrue();
    expect(app.shouldKeepSelection('popstate', flag)).toBeFalse();
    expect(app.shouldKeepSelection('hashchange', flag)).toBeTrue();
    expect(app.shouldKeepSelection('imperative', undefined)).toBeFalse();
  });

  // E2.3 (P2-04): the drawer is scoped to the WORKSPACE (first path segment), not the path.
  describe('workspace scope and Pin (E2.3)', () => {
    it('[AC] the drawer never persists into another workspace: /detect/sigma to /intel/groups closes it', async () => {
      wireHandler();
      await router.navigateByUrl('/detect/sigma');
      filter_.selectTechnique(TECH);
      await router.navigateByUrl('/intel/groups');
      expect(current()).toBeNull();
    });

    it('keeps the drawer on a tab change inside one workspace: /detect/sigma to /detect/validation', async () => {
      wireHandler();
      await router.navigateByUrl('/detect/sigma');
      filter_.selectTechnique(TECH);
      await router.navigateByUrl('/detect/validation');
      expect(current()).toBe(TECH);
    });

    it('a pinned drawer stays open across workspaces; closing it unpins', async () => {
      wireHandler();
      await router.navigateByUrl('/detect/sigma');
      filter_.selectTechnique(TECH);
      filter_.setDrawerPinned(true);
      await router.navigateByUrl('/intel/groups');
      expect(current()).toBe(TECH);
      await router.navigateByUrl('/matrix');
      expect(current()).toBe(TECH);
      filter_.selectTechnique(null); // the close button, Escape
      filter_.selectTechnique(OTHER);
      await router.navigateByUrl('/detect/sigma');
      expect(current()).toBeNull();
    });

    // Regression for #170 under the workspace rule: Back to an entry pushed WITH
    // keepTechniqueSelection restores that stale flag; popstate must still close.
    it('popstate with a stale keep flag still closes (#170 regression)', async () => {
      wireHandler();
      router.setUpLocationChangeListener();
      const location = TestBed.inject(Location);
      const panelNav = TestBed.inject(PanelNavService);
      await router.navigateByUrl('/matrix');
      filter_.selectTechnique(TECH);
      panelNav.open('technique-graph', { keepTechniqueSelection: true }); // pushes /exposure/graph WITH keep state
      await tick();
      expect(router.url).toBe('/exposure/graph');
      expect(current()).toBe(TECH);
      await router.navigateByUrl('/intel/actors'); // another workspace: closes
      expect(current()).toBeNull();
      filter_.selectTechnique(OTHER);
      location.back(); // Back to the flagged /exposure/graph entry
      await tick(80);
      expect(router.url).toBe('/exposure/graph');
      expect(current()).toBeNull();
    });
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
