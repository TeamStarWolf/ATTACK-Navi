// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { Component } from '@angular/core';
import { Location } from '@angular/common';
import { TestBed, fakeAsync, flush, tick as fakeTick } from '@angular/core/testing';
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
import { DataService } from './services/data.service';
import { HeatmapMode } from './services/filter.service';
import { HotkeysService } from './services/hotkeys.service';
import { ThemeService } from './services/theme.service';
import { ImplementationService } from './services/implementation.service';
import { PostureService } from './services/posture.service';
import { TECHNIQUE_MARKS_KEY } from './services/technique-marks.service';
import { VALIDATION_RUNS_V2_KEY } from './services/validation.service';
import { MatrixPageComponent } from './pages/matrix/matrix-page.component';
import { MatrixComponent } from './components/matrix/matrix.component';
import { PostureCardComponent } from './components/posture-card/posture-card.component';
import { Domain } from './models/domain';
import { parseFixtureDomain, resetBrowserState } from './testing/lens-harness';

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

// Phase 2 design §3 P2-19 (E2.4): the default-lens rule. Booted through the
// real ngOnInit on the real stores (seeded in localStorage before the services
// are built), with DataService.loadDomain stubbed to emit the lens fixture.
// Precedence: an explicit heat=, then a specialist viewpoint's lens, then D4's
// Posture, then frequency. The banner is P2-05's rule, read off the real
// matrix page.
describe('AppComponent: default-lens rule at boot (P2-19, E2.4)', () => {
  const IMPL_KEY = 'mitre-nav-impl-v1';
  const CONTROLS_KEY = 'mitre-nav-controls-v1';
  const VIEWPOINT_KEY = 'attack-navi-viewpoint';
  let domain: Domain;
  let router: Router;

  const mitigationId = (d: Domain, attackId: string) => d.mitigations.find(m => m.attackId === attackId)!.id;
  const firstParent = (d: Domain) => d.techniques.filter(t => !t.isSubtechnique).sort((a, b) => a.attackId.localeCompare(b.attackId))[0];
  /** One v2 validation run (the store's envelope): a passed own run on the fixture's first parent technique. */
  const oneRun = (d: Domain) => () => localStorage.setItem(VALIDATION_RUNS_V2_KEY, JSON.stringify({
    schema: 2, tombstones: [],
    records: [{
      id: 'p2-19-run', techniqueId: firstParent(d).attackId, runDate: new Date(Date.now() - 86_400_000).toISOString(),
      status: 'passed', attackResult: 'executed', source: 'manual', domain: null, attackVersion: 'unknown',
      createdAt: 'a', updatedAt: 'a', techniqueRef: null, outcomes: [], proofScope: 'own-run', statusFromSource: false,
    }],
  }));
  const impl = (entries: [string, string][]) => () => localStorage.setItem(IMPL_KEY, JSON.stringify(entries));
  const implementedM1047 = (d: Domain) => impl([[mitigationId(d, 'M1047'), 'implemented']]);
  const mark = (d: Domain, source: string) => () => localStorage.setItem(TECHNIQUE_MARKS_KEY, JSON.stringify({
    schema: 2, tombstones: [],
    records: [{ ref: `attack/enterprise/${firstParent(d).attackId}@19.2`, status: 'implemented', source, createdAt: 'a', updatedAt: 'a' }],
  }));
  const nothing = () => () => undefined;

  /**
   * A fresh TestBed over `seed`'s storage. The domain arrives `delayMs` after
   * loadDomain() (synchronously when 0). Theme and hotkeys are not under test.
   */
  function configure(seed: (d: Domain) => () => void, delayMs = 0): void {
    TestBed.resetTestingModule();
    resetBrowserState();
    window.location.hash = '';
    domain = parseFixtureDomain();
    seed(domain)();
    TestBed.configureTestingModule({
      imports: [AppComponent, MatrixPageComponent, PostureCardComponent],
      providers: [
        provideHttpClient(withXhr()),
        provideHttpClientTesting(),
        provideRouter([{ path: 'matrix', component: Blank }, { path: '**', component: Blank }]),
        provideLocationMocks(),
      ],
    });
    // The grid itself is not under test: the matrix page renders its chrome only.
    TestBed.overrideTemplate(MatrixComponent, '');
    const data = TestBed.inject(DataService);
    const emit = () => (data as unknown as { domainSubject: { next(d: Domain): void } }).domainSubject.next(domain);
    spyOn(data, 'loadDomain').and.callFake(() => { if (delayMs) setTimeout(emit, delayMs); else emit(); });
    spyOn(TestBed.inject(ThemeService), 'init');
    spyOn(TestBed.inject(HotkeysService), 'init');
    router = TestBed.inject(Router);
  }

  /** Run the real AppComponent.ngOnInit (no template). */
  function boot(): void {
    TestBed.createComponent(AppComponent).componentInstance.ngOnInit();
  }

  function heat(): HeatmapMode {
    return TestBed.inject(FilterService).getStateSnapshot().heatmapMode as HeatmapMode;
  }

  /** P2-05's banner, read off the real matrix page. */
  function bannerShown(): boolean {
    const page = TestBed.createComponent(MatrixPageComponent);
    page.detectChanges();
    return page.nativeElement.querySelector('.first-glance-banner') !== null;
  }

  /** Boot, run the first navigation (the URL reader) and the URL writer's first pass (300 ms debounce). */
  async function bootAt(url = '/matrix'): Promise<void> {
    boot();
    await router.navigateByUrl(url);
    await tick(400);
  }

  afterEach(() => {
    window.location.hash = '';
    resetBrowserState();
  });

  it('FilterService.defaultLens follows ownerDataPresent: posture with owner data, else frequency', () => {
    configure(nothing);
    const filterService = TestBed.inject(FilterService);
    expect(filterService.defaultLens).toBe('frequency');
    filterService.ownerDataPresent.next(true);
    expect(filterService.defaultLens).toBe('posture');
  });

  it('[AC] a fresh profile opens Prevalence: empty storage gives heat frequency and the banner', async () => {
    configure(nothing);
    await bootAt();
    expect(heat()).toBe('frequency');
    expect(router.url).not.toContain('heat=');
    expect(bannerShown()).toBeTrue();
  });

  it('[AC] one recorded run switches the default to Posture: heat posture, heat=posture in the URL, no banner', async () => {
    configure(oneRun);
    boot();
    expect(heat()).withContext('applied in ngOnInit, before any navigation').toBe('posture');
    await router.navigateByUrl('/matrix');
    await tick(400);
    expect(heat()).toBe('posture');
    expect(router.url).toContain('heat=posture');
    expect(bannerShown()).toBeFalse();
  });

  it('a delayed domain (2 s): posture at boot and still posture after the domain emits (no race, R11)', fakeAsync(() => {
    configure(implementedM1047, 2000);
    boot();
    expect(TestBed.inject(DataService).getCurrentDomain()).withContext('no domain yet').toBeNull();
    expect(heat()).toBe('posture');
    void router.navigateByUrl('/matrix');
    fakeTick(400);
    expect(heat()).toBe('posture');
    fakeTick(2000);
    expect(TestBed.inject(DataService).getCurrentDomain()).withContext('the domain emitted').not.toBeNull();
    fakeTick(400);
    expect(heat()).toBe('posture');
    expect(router.url).toContain('heat=posture');
    flush();
  }));

  it("only a 'planned' mitigation: frequency (D4 exact) and the banner", async () => {
    configure(d => impl([[mitigationId(d, 'M1047'), 'planned']]));
    await bootAt();
    expect(heat()).toBe('frequency');
    expect(bannerShown()).toBeTrue();
  });

  it("only an implemented wizard technique rating ('attack-pattern--*'): posture, no banner", async () => {
    configure(d => impl([[firstParent(d).id, 'implemented']]));
    await bootAt();
    expect(heat()).toBe('posture');
    expect(bannerShown()).toBeFalse();
  });

  for (const source of ['manual', 'layer:imported'] as const) {
    it(`only an implemented technique mark (source ${source}): posture, no banner`, async () => {
      configure(d => mark(d, source));
      await bootAt();
      expect(heat()).toBe('posture');
      expect(bannerShown()).toBeFalse();
    });
  }

  // The owner-decision case (§10.4 item 3), asserted so a change to it is
  // deliberate: controls do not switch the default lens, but they are owner
  // words, so the banner hides while the posture card counts the control.
  it('only one implemented control: frequency and NO banner, while the posture card shows its Covered count (owner decision)', async () => {
    configure(d => () => localStorage.setItem(CONTROLS_KEY, JSON.stringify([{
      id: 'c1', name: 'EDR policy', framework: 'Custom', controlRef: 'c1', description: '', mitigationIds: [mitigationId(d, 'M1047')], status: 'implemented',
    }])));
    await bootAt();
    expect(heat()).toBe('frequency');
    expect(router.url).not.toContain('heat=');
    expect(bannerShown()).toBeFalse();
    const card = TestBed.createComponent(PostureCardComponent);
    card.detectChanges();
    const covered = Number((card.nativeElement as HTMLElement).querySelector('[data-posture="covered"]')?.textContent);
    expect(covered).withContext("the control's Covered count").toBeGreaterThan(0);
    expect(covered).toBe(TestBed.inject(PostureService).rollup().overall.covered);
  });

  it("a stored specialist viewpoint (red) with owner data gives its lens, 'atomic'", async () => {
    configure(d => () => { implementedM1047(d)(); localStorage.setItem(VIEWPOINT_KEY, 'red'); });
    await bootAt();
    expect(heat()).toBe('atomic');
  });

  it('a stored analyst viewpoint (the default lens) with owner data still gives posture', async () => {
    configure(d => () => { implementedM1047(d)(); localStorage.setItem(VIEWPOINT_KEY, 'analyst'); });
    await bootAt();
    expect(heat()).toBe('posture');
  });

  it('an explicit heat=kev wins over D4', async () => {
    configure(implementedM1047);
    window.location.hash = '#/matrix?heat=kev';
    boot();
    expect(heat()).withContext('the rule stands aside for a heat= link').toBe('frequency');
    await router.navigateByUrl('/matrix?heat=kev');
    await tick(400);
    expect(heat()).toBe('kev');
    expect(router.url).toContain('heat=kev');
  });

  // RP-F item 1: a heat= that names no registered lens is not an explicit lens
  // choice. It used to stop the rule (the key existed), boot Frequency with the
  // banner hidden and rewrite the link to heat=frequency, pinning it on every reshare.
  for (const bad of ['bogus', ''] as const) {
    it(`an invalid heat=${bad} with one recorded run still runs D4: posture, heat=posture in the URL, no banner`, async () => {
      configure(oneRun);
      window.location.hash = `#/matrix?heat=${bad}`;
      boot();
      expect(heat()).withContext('the rule treats the invalid heat as absent').toBe('posture');
      await router.navigateByUrl(`/matrix?heat=${bad}`);
      await tick(400);
      expect(heat()).toBe('posture');
      expect(router.url).toContain('heat=posture');
      expect(router.url).not.toContain('heat=frequency');
      expect(router.url).not.toContain('bogus');
      expect(bannerShown()).toBeFalse();
    });

    it(`an invalid heat=${bad} with no owner data: frequency with the banner, and the invalid key is dropped`, async () => {
      configure(nothing);
      window.location.hash = `#/matrix?heat=${bad}`;
      boot();
      await router.navigateByUrl(`/matrix?heat=${bad}`);
      await tick(400);
      expect(heat()).toBe('frequency');
      expect(router.url).not.toContain('heat=');
      expect(bannerShown()).toBeTrue();
    });
  }

  it("an invalid heat=bogus does not stand a stored specialist viewpoint aside: red gives 'atomic'", async () => {
    configure(d => () => { implementedM1047(d)(); localStorage.setItem(VIEWPOINT_KEY, 'red'); });
    window.location.hash = '#/matrix?heat=bogus';
    boot();
    await router.navigateByUrl('/matrix?heat=bogus');
    await tick(400);
    expect(heat()).toBe('atomic');
    expect(router.url).toContain('heat=atomic');
  });

  it('owner data recorded later in the session never switches the lens on screen; the link then names it', async () => {
    configure(nothing);
    await bootAt();
    expect(heat()).toBe('frequency');
    expect(router.url).not.toContain('heat=');
    TestBed.inject(ImplementationService).setStatus(mitigationId(domain, 'M1047'), 'implemented');
    await tick(400);
    expect(TestBed.inject(FilterService).ownerDataPresent.value).toBeTrue();
    expect(heat()).toBe('frequency');
    expect(router.url).toContain('heat=frequency');
  });
});
