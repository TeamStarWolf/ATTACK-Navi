// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { signal, WritableSignal } from '@angular/core';
import { IMPL_FILTER_TITLE, MatrixControlsComponent, VIEW_MENU_MARGIN, VIEW_MENU_WIDTH, placeViewMenu } from './matrix-controls.component';
import { PostureService } from '../../services/posture.service';
import { DEFAULT_HEATMAP_MODE, FilterService, HeatmapMode } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { HttpClient } from '@angular/common/http';
import { MatrixControlService } from '../../services/matrix-control.service';
import { AttackCveService } from '../../services/attack-cve.service';
import { ViewpointService } from '../../services/viewpoint.service';
import { LibraryLayerService } from '../../services/library-layer.service';
import { UserLayerService } from '../../services/user-layer.service';
import { HEATMAP_MODES, heatmapModeDef, heatmapShortLabel, lensAvailability, unavailableLenses } from '../../models/heatmap-modes';
import { NO_OWNER_DATA_LINE } from '../../models/lens-registry';
import { LensCardService } from '../../services/lens-card.service';
import { SettingsService } from '../../services/settings.service';
import { THREAT_GAP_TOGGLE_LABEL } from '../../models/posture/gap';

describe('MatrixControlsComponent', () => {
  let component: MatrixControlsComponent;
  let fixture: ComponentFixture<MatrixControlsComponent>;
  let libraryStub: {
    manifest$: BehaviorSubject<{ file: string; name: string; description: string }[]>;
    manifestLoaded$: BehaviorSubject<boolean>;
    manifestError$: BehaviorSubject<string | null>;
    activeFile$: BehaviorSubject<string | null>;
    setActive: jasmine.Spy;
  };
  /** PostureService.implPartialOnly, the only member the impl= tooltip reads (P2-14). */
  let partialOnly: WritableSignal<{ count: number; via: string[] }>;
  /**
   * PostureService.ownerWords, which gates the Proven and Covered lenses in the
   * picker (§10.4 item 14). True by default so the other tests see every lens;
   * the 'owner-data gate' block sets it false for an empty user.
   */
  let ownerWords: WritableSignal<boolean>;
  let userLayerStub: {
    activeLayer$: BehaviorSubject<{ id: string; name: string; description: string } | null>;
    activeLayer: { id: string; name: string; description: string } | null;
    clearActive: jasmine.Spy;
  };

  beforeEach(() => {
    partialOnly = signal<{ count: number; via: string[] }>({ count: 0, via: [] });
    ownerWords = signal(true);
    libraryStub = {
      manifest$: new BehaviorSubject<{ file: string; name: string; description: string }[]>([]),
      manifestLoaded$: new BehaviorSubject(false),
      manifestError$: new BehaviorSubject<string | null>(null),
      activeFile$: new BehaviorSubject<string | null>(null),
      setActive: jasmine.createSpy('setActive'),
    };
    userLayerStub = {
      activeLayer$: new BehaviorSubject<{ id: string; name: string; description: string } | null>(null),
      activeLayer: null,
      clearActive: jasmine.createSpy('clearActive').and.callFake(() => {
        userLayerStub.activeLayer = null;
        userLayerStub.activeLayer$.next(null);
      }),
    };
    TestBed.configureTestingModule({
      imports: [MatrixControlsComponent],
      providers: [
        { provide: FilterService, useValue: {
            activeMitigationFilters$: new BehaviorSubject([]),
            techniqueQuery$: new BehaviorSubject(''),
            searchScope$: new BehaviorSubject('name'),
            searchFilterMode$: new BehaviorSubject(false),
            platformMulti$: new BehaviorSubject(new Set()),
            activeDataSource$: new BehaviorSubject(null),
            implStatusFilter$: new BehaviorSubject(null),
            heatmapMode$: new BehaviorSubject('coverage'),
            ownerDataPresent: new BehaviorSubject(false),
            sortMode$: new BehaviorSubject('alpha'),
            dimUncovered$: new BehaviorSubject(false),
            threatGapOverlay$: new BehaviorSubject(false),
            activeThreatGroupIds$: new BehaviorSubject(new Set()),
            setTechniqueQuery: jasmine.createSpy(),
            setHeatmapMode: jasmine.createSpy(),
            toggleThreatGapOverlay: jasmine.createSpy('toggleThreatGapOverlay'),
        }},
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null), currentDomain$: new BehaviorSubject('enterprise') }},
        { provide: MatrixControlService, useValue: {
            multiSelectMode$: new BehaviorSubject(false),
            expandAll: jasmine.createSpy(),
            collapseAll: jasmine.createSpy(),
            toggleMultiSelect: jasmine.createSpy(),
            requestGapView: jasmine.createSpy(),
        }},
        { provide: AttackCveService, useValue: { getMappingForCve: () => null }},
        { provide: LibraryLayerService, useValue: libraryStub },
        { provide: UserLayerService, useValue: userLayerStub },
        { provide: PostureService, useValue: { implPartialOnly: partialOnly, ownerWords } },
        { provide: ViewpointService, useValue: {
            viewpoint$: new BehaviorSubject({
              id: 'analyst', label: 'Analyst', short: 'Analyst', icon: 'compass',
              tagline: '', defaultLens: 'unified', homeRoute: '/matrix',
              featuredLenses: ['unified', 'coverage', 'risk', 'detection'],
            }),
        }},
      ],
    });
    fixture = TestBed.createComponent(MatrixControlsComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('is created', () => {
    expect(component).toBeTruthy();
  });

  // P2-19: the View button is highlighted when the lens is not the effective
  // default (Posture with owner data, else Prevalence).
  it('highlights the View button against the effective default lens (P2-19)', () => {
    const filter = TestBed.inject(FilterService) as unknown as {
      heatmapMode$: BehaviorSubject<HeatmapMode>; ownerDataPresent: BehaviorSubject<boolean>;
    };
    const active = (): boolean => {
      fixture.detectChanges();
      return (fixture.nativeElement.querySelector('.heatmap-btn') as HTMLElement).classList.contains('active');
    };
    filter.heatmapMode$.next('frequency');
    expect(component.defaultHeatmapMode).toBe(DEFAULT_HEATMAP_MODE);
    expect(active()).withContext('frequency, no owner data').toBeFalse();
    filter.heatmapMode$.next('posture');
    expect(active()).withContext('posture, no owner data').toBeTrue();
    filter.ownerDataPresent.next(true);
    expect(component.defaultHeatmapMode).toBe('posture');
    expect(active()).withContext('posture, owner data').toBeFalse();
    filter.heatmapMode$.next('frequency');
    expect(active()).withContext('frequency, owner data').toBeTrue();
  });

  it('renders the technique search with the canonical placeholder', () => {
    const input = fixture.nativeElement.querySelector('input[placeholder*="Search techniques"]');
    expect(input).toBeTruthy();
  });

  it('heatmap dropdown lists every mode from the single source of truth', () => {
    component.toggleViewMenu();
    fixture.detectChanges();
    const buttons = fixture.nativeElement.querySelectorAll('.heatmap-mode-btn');
    expect(buttons.length).toBe(HEATMAP_MODES.length);
  });

  // RP-F item 5: with the drawer open at 1440x900 the View button wraps to the row's
  // left end; the right-aligned absolute menu opened at x = -277, clipped by the
  // workspace and under the 260 px rail, whose labels took the clicks.
  describe('View menu placement (RP-F item 5)', () => {
    const RAIL_RIGHT = 260;

    it('the RP-F geometry: the menu starts at the row (the rail edge), not under the rail', () => {
      const p = placeViewMenu({ right: 382.84, bottom: 165.94 }, RAIL_RIGHT, { width: 1440, height: 900 });
      expect(p.left).toBe(RAIL_RIGHT);
      expect(p.width).toBe(VIEW_MENU_WIDTH);
      expect(p.left + p.width).toBeLessThanOrEqual(1440 - VIEW_MENU_MARGIN);
      expect(p.top).toBeCloseTo(169.94, 2);
      expect(p.top + p.maxHeight).toBeLessThanOrEqual(900 - VIEW_MENU_MARGIN);
    });

    it('still right-aligns under its button when there is room (unchanged look)', () => {
      const p = placeViewMenu({ right: 1200, bottom: 100 }, RAIL_RIGHT, { width: 1440, height: 900 });
      expect(p.left + p.width).toBe(1200);
      expect(p.width).toBe(VIEW_MENU_WIDTH);
    });

    it('never runs past the viewport right edge, and narrows to fit between the row and the edge', () => {
      const p = placeViewMenu({ right: 1430, bottom: 100 }, 900, { width: 1440, height: 900 });
      expect(p.left).toBe(900);
      expect(p.left + p.width).toBe(1440 - VIEW_MENU_MARGIN);
      const phone = placeViewMenu({ right: 360, bottom: 120 }, 0, { width: 375, height: 812 });
      expect(phone.left).toBe(VIEW_MENU_MARGIN);
      expect(phone.left + phone.width).toBe(375 - VIEW_MENU_MARGIN);
    });

    it('opening the menu places it fixed from the button, and a window resize re-places it', () => {
      const host = fixture.nativeElement as HTMLElement;
      component.toggleViewMenu();
      fixture.detectChanges();
      const menu = host.querySelector<HTMLElement>('.views-menu')!;
      expect(getComputedStyle(menu).position).toBe('fixed');
      expect(Number(getComputedStyle(menu).zIndex)).toBeGreaterThan(100);   // above --z-rail (50) and --z-sidebar (100)
      const placed = component.viewMenuPlacement!;
      expect(placed).not.toBeNull();
      expect(menu.style.left).toBe(`${placed.left}px`);
      expect(menu.style.top).toBe(`${placed.top}px`);
      expect(placed.left).toBeGreaterThanOrEqual(Math.max(host.getBoundingClientRect().left, VIEW_MENU_MARGIN));
      const button = host.querySelector('.heatmap-btn')!.getBoundingClientRect();
      expect(placed).toEqual(placeViewMenu(button, host.getBoundingClientRect().left, { width: window.innerWidth, height: window.innerHeight }));

      component.viewMenuPlacement = null;
      window.dispatchEvent(new Event('resize'));
      expect(component.viewMenuPlacement).withContext('re-placed on resize while open').not.toBeNull();

      component.toggleViewMenu();
      expect(component.viewMenuPlacement).withContext('cleared on close').toBeNull();
      window.dispatchEvent(new Event('resize'));
      expect(component.viewMenuPlacement).withContext('a closed menu is not placed').toBeNull();
    });
  });

  it('gap view request goes through MatrixControlService', () => {
    const svc = TestBed.inject(MatrixControlService) as any;
    component.onGapView();
    expect(svc.requestGapView).toHaveBeenCalled();
  });

  // P2-17: the legacy Gap view keeps its behaviour under an honest name, and
  // the two overlay toggles sit with the matrix display toggles (no new menu).
  describe('My marks and Threat gaps toggles; Unmapped techniques (P2-17)', () => {
    const menu = (): HTMLElement => {
      component.toggleViewMenu();
      fixture.detectChanges();
      return fixture.nativeElement.querySelector('.views-menu') as HTMLElement;
    };
    const matrixGroup = (m: HTMLElement): HTMLElement =>
      m.querySelector('.my-marks-toggle')!.closest('.view-actions') as HTMLElement;

    beforeEach(() => localStorage.removeItem('mitre-nav-settings-v1'));
    afterEach(() => localStorage.removeItem('mitre-nav-settings-v1'));

    it("relabels the Gap view entry 'Unmapped techniques (no ATT&CK mitigation)' and keeps its action", () => {
      const m = menu();
      const btn = m.querySelector('.unmapped-view-btn') as HTMLButtonElement;
      expect(btn.textContent!.trim()).toBe('⚠ Unmapped techniques (no ATT&CK mitigation)');
      expect(m.textContent).not.toContain('Gap view');
      btn.click();
      expect((TestBed.inject(MatrixControlService) as any).requestGapView).toHaveBeenCalled();
    });

    it('puts both toggles in the Matrix display toggles, with their exact labels', () => {
      const group = matrixGroup(menu());
      expect(group.querySelector('.threat-gaps-toggle')).not.toBeNull();
      expect(group.querySelector('.unmapped-view-btn')).not.toBeNull();
      expect(group.querySelector('.my-marks-toggle')!.textContent!.trim()).toBe('My marks');
      expect(group.querySelector('.threat-gaps-toggle')!.textContent!.trim()).toBe(THREAT_GAP_TOGGLE_LABEL);
      expect(group.querySelector('.threat-gaps-toggle')!.textContent!.trim())
        .toBe('Threat gaps: threat-relevant, posture None, Known only or contradicted');
    });

    it('Threat gaps toggles the session overlay and reflects it', () => {
      const filter = TestBed.inject(FilterService) as any;
      const m = menu();
      const btn = m.querySelector('.threat-gaps-toggle') as HTMLButtonElement;
      expect(btn.getAttribute('aria-pressed')).toBe('false');
      btn.click();
      expect(filter.toggleThreatGapOverlay).toHaveBeenCalledTimes(1);
      filter.threatGapOverlay$.next(true);
      fixture.detectChanges();
      expect(btn.classList).toContain('active');
      expect(btn.getAttribute('aria-pressed')).toBe('true');
    });

    it('My marks flips AppSettings.cellDisplay.myMarks (default on) and keeps the other cell settings', () => {
      const settings = TestBed.inject(SettingsService);
      expect(settings.current.cellDisplay.myMarks).toBeTrue();
      const m = menu();
      const btn = m.querySelector('.my-marks-toggle') as HTMLButtonElement;
      expect(btn.getAttribute('aria-pressed')).toBe('true');
      btn.click();
      fixture.detectChanges();
      expect(settings.current.cellDisplay.myMarks).toBeFalse();
      expect(settings.current.cellDisplay.noteDot).toBeTrue();
      expect(btn.getAttribute('aria-pressed')).toBe('false');
      btn.click();
      fixture.detectChanges();
      expect(settings.current.cellDisplay.myMarks).toBeTrue();
    });
  });

  it('shows no pinned featured group for the neutral analyst viewpoint', () => {
    component.toggleViewMenu();
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector('.featured-lenses')).toBeFalsy();
  });

  it('pins the active viewpoint featured lenses at the top of the lens menu', () => {
    const vp = TestBed.inject(ViewpointService) as any;
    vp.viewpoint$.next({
      id: 'vuln', label: 'Vulnerability & Exposure', short: 'Vuln', icon: 'shield-alert',
      tagline: '', defaultLens: 'kev', homeRoute: '/exposure',
      featuredLenses: ['kev', 'cve', 'epss'],
    });
    component.toggleViewMenu();
    fixture.detectChanges();

    const pinned = fixture.nativeElement.querySelector('.featured-lenses');
    expect(pinned).toBeTruthy();
    expect(pinned.querySelector('.featured-header').textContent).toContain('Vulnerability & Exposure');
    expect(pinned.querySelectorAll('.featured-lens-btn').length).toBe(3);
    // The full lens list is still present, unchanged.
    expect(fixture.nativeElement.querySelectorAll('.heatmap-mode-btn').length).toBe(HEATMAP_MODES.length);
  });

  describe('library layers in the View menu', () => {
    const LAYERS = [
      { file: 'web-application-attacks.json', name: 'TeamStarWolf - Web Application Attacks', description: 'curated' },
      { file: 'cloud-attacks.json', name: 'TeamStarWolf - Cloud Attacks', description: 'curated' },
    ];
    const IMPORTED = { id: 'layer-1', name: 'Imported Layer', description: 'from a file' };

    function menu(): HTMLElement {
      component.toggleViewMenu();
      fixture.detectChanges();
      return fixture.nativeElement;
    }

    it('says the list is loading until the manifest settles, then that it is empty', () => {
      let el = menu();
      expect(el.querySelector('.library-status')?.textContent).toContain('Loading');
      libraryStub.manifestLoaded$.next(true);
      fixture.detectChanges();
      el = fixture.nativeElement;
      expect(el.querySelector('.library-status')?.textContent).toContain('No library layers');
    });

    it('says the list failed, with the reason, when the manifest request fails (E1.3)', () => {
      let el = menu();
      expect(el.querySelector('.library-status')?.textContent).toContain('Loading');
      libraryStub.manifestError$.next('HTTP 404 Not Found');
      fixture.detectChanges();
      el = fixture.nativeElement;
      const text = el.querySelector('.library-status')?.textContent ?? '';
      expect(text).toContain('did not load');
      expect(text).toContain('HTTP 404 Not Found');
      expect(text).not.toContain('Loading');
    });

    it('picking a curated layer unloads an active imported layer so the pick is what shows', () => {
      const filterSvc = TestBed.inject(FilterService) as any;
      userLayerStub.activeLayer = IMPORTED;
      userLayerStub.activeLayer$.next(IMPORTED);
      libraryStub.manifest$.next(LAYERS);
      libraryStub.manifestLoaded$.next(true);

      component.pickLibraryLayer('cloud-attacks.json');

      expect(userLayerStub.clearActive).toHaveBeenCalled();
      expect(libraryStub.setActive).toHaveBeenCalledWith('cloud-attacks.json');
      expect(filterSvc.setHeatmapMode).toHaveBeenCalledWith('library');
    });

    it('does not touch the user layer service when no imported layer is active', () => {
      component.pickLibraryLayer('cloud-attacks.json');
      expect(userLayerStub.clearActive).not.toHaveBeenCalled();
      expect(libraryStub.setActive).toHaveBeenCalledWith('cloud-attacks.json');
    });

    it('shows the active imported layer with an unload action, and no curated layer as active', () => {
      const filterSvc = TestBed.inject(FilterService) as any;
      filterSvc.heatmapMode$.next('library');
      libraryStub.manifest$.next(LAYERS);
      libraryStub.manifestLoaded$.next(true);
      libraryStub.activeFile$.next('cloud-attacks.json');
      userLayerStub.activeLayer = IMPORTED;
      userLayerStub.activeLayer$.next(IMPORTED);

      const el = menu();
      expect(el.querySelector('.user-layer-name')?.textContent).toContain('Imported Layer');
      // The curated button is not highlighted while the imported layer outranks it.
      expect(el.querySelectorAll('.heatmap-mode-btn.active').length).toBe(1); // the 'library' mode itself

      (el.querySelector('.user-layer-unload') as HTMLButtonElement).click();
      fixture.detectChanges();
      expect(userLayerStub.clearActive).toHaveBeenCalled();
      expect(fixture.nativeElement.querySelector('.user-layer-name')).toBeNull();
      // With the imported layer gone, the picked curated layer is highlighted again.
      expect(fixture.nativeElement.querySelectorAll('.heatmap-mode-btn.active').length).toBe(2);
    });
  });

  it('trigger label uses the short name from heatmap-modes', () => {
    // The 'coverage' key now surfaces as "Mitigations" (mitigation is one lens,
    // not the app's headline); the key itself is unchanged.
    expect(component.heatmapShort).toBe('Mitigations mapped');
  });

  // E1.2 PR 2: lenses without data for the domain on screen are disabled with
  // a stated reason, and every lens has a '?' that opens its definition card.
  describe('lens availability and definition cards (E1.2)', () => {
    const dataSvc = () => TestBed.inject(DataService) as unknown as { currentDomain$: BehaviorSubject<string> };
    function openMenuIn(domain: string): HTMLElement {
      dataSvc().currentDomain$.next(domain);
      component.toggleViewMenu();
      fixture.detectChanges();
      return fixture.nativeElement;
    }
    const lensButton = (el: HTMLElement, mode: string): HTMLButtonElement =>
      el.querySelector(`.lens-item[data-lens="${mode}"] .heatmap-mode-btn`) as HTMLButtonElement;

    it('switching to ICS disables every lens whose domains[] lacks ics, each with an announced reason', () => {
      const el = openMenuIn('ics');
      const expected = unavailableLenses('ics');
      expect(expected.length).toBe(23);
      const disabled = Array.from(el.querySelectorAll<HTMLButtonElement>('.heatmap-groups .heatmap-mode-btn[aria-disabled="true"]'));
      expect(disabled.length).toBe(expected.length);
      for (const def of expected) {
        const btn = lensButton(el, def.value);
        expect(btn.getAttribute('aria-disabled')).withContext(def.value).toBe('true');
        expect(btn.classList).withContext(def.value).toContain('unavailable');
        expect(btn.textContent).withContext(def.value).toContain('n/a for ICS ATT&CK');
        const reasonEl = el.querySelector('#' + btn.getAttribute('aria-describedby')) as HTMLElement;
        expect(reasonEl).withContext(def.value).toBeTruthy();
        expect(reasonEl.textContent!.trim()).withContext(def.value).toBe(lensAvailability(def, 'ics').reason!);
        expect(btn.title).withContext(def.value).toBe(lensAvailability(def, 'ics').reason!);
      }
      for (const def of HEATMAP_MODES.filter((m) => m.domains.includes('ics'))) {
        const btn = lensButton(el, def.value);
        expect(btn.hasAttribute('aria-disabled')).withContext(def.value).toBeFalse();
        expect(btn.hasAttribute('aria-describedby')).withContext(def.value).toBeFalse();
      }
      expect(el.querySelector('.lens-na-summary')!.textContent).toContain('23 of 36 lenses have no ICS ATT&CK data');
      expect(el.querySelector('.lens-na-summary')!.getAttribute('role')).toBe('status');
    });

    it('a disabled lens cannot be picked; an available one can', () => {
      const filterSvc = TestBed.inject(FilterService) as any;
      const el = openMenuIn('ics');
      lensButton(el, 'sigma').click();
      expect(filterSvc.setHeatmapMode).not.toHaveBeenCalled();
      expect(component.showViewMenu).toBeTrue();
      lensButton(el, 'frequency').click();
      expect(filterSvc.setHeatmapMode).toHaveBeenCalledWith('frequency');
    });

    it('re-enables the lenses on the way back to Enterprise', () => {
      const el = openMenuIn('ics');
      dataSvc().currentDomain$.next('enterprise');
      fixture.detectChanges();
      const disabled = Array.from(el.querySelectorAll('.heatmap-groups .heatmap-mode-btn[aria-disabled="true"]'));
      expect(disabled.map((b) => b.closest('.lens-item')!.getAttribute('data-lens'))).toEqual(['f3-origin']);
    });

    it('marks the trigger when the active lens is n/a here', () => {
      const filterSvc = TestBed.inject(FilterService) as any;
      filterSvc.heatmapMode$.next('sigma');
      openMenuIn('ics');
      expect(component.activeLensUnavailable).toBeTrue();
      expect((fixture.nativeElement.querySelector('.heatmap-btn') as HTMLElement).textContent).toContain('(n/a)');
    });

    it("gives every lens a '?' that opens its definition card, disabled lenses included", () => {
      const cards = TestBed.inject(LensCardService);
      const el = openMenuIn('ics');
      const helps = el.querySelectorAll<HTMLButtonElement>('.lens-item .lens-help-btn');
      expect(helps.length).toBe(HEATMAP_MODES.length);
      const sigmaHelp = el.querySelector('.lens-item[data-lens="sigma"] .lens-help-btn') as HTMLButtonElement;
      expect(sigmaHelp.getAttribute('aria-label')).toBe('What is the Sigma Rules lens?');
      expect(sigmaHelp.getAttribute('aria-haspopup')).toBe('dialog');
      sigmaHelp.click();
      expect(cards.openMode()).toBe('sigma');
      cards.close();
    });

    it('disables featured lenses with the same reason', () => {
      const vp = TestBed.inject(ViewpointService) as any;
      vp.viewpoint$.next({
        id: 'vuln', label: 'Vulnerability & Exposure', short: 'Vuln', icon: 'shield-alert',
        tagline: '', defaultLens: 'kev', homeRoute: '/exposure',
        featuredLenses: ['kev', 'frequency'],
      });
      const el = openMenuIn('ics');
      const [kev, freq] = Array.from(el.querySelectorAll<HTMLButtonElement>('.featured-lens-btn'));
      expect(kev.getAttribute('aria-disabled')).toBe('true');
      const reason = el.querySelector('#' + kev.getAttribute('aria-describedby'))!.textContent!.trim();
      expect(reason).toBe(lensAvailability(HEATMAP_MODES.find((m) => m.value === 'kev')!, 'ics').reason!);
      expect(freq.hasAttribute('aria-disabled')).toBeFalse();
    });
  });

  // Plan P1 row E1.6: "data-source ids are normalised case-insensitively (macOS:unifiedlog
  // vs macos:unifiedlog)"; acceptance "the data-source filter lists each component once".
  // The bundle goes through the production parser; the bundled releases are checked in
  // utils/data-source-names.spec.ts.
  describe('data-source filter (E1.6)', () => {
    const dc = (id: string, name: string, logSources: string[]) => ({
      type: 'x-mitre-data-component', id: `x-mitre-data-component--${id}`, name,
      x_mitre_log_sources: logSources.map((n) => ({ name: n, channel: 'x' })),
    });
    // The upstream spells the unified log both ways on one source each.
    const BUNDLE = {
      objects: [
        dc('a', 'File Access', ['macOS:unifiedlog', 'macos:unifiedlog']),
        dc('b', 'Driver Metadata', ['macos:unifiedlog']),
        dc('c', 'Process Creation', ['WinEventLog:Sysmon']),
        dc('d', 'Network Connection Creation', ['NSM:FLow', 'NSM:Flow', 'NSM:Flow']),
      ],
    };
    const options = () => Array.from(fixture.nativeElement.querySelectorAll('.ds-select option') as NodeListOf<HTMLOptionElement>)
      .map((o) => o.textContent!.trim())
      .filter((t) => t !== 'All data sources');

    beforeEach(() => {
      // The production parser; the DataService token itself is stubbed above.
      const parser = new DataService(null as unknown as HttpClient) as unknown as { parseBundle(b: unknown): unknown };
      (TestBed.inject(DataService) as any).domain$.next(parser.parseBundle(BUNDLE));
      fixture.detectChanges();
    });

    it('lists each data source once, in one spelling, however the bundle spells it', () => {
      expect(options()).toEqual(['NSM:Flow', 'WinEventLog:Sysmon', 'macos:unifiedlog']);
      const keys = options().map((o) => o.toLowerCase());
      expect(new Set(keys).size).toBe(keys.length);
    });

    it('selects the listed spelling when a share link carries another one', () => {
      (TestBed.inject(FilterService) as any).activeDataSource$.next('macOS:unifiedlog');
      expect(component.selectedDataSource).toBe('macos:unifiedlog');
    });

    it('selects the listed spelling on a cold deep link, where the filter arrives before the domain', () => {
      const data = TestBed.inject(DataService) as any;
      data.domain$.next(null);
      (TestBed.inject(FilterService) as any).activeDataSource$.next('macOS:unifiedlog');
      const parser = new DataService(null as unknown as HttpClient) as unknown as { parseBundle(b: unknown): unknown };
      data.domain$.next(parser.parseBundle(BUNDLE));
      expect(component.selectedDataSource).toBe('macos:unifiedlog');
      fixture.detectChanges();
      const select = fixture.nativeElement.querySelector('.ds-select') as HTMLSelectElement;
      return fixture.whenStable().then(() => {
        fixture.detectChanges();
        expect(select.value).toBe('macos:unifiedlog');
      });
    });
  });
  describe('impl= tooltip (P2-14, breadth guard)', () => {
    const implSelect = (): HTMLSelectElement => {
      const el = Array.from(fixture.nativeElement.querySelectorAll('select.filter-select') as NodeListOf<HTMLSelectElement>)
        .find((s) => s.title.startsWith('Filter by implementation status'));
      if (!el) throw new Error('impl= select not rendered');
      return el;
    };
    const setFilter = (v: string | null): void => {
      (TestBed.inject(FilterService) as any).implStatusFilter$.next(v);
      fixture.detectChanges();
    };

    it('says broad mitigations count as partial and that Implemented matches full implementation only', () => {
      expect(IMPL_FILTER_TITLE).toContain('Broad mitigations count as partial');
      expect(IMPL_FILTER_TITLE).toContain('matches none of these values');
      expect(IMPL_FILTER_TITLE).toContain('Implemented matches full implementation only');
      expect(component.implFilterTitle).toBe(IMPL_FILTER_TITLE);
      expect(implSelect().title).toBe(IMPL_FILTER_TITLE);
    });

    it('keeps the base text with no value selected, even while partial-only techniques exist', () => {
      partialOnly.set({ count: 4, via: ['M1038'] });
      setFilter(null);
      expect(component.implFilterTitle).toBe(IMPL_FILTER_TITLE);
      expect(implSelect().title).toBe(IMPL_FILTER_TITLE);
    });

    it('keeps the base text with a value selected when no technique is partial only', () => {
      setFilter('implemented');
      expect(component.implFilterTitle).toBe(IMPL_FILTER_TITLE);
    });

    it('names the partial-only techniques and their broad mitigations while a value is selected', () => {
      partialOnly.set({ count: 79, via: ['M1026', 'M1038'] });
      setFilter('implemented');
      const expected = `${IMPL_FILTER_TITLE} Now 79 techniques are implemented, partial via M1026, M1038 and not shown as a match.`;
      expect(component.implFilterTitle).toBe(expected);
      expect(implSelect().title).toBe(expected);
    });

    it('uses the singular for one partial-only technique', () => {
      partialOnly.set({ count: 1, via: ['M1038'] });
      setFilter('in-progress');
      expect(component.implFilterTitle)
        .toBe(`${IMPL_FILTER_TITLE} Now 1 technique is implemented, partial via M1038 and not shown as a match.`);
    });
  });

  // Design §10.4 item 14: rung words never appear for an empty user. The
  // Proven and Covered lenses are named for a rung, so the picker offers and
  // names them only once owner data exists (lensNameVisible over
  // PostureService.ownerWords, the rule the settings sentence also reads).
  describe('owner-data gate on the Proven and Covered lenses (§10.4 item 14)', () => {
    const OWNER_WORD_MODES = ['proven', 'covered'];
    const openMenu = (): HTMLElement => {
      component.toggleViewMenu();
      fixture.detectChanges();
      return fixture.nativeElement;
    };
    /** Every string a reader sees or hears in the controls: the text, and title, aria-label, placeholder and alt. */
    const visibleStrings = (el: HTMLElement): string[] => {
      const out = [el.textContent ?? ''];
      for (const node of Array.from(el.querySelectorAll('*'))) {
        for (const attr of ['title', 'aria-label', 'placeholder', 'alt']) {
          const v = node.getAttribute(attr);
          if (v) out.push(v);
        }
      }
      return out;
    };
    const rungHits = (el: HTMLElement): string[] => visibleStrings(el).filter((v) => /\b(?:covered|proven)\b/i.test(v));
    const listed = (el: HTMLElement): string[] =>
      Array.from(el.querySelectorAll('.heatmap-groups .lens-item')).map((i) => i.getAttribute('data-lens')!);
    const lensButton = (el: HTMLElement, mode: string): HTMLButtonElement =>
      el.querySelector(`.lens-item[data-lens="${mode}"] .heatmap-mode-btn`) as HTMLButtonElement;
    const featureLenses = (featuredLenses: string[]): void => {
      (TestBed.inject(ViewpointService) as any).viewpoint$.next({
        id: 'purple', label: 'Purple Team', short: 'Purple', icon: 'swords',
        tagline: '', defaultLens: 'frequency', homeRoute: '/matrix', featuredLenses,
      });
    };

    it('an empty user: the picker lists neither lens, and no covered or proven string renders', () => {
      ownerWords.set(false);
      const el = openMenu();
      const shown = listed(el);
      expect(shown.length).toBe(HEATMAP_MODES.length - OWNER_WORD_MODES.length);
      for (const m of OWNER_WORD_MODES) expect(shown).withContext(m).not.toContain(m);
      expect(el.querySelectorAll('.heatmap-mode-btn').length).toBe(HEATMAP_MODES.length - OWNER_WORD_MODES.length);
      expect(rungHits(el)).toEqual([]);
    });

    it('with owner data: both lenses are listed, named and titled with their question', () => {
      const el = openMenu();
      expect(listed(el).length).toBe(HEATMAP_MODES.length);
      for (const m of OWNER_WORD_MODES) {
        const def = heatmapModeDef(m as HeatmapMode)!;
        expect(lensButton(el, m).textContent!.trim()).withContext(m).toBe(def.label);
        expect(lensButton(el, m).title).withContext(m).toBe(def.question);
        const help = el.querySelector(`.lens-item[data-lens="${m}"] .lens-help-btn`) as HTMLButtonElement;
        expect(help.getAttribute('aria-label')).withContext(m).toBe(`What is the ${def.label} lens?`);
      }
    });

    it('offers both lenses as soon as owner data appears, and withdraws them when it is cleared', () => {
      ownerWords.set(false);
      const el = openMenu();
      expect(listed(el)).not.toContain('covered');
      ownerWords.set(true);
      fixture.detectChanges();
      expect(listed(el)).toContain('covered');
      expect(listed(el)).toContain('proven');
      ownerWords.set(false);
      fixture.detectChanges();
      expect(listed(el)).not.toContain('proven');
    });

    it("titles the Posture lens 'No data of yours recorded' for an empty user (its question names Covered)", () => {
      ownerWords.set(false);
      let el = openMenu();
      expect(lensButton(el, 'posture').title).toBe(NO_OWNER_DATA_LINE);
      component.toggleViewMenu();
      ownerWords.set(true);
      fixture.detectChanges();
      el = openMenu();
      expect(lensButton(el, 'posture').title).toBe(heatmapModeDef('posture')!.question);
    });

    it('pins a featured Proven or Covered lens only with owner data', () => {
      featureLenses(['proven', 'covered', 'frequency']);
      ownerWords.set(false);
      let el = openMenu();
      const labels = (): string[] =>
        Array.from(el.querySelectorAll('.featured-lens-btn')).map((b) => b.textContent!.trim());
      expect(labels()).toEqual([heatmapModeDef('frequency')!.label]);
      expect(rungHits(el)).toEqual([]);
      component.toggleViewMenu();
      ownerWords.set(true);
      fixture.detectChanges();
      el = openMenu();
      expect(labels()).toEqual(['proven', 'covered', 'frequency'].map((m) => heatmapModeDef(m as HeatmapMode)!.label));
    });

    for (const mode of OWNER_WORD_MODES) {
      it(`the View button shows the default lens's name for heat=${mode} with no owner data`, () => {
        (TestBed.inject(FilterService) as any).heatmapMode$.next(mode);
        ownerWords.set(false);
        fixture.detectChanges();
        const btn = (): HTMLElement => fixture.nativeElement.querySelector('.heatmap-btn');
        expect(btn().textContent).toContain(heatmapShortLabel(DEFAULT_HEATMAP_MODE));
        expect(rungHits(fixture.nativeElement)).toEqual([]);
        ownerWords.set(true);
        fixture.detectChanges();
        expect(btn().textContent).toContain(heatmapShortLabel(mode as HeatmapMode));
      });
    }

    it('counts only the lenses on offer in the n/a summary', () => {
      ownerWords.set(false);
      (TestBed.inject(DataService) as any).currentDomain$.next('ics');
      let el = openMenu();
      const summary = (): string => el.querySelector('.lens-na-summary')!.textContent!;
      expect(summary()).toContain(`23 of ${HEATMAP_MODES.length - OWNER_WORD_MODES.length} lenses have no ICS ATT&CK data`);
      component.toggleViewMenu();
      ownerWords.set(true);
      fixture.detectChanges();
      el = openMenu();
      expect(summary()).toContain(`23 of ${HEATMAP_MODES.length} lenses have no ICS ATT&CK data`);
    });
  });
});
