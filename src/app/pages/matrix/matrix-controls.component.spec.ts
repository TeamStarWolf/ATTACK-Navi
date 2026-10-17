// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { MatrixControlsComponent } from './matrix-controls.component';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { HttpClient } from '@angular/common/http';
import { MatrixControlService } from '../../services/matrix-control.service';
import { AttackCveService } from '../../services/attack-cve.service';
import { ViewpointService } from '../../services/viewpoint.service';
import { LibraryLayerService } from '../../services/library-layer.service';
import { UserLayerService } from '../../services/user-layer.service';
import { HEATMAP_MODES, lensAvailability, unavailableLenses } from '../../models/heatmap-modes';
import { LensCardService } from '../../services/lens-card.service';

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
  let userLayerStub: {
    activeLayer$: BehaviorSubject<{ id: string; name: string; description: string } | null>;
    activeLayer: { id: string; name: string; description: string } | null;
    clearActive: jasmine.Spy;
  };

  beforeEach(() => {
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
            sortMode$: new BehaviorSubject('alpha'),
            dimUncovered$: new BehaviorSubject(false),
            activeThreatGroupIds$: new BehaviorSubject(new Set()),
            setTechniqueQuery: jasmine.createSpy(),
            setHeatmapMode: jasmine.createSpy(),
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

  it('gap view request goes through MatrixControlService', () => {
    const svc = TestBed.inject(MatrixControlService) as any;
    component.onGapView();
    expect(svc.requestGapView).toHaveBeenCalled();
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
      expect(el.querySelector('.lens-na-summary')!.textContent).toContain('23 of 33 lenses have no ICS ATT&CK data');
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
});
