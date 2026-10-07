// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
import { TestBed, ComponentFixture } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { MatrixControlsComponent } from './matrix-controls.component';
import { FilterService } from '../../services/filter.service';
import { DataService } from '../../services/data.service';
import { MatrixControlService } from '../../services/matrix-control.service';
import { AttackCveService } from '../../services/attack-cve.service';
import { ViewpointService } from '../../services/viewpoint.service';
import { LibraryLayerService } from '../../services/library-layer.service';
import { UserLayerService } from '../../services/user-layer.service';
import { HEATMAP_MODES } from '../../models/heatmap-modes';

describe('MatrixControlsComponent', () => {
  let component: MatrixControlsComponent;
  let fixture: ComponentFixture<MatrixControlsComponent>;
  let libraryStub: {
    manifest$: BehaviorSubject<{ file: string; name: string; description: string }[]>;
    manifestLoaded$: BehaviorSubject<boolean>;
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
        { provide: DataService, useValue: { domain$: new BehaviorSubject(null) }},
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
    expect(component.heatmapShort).toBe('Mitigations');
  });
});
