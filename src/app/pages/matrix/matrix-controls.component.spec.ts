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
import { HEATMAP_MODES } from '../../models/heatmap-modes';

describe('MatrixControlsComponent', () => {
  let component: MatrixControlsComponent;
  let fixture: ComponentFixture<MatrixControlsComponent>;

  beforeEach(() => {
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

  it('trigger label uses the short name from heatmap-modes', () => {
    // The 'coverage' key now surfaces as "Mitigations" (mitigation is one lens,
    // not the app's headline); the key itself is unchanged.
    expect(component.heatmapShort).toBe('Mitigations');
  });
});
